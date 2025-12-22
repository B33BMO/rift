use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::{Endpoint, ServerConfig, Connection, RecvStream, SendStream};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use rift_core::config::BeaconServerConfig;
use rift_core::crypto::KeyPair;
use rift_core::protocol::{Message, RegisterRequest, RegisterAck, PeerInfo, ErrorCode, PROTOCOL_VERSION};
use rift_core::peer::{PeerId, NatType};

use crate::discovery::PeerRegistry;
use crate::hole_punch::HolePunchCoordinator;
use crate::relay::RelayManager;

pub struct BeaconServer {
    config: BeaconServerConfig,
    keypair: KeyPair,
    endpoint: Endpoint,
    registry: Arc<PeerRegistry>,
    hole_punch: Arc<HolePunchCoordinator>,
    relay: Arc<RelayManager>,
}

impl BeaconServer {
    /// Get the shared relay manager (for use with RelayServer)
    pub fn relay_manager(&self) -> Arc<RelayManager> {
        self.relay.clone()
    }

    pub async fn new(mut config: BeaconServerConfig) -> Result<Self> {
        // Generate or load keypair
        let keypair = match &config.keys {
            Some(exported) => KeyPair::import(exported)?,
            None => {
                let kp = KeyPair::generate();
                config.keys = Some(kp.export_private());
                info!("Generated new beacon keypair");
                kp
            }
        };

        info!("Beacon public key: {}", keypair.public_key().fingerprint());

        // Create QUIC endpoint
        let server_config = create_server_config()?;
        let endpoint = Endpoint::server(server_config, config.listen_addr)?;

        // Initialize components
        let registry = Arc::new(PeerRegistry::new(&config.virtual_network));
        let hole_punch = Arc::new(HolePunchCoordinator::new());
        let relay = Arc::new(RelayManager::new(
            config.max_relay_sessions,
            Duration::from_secs(config.session_timeout_secs),
        ));

        Ok(Self {
            config,
            keypair,
            endpoint,
            registry,
            hole_punch,
            relay,
        })
    }

    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);

        // Spawn cleanup task
        let registry_cleanup = server.registry.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                registry_cleanup.cleanup_stale(Duration::from_secs(300));
            }
        });

        info!("Beacon server listening on {}", server.config.listen_addr);

        // Accept connections
        while let Some(conn) = server.endpoint.accept().await {
            let server = server.clone();
            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        if let Err(e) = server.handle_connection(connection).await {
                            warn!("Connection error: {}", e);
                        }
                    }
                    Err(e) => warn!("Failed to accept connection: {}", e),
                }
            });
        }

        Ok(())
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_addr = connection.remote_address();
        debug!("New connection from {}", remote_addr);

        loop {
            // Accept bidirectional streams
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Connection closed by peer");
                    break;
                }
                Err(e) => {
                    warn!("Failed to accept stream: {}", e);
                    break;
                }
            };

            let this = self.clone_refs();
            tokio::spawn(async move {
                if let Err(e) = this.handle_stream(send, recv, remote_addr).await {
                    warn!("Stream error from {}: {}", remote_addr, e);
                }
            });
        }

        Ok(())
    }

    fn clone_refs(&self) -> BeaconServerRefs {
        BeaconServerRefs {
            keypair: self.keypair.clone(),
            registry: self.registry.clone(),
            hole_punch: self.hole_punch.clone(),
            relay: self.relay.clone(),
            enable_relay: self.config.enable_relay,
        }
    }
}

/// Lightweight refs for spawned tasks
struct BeaconServerRefs {
    keypair: KeyPair,
    registry: Arc<PeerRegistry>,
    hole_punch: Arc<HolePunchCoordinator>,
    relay: Arc<RelayManager>,
    enable_relay: bool,
}

impl BeaconServerRefs {
    async fn handle_stream(
        &self,
        mut send: SendStream,
        mut recv: RecvStream,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        // Read message
        let data = recv.read_to_end(64 * 1024).await?;
        let message = Message::decode(&data)?;

        // Process and respond
        let response = self.process_message(message, remote_addr).await;

        // Send response
        let response_data = response.encode()?;
        send.write_all(&response_data).await?;
        send.finish()?;

        Ok(())
    }

    async fn process_message(&self, message: Message, remote_addr: SocketAddr) -> Message {
        match message {
            Message::Register(req) => self.handle_register(req, remote_addr).await,
            Message::ListPeers => self.handle_list_peers().await,
            Message::GetPeer { peer_id } => self.handle_get_peer(peer_id).await,
            Message::HolePunchRequest { target_peer } => {
                self.handle_hole_punch_request(target_peer, remote_addr).await
            }
            Message::RelayRequest { target_peer } => {
                self.handle_relay_request(target_peer, remote_addr).await
            }
            Message::Ping { timestamp } => Message::Pong { timestamp },
            _ => Message::Error {
                code: ErrorCode::Unknown,
                message: "Unexpected message type".to_string(),
            },
        }
    }

    async fn handle_register(&self, req: RegisterRequest, remote_addr: SocketAddr) -> Message {
        // Version check
        if req.version != PROTOCOL_VERSION {
            return Message::Error {
                code: ErrorCode::VersionMismatch,
                message: format!("Expected version {}, got {}", PROTOCOL_VERSION, req.version),
            };
        }

        // Verify signature
        let sig_data = format!("{}{}{}", req.version, req.public_key.to_base64(), req.timestamp);
        if let Err(_) = req.public_key.verify(sig_data.as_bytes(), &req.signature) {
            return Message::Error {
                code: ErrorCode::AuthFailed,
                message: "Invalid signature".to_string(),
            };
        }

        // Detect NAT type (simplified - real impl would do STUN-like probing)
        let nat_type = detect_nat_type(&remote_addr, &req.local_addr);

        // Register peer and get virtual IP
        let (peer_id, virtual_ip) = self.registry.register(
            req.public_key.clone(),
            req.name,
            remote_addr,
            req.local_addr,
            nat_type.clone(),
        );

        info!("Registered peer {} ({}) from {}", peer_id, virtual_ip, remote_addr);

        Message::RegisterAck(RegisterAck {
            peer_id,
            observed_addr: remote_addr,
            nat_type,
            virtual_ip,
            beacon_public_key: self.keypair.public_key(),
        })
    }

    async fn handle_list_peers(&self) -> Message {
        let peers = self.registry.list_online_peers();
        Message::PeerList(peers)
    }

    async fn handle_get_peer(&self, peer_id: PeerId) -> Message {
        let peer = self.registry.get_peer(&peer_id);
        Message::PeerInfo(peer)
    }

    async fn handle_hole_punch_request(&self, target_peer: PeerId, from_addr: SocketAddr) -> Message {
        // Get target peer info
        let target = match self.registry.get_peer(&target_peer) {
            Some(p) => p,
            None => {
                return Message::Error {
                    code: ErrorCode::PeerNotFound,
                    message: format!("Peer {} not found", target_peer),
                };
            }
        };

        if !target.online {
            return Message::Error {
                code: ErrorCode::PeerOffline,
                message: format!("Peer {} is offline", target_peer),
            };
        }

        // Coordinate hole punch
        let info = self.hole_punch.initiate(
            target.public_key,
            target.public_addr,
            from_addr,
        );

        Message::HolePunchBegin(info)
    }

    async fn handle_relay_request(&self, target_peer: PeerId, from_addr: SocketAddr) -> Message {
        if !self.enable_relay {
            return Message::Error {
                code: ErrorCode::RelayUnavailable,
                message: "Relay is disabled on this beacon".to_string(),
            };
        }

        // Get target peer
        let target = match self.registry.get_peer(&target_peer) {
            Some(p) => p,
            None => {
                return Message::Error {
                    code: ErrorCode::PeerNotFound,
                    message: format!("Peer {} not found", target_peer),
                };
            }
        };

        // Create relay session
        match self.relay.create_session(from_addr, target.public_addr) {
            Some(session_id) => {
                info!("Created relay session {} between {} and {}", session_id, from_addr, target.public_addr);
                Message::RelayEstablished { session_id }
            }
            None => Message::Error {
                code: ErrorCode::RelayUnavailable,
                message: "Max relay sessions reached".to_string(),
            },
        }
    }
}

fn create_server_config() -> Result<ServerConfig> {
    // Generate self-signed cert for QUIC using rcgen
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec!["rift-beacon".to_string()]);
    params.distinguished_name.push(rcgen::DnType::CommonName, "rift-beacon");
    params.key_pair = Some(key_pair);

    // Generate the self-signed certificate
    let cert = rcgen::Certificate::from_params(params)?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.serialize_der()?);
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());

    let cert_chain = vec![cert_der];

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;

    server_crypto.alpn_protocols = vec![b"rift".to_vec()];

    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?
    )))
}

fn detect_nat_type(public_addr: &SocketAddr, local_addr: &Option<SocketAddr>) -> NatType {
    // Simplified NAT detection
    // Real implementation would involve multiple STUN-like probes
    match local_addr {
        Some(local) if local.ip() == public_addr.ip() => NatType::None,
        Some(local) if local.port() == public_addr.port() => NatType::FullCone,
        Some(_) => NatType::PortRestricted,
        None => NatType::Unknown,
    }
}
