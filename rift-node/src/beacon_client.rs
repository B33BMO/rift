use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use quinn::{ClientConfig, Endpoint, Connection};
use tokio::sync::RwLock;
use tracing::{info, warn, debug, error};

use rift_core::config::Config;
use rift_core::crypto::KeyPair;
use rift_core::protocol::{
    Message, RegisterRequest, RegisterAck, PeerInfo, HolePunchInfo,
    PROTOCOL_VERSION,
};
use rift_core::peer::PeerId;

/// Client for communicating with the Beacon server
pub struct BeaconClient {
    config: Config,
    keypair: KeyPair,
    endpoint: Endpoint,
    connection: RwLock<Option<Connection>>,
    registration: RwLock<Option<RegisterAck>>,
}

impl BeaconClient {
    pub async fn connect(config: &Config, keypair: KeyPair) -> Result<Self> {
        // Create QUIC endpoint
        let client_config = create_client_config()?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let client = Self {
            config: config.clone(),
            keypair,
            endpoint,
            connection: RwLock::new(None),
            registration: RwLock::new(None),
        };

        // Establish initial connection
        client.ensure_connected().await?;

        Ok(client)
    }

    /// Ensure we have an active connection to the beacon
    async fn ensure_connected(&self) -> Result<Connection> {
        // Check existing connection
        {
            let conn = self.connection.read().await;
            if let Some(ref c) = *conn {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
            }
        }

        // Need to connect
        let addr: SocketAddr = self.config.beacon.address.parse()?;
        debug!("Connecting to beacon at {}", addr);

        let connection = self.endpoint
            .connect(addr, "rift-beacon")?
            .await?;

        info!("Connected to beacon");

        // Store connection
        {
            let mut conn = self.connection.write().await;
            *conn = Some(connection.clone());
        }

        Ok(connection)
    }

    /// Send a message and receive response
    async fn request(&self, message: Message) -> Result<Message> {
        let connection = self.ensure_connected().await?;

        let (mut send, mut recv) = connection.open_bi().await?;

        // Send request
        let data = message.encode()?;
        send.write_all(&data).await?;
        send.finish()?;

        // Receive response
        let response_data = recv.read_to_end(64 * 1024).await?;
        let response = Message::decode(&response_data)?;

        Ok(response)
    }

    /// Register this node with the beacon
    pub async fn register(&self) -> Result<RegisterAck> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let public_key = self.keypair.public_key();

        // Create signature
        let sig_data = format!("{}{}{}", PROTOCOL_VERSION, public_key.to_base64(), timestamp);
        let signature = self.keypair.sign(sig_data.as_bytes());

        let request = Message::Register(RegisterRequest {
            version: PROTOCOL_VERSION,
            public_key,
            name: self.config.node.name.clone(),
            local_addr: get_local_addr(),
            signature,
            timestamp,
        });

        let response = self.request(request).await?;

        match response {
            Message::RegisterAck(ack) => {
                let mut reg = self.registration.write().await;
                *reg = Some(ack.clone());
                Ok(ack)
            }
            Message::Error { code, message } => {
                anyhow::bail!("Registration failed: {:?} - {}", code, message)
            }
            _ => anyhow::bail!("Unexpected response to registration"),
        }
    }

    /// Get our registration info
    pub async fn get_registration(&self) -> Option<RegisterAck> {
        self.registration.read().await.clone()
    }

    /// List all online peers
    pub async fn list_peers(&self) -> Result<Vec<PeerInfo>> {
        let response = self.request(Message::ListPeers).await?;

        match response {
            Message::PeerList(peers) => Ok(peers),
            Message::Error { code, message } => {
                anyhow::bail!("List peers failed: {:?} - {}", code, message)
            }
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    /// Get specific peer info
    pub async fn get_peer(&self, peer_id: &PeerId) -> Result<Option<PeerInfo>> {
        let response = self.request(Message::GetPeer {
            peer_id: peer_id.clone(),
        }).await?;

        match response {
            Message::PeerInfo(info) => Ok(info),
            Message::Error { code, message } => {
                anyhow::bail!("Get peer failed: {:?} - {}", code, message)
            }
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    /// Request hole punch coordination
    pub async fn request_hole_punch(&self, target_peer: &PeerId) -> Result<HolePunchInfo> {
        let response = self.request(Message::HolePunchRequest {
            target_peer: target_peer.clone(),
        }).await?;

        match response {
            Message::HolePunchBegin(info) => Ok(info),
            Message::Error { code, message } => {
                anyhow::bail!("Hole punch request failed: {:?} - {}", code, message)
            }
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    /// Request relay to a peer
    pub async fn request_relay(&self, target_peer: &PeerId) -> Result<String> {
        let response = self.request(Message::RelayRequest {
            target_peer: target_peer.clone(),
        }).await?;

        match response {
            Message::RelayEstablished { session_id } => Ok(session_id),
            Message::Error { code, message } => {
                anyhow::bail!("Relay request failed: {:?} - {}", code, message)
            }
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    /// Send keepalive ping
    pub async fn ping(&self) -> Result<Duration> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64;

        let response = self.request(Message::Ping { timestamp }).await?;

        match response {
            Message::Pong { timestamp: sent_ts } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_millis() as u64;
                Ok(Duration::from_millis(now - sent_ts))
            }
            _ => anyhow::bail!("Unexpected response to ping"),
        }
    }

    /// Start keepalive task
    pub fn start_keepalive(self: &Arc<Self>) {
        let client = self.clone();
        let interval = Duration::from_secs(self.config.beacon.keepalive_secs);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                match client.ping().await {
                    Ok(rtt) => debug!("Beacon ping: {}ms", rtt.as_millis()),
                    Err(e) => {
                        warn!("Beacon keepalive failed: {}", e);
                        // Connection will be re-established on next request
                    }
                }
            }
        });
    }
}

fn create_client_config() -> Result<ClientConfig> {
    // For now, accept any certificate (beacon uses self-signed)
    // In production, you'd verify the beacon's public key
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    // Set ALPN
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Skip TLS verification (beacon uses self-signed certs)
/// In production, verify beacon's public key instead
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Get local address for NAT detection
fn get_local_addr() -> Option<SocketAddr> {
    // Try to determine local IP by connecting to a public address
    // This doesn't actually send any data
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    socket.local_addr().ok()
}
