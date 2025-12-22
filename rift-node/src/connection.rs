//! Connection management and state machine
//!
//! Handles the complete peer connection lifecycle:
//! Discovery → Hole Punch → Handshake → Connected (with rekeying)
//!
//! Falls back to relay when direct connection fails.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::interval;
use tracing::{info, debug, warn, error};

use rift_core::crypto::{KeyPair, PublicKey};
use rift_core::handshake::{HandshakeInitiator, HandshakeResponder, HandshakeInit, HandshakeResponse};
use rift_core::noise::Session;
use rift_core::peer::PeerId;
use rift_core::protocol::PeerInfo;

use crate::relay_client::RelayClient;

/// Connection state for a peer
#[derive(Clone, Debug)]
pub enum ConnectionState {
    /// Just discovered, not yet connected
    Discovered {
        discovered_at: Instant,
    },
    /// Attempting hole punch
    HolePunching {
        started_at: Instant,
        attempts: u32,
    },
    /// Performing Noise IK handshake
    Handshaking {
        started_at: Instant,
        initiator: bool,
    },
    /// Fully connected with active session
    Connected {
        connected_at: Instant,
        last_handshake: Instant,
        session_index: u32,
        direct: bool, // true = direct, false = relayed
    },
    /// Using relay through beacon
    Relayed {
        connected_at: Instant,
        session_id: String,
    },
    /// Disconnected, waiting to retry
    Disconnected {
        disconnected_at: Instant,
        retry_count: u32,
        next_retry: Instant,
    },
    /// Failed permanently (e.g., auth failure)
    Failed {
        reason: String,
    },
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. } | ConnectionState::Relayed { .. })
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, ConnectionState::Connected { direct: true, .. })
    }

    pub fn state_name(&self) -> &'static str {
        match self {
            ConnectionState::Discovered { .. } => "discovered",
            ConnectionState::HolePunching { .. } => "hole_punching",
            ConnectionState::Handshaking { .. } => "handshaking",
            ConnectionState::Connected { direct: true, .. } => "connected",
            ConnectionState::Connected { direct: false, .. } => "connected_relay",
            ConnectionState::Relayed { .. } => "relayed",
            ConnectionState::Disconnected { .. } => "disconnected",
            ConnectionState::Failed { .. } => "failed",
        }
    }
}

/// Peer connection with all associated state
pub struct PeerConnection {
    /// Peer's ID
    pub peer_id: PeerId,
    /// Peer's public key
    pub public_key: PublicKey,
    /// Peer's virtual IP in the mesh
    pub virtual_ip: Ipv4Addr,
    /// Peer's human-readable name
    pub name: String,
    /// Current endpoint (may change with NAT)
    pub endpoint: RwLock<Option<SocketAddr>>,
    /// Connection state
    pub state: RwLock<ConnectionState>,
    /// Active encryption session
    pub session: RwLock<Option<Session>>,
    /// Relay session ID (if using relay)
    pub relay_session: RwLock<Option<String>>,
    /// Bytes sent
    pub bytes_tx: std::sync::atomic::AtomicU64,
    /// Bytes received
    pub bytes_rx: std::sync::atomic::AtomicU64,
    /// Last activity time
    pub last_activity: RwLock<Instant>,
}

impl PeerConnection {
    pub fn new(peer_id: PeerId, public_key: PublicKey, virtual_ip: Ipv4Addr, name: String) -> Self {
        Self {
            peer_id,
            public_key,
            virtual_ip,
            name,
            endpoint: RwLock::new(None),
            state: RwLock::new(ConnectionState::Discovered {
                discovered_at: Instant::now(),
            }),
            session: RwLock::new(None),
            relay_session: RwLock::new(None),
            bytes_tx: std::sync::atomic::AtomicU64::new(0),
            bytes_rx: std::sync::atomic::AtomicU64::new(0),
            last_activity: RwLock::new(Instant::now()),
        }
    }

    pub async fn update_endpoint(&self, endpoint: SocketAddr) {
        *self.endpoint.write().await = Some(endpoint);
    }

    pub async fn get_endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read().await
    }
}

/// Configuration for connection management
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    /// Max hole punch attempts before falling back to relay
    pub max_hole_punch_attempts: u32,
    /// Timeout for hole punch phase
    pub hole_punch_timeout: Duration,
    /// Timeout for handshake phase
    pub handshake_timeout: Duration,
    /// Interval between keepalive packets
    pub keepalive_interval: Duration,
    /// Time without activity before peer is considered dead
    pub dead_peer_timeout: Duration,
    /// Session rekey interval (WireGuard uses 2 minutes)
    pub rekey_interval: Duration,
    /// Base delay for reconnection backoff
    pub reconnect_base_delay: Duration,
    /// Max delay for reconnection backoff
    pub reconnect_max_delay: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_hole_punch_attempts: 5,
            hole_punch_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(25),
            dead_peer_timeout: Duration::from_secs(180),
            rekey_interval: Duration::from_secs(120), // 2 minutes like WireGuard
            reconnect_base_delay: Duration::from_secs(1),
            reconnect_max_delay: Duration::from_secs(60),
        }
    }
}

/// Manages all peer connections
pub struct ConnectionManager {
    /// Our keypair
    keypair: KeyPair,
    /// Our virtual IP
    our_ip: Ipv4Addr,
    /// Configuration
    config: ConnectionConfig,
    /// All peer connections indexed by virtual IP
    peers: DashMap<Ipv4Addr, Arc<PeerConnection>>,
    /// UDP socket for WireGuard traffic
    socket: Arc<UdpSocket>,
    /// Relay client for fallback
    relay_client: Option<Arc<RelayClient>>,
    /// Pending handshakes (initiator side)
    pending_initiator: DashMap<u32, HandshakeInitiator>,
    /// Pending handshakes (responder side)
    pending_responder: DashMap<SocketAddr, HandshakeResponder>,
    /// Channel to send decrypted packets to TUN
    tun_tx: mpsc::Sender<Vec<u8>>,
    /// Beacon relay address
    beacon_relay_addr: Option<SocketAddr>,
}

impl ConnectionManager {
    pub async fn new(
        keypair: KeyPair,
        our_ip: Ipv4Addr,
        bind_addr: SocketAddr,
        tun_tx: mpsc::Sender<Vec<u8>>,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!("Connection manager bound to {}", bind_addr);

        Ok(Self {
            keypair,
            our_ip,
            config,
            peers: DashMap::new(),
            socket: Arc::new(socket),
            relay_client: None,
            pending_initiator: DashMap::new(),
            pending_responder: DashMap::new(),
            tun_tx,
            beacon_relay_addr: None,
        })
    }

    /// Set the relay client for fallback connections
    pub fn set_relay_client(&mut self, client: Arc<RelayClient>, beacon_addr: SocketAddr) {
        self.relay_client = Some(client);
        self.beacon_relay_addr = Some(beacon_addr);
    }

    /// Add a peer from discovery
    pub fn add_peer(&self, info: &PeerInfo) -> Arc<PeerConnection> {
        let conn = Arc::new(PeerConnection::new(
            info.peer_id.clone(),
            info.public_key.clone(),
            info.virtual_ip,
            info.name.clone(),
        ));

        // Set initial endpoint
        let endpoint = info.public_addr;
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            conn_clone.update_endpoint(endpoint).await;
        });

        self.peers.insert(info.virtual_ip, conn.clone());
        info!("Added peer {} ({}) at {}", info.name, info.virtual_ip, info.public_addr);
        conn
    }

    /// Remove a peer
    pub fn remove_peer(&self, virtual_ip: &Ipv4Addr) {
        if let Some((_, conn)) = self.peers.remove(virtual_ip) {
            info!("Removed peer {} ({})", conn.name, virtual_ip);
        }
    }

    /// Get a peer by virtual IP
    pub fn get_peer(&self, virtual_ip: &Ipv4Addr) -> Option<Arc<PeerConnection>> {
        self.peers.get(virtual_ip).map(|r| r.clone())
    }

    /// Initiate connection to a peer
    pub async fn connect_peer(&self, virtual_ip: &Ipv4Addr) -> Result<()> {
        let peer = self.peers.get(virtual_ip)
            .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;

        let peer = peer.clone();
        let endpoint = peer.get_endpoint().await
            .ok_or_else(|| anyhow::anyhow!("No endpoint for peer"))?;

        // Determine if we should be the initiator based on key ordering
        let our_key = self.keypair.public_key().to_base64();
        let peer_key = peer.public_key.to_base64();
        let is_initiator = our_key < peer_key;

        if is_initiator {
            self.initiate_handshake(&peer, endpoint).await?;
        } else {
            // Wait for peer to initiate
            debug!("Waiting for {} to initiate handshake", peer.name);
            *peer.state.write().await = ConnectionState::Handshaking {
                started_at: Instant::now(),
                initiator: false,
            };
        }

        Ok(())
    }

    /// Initiate a Noise IK handshake
    async fn initiate_handshake(&self, peer: &PeerConnection, endpoint: SocketAddr) -> Result<()> {
        info!("Initiating handshake with {} at {}", peer.name, endpoint);

        // Update state
        *peer.state.write().await = ConnectionState::Handshaking {
            started_at: Instant::now(),
            initiator: true,
        };

        // Create handshake initiator
        let mut initiator = HandshakeInitiator::new(
            self.keypair.clone(),
            peer.public_key.clone(),
        );

        // Generate init message
        let init = initiator.create_init()?;
        let sender_index = initiator.sender_index();

        // Store pending handshake
        self.pending_initiator.insert(sender_index, initiator);

        // Send init message
        let init_bytes = init.to_bytes();
        self.socket.send_to(&init_bytes, endpoint).await?;

        debug!("Sent handshake init to {} (index {})", peer.name, sender_index);

        Ok(())
    }

    /// Process incoming UDP packet
    pub async fn process_incoming(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Check packet type (first byte)
        match data[0] {
            1 => self.handle_handshake_init(data, from).await,
            2 => self.handle_handshake_response(data, from).await,
            4 => self.handle_transport_data(data, from).await,
            _ => {
                debug!("Unknown packet type {} from {}", data[0], from);
                Ok(())
            }
        }
    }

    /// Handle incoming handshake init
    async fn handle_handshake_init(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        let init = HandshakeInit::from_bytes(data)?;
        debug!("Received handshake init from {} (index {})", from, init.sender_index);

        // Create responder
        let mut responder = HandshakeResponder::new(self.keypair.clone());

        // Process init and generate response
        let response = responder.process_init(&init)?;

        // Finalize to get session and peer key
        let (session, peer_public_key, initiator_index) = responder.finalize()?;

        // Find peer by public key
        let peer = self.find_peer_by_public_key(&peer_public_key).await;

        if let Some(peer) = peer {
            // Update peer state
            *peer.session.write().await = Some(session);
            *peer.state.write().await = ConnectionState::Connected {
                connected_at: Instant::now(),
                last_handshake: Instant::now(),
                session_index: initiator_index,
                direct: true,
            };
            peer.update_endpoint(from).await;

            info!("Completed handshake with {} (responder)", peer.name);
        } else {
            warn!("Handshake from unknown peer at {}", from);
        }

        // Send response
        let response_bytes = response.to_bytes();
        self.socket.send_to(&response_bytes, from).await?;

        Ok(())
    }

    /// Handle incoming handshake response
    async fn handle_handshake_response(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        let response = HandshakeResponse::from_bytes(data)?;
        debug!("Received handshake response from {} (index {})", from, response.sender_index);

        // Find pending initiator
        let initiator = self.pending_initiator.remove(&response.receiver_index);

        if let Some((_, mut initiator)) = initiator {
            // Process response and get session
            let (session, responder_index) = initiator.process_response(&response)?;

            // Find peer by endpoint
            let peer = self.find_peer_by_endpoint(from).await;

            if let Some(peer) = peer {
                // Update peer state
                *peer.session.write().await = Some(session);
                *peer.state.write().await = ConnectionState::Connected {
                    connected_at: Instant::now(),
                    last_handshake: Instant::now(),
                    session_index: responder_index,
                    direct: true,
                };

                info!("Completed handshake with {} (initiator)", peer.name);
            }
        } else {
            warn!("Handshake response for unknown index {} from {}", response.receiver_index, from);
        }

        Ok(())
    }

    /// Handle incoming transport data
    async fn handle_transport_data(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        // Find peer by endpoint
        let peer = self.find_peer_by_endpoint(from).await;

        if let Some(peer) = peer {
            let mut session_guard = peer.session.write().await;
            if let Some(ref mut session) = *session_guard {
                // Decrypt packet
                match session.decrypt(&data[16..]) { // Skip header
                    Ok(plaintext) => {
                        // Update stats
                        peer.bytes_rx.fetch_add(plaintext.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        *peer.last_activity.write().await = Instant::now();

                        // Send to TUN
                        self.tun_tx.send(plaintext).await?;
                    }
                    Err(e) => {
                        warn!("Decryption failed from {}: {}", from, e);
                    }
                }
            }
        } else {
            debug!("Transport data from unknown endpoint {}", from);
        }

        Ok(())
    }

    /// Send data to a peer
    pub async fn send_to_peer(&self, virtual_ip: &Ipv4Addr, data: &[u8]) -> Result<()> {
        let peer = self.peers.get(virtual_ip)
            .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;

        let peer = peer.clone();
        let state = peer.state.read().await.clone();

        match state {
            ConnectionState::Connected { direct: true, .. } => {
                // Send directly
                let endpoint = peer.get_endpoint().await
                    .ok_or_else(|| anyhow::anyhow!("No endpoint"))?;

                let mut session_guard = peer.session.write().await;
                if let Some(ref mut session) = *session_guard {
                    let encrypted = session.encrypt(data)?;

                    // Build transport packet
                    let mut packet = Vec::with_capacity(16 + encrypted.len());
                    packet.push(4); // Transport data type
                    packet.extend_from_slice(&[0; 3]); // Reserved
                    packet.extend_from_slice(&[0; 4]); // Receiver index (TODO)
                    packet.extend_from_slice(&[0; 8]); // Counter (in encrypted data)
                    packet.extend_from_slice(&encrypted);

                    self.socket.send_to(&packet, endpoint).await?;
                    peer.bytes_tx.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
            }
            ConnectionState::Connected { direct: false, .. } | ConnectionState::Relayed { .. } => {
                // Send via relay
                if let Some(ref relay) = self.relay_client {
                    let mut session_guard = peer.session.write().await;
                    if let Some(ref mut session) = *session_guard {
                        let encrypted = session.encrypt(data)?;
                        relay.send_to_peer(*virtual_ip, &encrypted).await?;
                        peer.bytes_tx.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            _ => {
                debug!("Cannot send to {} in state {:?}", virtual_ip, state.state_name());
            }
        }

        *peer.last_activity.write().await = Instant::now();
        Ok(())
    }

    /// Find peer by public key
    async fn find_peer_by_public_key(&self, public_key: &PublicKey) -> Option<Arc<PeerConnection>> {
        let wg_key = public_key.wg_public_key();
        for entry in self.peers.iter() {
            if entry.public_key.wg_public_key() == wg_key {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Find peer by endpoint
    async fn find_peer_by_endpoint(&self, endpoint: SocketAddr) -> Option<Arc<PeerConnection>> {
        for entry in self.peers.iter() {
            if entry.get_endpoint().await == Some(endpoint) {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Get list of all peers with status
    pub fn list_peers(&self) -> Vec<Arc<PeerConnection>> {
        self.peers.iter().map(|r| r.clone()).collect()
    }

    /// Get socket for external use
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Run maintenance tasks (keepalive, rekeying, dead peer detection)
    pub async fn run_maintenance(self: Arc<Self>) {
        let mut keepalive_interval = interval(self.config.keepalive_interval);
        let mut rekey_check_interval = interval(Duration::from_secs(10));
        let mut dead_peer_interval = interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = keepalive_interval.tick() => {
                    self.send_keepalives().await;
                }
                _ = rekey_check_interval.tick() => {
                    self.check_rekeying().await;
                }
                _ = dead_peer_interval.tick() => {
                    self.check_dead_peers().await;
                }
            }
        }
    }

    /// Send keepalive packets to all connected peers
    async fn send_keepalives(&self) {
        for entry in self.peers.iter() {
            let peer = entry.clone();
            let state = peer.state.read().await.clone();

            if state.is_connected() {
                if let Some(endpoint) = peer.get_endpoint().await {
                    // Send empty encrypted packet as keepalive
                    let mut session_guard = peer.session.write().await;
                    if let Some(ref mut session) = *session_guard {
                        if let Ok(encrypted) = session.encrypt(&[]) {
                            let mut packet = Vec::with_capacity(16 + encrypted.len());
                            packet.push(4);
                            packet.extend_from_slice(&[0; 15]);
                            packet.extend_from_slice(&encrypted);
                            let _ = self.socket.send_to(&packet, endpoint).await;
                        }
                    }
                }
            }
        }
    }

    /// Check if any sessions need rekeying
    async fn check_rekeying(&self) {
        let now = Instant::now();

        for entry in self.peers.iter() {
            let peer = entry.clone();
            let state = peer.state.read().await.clone();

            if let ConnectionState::Connected { last_handshake, .. } = state {
                if now.duration_since(last_handshake) > self.config.rekey_interval {
                    info!("Session with {} needs rekeying", peer.name);
                    // Initiate new handshake
                    if let Some(endpoint) = peer.get_endpoint().await {
                        let _ = self.initiate_handshake(&peer, endpoint).await;
                    }
                }
            }
        }
    }

    /// Check for dead peers
    async fn check_dead_peers(&self) {
        let now = Instant::now();

        for entry in self.peers.iter() {
            let peer = entry.clone();
            let last_activity = *peer.last_activity.read().await;
            let state = peer.state.read().await.clone();

            if state.is_connected() && now.duration_since(last_activity) > self.config.dead_peer_timeout {
                warn!("Peer {} appears dead, marking disconnected", peer.name);
                *peer.state.write().await = ConnectionState::Disconnected {
                    disconnected_at: now,
                    retry_count: 0,
                    next_retry: now + self.config.reconnect_base_delay,
                };
            }
        }
    }

    /// Run reconnection loop for disconnected peers
    pub async fn run_reconnection(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(5));

        loop {
            interval.tick().await;
            self.attempt_reconnections().await;
        }
    }

    /// Attempt to reconnect disconnected peers
    async fn attempt_reconnections(&self) {
        let now = Instant::now();

        for entry in self.peers.iter() {
            let peer = entry.clone();
            let mut state = peer.state.write().await;

            if let ConnectionState::Disconnected { retry_count, next_retry, .. } = *state {
                if now >= next_retry {
                    info!("Attempting reconnection to {} (attempt {})", peer.name, retry_count + 1);

                    // Calculate next retry with exponential backoff
                    let delay = std::cmp::min(
                        self.config.reconnect_base_delay * 2u32.saturating_pow(retry_count),
                        self.config.reconnect_max_delay,
                    );

                    *state = ConnectionState::Disconnected {
                        disconnected_at: now,
                        retry_count: retry_count + 1,
                        next_retry: now + delay,
                    };

                    drop(state); // Release lock before async operation

                    // Attempt connection
                    if let Some(endpoint) = peer.get_endpoint().await {
                        let _ = self.initiate_handshake(&peer, endpoint).await;
                    }
                }
            }
        }
    }
}

/// Run the connection manager's receive loop
pub async fn run_connection_manager(
    manager: Arc<ConnectionManager>,
) -> Result<()> {
    let socket = manager.socket();
    let mut buf = [0u8; 65535];

    // Spawn maintenance task
    let manager_maintenance = manager.clone();
    tokio::spawn(async move {
        manager_maintenance.run_maintenance().await;
    });

    // Spawn reconnection task
    let manager_reconnect = manager.clone();
    tokio::spawn(async move {
        manager_reconnect.run_reconnection().await;
    });

    // Main receive loop
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                if let Err(e) = manager.process_incoming(&buf[..len], from).await {
                    warn!("Error processing packet from {}: {}", from, e);
                }
            }
            Err(e) => {
                error!("Socket recv error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_names() {
        let state = ConnectionState::Discovered { discovered_at: Instant::now() };
        assert_eq!(state.state_name(), "discovered");

        let state = ConnectionState::Connected {
            connected_at: Instant::now(),
            last_handshake: Instant::now(),
            session_index: 1,
            direct: true,
        };
        assert_eq!(state.state_name(), "connected");
        assert!(state.is_connected());
        assert!(state.is_direct());
    }

    #[test]
    fn test_default_config() {
        let config = ConnectionConfig::default();
        assert_eq!(config.rekey_interval, Duration::from_secs(120));
        assert_eq!(config.keepalive_interval, Duration::from_secs(25));
    }
}
