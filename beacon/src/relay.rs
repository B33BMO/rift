use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{info, debug, warn, error};
use uuid::Uuid;

/// Manages relay sessions for peers that can't establish direct connections
pub struct RelayManager {
    /// Active relay sessions
    sessions: DashMap<String, RelaySession>,
    /// Sessions indexed by peer address for quick lookup
    sessions_by_addr: DashMap<SocketAddr, String>,
    /// Max allowed concurrent sessions
    max_sessions: usize,
    /// Current session count
    session_count: AtomicUsize,
    /// Session timeout
    timeout: Duration,
}

struct RelaySession {
    /// Session ID
    id: String,
    /// First peer's address
    peer_a: SocketAddr,
    /// Second peer's address
    peer_b: SocketAddr,
    /// When session was created
    created_at: Instant,
    /// Last activity
    last_activity: Instant,
    /// Bytes relayed (for stats)
    bytes_relayed: AtomicUsize,
}

impl RelayManager {
    pub fn new(max_sessions: usize, timeout: Duration) -> Self {
        Self {
            sessions: DashMap::new(),
            sessions_by_addr: DashMap::new(),
            max_sessions,
            session_count: AtomicUsize::new(0),
            timeout,
        }
    }

    /// Create a new relay session between two peers
    pub fn create_session(&self, peer_a: SocketAddr, peer_b: SocketAddr) -> Option<String> {
        // Check capacity
        let current = self.session_count.load(Ordering::Relaxed);
        if current >= self.max_sessions {
            warn!("Max relay sessions ({}) reached", self.max_sessions);
            return None;
        }

        // Check if session already exists
        let existing_id = self.find_session(peer_a, peer_b);
        if let Some(id) = existing_id {
            debug!("Reusing existing relay session {}", id);
            return Some(id);
        }

        // Create new session
        let session_id = Uuid::new_v4().to_string();
        let session = RelaySession {
            id: session_id.clone(),
            peer_a,
            peer_b,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            bytes_relayed: AtomicUsize::new(0),
        };

        // Index by both addresses for quick lookup
        self.sessions_by_addr.insert(peer_a, session_id.clone());
        self.sessions_by_addr.insert(peer_b, session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.session_count.fetch_add(1, Ordering::Relaxed);

        info!(
            "Created relay session {} for {} <-> {}",
            session_id, peer_a, peer_b
        );

        Some(session_id)
    }

    /// Get session ID by peer address
    pub fn get_session_by_addr(&self, addr: &SocketAddr) -> Option<String> {
        self.sessions_by_addr.get(addr).map(|r| r.clone())
    }

    /// Find existing session between two peers
    fn find_session(&self, peer_a: SocketAddr, peer_b: SocketAddr) -> Option<String> {
        for entry in self.sessions.iter() {
            let session = entry.value();
            if (session.peer_a == peer_a && session.peer_b == peer_b)
                || (session.peer_a == peer_b && session.peer_b == peer_a)
            {
                return Some(session.id.clone());
            }
        }
        None
    }

    /// Get the other peer in a relay session
    pub fn get_relay_target(&self, session_id: &str, from: SocketAddr) -> Option<SocketAddr> {
        self.sessions.get(session_id).map(|session| {
            if session.peer_a == from {
                session.peer_b
            } else {
                session.peer_a
            }
        })
    }

    /// Record data being relayed
    pub fn record_relay(&self, session_id: &str, bytes: usize) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.last_activity = Instant::now();
            session.bytes_relayed.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Close a relay session
    pub fn close_session(&self, session_id: &str) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            // Clean up address index
            self.sessions_by_addr.remove(&session.peer_a);
            self.sessions_by_addr.remove(&session.peer_b);
            self.session_count.fetch_sub(1, Ordering::Relaxed);
            let bytes = session.bytes_relayed.load(Ordering::Relaxed);
            info!(
                "Closed relay session {} ({} bytes relayed)",
                session_id, bytes
            );
        }
    }

    /// Clean up timed-out sessions
    pub fn cleanup_stale(&self) {
        let now = Instant::now();
        let mut to_remove = vec![];

        for entry in self.sessions.iter() {
            if now.duration_since(entry.last_activity) > self.timeout {
                to_remove.push(entry.key().clone());
            }
        }

        for id in to_remove {
            self.close_session(&id);
        }
    }

    /// Get stats
    pub fn stats(&self) -> RelayStats {
        let mut total_bytes = 0;
        let mut oldest_session = None;

        for entry in self.sessions.iter() {
            total_bytes += entry.bytes_relayed.load(Ordering::Relaxed);
            let age = entry.created_at.elapsed();
            if oldest_session.map_or(true, |o| age > o) {
                oldest_session = Some(age);
            }
        }

        RelayStats {
            active_sessions: self.session_count.load(Ordering::Relaxed),
            max_sessions: self.max_sessions,
            total_bytes_relayed: total_bytes,
            oldest_session_age: oldest_session,
        }
    }
}

#[derive(Debug)]
pub struct RelayStats {
    pub active_sessions: usize,
    pub max_sessions: usize,
    pub total_bytes_relayed: usize,
    pub oldest_session_age: Option<Duration>,
}

/// UDP Relay Server that forwards encrypted packets between peers
pub struct RelayServer {
    socket: Arc<UdpSocket>,
    manager: Arc<RelayManager>,
}

impl RelayServer {
    /// Create and bind a new relay server
    pub async fn bind(addr: SocketAddr, manager: Arc<RelayManager>) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!("UDP relay server bound to {}", addr);
        Ok(Self {
            socket: Arc::new(socket),
            manager,
        })
    }

    /// Run the relay server (blocking)
    pub async fn run(self) -> Result<()> {
        let mut buf = [0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, from_addr)) => {
                    let data = &buf[..len];
                    self.handle_packet(data, from_addr).await;
                }
                Err(e) => {
                    error!("UDP relay recv error: {}", e);
                }
            }
        }
    }

    /// Handle an incoming relay packet
    async fn handle_packet(&self, data: &[u8], from_addr: SocketAddr) {
        // Check minimum packet size (header + some data)
        if data.len() < 8 {
            debug!("Dropping too-small packet from {}", from_addr);
            return;
        }

        // Packet format:
        // [0..4]  - Magic bytes "RIFT"
        // [4..8]  - Session ID length (u32 LE)
        // [8..N]  - Session ID (UTF-8 string)
        // [N..]   - Encrypted WireGuard payload

        // Check magic
        if &data[0..4] != b"RIFT" {
            debug!("Invalid magic from {}", from_addr);
            return;
        }

        let session_id_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        if data.len() < 8 + session_id_len {
            debug!("Malformed packet from {}", from_addr);
            return;
        }

        let session_id = match std::str::from_utf8(&data[8..8 + session_id_len]) {
            Ok(s) => s,
            Err(_) => {
                debug!("Invalid session ID encoding from {}", from_addr);
                return;
            }
        };

        let payload = &data[8 + session_id_len..];

        // Find target peer
        let target_addr = match self.manager.get_relay_target(session_id, from_addr) {
            Some(addr) => addr,
            None => {
                debug!("No relay session {} for {}", session_id, from_addr);
                return;
            }
        };

        // Build packet for target (same format)
        let mut forward_packet = Vec::with_capacity(8 + session_id_len + payload.len());
        forward_packet.extend_from_slice(b"RIFT");
        forward_packet.extend_from_slice(&(session_id_len as u32).to_le_bytes());
        forward_packet.extend_from_slice(session_id.as_bytes());
        forward_packet.extend_from_slice(payload);

        // Forward to target
        match self.socket.send_to(&forward_packet, target_addr).await {
            Ok(sent) => {
                self.manager.record_relay(session_id, sent);
                debug!("Relayed {} bytes: {} -> {}", sent, from_addr, target_addr);
            }
            Err(e) => {
                warn!("Failed to relay to {}: {}", target_addr, e);
            }
        }
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(Into::into)
    }
}

/// Relay operation mode
///
/// ## How Relay Works:
///
/// When UDP hole punching fails (typically due to symmetric NAT),
/// peers fall back to relaying traffic through the Beacon.
///
/// ```text
///     Peer A                  Beacon                  Peer B
///        │                      │                        │
///        │──RelayRequest───────>│                        │
///        │<─RelayEstablished────│                        │
///        │                      │                        │
///        │                      │<──RelayRequest─────────│
///        │                      │───RelayEstablished────>│
///        │                      │                        │
///        │══RelayData══════════>│                        │
///        │                      │══════RelayData════════>│
///        │                      │                        │
///        │                      │<═════RelayData═════════│
///        │<═════RelayData═══════│                        │
/// ```
///
/// ## Security:
///
/// - All relayed data is still WireGuard-encrypted end-to-end
/// - Beacon cannot read the traffic contents
/// - Beacon only sees metadata: who is talking to whom, packet sizes, timing
///
/// ## Performance:
///
/// - Adds latency: A->Beacon->B instead of A->B directly
/// - Beacon bandwidth becomes a bottleneck
/// - Consider running multiple beacons for redundancy
///
/// ## Privacy Trade-offs:
///
/// - Direct connection: Only ISPs see the connection
/// - Relayed: Beacon sees connection metadata
/// - For maximum privacy, users should run their own beacon
pub struct RelayMode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let manager = RelayManager::new(10, Duration::from_secs(300));

        let addr_a: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let addr_b: SocketAddr = "192.168.1.2:5000".parse().unwrap();

        let session_id = manager.create_session(addr_a, addr_b);
        assert!(session_id.is_some());

        // Same peers should reuse session
        let session_id_2 = manager.create_session(addr_a, addr_b);
        assert_eq!(session_id, session_id_2);

        // Reversed order should also reuse
        let session_id_3 = manager.create_session(addr_b, addr_a);
        assert_eq!(session_id, session_id_3);
    }

    #[test]
    fn test_max_sessions() {
        let manager = RelayManager::new(2, Duration::from_secs(300));

        let s1 = manager.create_session(
            "192.168.1.1:5000".parse().unwrap(),
            "192.168.1.2:5000".parse().unwrap(),
        );
        let s2 = manager.create_session(
            "192.168.1.3:5000".parse().unwrap(),
            "192.168.1.4:5000".parse().unwrap(),
        );
        let s3 = manager.create_session(
            "192.168.1.5:5000".parse().unwrap(),
            "192.168.1.6:5000".parse().unwrap(),
        );

        assert!(s1.is_some());
        assert!(s2.is_some());
        assert!(s3.is_none()); // Max reached
    }
}
