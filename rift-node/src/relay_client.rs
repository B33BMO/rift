//! Relay client for fallback when direct connection fails
//!
//! When UDP hole punching fails (symmetric NAT, strict firewalls),
//! packets are relayed through the beacon server.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, debug, warn, error};

/// Relay client that forwards packets through the beacon
pub struct RelayClient {
    /// UDP socket for relay communication
    socket: Arc<UdpSocket>,
    /// Beacon's relay server address
    beacon_relay_addr: SocketAddr,
    /// Active relay sessions by peer virtual IP
    sessions: DashMap<std::net::Ipv4Addr, RelaySession>,
    /// Channel to send received packets to the router
    packet_tx: mpsc::Sender<(Vec<u8>, std::net::Ipv4Addr)>,
}

/// A relay session to a specific peer
#[derive(Clone)]
struct RelaySession {
    /// Session ID assigned by beacon
    session_id: String,
    /// Peer's virtual IP
    peer_ip: std::net::Ipv4Addr,
}

impl RelayClient {
    /// Create a new relay client
    pub async fn new(
        bind_addr: SocketAddr,
        beacon_relay_addr: SocketAddr,
        packet_tx: mpsc::Sender<(Vec<u8>, std::net::Ipv4Addr)>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!("Relay client bound to {}", bind_addr);

        Ok(Self {
            socket: Arc::new(socket),
            beacon_relay_addr,
            sessions: DashMap::new(),
            packet_tx,
        })
    }

    /// Register a relay session for a peer
    pub fn add_session(&self, peer_ip: std::net::Ipv4Addr, session_id: String) {
        info!("Added relay session {} for peer {}", session_id, peer_ip);
        self.sessions.insert(peer_ip, RelaySession {
            session_id,
            peer_ip,
        });
    }

    /// Remove a relay session
    pub fn remove_session(&self, peer_ip: &std::net::Ipv4Addr) {
        if self.sessions.remove(peer_ip).is_some() {
            info!("Removed relay session for peer {}", peer_ip);
        }
    }

    /// Check if we have a relay session for a peer
    pub fn has_session(&self, peer_ip: &std::net::Ipv4Addr) -> bool {
        self.sessions.contains_key(peer_ip)
    }

    /// Send a packet through the relay
    pub async fn send_to_peer(&self, peer_ip: std::net::Ipv4Addr, data: &[u8]) -> Result<()> {
        let session = self.sessions.get(&peer_ip)
            .ok_or_else(|| anyhow::anyhow!("No relay session for {}", peer_ip))?;

        // Build relay packet
        // Format: "RIFT" + session_id_len (u32 LE) + session_id + payload
        let session_id = &session.session_id;
        let mut packet = Vec::with_capacity(8 + session_id.len() + data.len());
        packet.extend_from_slice(b"RIFT");
        packet.extend_from_slice(&(session_id.len() as u32).to_le_bytes());
        packet.extend_from_slice(session_id.as_bytes());
        packet.extend_from_slice(data);

        self.socket.send_to(&packet, self.beacon_relay_addr).await?;
        debug!("Sent {} bytes to {} via relay", data.len(), peer_ip);

        Ok(())
    }

    /// Run the receive loop (call this in a spawned task)
    pub async fn run_receive_loop(self: Arc<Self>) -> Result<()> {
        let mut buf = [0u8; 65535];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    if from != self.beacon_relay_addr {
                        debug!("Ignoring packet from unexpected source {}", from);
                        continue;
                    }

                    if let Err(e) = self.handle_packet(&buf[..len]).await {
                        warn!("Error handling relay packet: {}", e);
                    }
                }
                Err(e) => {
                    error!("Relay socket recv error: {}", e);
                }
            }
        }
    }

    /// Handle an incoming relay packet
    async fn handle_packet(&self, data: &[u8]) -> Result<()> {
        // Check minimum size
        if data.len() < 8 {
            anyhow::bail!("Packet too small");
        }

        // Check magic
        if &data[0..4] != b"RIFT" {
            anyhow::bail!("Invalid magic");
        }

        let session_id_len = u32::from_le_bytes(data[4..8].try_into()?) as usize;
        if data.len() < 8 + session_id_len {
            anyhow::bail!("Malformed packet");
        }

        let session_id = std::str::from_utf8(&data[8..8 + session_id_len])?;
        let payload = &data[8 + session_id_len..];

        // Find the peer IP for this session
        let peer_ip = self.find_peer_by_session(session_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown session {}", session_id))?;

        debug!("Received {} bytes from {} via relay", payload.len(), peer_ip);

        // Send to router
        self.packet_tx.send((payload.to_vec(), peer_ip)).await?;

        Ok(())
    }

    /// Find peer IP by session ID
    fn find_peer_by_session(&self, session_id: &str) -> Option<std::net::Ipv4Addr> {
        for entry in self.sessions.iter() {
            if entry.session_id == session_id {
                return Some(*entry.key());
            }
        }
        None
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(Into::into)
    }
}

/// Relay packet format for documentation
///
/// ```text
/// ┌──────────────────────────────────────────────────────────────┐
/// │ 0x00-0x03 │ Magic: "RIFT" (4 bytes)                          │
/// ├───────────┼──────────────────────────────────────────────────┤
/// │ 0x04-0x07 │ Session ID length (u32 LE)                       │
/// ├───────────┼──────────────────────────────────────────────────┤
/// │ 0x08-N    │ Session ID (UTF-8 string)                        │
/// ├───────────┼──────────────────────────────────────────────────┤
/// │ N+1-end   │ Encrypted WireGuard payload                      │
/// └───────────┴──────────────────────────────────────────────────┘
/// ```
///
/// The payload is the encrypted WireGuard packet (already encrypted
/// end-to-end). The beacon cannot read the contents.
pub struct RelayPacketFormat;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_packet_format() {
        // Build a sample relay packet
        let session_id = "test-session-123";
        let payload = b"encrypted data here";

        let mut packet = Vec::new();
        packet.extend_from_slice(b"RIFT");
        packet.extend_from_slice(&(session_id.len() as u32).to_le_bytes());
        packet.extend_from_slice(session_id.as_bytes());
        packet.extend_from_slice(payload);

        // Verify format
        assert_eq!(&packet[0..4], b"RIFT");

        let len = u32::from_le_bytes(packet[4..8].try_into().unwrap()) as usize;
        assert_eq!(len, session_id.len());

        let id = std::str::from_utf8(&packet[8..8 + len]).unwrap();
        assert_eq!(id, session_id);

        let data = &packet[8 + len..];
        assert_eq!(data, payload);
    }
}
