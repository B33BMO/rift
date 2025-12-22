//! Packet routing and session management
//!
//! Routes packets between the TUN device and peer connections,
//! handling encryption/decryption and session management.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, debug, warn, error};

use rift_core::crypto::KeyPair;
use rift_core::noise::Session;
use rift_core::peer::PeerId;

use crate::tun_device::{TunDevice, TunConfig, parse_ipv4_dst, parse_ipv4_src};

/// Maximum packet size (MTU + headers)
const MAX_PACKET_SIZE: usize = 1500;

/// Peer session with routing information
pub struct PeerSession {
    /// Encryption session
    pub session: Session,
    /// Peer's UDP endpoint
    pub endpoint: SocketAddr,
    /// Peer's virtual IP
    pub virtual_ip: Ipv4Addr,
    /// Peer ID
    pub peer_id: PeerId,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
}

/// Router manages packet flow between TUN and UDP
pub struct Router {
    /// Our keypair
    keypair: KeyPair,
    /// Our virtual IP
    our_ip: Ipv4Addr,
    /// Sessions indexed by virtual IP
    sessions_by_ip: DashMap<Ipv4Addr, PeerSession>,
    /// Sessions indexed by UDP endpoint
    sessions_by_endpoint: DashMap<SocketAddr, Ipv4Addr>,
    /// UDP socket for WireGuard traffic
    socket: Arc<UdpSocket>,
    /// Channel to send packets to TUN
    tun_tx: mpsc::Sender<Vec<u8>>,
}

impl Router {
    /// Create a new router
    pub async fn new(
        keypair: KeyPair,
        our_ip: Ipv4Addr,
        bind_addr: SocketAddr,
        tun_tx: mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        info!("Router bound to {}", bind_addr);

        Ok(Self {
            keypair,
            our_ip,
            sessions_by_ip: DashMap::new(),
            sessions_by_endpoint: DashMap::new(),
            socket: Arc::new(socket),
            tun_tx,
        })
    }

    /// Add a peer session
    pub fn add_peer(
        &self,
        peer_id: PeerId,
        peer_public_key: rift_core::crypto::PublicKey,
        virtual_ip: Ipv4Addr,
        endpoint: SocketAddr,
        is_initiator: bool,
    ) {
        let session = Session::new(&self.keypair, peer_public_key, is_initiator);

        let peer_session = PeerSession {
            session,
            endpoint,
            virtual_ip,
            peer_id: peer_id.clone(),
            last_activity: std::time::Instant::now(),
        };

        info!("Adding peer {} at {} with virtual IP {}", peer_id, endpoint, virtual_ip);

        self.sessions_by_endpoint.insert(endpoint, virtual_ip);
        self.sessions_by_ip.insert(virtual_ip, peer_session);
    }

    /// Remove a peer session
    pub fn remove_peer(&self, virtual_ip: &Ipv4Addr) {
        if let Some((_, session)) = self.sessions_by_ip.remove(virtual_ip) {
            self.sessions_by_endpoint.remove(&session.endpoint);
            info!("Removed peer {} ({})", session.peer_id, virtual_ip);
        }
    }

    /// Get the UDP socket for external use
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Process an outbound packet from TUN (plaintext -> encrypted -> UDP)
    pub async fn process_outbound(&self, packet: &[u8]) -> anyhow::Result<()> {
        // Parse destination IP
        let dst_ip = match parse_ipv4_dst(packet) {
            Some(ip) => ip,
            None => {
                debug!("Dropping non-IPv4 packet");
                return Ok(());
            }
        };

        // Look up session by destination IP
        let mut session_entry = match self.sessions_by_ip.get_mut(&dst_ip) {
            Some(entry) => entry,
            None => {
                debug!("No session for destination {}, dropping packet", dst_ip);
                return Ok(());
            }
        };

        let endpoint = session_entry.endpoint;

        // Encrypt the packet
        let encrypted = session_entry.session.encrypt(packet)?;

        // Send via UDP
        self.socket.send_to(&encrypted, endpoint).await?;
        session_entry.last_activity = std::time::Instant::now();

        debug!("Sent {} bytes to {} (encrypted {} bytes)", packet.len(), endpoint, encrypted.len());

        Ok(())
    }

    /// Process an inbound packet from UDP (encrypted -> decrypted -> TUN)
    pub async fn process_inbound(&self, encrypted: &[u8], from: SocketAddr) -> anyhow::Result<()> {
        // Look up session by source endpoint
        let virtual_ip = match self.sessions_by_endpoint.get(&from) {
            Some(ip) => *ip,
            None => {
                debug!("No session for endpoint {}, dropping packet", from);
                return Ok(());
            }
        };

        let mut session_entry = match self.sessions_by_ip.get_mut(&virtual_ip) {
            Some(entry) => entry,
            None => {
                debug!("Session not found for {}, dropping packet", virtual_ip);
                return Ok(());
            }
        };

        // Decrypt the packet
        let decrypted = match session_entry.session.decrypt(encrypted) {
            Ok(data) => data,
            Err(e) => {
                warn!("Decryption failed from {}: {}", from, e);
                return Ok(());
            }
        };

        session_entry.last_activity = std::time::Instant::now();

        debug!("Received {} bytes from {} (decrypted {} bytes)", encrypted.len(), from, decrypted.len());

        // Send to TUN
        self.tun_tx.send(decrypted).await?;

        Ok(())
    }

    /// Update peer endpoint (for NAT traversal)
    pub fn update_endpoint(&self, virtual_ip: &Ipv4Addr, new_endpoint: SocketAddr) {
        if let Some(mut session) = self.sessions_by_ip.get_mut(virtual_ip) {
            let old_endpoint = session.endpoint;
            if old_endpoint != new_endpoint {
                self.sessions_by_endpoint.remove(&old_endpoint);
                self.sessions_by_endpoint.insert(new_endpoint, *virtual_ip);
                session.endpoint = new_endpoint;
                info!("Updated endpoint for {} from {} to {}", virtual_ip, old_endpoint, new_endpoint);
            }
        }
    }

    /// Get list of connected peers
    pub fn connected_peers(&self) -> Vec<(PeerId, Ipv4Addr, SocketAddr)> {
        self.sessions_by_ip
            .iter()
            .map(|entry| {
                (
                    entry.peer_id.clone(),
                    entry.virtual_ip,
                    entry.endpoint,
                )
            })
            .collect()
    }

    /// Check session health (for keepalive)
    pub fn stale_sessions(&self, timeout: std::time::Duration) -> Vec<Ipv4Addr> {
        let now = std::time::Instant::now();
        self.sessions_by_ip
            .iter()
            .filter(|entry| now.duration_since(entry.last_activity) > timeout)
            .map(|entry| entry.virtual_ip)
            .collect()
    }
}

/// Run the main packet processing loops
pub async fn run_router(
    mut tun_device: TunDevice,
    router: Arc<Router>,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let socket = router.socket();

    // Spawn TUN read loop (outbound: TUN -> UDP)
    let router_outbound = router.clone();
    let tun_read_handle = tokio::spawn(async move {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            match tun_device.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if let Err(e) = router_outbound.process_outbound(&buf[..n]).await {
                        error!("Outbound processing error: {}", e);
                    }
                }
                Ok(_) => continue,
                Err(e) => {
                    error!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });

    // Spawn UDP read loop (inbound: UDP -> TUN)
    let router_inbound = router.clone();
    let udp_read_handle = tokio::spawn(async move {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, from)) if n > 0 => {
                    if let Err(e) = router_inbound.process_inbound(&buf[..n], from).await {
                        error!("Inbound processing error: {}", e);
                    }
                }
                Ok(_) => continue,
                Err(e) => {
                    error!("UDP read error: {}", e);
                    break;
                }
            }
        }
    });

    // Spawn TUN write loop (writes decrypted packets to TUN)
    let tun_write_handle = tokio::spawn(async move {
        // We need another TUN handle for writing
        // In practice, we'd split the device or use a different approach
        // For now, this receives from the channel
        while let Some(_packet) = tun_rx.recv().await {
            // In a complete implementation, we'd write to TUN here
            // tun_device.write(&packet).await
            debug!("Would write packet to TUN");
        }
    });

    // Wait for any task to complete (they shouldn't normally)
    tokio::select! {
        _ = tun_read_handle => error!("TUN read loop exited"),
        _ = udp_read_handle => error!("UDP read loop exited"),
        _ = tun_write_handle => error!("TUN write loop exited"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Router tests would require mocking the UDP socket and TUN device
    // For now, we test the helper functions

    #[test]
    fn test_session_by_ip_lookup() {
        // Basic data structure test
        let sessions: DashMap<Ipv4Addr, ()> = DashMap::new();
        sessions.insert(Ipv4Addr::new(10, 99, 0, 1), ());

        assert!(sessions.contains_key(&Ipv4Addr::new(10, 99, 0, 1)));
        assert!(!sessions.contains_key(&Ipv4Addr::new(10, 99, 0, 2)));
    }
}
