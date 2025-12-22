//! WireGuard tunnel management
//!
//! Coordinates the TUN device, packet routing, and peer sessions.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn, debug, error};

use rift_core::config::NetworkConfig;
use rift_core::crypto::{KeyPair, PublicKey};
use rift_core::peer::PeerId;

use crate::peer_manager::PeerManager;
use crate::tun_device::{TunDevice, TunConfig};
use crate::router::{Router, run_router};

/// Manages the complete WireGuard tunnel stack
pub struct TunnelManager {
    keypair: KeyPair,
    config: NetworkConfig,
    our_ip: Option<Ipv4Addr>,
    router: Option<Arc<Router>>,
    peer_manager: Arc<PeerManager>,
}

impl TunnelManager {
    /// Create a new tunnel manager (doesn't start the tunnel yet)
    pub fn new(
        keypair: KeyPair,
        config: NetworkConfig,
        peer_manager: Arc<PeerManager>,
    ) -> Self {
        Self {
            keypair,
            config,
            our_ip: None,
            router: None,
            peer_manager,
        }
    }

    /// Initialize and start the tunnel
    pub async fn start(&mut self, virtual_ip: Ipv4Addr) -> Result<()> {
        self.our_ip = Some(virtual_ip);

        info!("Starting tunnel with virtual IP {}", virtual_ip);

        // Parse network config
        let netmask = self.parse_netmask()?;

        // Create TUN device
        let tun_config = TunConfig::new(&self.config.interface_name, virtual_ip, netmask);
        let tun_device = TunDevice::create(tun_config).await?;

        info!("TUN device {} created with IP {}/{}", self.config.interface_name, virtual_ip, netmask);

        // Create packet channel for TUN writes
        let (tun_tx, tun_rx) = mpsc::channel(1024);

        // Create router
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", self.config.wg_port).parse()?;
        let router = Arc::new(Router::new(
            self.keypair.clone(),
            virtual_ip,
            bind_addr,
            tun_tx,
        ).await?);

        self.router = Some(router.clone());

        info!("Router started on port {}", self.config.wg_port);

        // Spawn the main processing loop
        tokio::spawn(async move {
            if let Err(e) = run_router(tun_device, router, tun_rx).await {
                error!("Router error: {}", e);
            }
        });

        // Start keepalive task
        self.start_keepalive();

        info!("Tunnel fully operational");

        Ok(())
    }

    /// Parse netmask from config (e.g., "10.99.0.0/16" -> 16)
    fn parse_netmask(&self) -> Result<u8> {
        let parts: Vec<&str> = self.config.virtual_network.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid virtual_network format: {}", self.config.virtual_network);
        }
        parts[1].parse().map_err(|e| anyhow::anyhow!("Invalid netmask: {}", e))
    }

    /// Add a peer to the tunnel
    pub fn add_peer(
        &self,
        peer_id: PeerId,
        public_key: PublicKey,
        virtual_ip: Ipv4Addr,
        endpoint: SocketAddr,
    ) -> Result<()> {
        let router = self.router.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Tunnel not started"))?;

        // Determine if we're the initiator based on key ordering
        let our_key = self.keypair.public_key().to_base64();
        let peer_key = public_key.to_base64();
        let is_initiator = our_key < peer_key;

        router.add_peer(peer_id, public_key, virtual_ip, endpoint, is_initiator);

        Ok(())
    }

    /// Remove a peer from the tunnel
    pub fn remove_peer(&self, virtual_ip: &Ipv4Addr) -> Result<()> {
        let router = self.router.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Tunnel not started"))?;

        router.remove_peer(virtual_ip);

        Ok(())
    }

    /// Update a peer's endpoint
    pub fn update_peer_endpoint(&self, virtual_ip: &Ipv4Addr, endpoint: SocketAddr) -> Result<()> {
        let router = self.router.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Tunnel not started"))?;

        router.update_endpoint(virtual_ip, endpoint);

        Ok(())
    }

    /// Get list of connected peers
    pub fn connected_peers(&self) -> Vec<(PeerId, Ipv4Addr, SocketAddr)> {
        self.router
            .as_ref()
            .map(|r| r.connected_peers())
            .unwrap_or_default()
    }

    /// Start the keepalive task
    fn start_keepalive(&self) {
        let router = match &self.router {
            Some(r) => r.clone(),
            None => return,
        };

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(25));

            loop {
                interval.tick().await;

                // Check for stale sessions
                let stale = router.stale_sessions(Duration::from_secs(120));
                for ip in stale {
                    warn!("Session to {} is stale", ip);
                    // In a full implementation, we'd trigger reconnection here
                }
            }
        });
    }

    /// Get our virtual IP
    pub fn our_ip(&self) -> Option<Ipv4Addr> {
        self.our_ip
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.router.is_some()
    }
}

/// WireGuard packet processing documentation
///
/// ## Packet Flow
///
/// ```text
/// Application (e.g., ping 10.99.0.5)
///         │
///         ▼
/// ┌───────────────────┐
/// │    OS Routing     │
/// │ (10.99.0.0/16 →   │
/// │    rift0)         │
/// └───────────────────┘
///         │
///         ▼
/// ┌───────────────────┐
/// │   TUN Device      │  ← Read plaintext IP packet
/// │   (rift0)         │
/// └───────────────────┘
///         │
///         ▼
/// ┌───────────────────┐
/// │   Router          │
/// │ - Parse dst IP    │  ← Look up peer by destination
/// │ - Find session    │
/// │ - Encrypt packet  │  ← ChaCha20-Poly1305
/// └───────────────────┘
///         │
///         ▼
/// ┌───────────────────┐
/// │   UDP Socket      │  ← Send to peer's endpoint
/// │   (port 51820)    │
/// └───────────────────┘
///         │
///         ▼
///    [ Internet ]
///         │
///         ▼
///    [ Peer Node ]     ← Receives, decrypts, injects to their TUN
/// ```
///
/// ## Security Properties
///
/// - **Confidentiality**: ChaCha20-Poly1305 AEAD encryption
/// - **Integrity**: Poly1305 authentication tag
/// - **Replay Protection**: Monotonic nonce with sliding window
/// - **Forward Secrecy**: Session keys derived from ephemeral DH
/// - **Identity Hiding**: Static keys not exposed in cleartext
pub struct PacketFlow;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_netmask_format() {
        // Test the netmask parsing logic directly
        let network = "10.99.0.0/16";
        let parts: Vec<&str> = network.split('/').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "10.99.0.0");
        assert_eq!(parts[1], "16");

        let netmask: u8 = parts[1].parse().unwrap();
        assert_eq!(netmask, 16);
    }

    #[test]
    fn test_netmask_24() {
        let network = "192.168.1.0/24";
        let parts: Vec<&str> = network.split('/').collect();
        let netmask: u8 = parts[1].parse().unwrap();
        assert_eq!(netmask, 24);
    }
}
