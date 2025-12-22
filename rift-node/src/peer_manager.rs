use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{info, warn, debug, error};

use rift_core::config::NetworkConfig;
use rift_core::crypto::KeyPair;
use rift_core::peer::{Peer, PeerId, ConnectionState, NatType};
use rift_core::protocol::PeerInfo;

use crate::beacon_client::BeaconClient;
use crate::nat::HolePuncher;

/// Manages connections to other peers in the mesh
pub struct PeerManager {
    keypair: KeyPair,
    config: NetworkConfig,
    beacon: Arc<BeaconClient>,

    /// Known peers
    peers: DashMap<PeerId, ManagedPeer>,

    /// Hole punch attempts in progress
    punching: DashMap<PeerId, HolePunchAttempt>,
}

struct ManagedPeer {
    info: PeerInfo,
    state: ConnectionState,
    wg_endpoint: Option<SocketAddr>,
    last_handshake: Option<std::time::Instant>,
}

struct HolePunchAttempt {
    target: PeerId,
    attempts: u32,
    started: std::time::Instant,
}

impl PeerManager {
    pub fn new(
        keypair: KeyPair,
        config: NetworkConfig,
        beacon: Arc<BeaconClient>,
    ) -> Self {
        Self {
            keypair,
            config,
            beacon,
            peers: DashMap::new(),
            punching: DashMap::new(),
        }
    }

    /// Start peer discovery loop
    pub async fn start_discovery(self: &Arc<Self>) {
        let manager = self.clone();

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(30));

            loop {
                ticker.tick().await;

                if let Err(e) = manager.discover_peers().await {
                    warn!("Peer discovery failed: {}", e);
                }
            }
        });

        // Start connection maintenance loop
        let manager = self.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));

            loop {
                ticker.tick().await;
                manager.maintain_connections().await;
            }
        });
    }

    /// Discover peers from beacon
    async fn discover_peers(&self) -> anyhow::Result<()> {
        let peers = self.beacon.list_peers().await?;
        let my_key = self.keypair.public_key().to_base64();

        for peer_info in peers {
            // Skip ourselves
            if peer_info.public_key.to_base64() == my_key {
                continue;
            }

            let peer_id = peer_info.peer_id.clone();

            // Add or update peer
            if self.peers.contains_key(&peer_id) {
                // Update existing
                if let Some(mut p) = self.peers.get_mut(&peer_id) {
                    p.info = peer_info;
                }
            } else {
                // Add new peer
                info!("Discovered peer: {} ({})", peer_info.name, peer_id);

                self.peers.insert(peer_id.clone(), ManagedPeer {
                    info: peer_info,
                    state: ConnectionState::Disconnected,
                    wg_endpoint: None,
                    last_handshake: None,
                });

                // Try to connect to new peer
                self.initiate_connection(&peer_id).await;
            }
        }

        Ok(())
    }

    /// Maintain existing connections
    async fn maintain_connections(&self) {
        for mut entry in self.peers.iter_mut() {
            let peer_id = entry.key().clone();
            let peer = entry.value_mut();

            match &peer.state {
                ConnectionState::Disconnected => {
                    // Try to connect
                    debug!("Attempting connection to disconnected peer {}", peer_id);
                    drop(entry);
                    self.initiate_connection(&peer_id).await;
                }
                ConnectionState::HolePunching { attempts } => {
                    if *attempts >= self.config.hole_punch_attempts {
                        // Switch to relay
                        info!("Hole punch failed for {}, switching to relay", peer_id);
                        drop(entry);
                        self.setup_relay(&peer_id).await;
                    }
                }
                ConnectionState::Direct | ConnectionState::Relayed => {
                    // Check if still alive
                    if let Some(last) = peer.last_handshake {
                        if last.elapsed() > Duration::from_secs(180) {
                            warn!("Peer {} handshake stale, reconnecting", peer_id);
                            peer.state = ConnectionState::Disconnected;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Initiate connection to a peer
    async fn initiate_connection(&self, peer_id: &PeerId) {
        let peer = match self.peers.get(peer_id) {
            Some(p) => p,
            None => return,
        };

        // Check if we should try hole punching
        let should_punch = match peer.info.nat_type {
            NatType::Symmetric => false, // Will need relay
            _ => true,
        };

        drop(peer);

        if should_punch {
            self.attempt_hole_punch(peer_id).await;
        } else if self.config.allow_relay {
            self.setup_relay(peer_id).await;
        }
    }

    /// Attempt UDP hole punch to peer
    async fn attempt_hole_punch(&self, peer_id: &PeerId) {
        // Update state
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.state = ConnectionState::HolePunching { attempts: 1 };
        }

        // Request hole punch coordination from beacon
        let punch_info = match self.beacon.request_hole_punch(peer_id).await {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to get hole punch info: {}", e);
                return;
            }
        };

        info!(
            "Attempting hole punch to {} at {}",
            peer_id, punch_info.peer_addr
        );

        // Perform hole punch
        let puncher = HolePuncher::new(self.config.wg_port);

        match puncher.punch(
            punch_info.peer_addr,
            punch_info.packet_count,
            Duration::from_millis(punch_info.interval_ms as u64),
        ).await {
            Ok(true) => {
                info!("Hole punch successful to {}", peer_id);
                if let Some(mut peer) = self.peers.get_mut(peer_id) {
                    peer.state = ConnectionState::Direct;
                    peer.wg_endpoint = Some(punch_info.peer_addr);
                }
            }
            Ok(false) => {
                warn!("Hole punch failed to {}", peer_id);
                if let Some(mut peer) = self.peers.get_mut(peer_id) {
                    if let ConnectionState::HolePunching { attempts } = peer.state {
                        if attempts < self.config.hole_punch_attempts {
                            peer.state = ConnectionState::HolePunching {
                                attempts: attempts + 1,
                            };
                        }
                    }
                }
            }
            Err(e) => {
                error!("Hole punch error: {}", e);
            }
        }
    }

    /// Set up relay connection to peer
    async fn setup_relay(&self, peer_id: &PeerId) {
        if !self.config.allow_relay {
            warn!("Relay disabled, cannot connect to {}", peer_id);
            return;
        }

        info!("Setting up relay to {}", peer_id);

        match self.beacon.request_relay(peer_id).await {
            Ok(session_id) => {
                info!("Relay established to {} (session {})", peer_id, session_id);
                if let Some(mut peer) = self.peers.get_mut(peer_id) {
                    peer.state = ConnectionState::Relayed;
                }
            }
            Err(e) => {
                error!("Failed to establish relay: {}", e);
            }
        }
    }

    /// Get all connected peers
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .filter(|p| matches!(p.state, ConnectionState::Direct | ConnectionState::Relayed))
            .map(|p| p.info.clone())
            .collect()
    }

    /// Get peer connection state
    pub fn get_peer_state(&self, peer_id: &PeerId) -> Option<ConnectionState> {
        self.peers.get(peer_id).map(|p| p.state.clone())
    }

    /// Notify that a WireGuard handshake succeeded
    pub fn handshake_complete(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.last_handshake = Some(std::time::Instant::now());
        }
    }
}
