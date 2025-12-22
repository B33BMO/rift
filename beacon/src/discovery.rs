use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use chrono::{DateTime, Utc};
use tracing::{info, debug};

use rift_core::crypto::PublicKey;
use rift_core::peer::{PeerId, NatType};
use rift_core::protocol::PeerInfo;

/// Registered peer state
struct RegisteredPeer {
    peer_id: PeerId,
    public_key: PublicKey,
    name: String,
    public_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    nat_type: NatType,
    virtual_ip: Ipv4Addr,
    last_seen: DateTime<Utc>,
    online: bool,
}

/// Registry of all known peers
pub struct PeerRegistry {
    /// Peers indexed by ID
    peers: DashMap<PeerId, RegisteredPeer>,
    /// Peers indexed by public key
    by_public_key: DashMap<String, PeerId>,
    /// Virtual IP allocator
    ip_allocator: IpAllocator,
}

impl PeerRegistry {
    pub fn new(virtual_network: &str) -> Self {
        Self {
            peers: DashMap::new(),
            by_public_key: DashMap::new(),
            ip_allocator: IpAllocator::new(virtual_network),
        }
    }

    /// Register or update a peer
    pub fn register(
        &self,
        public_key: PublicKey,
        name: String,
        public_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        nat_type: NatType,
    ) -> (PeerId, Ipv4Addr) {
        let pk_string = public_key.to_base64();
        let peer_id = PeerId::from_public_key(&public_key);

        // Check if peer already exists
        if let Some(existing_id) = self.by_public_key.get(&pk_string) {
            // Update existing peer
            if let Some(mut peer) = self.peers.get_mut(&existing_id) {
                peer.public_addr = public_addr;
                peer.local_addr = local_addr;
                peer.nat_type = nat_type;
                peer.last_seen = Utc::now();
                peer.online = true;
                let ip = peer.virtual_ip;
                debug!("Updated peer {} at {}", peer_id, public_addr);
                return (peer_id, ip);
            }
        }

        // Allocate new virtual IP
        let virtual_ip = self.ip_allocator.allocate();

        let peer = RegisteredPeer {
            peer_id: peer_id.clone(),
            public_key,
            name,
            public_addr,
            local_addr,
            nat_type,
            virtual_ip,
            last_seen: Utc::now(),
            online: true,
        };

        self.peers.insert(peer_id.clone(), peer);
        self.by_public_key.insert(pk_string, peer_id.clone());

        info!("New peer {} assigned virtual IP {}", peer_id, virtual_ip);

        (peer_id, virtual_ip)
    }

    /// Get peer info by ID
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.get(peer_id).map(|p| PeerInfo {
            peer_id: p.peer_id.clone(),
            public_key: p.public_key.clone(),
            name: p.name.clone(),
            public_addr: p.public_addr,
            nat_type: p.nat_type.clone(),
            virtual_ip: p.virtual_ip,
            online: p.online,
            last_seen: p.last_seen.timestamp() as u64,
        })
    }

    /// Get peer by public key
    pub fn get_peer_by_key(&self, public_key: &PublicKey) -> Option<PeerInfo> {
        let pk_string = public_key.to_base64();
        self.by_public_key
            .get(&pk_string)
            .and_then(|id| self.get_peer(&id))
    }

    /// List all online peers
    pub fn list_online_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .filter(|p| p.online)
            .map(|p| PeerInfo {
                peer_id: p.peer_id.clone(),
                public_key: p.public_key.clone(),
                name: p.name.clone(),
                public_addr: p.public_addr,
                nat_type: p.nat_type.clone(),
                virtual_ip: p.virtual_ip,
                online: p.online,
                last_seen: p.last_seen.timestamp() as u64,
            })
            .collect()
    }

    /// Update peer's last seen timestamp
    pub fn touch(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.last_seen = Utc::now();
            peer.online = true;
        }
    }

    /// Mark peer as offline
    pub fn mark_offline(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.online = false;
        }
    }

    /// Clean up stale peers (mark offline if no recent activity)
    pub fn cleanup_stale(&self, timeout: Duration) {
        let cutoff = Utc::now() - chrono::Duration::from_std(timeout).unwrap();

        for mut peer in self.peers.iter_mut() {
            if peer.online && peer.last_seen < cutoff {
                debug!("Marking peer {} as offline (stale)", peer.peer_id);
                peer.online = false;
            }
        }
    }
}

/// Simple virtual IP allocator
struct IpAllocator {
    base: u32,
    mask: u32,
    next: AtomicU32,
}

impl IpAllocator {
    fn new(cidr: &str) -> Self {
        // Parse CIDR like "10.99.0.0/16"
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip: Ipv4Addr = parts[0].parse().unwrap_or(Ipv4Addr::new(10, 99, 0, 0));
        let prefix_len: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(16);

        let base = u32::from(ip);
        let mask = !((1u32 << (32 - prefix_len)) - 1);

        Self {
            base: base & mask,
            mask,
            next: AtomicU32::new(1), // Start at .1, .0 is network
        }
    }

    fn allocate(&self) -> Ipv4Addr {
        let offset = self.next.fetch_add(1, Ordering::Relaxed);
        let host_bits = !self.mask;

        // Wrap around within the subnet, skip .0 and .255
        let host = ((offset - 1) % (host_bits - 1)) + 1;
        Ipv4Addr::from(self.base | host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allocator() {
        let alloc = IpAllocator::new("10.99.0.0/16");

        let ip1 = alloc.allocate();
        let ip2 = alloc.allocate();
        let ip3 = alloc.allocate();

        assert_eq!(ip1, Ipv4Addr::new(10, 99, 0, 1));
        assert_eq!(ip2, Ipv4Addr::new(10, 99, 0, 2));
        assert_eq!(ip3, Ipv4Addr::new(10, 99, 0, 3));
    }
}
