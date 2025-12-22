use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::crypto::PublicKey;

/// Unique identifier for a peer (derived from public key)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(String);

impl PeerId {
    /// Create from a public key
    pub fn from_public_key(pk: &PublicKey) -> Self {
        // Use first 16 chars of base64 public key as ID
        let b64 = pk.to_base64();
        Self(b64[..16].to_string())
    }

    /// Create from raw string (for deserialization)
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Connection state of a peer
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Attempting to connect
    Connecting,
    /// Performing UDP hole punch
    HolePunching { attempts: u32 },
    /// Connected directly (peer-to-peer)
    Direct,
    /// Connected via relay
    Relayed,
}

/// NAT type detected for this node
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestricted,
    /// Symmetric NAT (hardest, usually requires relay)
    Symmetric,
    /// Unknown/not yet detected
    Unknown,
}

/// Information about a peer's network endpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    /// Public address as seen by beacon
    pub public_addr: SocketAddr,
    /// Local/private address (for LAN detection)
    pub local_addr: Option<SocketAddr>,
    /// Detected NAT type
    pub nat_type: NatType,
    /// Last time this endpoint was confirmed valid
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Full peer information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    /// Unique peer ID
    pub id: PeerId,
    /// Peer's public key
    pub public_key: PublicKey,
    /// Human-readable name
    pub name: String,
    /// Current endpoint info (if known)
    pub endpoint: Option<Endpoint>,
    /// Current connection state
    pub state: ConnectionState,
    /// Assigned virtual IP in the mesh
    pub virtual_ip: Option<std::net::Ipv4Addr>,
    /// Is this peer authorized to connect?
    pub authorized: bool,
}

impl Peer {
    pub fn new(public_key: PublicKey, name: String) -> Self {
        let id = PeerId::from_public_key(&public_key);
        Self {
            id,
            public_key,
            name,
            endpoint: None,
            state: ConnectionState::Disconnected,
            virtual_ip: None,
            authorized: false,
        }
    }

    /// Check if we can attempt a direct connection
    pub fn can_hole_punch(&self) -> bool {
        if let Some(ref ep) = self.endpoint {
            // Symmetric NAT usually requires relay
            !matches!(ep.nat_type, NatType::Symmetric)
        } else {
            false
        }
    }
}

/// Authorized peer entry (for config file)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizedPeer {
    pub public_key: String,
    pub name: String,
    /// Optional static endpoint (for peers with known public IPs)
    pub endpoint: Option<String>,
}
