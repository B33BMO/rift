use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::crypto::PublicKey;
use crate::peer::{NatType, PeerId};

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// All messages in the Rift protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    // === Beacon Registration ===

    /// Node registers with beacon
    Register(RegisterRequest),
    /// Beacon acknowledges registration
    RegisterAck(RegisterAck),

    // === Peer Discovery ===

    /// Request list of online peers
    ListPeers,
    /// Response with peer list
    PeerList(Vec<PeerInfo>),

    /// Request specific peer's endpoint
    GetPeer { peer_id: PeerId },
    /// Response with peer info
    PeerInfo(Option<PeerInfo>),

    // === Hole Punching ===

    /// Request hole punch coordination
    HolePunchRequest { target_peer: PeerId },
    /// Beacon instructs peer to begin hole punch
    HolePunchBegin(HolePunchInfo),
    /// Report hole punch result
    HolePunchResult { target_peer: PeerId, success: bool },

    // === Relay ===

    /// Request relay through beacon
    RelayRequest { target_peer: PeerId },
    /// Beacon confirms relay established
    RelayEstablished { session_id: String },
    /// Relayed data packet
    RelayData { session_id: String, data: Vec<u8> },
    /// Close relay session
    RelayClose { session_id: String },

    // === Keepalive ===

    /// Ping to maintain connection
    Ping { timestamp: u64 },
    /// Pong response
    Pong { timestamp: u64 },

    // === Errors ===

    /// Error response
    Error { code: ErrorCode, message: String },
}

/// Registration request from node to beacon
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Protocol version
    pub version: u32,
    /// Node's public key
    pub public_key: PublicKey,
    /// Human-readable node name
    pub name: String,
    /// Node's local/private address
    pub local_addr: Option<SocketAddr>,
    /// Signature over (version || public_key || timestamp)
    pub signature: Vec<u8>,
    /// Timestamp for replay protection
    pub timestamp: u64,
}

/// Beacon's response to registration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterAck {
    /// Assigned peer ID
    pub peer_id: PeerId,
    /// Node's public address as seen by beacon
    pub observed_addr: SocketAddr,
    /// Detected NAT type
    pub nat_type: NatType,
    /// Assigned virtual IP
    pub virtual_ip: std::net::Ipv4Addr,
    /// Beacon's public key (for verification)
    pub beacon_public_key: PublicKey,
}

/// Information about a peer (from beacon)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's unique ID
    pub peer_id: PeerId,
    /// Peer's public key
    pub public_key: PublicKey,
    /// Human-readable name
    pub name: String,
    /// Peer's public endpoint
    pub public_addr: SocketAddr,
    /// Peer's NAT type
    pub nat_type: NatType,
    /// Virtual IP in mesh
    pub virtual_ip: std::net::Ipv4Addr,
    /// Is peer currently online
    pub online: bool,
    /// Last seen timestamp
    pub last_seen: u64,
}

/// Hole punch coordination info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HolePunchInfo {
    /// Target peer's public key
    pub peer_public_key: PublicKey,
    /// Target peer's public endpoint to punch towards
    pub peer_addr: SocketAddr,
    /// Your public endpoint (as seen by beacon)
    pub your_addr: SocketAddr,
    /// Suggested punch timing (ms from now)
    pub punch_at: u64,
    /// Number of packets to send
    pub packet_count: u32,
    /// Interval between packets (ms)
    pub interval_ms: u32,
}

/// Protocol error codes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    /// Unknown/internal error
    Unknown,
    /// Unsupported protocol version
    VersionMismatch,
    /// Invalid signature
    AuthFailed,
    /// Peer not found
    PeerNotFound,
    /// Peer offline
    PeerOffline,
    /// Rate limited
    RateLimited,
    /// Relay unavailable
    RelayUnavailable,
}

impl Message {
    /// Serialize message to bytes
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize message from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::Ping { timestamp: 12345 };
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();

        match decoded {
            Message::Ping { timestamp } => assert_eq!(timestamp, 12345),
            _ => panic!("Wrong message type"),
        }
    }
}
