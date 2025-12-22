use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{info, debug};

use rift_core::crypto::PublicKey;
use rift_core::protocol::HolePunchInfo;

/// Coordinates UDP hole punching between peers
pub struct HolePunchCoordinator {
    /// Active hole punch sessions
    sessions: DashMap<String, HolePunchSession>,
}

struct HolePunchSession {
    initiator_addr: SocketAddr,
    target_addr: SocketAddr,
    created_at: Instant,
    state: HolePunchState,
}

#[derive(Clone, Debug)]
enum HolePunchState {
    Initiated,
    BothNotified,
    Completed { success: bool },
}

impl HolePunchCoordinator {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Initiate a hole punch from one peer to another
    pub fn initiate(
        &self,
        target_public_key: PublicKey,
        target_addr: SocketAddr,
        initiator_addr: SocketAddr,
    ) -> HolePunchInfo {
        let session_id = format!("{}-{}", initiator_addr, target_addr);

        let session = HolePunchSession {
            initiator_addr,
            target_addr,
            created_at: Instant::now(),
            state: HolePunchState::Initiated,
        };

        self.sessions.insert(session_id.clone(), session);

        debug!(
            "Hole punch initiated: {} -> {}",
            initiator_addr, target_addr
        );

        // Return punch instructions
        // Both peers should send packets at approximately the same time
        HolePunchInfo {
            peer_public_key: target_public_key,
            peer_addr: target_addr,
            your_addr: initiator_addr,
            // Punch in 100ms to allow for message propagation
            punch_at: 100,
            // Send 5 packets
            packet_count: 5,
            // 50ms between packets
            interval_ms: 50,
        }
    }

    /// Record the result of a hole punch attempt
    pub fn record_result(&self, initiator_addr: SocketAddr, target_addr: SocketAddr, success: bool) {
        let session_id = format!("{}-{}", initiator_addr, target_addr);

        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.state = HolePunchState::Completed { success };

            if success {
                info!(
                    "Hole punch successful: {} <-> {}",
                    initiator_addr, target_addr
                );
            } else {
                info!(
                    "Hole punch failed: {} <-> {} (will need relay)",
                    initiator_addr, target_addr
                );
            }
        }
    }

    /// Check if hole punch is still pending
    pub fn is_pending(&self, initiator_addr: SocketAddr, target_addr: SocketAddr) -> bool {
        let session_id = format!("{}-{}", initiator_addr, target_addr);

        self.sessions
            .get(&session_id)
            .map(|s| !matches!(s.state, HolePunchState::Completed { .. }))
            .unwrap_or(false)
    }

    /// Clean up old sessions
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now.duration_since(session.created_at) < max_age
        });
    }
}

/// UDP hole punching strategy
///
/// ## How it works:
///
/// 1. Peer A wants to connect to Peer B (both behind NAT)
/// 2. Both peers are connected to the Beacon via QUIC
/// 3. Beacon knows both peers' public IP:port (as seen by the Beacon)
/// 4. When A requests to connect to B:
///    - Beacon tells A: "Send UDP packets to B's public endpoint"
///    - Beacon tells B: "Send UDP packets to A's public endpoint"
///    - Both peers send packets at approximately the same time
/// 5. The NAT tables on both sides create mappings:
///    - A's NAT: allows packets from B's public IP
///    - B's NAT: allows packets from A's public IP
/// 6. Once bidirectional communication is established, WireGuard takes over
///
/// ## NAT Types and Success Rates:
///
/// | A's NAT        | B's NAT        | Success |
/// |----------------|----------------|---------|
/// | None           | Any            | Yes     |
/// | Full Cone      | Full Cone      | Yes     |
/// | Full Cone      | Restricted     | Yes     |
/// | Full Cone      | Port Restr.    | Yes     |
/// | Full Cone      | Symmetric      | Likely  |
/// | Restricted     | Restricted     | Yes     |
/// | Restricted     | Port Restr.    | Yes     |
/// | Restricted     | Symmetric      | Maybe   |
/// | Port Restr.    | Port Restr.    | Yes     |
/// | Port Restr.    | Symmetric      | Unlikely|
/// | Symmetric      | Symmetric      | No      |
///
/// For Symmetric NAT, the port changes with each destination,
/// making it impossible to predict the correct port to punch through.
/// In these cases, relay is required.
pub struct HolePunchStrategy;

impl HolePunchStrategy {
    /// Determine if hole punching is likely to succeed
    pub fn should_attempt(
        nat_a: &rift_core::peer::NatType,
        nat_b: &rift_core::peer::NatType,
    ) -> bool {
        use rift_core::peer::NatType::*;

        match (nat_a, nat_b) {
            // At least one has no NAT
            (None, _) | (_, None) => true,
            // Both symmetric = won't work
            (Symmetric, Symmetric) => false,
            // One symmetric + port restricted = unlikely
            (Symmetric, PortRestricted) | (PortRestricted, Symmetric) => false,
            // Everything else is worth trying
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rift_core::peer::NatType;

    #[test]
    fn test_should_attempt() {
        assert!(HolePunchStrategy::should_attempt(&NatType::None, &NatType::Symmetric));
        assert!(HolePunchStrategy::should_attempt(&NatType::FullCone, &NatType::PortRestricted));
        assert!(!HolePunchStrategy::should_attempt(&NatType::Symmetric, &NatType::Symmetric));
    }
}
