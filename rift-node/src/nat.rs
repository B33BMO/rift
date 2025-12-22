use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::time::{timeout, sleep};
use tracing::{debug, info};

/// UDP hole punching implementation
pub struct HolePuncher {
    local_port: u16,
}

impl HolePuncher {
    pub fn new(local_port: u16) -> Self {
        Self { local_port }
    }

    /// Attempt to punch through NAT to reach a peer
    ///
    /// This works by:
    /// 1. Binding to our WireGuard port
    /// 2. Sending packets to the peer's public endpoint
    /// 3. This creates a NAT mapping that allows return traffic
    /// 4. Simultaneously, the peer does the same towards us
    /// 5. When both NAT mappings exist, bidirectional traffic flows
    pub async fn punch(
        &self,
        peer_addr: SocketAddr,
        packet_count: u32,
        interval: Duration,
    ) -> Result<bool> {
        // Bind to our WireGuard port
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", self.local_port).parse()?;
        let socket = UdpSocket::bind(bind_addr).await?;

        debug!(
            "Hole punching from {} to {}",
            socket.local_addr()?,
            peer_addr
        );

        // The punch packet - just random data, WireGuard will ignore non-WG packets
        // We just need to create the NAT mapping
        let punch_packet = b"RIFT_PUNCH";

        // Send punch packets
        for i in 0..packet_count {
            socket.send_to(punch_packet, peer_addr).await?;
            debug!("Sent punch packet {} to {}", i + 1, peer_addr);

            if i < packet_count - 1 {
                sleep(interval).await;
            }
        }

        // Wait for a response (peer punching back)
        let mut buf = [0u8; 64];

        match timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                debug!("Received {} bytes from {}", len, from);
                // If we received anything from the peer's direction, the punch worked
                if from.ip() == peer_addr.ip() {
                    info!("Hole punch successful - received response from peer");
                    return Ok(true);
                }
            }
            Ok(Err(e)) => {
                debug!("Receive error: {}", e);
            }
            Err(_) => {
                debug!("No response received (timeout)");
            }
        }

        // Even without a response, the punch might have worked
        // WireGuard will handle the actual connectivity test
        // We return false to indicate we didn't confirm success
        Ok(false)
    }
}

/// STUN-like NAT type detection
pub struct NatDetector;

impl NatDetector {
    /// Detect NAT type by probing behavior
    ///
    /// This is a simplified version. Full STUN would use multiple servers
    /// and more sophisticated probing.
    pub async fn detect(beacon_addr: SocketAddr) -> Result<rift_core::peer::NatType> {
        use rift_core::peer::NatType;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;

        // Send a probe to beacon
        socket.send_to(b"STUN_PROBE", beacon_addr).await?;

        // In a real implementation:
        // 1. Beacon would reply with our observed IP:port
        // 2. We'd compare to local_addr to detect NAT presence
        // 3. We'd probe from different ports to detect port mapping behavior
        // 4. We'd have beacon probe us from different ports to detect filtering

        // For now, use heuristics based on local address
        let local_ip = local_addr.ip();

        if local_ip.is_loopback() {
            return Ok(NatType::Unknown);
        }

        // Check if we appear to have a public IP
        let is_private = match local_ip {
            std::net::IpAddr::V4(ip) => {
                ip.is_private() || ip.is_loopback() || ip.is_link_local()
            }
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback() // IPv6 NAT is rare
            }
        };

        if !is_private {
            Ok(NatType::None)
        } else {
            // Behind NAT, assume port-restricted (common case)
            Ok(NatType::PortRestricted)
        }
    }
}

/// Simultaneous hole punch with timing coordination
pub struct CoordinatedPunch;

impl CoordinatedPunch {
    /// Execute a coordinated hole punch with precise timing
    ///
    /// Both peers should call this at approximately the same time
    /// (coordinated via beacon timestamp)
    pub async fn execute(
        local_port: u16,
        peer_addr: SocketAddr,
        punch_at_ms: u64,
        packet_count: u32,
        interval_ms: u32,
    ) -> Result<bool> {
        // Wait until the coordinated punch time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64;

        if punch_at_ms > now {
            let wait = Duration::from_millis(punch_at_ms - now);
            debug!("Waiting {}ms for coordinated punch", wait.as_millis());
            sleep(wait).await;
        }

        // Execute punch
        let puncher = HolePuncher::new(local_port);
        puncher.punch(
            peer_addr,
            packet_count,
            Duration::from_millis(interval_ms as u64),
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hole_puncher_creation() {
        let puncher = HolePuncher::new(51820);
        assert_eq!(puncher.local_port, 51820);
    }
}
