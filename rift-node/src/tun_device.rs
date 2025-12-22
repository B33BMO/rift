//! TUN device management for the virtual network interface
//!
//! Creates and manages the rift0 (or similar) interface that captures
//! IP traffic destined for the mesh network.

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, error, warn};

/// Configuration for the TUN device
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Interface name (e.g., "rift0")
    pub name: String,
    /// MTU for the interface
    pub mtu: u16,
    /// Virtual IP address for this node
    pub address: Ipv4Addr,
    /// Network mask (e.g., 16 for /16)
    pub netmask: u8,
}

impl TunConfig {
    pub fn new(name: &str, address: Ipv4Addr, netmask: u8) -> Self {
        Self {
            name: name.to_string(),
            mtu: 1420, // WireGuard default
            address,
            netmask,
        }
    }

    /// Calculate the network address
    pub fn network(&self) -> Ipv4Addr {
        let addr = u32::from(self.address);
        let mask = !((1u32 << (32 - self.netmask)) - 1);
        Ipv4Addr::from(addr & mask)
    }

    /// Calculate the netmask as an IP address
    pub fn netmask_addr(&self) -> Ipv4Addr {
        let mask = !((1u32 << (32 - self.netmask)) - 1);
        Ipv4Addr::from(mask)
    }
}

/// TUN device wrapper with async I/O
pub struct TunDevice {
    config: TunConfig,
    device: tun::AsyncDevice,
}

impl TunDevice {
    /// Create and configure a new TUN device
    pub async fn create(config: TunConfig) -> Result<Self> {
        info!("Creating TUN device {} with address {}/{}",
              config.name, config.address, config.netmask);

        let mut tun_config = tun::Configuration::default();

        tun_config
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask_addr())
            .mtu(config.mtu as i32)
            .up();

        // Platform-specific settings
        #[cfg(target_os = "linux")]
        tun_config.platform(|platform| {
            // On Linux, disable packet information header
            platform.packet_information(false);
        });

        // macOS doesn't need special platform configuration
        #[cfg(target_os = "macos")]
        {
            // macOS TUN devices don't have the packet_information option
        }

        let device = tun::create_as_async(&tun_config)
            .context("Failed to create TUN device")?;

        info!("TUN device {} created successfully", config.name);

        // Configure routing
        Self::configure_routes(&config).await?;

        Ok(Self { config, device })
    }

    /// Configure system routes for the virtual network
    async fn configure_routes(config: &TunConfig) -> Result<()> {
        let network = config.network();
        let netmask = config.netmask;
        let interface = &config.name;

        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            // Add route for the virtual network
            let output = Command::new("ip")
                .args(["route", "add", &format!("{}/{}", network, netmask), "dev", interface])
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Ignore "file exists" error (route already exists)
                if !stderr.contains("File exists") {
                    warn!("Failed to add route: {}", stderr);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;

            // macOS uses different route command syntax
            let output = Command::new("route")
                .args(["-n", "add", "-net", &format!("{}/{}", network, netmask), "-interface", interface])
                .output()
                .await?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    warn!("Failed to add route: {}", stderr);
                }
            }
        }

        info!("Routes configured for {}/{} via {}", network, netmask, interface);
        Ok(())
    }

    /// Read a packet from the TUN device
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.device.read(buf).await?;
        debug!("TUN read {} bytes", n);
        Ok(n)
    }

    /// Write a packet to the TUN device
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.device.write(buf).await?;
        debug!("TUN write {} bytes", n);
        Ok(n)
    }

    /// Get the device configuration
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Get the interface name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the assigned IP address
    pub fn address(&self) -> Ipv4Addr {
        self.config.address
    }
}

/// Parse an IPv4 packet to extract destination address
pub fn parse_ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }

    // Check IPv4 version
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    // Destination IP is at bytes 16-19
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some(dst)
}

/// Parse an IPv4 packet to extract source address
pub fn parse_ipv4_src(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }

    // Check IPv4 version
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    // Source IP is at bytes 12-15
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    Some(src)
}

/// Check if an IP address is within a network
pub fn is_in_network(addr: Ipv4Addr, network: Ipv4Addr, netmask: u8) -> bool {
    let addr_u32 = u32::from(addr);
    let network_u32 = u32::from(network);
    let mask = !((1u32 << (32 - netmask)) - 1);

    (addr_u32 & mask) == (network_u32 & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_dst() {
        // Minimal IPv4 header
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 99;
        packet[18] = 0;
        packet[19] = 5;

        let dst = parse_ipv4_dst(&packet).unwrap();
        assert_eq!(dst, Ipv4Addr::new(10, 99, 0, 5));
    }

    #[test]
    fn test_is_in_network() {
        let network = Ipv4Addr::new(10, 99, 0, 0);

        assert!(is_in_network(Ipv4Addr::new(10, 99, 0, 1), network, 16));
        assert!(is_in_network(Ipv4Addr::new(10, 99, 255, 255), network, 16));
        assert!(!is_in_network(Ipv4Addr::new(10, 100, 0, 1), network, 16));
        assert!(!is_in_network(Ipv4Addr::new(192, 168, 1, 1), network, 16));
    }

    #[test]
    fn test_tun_config_network() {
        let config = TunConfig::new("rift0", Ipv4Addr::new(10, 99, 5, 23), 16);
        assert_eq!(config.network(), Ipv4Addr::new(10, 99, 0, 0));
        assert_eq!(config.netmask_addr(), Ipv4Addr::new(255, 255, 0, 0));
    }
}
