use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

use crate::crypto::{ExportedKeyPair, KeyPair};
use crate::peer::AuthorizedPeer;
use crate::error::{RiftError, Result};

/// Main configuration for a Rift node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Node settings
    pub node: NodeConfig,
    /// Beacon connection settings
    pub beacon: BeaconConfig,
    /// Network settings
    pub network: NetworkConfig,
    /// List of authorized peers
    #[serde(default)]
    pub peers: Vec<AuthorizedPeer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Human-readable node name
    pub name: String,
    /// Node's private keys (base64 encoded)
    #[serde(flatten)]
    pub keys: Option<ExportedKeyPair>,
    /// Path to store runtime data
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

fn default_data_dir() -> String {
    // Platform-specific data directory
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .map(|h| format!("{}/Library/Application Support/rift", h))
            .unwrap_or_else(|_| "/var/lib/rift".to_string())
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_DATA_HOME")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.local/share", h)))
            .map(|d| format!("{}/rift", d))
            .unwrap_or_else(|_| "/var/lib/rift".to_string())
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .map(|d| format!("{}\\rift", d))
            .unwrap_or_else(|_| "C:\\ProgramData\\rift".to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "/var/lib/rift".to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconConfig {
    /// Beacon server address
    pub address: String,
    /// Beacon's public key (for verification)
    pub public_key: Option<String>,
    /// Connection timeout (seconds)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Keepalive interval (seconds)
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
}

fn default_timeout() -> u64 { 30 }
fn default_keepalive() -> u64 { 25 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen port for WireGuard (0 = auto)
    #[serde(default = "default_wg_port")]
    pub wg_port: u16,
    /// Virtual network CIDR (e.g., "10.99.0.0/16")
    #[serde(default = "default_virtual_network")]
    pub virtual_network: String,
    /// TUN interface name
    #[serde(default = "default_interface_name")]
    pub interface_name: String,
    /// MTU for tunnel
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Enable relay fallback
    #[serde(default = "default_true")]
    pub allow_relay: bool,
    /// Max hole punch attempts before relay
    #[serde(default = "default_hole_punch_attempts")]
    pub hole_punch_attempts: u32,
}

fn default_wg_port() -> u16 { 51820 }
fn default_virtual_network() -> String { "10.99.0.0/16".to_string() }
fn default_interface_name() -> String { "rift0".to_string() }
fn default_mtu() -> u16 { 1420 }
fn default_true() -> bool { true }
fn default_hole_punch_attempts() -> u32 { 5 }

impl Config {
    /// Load config from TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RiftError::Config(format!("Failed to read config: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| RiftError::Config(format!("Failed to parse config: {}", e)))
    }

    /// Save config to TOML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| RiftError::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get or generate keypair
    pub fn get_or_create_keypair(&mut self) -> Result<KeyPair> {
        match &self.node.keys {
            Some(exported) => KeyPair::import(exported),
            None => {
                let kp = KeyPair::generate();
                self.node.keys = Some(kp.export_private());
                Ok(kp)
            }
        }
    }

    /// Create a default config
    pub fn default_config(name: &str, beacon_address: &str) -> Self {
        Self {
            node: NodeConfig {
                name: name.to_string(),
                keys: None,
                data_dir: default_data_dir(),
            },
            beacon: BeaconConfig {
                address: beacon_address.to_string(),
                public_key: None,
                timeout_secs: default_timeout(),
                keepalive_secs: default_keepalive(),
            },
            network: NetworkConfig {
                wg_port: default_wg_port(),
                virtual_network: default_virtual_network(),
                interface_name: default_interface_name(),
                mtu: default_mtu(),
                allow_relay: true,
                hole_punch_attempts: default_hole_punch_attempts(),
            },
            peers: vec![],
        }
    }
}

/// Configuration for the beacon server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BeaconServerConfig {
    /// Listen address for QUIC control plane
    pub listen_addr: SocketAddr,
    /// UDP relay port (for forwarding encrypted packets)
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
    /// Private keys
    #[serde(flatten)]
    pub keys: Option<ExportedKeyPair>,
    /// Virtual network to assign IPs from
    pub virtual_network: String,
    /// Enable relay functionality
    #[serde(default = "default_true")]
    pub enable_relay: bool,
    /// Max concurrent relay sessions
    #[serde(default = "default_max_relays")]
    pub max_relay_sessions: usize,
    /// Session timeout (seconds)
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,
}

fn default_relay_port() -> u16 { 7771 }

fn default_max_relays() -> usize { 1000 }
fn default_session_timeout() -> u64 { 300 }

impl BeaconServerConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RiftError::Config(format!("Failed to read config: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| RiftError::Config(format!("Failed to parse config: {}", e)))
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| RiftError::Config(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn default_config(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            relay_port: default_relay_port(),
            keys: None,
            virtual_network: "10.99.0.0/16".to_string(),
            enable_relay: true,
            max_relay_sessions: default_max_relays(),
            session_timeout_secs: default_session_timeout(),
        }
    }

    /// Get the relay server address (same IP as listen_addr, different port)
    pub fn relay_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_addr.ip(), self.relay_port)
    }
}
