//! IPC (Inter-Process Communication) for daemon control
//!
//! Provides a Unix socket interface for controlling the running daemon
//! from the CLI or other processes.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, debug, warn, error};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// IPC command from client to daemon
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcCommand {
    /// Get daemon status
    Status,
    /// List connected peers
    ListPeers,
    /// Get specific peer info
    GetPeer { virtual_ip: Ipv4Addr },
    /// Add a peer manually
    AddPeer {
        public_key: String,
        endpoint: Option<String>,
    },
    /// Remove a peer
    RemovePeer { virtual_ip: Ipv4Addr },
    /// Request relay for a peer
    RequestRelay { virtual_ip: Ipv4Addr },
    /// Force reconnect to beacon
    Reconnect,
    /// Ping (for connection test)
    Ping,
    /// Shutdown the daemon
    Shutdown,
}

/// IPC response from daemon to client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Success with optional message
    Ok { message: Option<String> },
    /// Error with message
    Error { message: String },
    /// Status information
    Status(DaemonStatus),
    /// Peer list
    PeerList(Vec<PeerStatus>),
    /// Single peer info
    PeerInfo(Option<PeerStatus>),
    /// Pong response
    Pong,
}

/// Daemon status information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Node name
    pub node_name: String,
    /// Our virtual IP
    pub virtual_ip: Ipv4Addr,
    /// Connection to beacon
    pub beacon_connected: bool,
    /// Number of connected peers
    pub peer_count: usize,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// TUN interface status
    pub tunnel_active: bool,
}

/// Peer status information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    /// Peer's virtual IP
    pub virtual_ip: Ipv4Addr,
    /// Peer's name
    pub name: String,
    /// Connection state
    pub state: String,
    /// Last handshake time (unix timestamp)
    pub last_handshake: Option<u64>,
    /// Bytes sent
    pub bytes_tx: u64,
    /// Bytes received
    pub bytes_rx: u64,
    /// Using relay
    pub relayed: bool,
}

/// Default socket path
pub fn default_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/run/rift/rift-node.sock")
    }
    #[cfg(not(unix))]
    {
        PathBuf::from("\\\\.\\pipe\\rift-node")
    }
}

/// IPC Server that listens for control commands
#[cfg(unix)]
pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

#[cfg(unix)]
impl IpcServer {
    /// Create and bind a new IPC server
    pub async fn bind(socket_path: &Path) -> Result<Self> {
        // Remove existing socket if present
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        info!("IPC server listening on {:?}", socket_path);

        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// Run the IPC server with a command handler
    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(IpcCommand) -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = IpcResponse> + Send,
    {
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, handler).await {
                            warn!("IPC client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("IPC accept error: {}", e);
                }
            }
        }
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(unix)]
impl Drop for IpcServer {
    fn drop(&mut self) {
        // Clean up socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Handle a single IPC client connection
#[cfg(unix)]
async fn handle_client<F, Fut>(stream: UnixStream, handler: F) -> Result<()>
where
    F: Fn(IpcCommand) -> Fut,
    Fut: std::future::Future<Output = IpcResponse>,
{
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read command
    reader.read_line(&mut line).await?;
    let command: IpcCommand = serde_json::from_str(line.trim())?;

    debug!("IPC command: {:?}", command);

    // Handle command
    let response = handler(command).await;

    // Send response
    let response_json = serde_json::to_string(&response)?;
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    Ok(())
}

/// IPC Client for sending commands to the daemon
pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send a command and receive a response
    #[cfg(unix)]
    pub async fn send(&self, command: IpcCommand) -> Result<IpcResponse> {
        let stream = UnixStream::connect(&self.socket_path).await
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        let (reader, mut writer) = stream.into_split();

        // Send command
        let command_json = serde_json::to_string(&command)?;
        writer.write_all(command_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.shutdown().await?;

        // Read response
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let response: IpcResponse = serde_json::from_str(line.trim())?;
        Ok(response)
    }

    #[cfg(not(unix))]
    pub async fn send(&self, _command: IpcCommand) -> Result<IpcResponse> {
        anyhow::bail!("IPC not supported on this platform");
    }

    /// Check if daemon is running
    pub async fn is_running(&self) -> bool {
        matches!(self.send(IpcCommand::Ping).await, Ok(IpcResponse::Pong))
    }
}

/// Helper to create a command handler closure
#[macro_export]
macro_rules! ipc_handler {
    ($state:expr, |$cmd:ident| $body:expr) => {
        {
            let state = $state.clone();
            move |$cmd: IpcCommand| {
                let state = state.clone();
                async move {
                    $body
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let cmd = IpcCommand::Status;
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::Status));
    }

    #[test]
    fn test_response_serialization() {
        let resp = IpcResponse::Status(DaemonStatus {
            node_name: "test-node".to_string(),
            virtual_ip: Ipv4Addr::new(10, 99, 0, 1),
            beacon_connected: true,
            peer_count: 5,
            uptime_secs: 3600,
            tunnel_active: true,
        });

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();

        if let IpcResponse::Status(status) = parsed {
            assert_eq!(status.node_name, "test-node");
            assert_eq!(status.peer_count, 5);
        } else {
            panic!("Wrong response type");
        }
    }

    #[test]
    fn test_peer_list_serialization() {
        let resp = IpcResponse::PeerList(vec![
            PeerStatus {
                virtual_ip: Ipv4Addr::new(10, 99, 0, 2),
                name: "peer1".to_string(),
                state: "connected".to_string(),
                last_handshake: Some(1234567890),
                bytes_tx: 1024,
                bytes_rx: 2048,
                relayed: false,
            },
        ]);

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("peer1"));
        assert!(json.contains("10.99.0.2"));
    }
}
