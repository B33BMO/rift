use std::path::PathBuf;
use std::sync::Arc;
use std::fs;
use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, warn, error, Level};
use tracing_subscriber::{FmtSubscriber, EnvFilter};

mod beacon_client;
mod tunnel;
mod peer_manager;
mod nat;
mod tun_device;
mod router;
mod relay_client;
mod ipc;
mod connection;

use rift_core::config::Config;
use beacon_client::BeaconClient;
use peer_manager::PeerManager;
use tunnel::TunnelManager;

#[derive(Parser, Debug)]
#[command(name = "rift-node")]
#[command(about = "Rift mesh VPN node daemon")]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "rift.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new config file
    Init {
        /// Node name
        #[arg(short, long)]
        name: String,

        /// Beacon server address
        #[arg(short, long)]
        beacon: String,
    },

    /// Run the daemon (default)
    Run {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,

        /// PID file path (for daemon mode)
        #[arg(long, default_value = "/var/run/rift/rift-node.pid")]
        pid_file: PathBuf,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Show node status
    Status,

    /// Show public key
    Pubkey,

    /// Stop a running daemon
    Stop {
        /// PID file path
        #[arg(long, default_value = "/var/run/rift/rift-node.pid")]
        pid_file: PathBuf,
    },

    /// List connected peers (requires running daemon)
    Peers {
        /// IPC socket path
        #[arg(long)]
        socket: Option<PathBuf>,
    },

    /// Control daemon via IPC
    Ctl {
        /// IPC socket path
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Command to send
        #[arg(value_enum)]
        action: CtlAction,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum CtlAction {
    /// Get daemon status
    Status,
    /// List peers
    Peers,
    /// Ping daemon
    Ping,
    /// Request beacon reconnect
    Reconnect,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Commands::Init { name, beacon }) => {
            // Simple logging for init
            FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();
            init_config(&args.config, &name, &beacon)?;
        }
        Some(Commands::Run { foreground, pid_file, log_level }) => {
            // Parse log level
            let level = match log_level.to_lowercase().as_str() {
                "trace" => Level::TRACE,
                "debug" => Level::DEBUG,
                "info" => Level::INFO,
                "warn" => Level::WARN,
                "error" => Level::ERROR,
                _ => Level::INFO,
            };

            // Initialize logging
            FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(false)
                .init();

            // Write PID file if not foreground
            if !foreground {
                write_pid_file(&pid_file)?;
            }

            // Setup signal handlers
            let result = run_daemon_with_signals(&args.config).await;

            // Cleanup PID file
            if !foreground {
                let _ = fs::remove_file(&pid_file);
            }

            result?;
        }
        None => {
            // Default: run in foreground
            FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();
            run_daemon_with_signals(&args.config).await?;
        }
        Some(Commands::Status) => {
            FmtSubscriber::builder()
                .with_max_level(Level::WARN)
                .with_target(false)
                .init();
            show_status(&args.config).await?;
        }
        Some(Commands::Pubkey) => {
            show_pubkey(&args.config)?;
        }
        Some(Commands::Stop { pid_file }) => {
            stop_daemon(&pid_file)?;
        }
        Some(Commands::Peers { socket }) => {
            let socket_path = socket.unwrap_or_else(ipc::default_socket_path);
            handle_ipc_command(socket_path, ipc::IpcCommand::ListPeers).await?;
        }
        Some(Commands::Ctl { socket, action }) => {
            let socket_path = socket.unwrap_or_else(ipc::default_socket_path);
            let cmd = match action {
                CtlAction::Status => ipc::IpcCommand::Status,
                CtlAction::Peers => ipc::IpcCommand::ListPeers,
                CtlAction::Ping => ipc::IpcCommand::Ping,
                CtlAction::Reconnect => ipc::IpcCommand::Reconnect,
            };
            handle_ipc_command(socket_path, cmd).await?;
        }
    }

    Ok(())
}

/// Handle IPC command and display response
async fn handle_ipc_command(socket_path: PathBuf, command: ipc::IpcCommand) -> Result<()> {
    let client = ipc::IpcClient::new(socket_path);

    match client.send(command).await {
        Ok(response) => {
            match response {
                ipc::IpcResponse::Ok { message } => {
                    if let Some(msg) = message {
                        println!("{}", msg);
                    } else {
                        println!("OK");
                    }
                }
                ipc::IpcResponse::Error { message } => {
                    eprintln!("Error: {}", message);
                }
                ipc::IpcResponse::Status(status) => {
                    println!("Rift Node Status");
                    println!("================");
                    println!("Node:            {}", status.node_name);
                    println!("Virtual IP:      {}", status.virtual_ip);
                    println!("Beacon:          {}", if status.beacon_connected { "connected" } else { "disconnected" });
                    println!("Tunnel:          {}", if status.tunnel_active { "active" } else { "inactive" });
                    println!("Connected peers: {}", status.peer_count);
                    println!("Uptime:          {}s", status.uptime_secs);
                }
                ipc::IpcResponse::PeerList(peers) => {
                    if peers.is_empty() {
                        println!("No connected peers");
                    } else {
                        println!("{:<16} {:<20} {:<12} {:<10}", "VIRTUAL IP", "NAME", "STATE", "RELAY");
                        println!("{}", "-".repeat(60));
                        for peer in peers {
                            println!("{:<16} {:<20} {:<12} {:<10}",
                                peer.virtual_ip,
                                peer.name,
                                peer.state,
                                if peer.relayed { "yes" } else { "no" }
                            );
                        }
                    }
                }
                ipc::IpcResponse::PeerInfo(Some(peer)) => {
                    println!("Peer: {}", peer.name);
                    println!("  Virtual IP:     {}", peer.virtual_ip);
                    println!("  State:          {}", peer.state);
                    println!("  Relayed:        {}", peer.relayed);
                    println!("  Bytes TX:       {}", peer.bytes_tx);
                    println!("  Bytes RX:       {}", peer.bytes_rx);
                }
                ipc::IpcResponse::PeerInfo(None) => {
                    println!("Peer not found");
                }
                ipc::IpcResponse::Pong => {
                    println!("Daemon is running");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to communicate with daemon: {}", e);
            eprintln!("Is the daemon running?");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Write PID to file
fn write_pid_file(path: &PathBuf) -> Result<()> {
    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let pid = std::process::id();
    let mut file = fs::File::create(path)?;
    writeln!(file, "{}", pid)?;
    info!("Wrote PID {} to {:?}", pid, path);
    Ok(())
}

/// Stop a running daemon by reading PID file
fn stop_daemon(pid_file: &PathBuf) -> Result<()> {
    let pid_str = fs::read_to_string(pid_file)
        .map_err(|e| anyhow::anyhow!("Failed to read PID file: {}", e))?;

    let pid: i32 = pid_str.trim().parse()
        .map_err(|e| anyhow::anyhow!("Invalid PID: {}", e))?;

    // Send SIGTERM
    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|e| anyhow::anyhow!("Failed to send signal: {}", e))?;
        println!("Sent SIGTERM to PID {}", pid);
    }

    #[cfg(not(unix))]
    {
        println!("Stop command not supported on this platform");
    }

    Ok(())
}

/// Run daemon with proper signal handling
async fn run_daemon_with_signals(config_path: &PathBuf) -> Result<()> {
    // Setup graceful shutdown
    let shutdown = setup_signal_handlers().await;

    // Run the daemon
    tokio::select! {
        result = run_daemon(config_path) => {
            result
        }
        _ = shutdown => {
            info!("Received shutdown signal, stopping...");
            Ok(())
        }
    }
}

/// Setup signal handlers for graceful shutdown
async fn setup_signal_handlers() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sighup = signal(SignalKind::hangup()).unwrap();

        async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP (reload not yet implemented)");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        async move {
            tokio::signal::ctrl_c().await.ok();
            info!("Received Ctrl+C");
        }
    }
}

fn init_config(path: &PathBuf, name: &str, beacon: &str) -> Result<()> {
    if path.exists() {
        anyhow::bail!("Config file already exists at {:?}", path);
    }

    let mut config = Config::default_config(name, beacon);

    // Generate keypair
    let keypair = config.get_or_create_keypair()?;

    config.save(path)?;

    info!("Created config at {:?}", path);
    info!("Node public key: {}", keypair.public_key().to_base64());

    Ok(())
}

async fn run_daemon(config_path: &PathBuf) -> Result<()> {
    let mut config = Config::load(config_path)?;
    let keypair = config.get_or_create_keypair()?;
    let start_time = std::time::Instant::now();

    info!("Starting Rift node: {}", config.node.name);
    info!("Public key: {}", keypair.public_key().fingerprint());

    // Connect to beacon
    info!("Connecting to beacon at {}...", config.beacon.address);
    let beacon_client = BeaconClient::connect(&config, keypair.clone()).await?;
    let beacon_client = Arc::new(beacon_client);

    info!("Connected to beacon");

    // Register with beacon
    let registration = beacon_client.register().await?;
    info!("Registered with beacon:");
    info!("  Virtual IP: {}", registration.virtual_ip);
    info!("  NAT type: {:?}", registration.nat_type);
    info!("  Observed address: {}", registration.observed_addr);

    // Create TUN packet channel
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    // Initialize connection manager
    let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", config.network.wg_port).parse()?;
    let conn_config = connection::ConnectionConfig::default();
    let conn_manager = Arc::new(
        connection::ConnectionManager::new(
            keypair.clone(),
            registration.virtual_ip,
            bind_addr,
            tun_tx.clone(),
            conn_config,
        ).await?
    );

    info!("Connection manager ready on port {}", config.network.wg_port);

    // Initialize peer manager (for discovery)
    let peer_manager = Arc::new(PeerManager::new(
        keypair.clone(),
        config.network.clone(),
        beacon_client.clone(),
    ));

    // Try to create TUN device (requires root/admin privileges)
    let mut tunnel_manager = TunnelManager::new(
        keypair.clone(),
        config.network.clone(),
        peer_manager.clone(),
    );

    let tunnel_active = match tunnel_manager.start(registration.virtual_ip).await {
        Ok(()) => {
            info!("Tunnel interface {} is up with IP {}",
                  config.network.interface_name,
                  registration.virtual_ip);
            true
        }
        Err(e) => {
            warn!("Failed to create TUN device: {}", e);
            warn!("Running in limited mode (no tunnel interface)");
            warn!("To create TUN device, run with: sudo rift-node run");
            false
        }
    };

    // Start IPC server
    #[cfg(unix)]
    let ipc_handle = {
        let socket_path = ipc::default_socket_path();
        let node_name = config.node.name.clone();
        let virtual_ip = registration.virtual_ip;
        let conn_manager_ipc = conn_manager.clone();
        let beacon_connected = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let beacon_connected_clone = beacon_connected.clone();

        match ipc::IpcServer::bind(&socket_path).await {
            Ok(ipc_server) => {
                info!("IPC server listening on {:?}", socket_path);
                Some(tokio::spawn(async move {
                    let handler = move |cmd: ipc::IpcCommand| {
                        let node_name = node_name.clone();
                        let conn_manager = conn_manager_ipc.clone();
                        let beacon_connected = beacon_connected_clone.clone();
                        async move {
                            match cmd {
                                ipc::IpcCommand::Ping => ipc::IpcResponse::Pong,
                                ipc::IpcCommand::Status => {
                                    let peers = conn_manager.list_peers();
                                    let connected_count = peers.iter()
                                        .filter(|p| {
                                            let state = p.state.try_read();
                                            state.map(|s| s.is_connected()).unwrap_or(false)
                                        })
                                        .count();

                                    ipc::IpcResponse::Status(ipc::DaemonStatus {
                                        node_name: node_name.clone(),
                                        virtual_ip,
                                        beacon_connected: beacon_connected.load(std::sync::atomic::Ordering::Relaxed),
                                        peer_count: connected_count,
                                        uptime_secs: start_time.elapsed().as_secs(),
                                        tunnel_active,
                                    })
                                }
                                ipc::IpcCommand::ListPeers => {
                                    let peers = conn_manager.list_peers();
                                    let mut peer_list = Vec::new();

                                    for peer in peers {
                                        let state = peer.state.try_read()
                                            .map(|s| s.state_name().to_string())
                                            .unwrap_or_else(|_| "unknown".to_string());
                                        let relay_session = peer.relay_session.try_read()
                                            .map(|r| r.is_some())
                                            .unwrap_or(false);

                                        peer_list.push(ipc::PeerStatus {
                                            virtual_ip: peer.virtual_ip,
                                            name: peer.name.clone(),
                                            state,
                                            last_handshake: None, // TODO: track this
                                            bytes_tx: peer.bytes_tx.load(std::sync::atomic::Ordering::Relaxed),
                                            bytes_rx: peer.bytes_rx.load(std::sync::atomic::Ordering::Relaxed),
                                            relayed: relay_session,
                                        });
                                    }

                                    ipc::IpcResponse::PeerList(peer_list)
                                }
                                ipc::IpcCommand::GetPeer { virtual_ip: ip } => {
                                    if let Some(peer) = conn_manager.get_peer(&ip) {
                                        let state = peer.state.try_read()
                                            .map(|s| s.state_name().to_string())
                                            .unwrap_or_else(|_| "unknown".to_string());
                                        let relayed = peer.relay_session.try_read()
                                            .map(|r| r.is_some())
                                            .unwrap_or(false);

                                        ipc::IpcResponse::PeerInfo(Some(ipc::PeerStatus {
                                            virtual_ip: peer.virtual_ip,
                                            name: peer.name.clone(),
                                            state,
                                            last_handshake: None,
                                            bytes_tx: peer.bytes_tx.load(std::sync::atomic::Ordering::Relaxed),
                                            bytes_rx: peer.bytes_rx.load(std::sync::atomic::Ordering::Relaxed),
                                            relayed,
                                        }))
                                    } else {
                                        ipc::IpcResponse::PeerInfo(None)
                                    }
                                }
                                ipc::IpcCommand::Reconnect => {
                                    ipc::IpcResponse::Ok { message: Some("Reconnect initiated".to_string()) }
                                }
                                ipc::IpcCommand::Shutdown => {
                                    ipc::IpcResponse::Ok { message: Some("Shutdown requested".to_string()) }
                                }
                                _ => ipc::IpcResponse::Error { message: "Not implemented".to_string() },
                            }
                        }
                    };
                    let _ = ipc_server.run(handler).await;
                }))
            }
            Err(e) => {
                warn!("Failed to start IPC server: {}", e);
                None
            }
        }
    };

    #[cfg(not(unix))]
    let ipc_handle: Option<tokio::task::JoinHandle<()>> = None;

    // Start peer discovery
    peer_manager.start_discovery().await;

    // Start beacon keepalive
    beacon_client.start_keepalive();

    // Start connection manager receive loop
    let conn_manager_run = conn_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = connection::run_connection_manager(conn_manager_run).await {
            error!("Connection manager error: {}", e);
        }
    });

    // Add configured peers
    for peer_config in &config.peers {
        match rift_core::crypto::PublicKey::from_base64(&peer_config.public_key) {
            Ok(pubkey) => {
                info!("Configured peer: {} ({})", peer_config.name, pubkey.fingerprint());
                // TODO: Add to connection manager when they're discovered
            }
            Err(e) => {
                warn!("Invalid public key for peer {}: {}", peer_config.name, e);
            }
        }
    }

    // Log startup complete
    info!("");
    info!("===========================================");
    info!("  Rift node running");
    info!("  Virtual IP: {}", registration.virtual_ip);
    info!("  PID: {}", std::process::id());
    info!("  IPC: {:?}", ipc::default_socket_path());
    info!("===========================================");
    info!("");

    // Keep running until shutdown signal
    std::future::pending::<()>().await;

    Ok(())
}

async fn show_status(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;

    println!("Rift Node Status");
    println!("================");
    println!();
    println!("Node:     {}", config.node.name);
    println!("Beacon:   {}", config.beacon.address);
    println!("Interface: {}", config.network.interface_name);
    println!("Network:  {}", config.network.virtual_network);
    println!("WG Port:  {}", config.network.wg_port);
    println!();
    println!("Configured peers: {}", config.peers.len());
    for peer in &config.peers {
        println!("  - {} ({}...)", peer.name, &peer.public_key[..16]);
    }

    Ok(())
}

fn show_pubkey(config_path: &PathBuf) -> Result<()> {
    let mut config = Config::load(config_path)?;
    let keypair = config.get_or_create_keypair()?;

    println!("{}", keypair.public_key().to_base64());

    // Save if we generated a new key
    config.save(config_path)?;

    Ok(())
}
