use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

mod commands;

use commands::{init, keys};

#[derive(Parser)]
#[command(name = "rift")]
#[command(author, version, about = "Rift - Peer-to-peer mesh VPN")]
#[command(propagate_version = true)]
struct Cli {
    /// Config file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to the mesh VPN
    #[command(alias = "up")]
    Connect {
        /// Beacon server address (overrides config)
        #[arg(short, long)]
        beacon: Option<String>,
    },

    /// Disconnect from the mesh VPN (when running in background)
    #[command(alias = "down")]
    Disconnect,

    /// Show connection status
    Status,

    /// List connected peers
    Peers,

    /// Initialize a new Rift config
    Init {
        /// Node name
        #[arg(short, long)]
        name: String,

        /// Beacon server address (host:port)
        #[arg(short, long)]
        beacon: String,
    },

    /// Show this node's public key
    Key,

    /// Add a peer
    #[command(subcommand)]
    Peer(PeerCommands),
}

#[derive(Subcommand)]
enum PeerCommands {
    /// Add a peer by public key
    Add {
        /// Peer's public key (base64)
        #[arg(short, long)]
        key: String,

        /// Peer name
        #[arg(short, long)]
        name: String,
    },

    /// Remove a peer
    Remove {
        /// Peer name
        name: String,
    },
}

fn get_config_path(cli_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_path {
        return path;
    }

    // Check OS-specific default locations
    #[cfg(target_os = "macos")]
    {
        let path = PathBuf::from("/usr/local/etc/rift/rift.toml");
        if path.exists() {
            return path;
        }
    }

    #[cfg(target_os = "linux")]
    {
        let path = PathBuf::from("/etc/rift/rift.toml");
        if path.exists() {
            return path;
        }
    }

    // Check home directory
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".config/rift/rift.toml");
        if path.exists() {
            return path;
        }
    }

    // Default to current directory
    PathBuf::from("rift.toml")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = get_config_path(cli.config);

    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };

    match cli.command {
        Commands::Connect { beacon } => {
            // Initialize logging
            FmtSubscriber::builder()
                .with_max_level(log_level)
                .with_target(false)
                .init();

            connect(&config_path, beacon).await?;
        }

        Commands::Disconnect => {
            disconnect().await?;
        }

        Commands::Status => {
            status(&config_path).await?;
        }

        Commands::Peers => {
            peers().await?;
        }

        Commands::Init { name, beacon } => {
            FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .with_target(false)
                .without_time()
                .init();

            init::run(&config_path, &name, &beacon)?;
        }

        Commands::Key => {
            keys::show(&config_path)?;
        }

        Commands::Peer(cmd) => match cmd {
            PeerCommands::Add { key, name } => {
                commands::peers::add(&config_path, &key, &name, None)?;
            }
            PeerCommands::Remove { name } => {
                commands::peers::remove(&config_path, &name)?;
            }
        },
    }

    Ok(())
}

/// Connect to the mesh VPN
async fn connect(config_path: &PathBuf, beacon_override: Option<String>) -> Result<()> {
    use rift_core::config::Config;

    // Load config
    let mut config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            eprintln!();
            eprintln!("Run {} to create a config file", "rift init".cyan());
            std::process::exit(1);
        }
    };

    // Override beacon if specified
    if let Some(beacon) = beacon_override {
        config.beacon.address = beacon;
    }

    let keypair = config.get_or_create_keypair()?;

    println!();
    println!("  {} {}", "Rift".cyan().bold(), "Mesh VPN".dimmed());
    println!("  {}", "─".repeat(30).dimmed());
    println!("  {} {}", "Node:".dimmed(), config.node.name);
    println!("  {} {}", "Key:".dimmed(), keypair.public_key().fingerprint());
    println!();

    // Connect to beacon
    print!("  {} Connecting to beacon...", "●".yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    // Import beacon_client from rift_node or implement here
    // For now, use the rift_core protocol directly
    let beacon_addr: std::net::SocketAddr = config.beacon.address.parse()
        .map_err(|_| anyhow::anyhow!("Invalid beacon address: {}", config.beacon.address))?;

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(beacon_addr).await?;

    // Build registration request
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign the registration (version || public_key wg bytes || timestamp)
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&rift_core::protocol::PROTOCOL_VERSION.to_le_bytes());
    sign_data.extend_from_slice(&keypair.public_key().wg_public_key());
    sign_data.extend_from_slice(&timestamp.to_le_bytes());
    let signature = keypair.sign(&sign_data);

    let register_req = rift_core::protocol::Message::Register(rift_core::protocol::RegisterRequest {
        version: rift_core::protocol::PROTOCOL_VERSION,
        public_key: keypair.public_key().clone(),
        name: config.node.name.clone(),
        local_addr: None,
        signature: signature.to_vec(),
        timestamp,
    });

    let data = serde_json::to_vec(&register_req)?;
    socket.send(&data).await?;

    // Wait for response
    let mut buf = vec![0u8; 65535];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv(&mut buf)
    ).await;

    let n = match timeout {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            println!("\r  {} Connection failed: {}", "✗".red(), e);
            std::process::exit(1);
        }
        Err(_) => {
            println!("\r  {} Connection timed out", "✗".red());
            std::process::exit(1);
        }
    };

    let response: rift_core::protocol::Message = serde_json::from_slice(&buf[..n])?;

    let registration = match response {
        rift_core::protocol::Message::RegisterAck(ack) => ack,
        rift_core::protocol::Message::Error { code, message } => {
            println!("\r  {} Beacon error: {} ({:?})", "✗".red(), message, code);
            std::process::exit(1);
        }
        _ => {
            println!("\r  {} Unexpected response from beacon", "✗".red());
            std::process::exit(1);
        }
    };

    println!("\r  {} Connected to beacon            ", "✓".green());
    println!("  {} {}", "Virtual IP:".dimmed(), registration.virtual_ip.to_string().green());
    println!("  {} {:?}", "NAT type:".dimmed(), registration.nat_type);
    println!();

    // Discover peers from beacon
    print!("  {} Discovering peers...", "●".yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    let list_msg = rift_core::protocol::Message::ListPeers;
    let data = serde_json::to_vec(&list_msg)?;
    socket.send(&data).await?;

    let mut buf = vec![0u8; 65535];
    let peers = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv(&mut buf)
    ).await {
        Ok(Ok(n)) => {
            match serde_json::from_slice::<rift_core::protocol::Message>(&buf[..n]) {
                Ok(rift_core::protocol::Message::PeerList(peers)) => peers,
                _ => vec![],
            }
        }
        _ => vec![],
    };

    // Filter out ourselves
    let other_peers: Vec<_> = peers.iter()
        .filter(|p| p.virtual_ip != registration.virtual_ip)
        .collect();

    if other_peers.is_empty() {
        println!("\r  {} No other peers online          ", "●".yellow());
    } else {
        println!("\r  {} Found {} peer(s)                ", "✓".green(), other_peers.len());
        for peer in &other_peers {
            let status = if peer.online { "online".green() } else { "offline".yellow() };
            println!("      {} {} ({})", "→".dimmed(), peer.name, status);
        }
    }
    println!();

    // Try to create TUN device
    print!("  {} Creating tunnel interface...", "●".yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    #[cfg(target_os = "macos")]
    let tun_result = create_tun_macos(&config.network.interface_name, registration.virtual_ip).await;

    #[cfg(target_os = "linux")]
    let tun_result = create_tun_linux(&config.network.interface_name, registration.virtual_ip).await;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let tun_result: Result<(), anyhow::Error> = Err(anyhow::anyhow!("Unsupported platform"));

    match tun_result {
        Ok(()) => {
            println!("\r  {} Tunnel interface up              ", "✓".green());
        }
        Err(e) => {
            println!("\r  {} Tunnel failed: {}", "✗".yellow(), e);
            if !nix::unistd::Uid::effective().is_root() {
                println!("  {} Run with sudo for full functionality", "→".dimmed());
            }
        }
    }

    println!();
    println!("  {} Press {} to disconnect", "→".dimmed(), "Ctrl+C".cyan());
    println!();

    // Setup signal handler and wait
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        // Start keepalive loop
        let socket = Arc::new(socket);
        let socket_ka = socket.clone();
        let keepalive = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(25));
            loop {
                interval.tick().await;
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let msg = rift_core::protocol::Message::Ping { timestamp: ts };
                if let Ok(data) = serde_json::to_vec(&msg) {
                    let _ = socket_ka.send(&data).await;
                }
            }
        });

        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }

        keepalive.abort();
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    println!();
    println!("  {} Disconnected", "●".yellow());
    println!();

    Ok(())
}

#[cfg(target_os = "macos")]
async fn create_tun_macos(name: &str, ip: std::net::Ipv4Addr) -> Result<()> {
    use tokio::process::Command;

    // macOS uses utun devices - we can't name them, but we can configure them
    // For now, just configure routing
    let ip_str = ip.to_string();
    let network = format!("{}/24", ip_str.rsplit_once('.').map(|(prefix, _)| format!("{}.0", prefix)).unwrap_or(ip_str.clone()));

    // Add route for the virtual network
    Command::new("route")
        .args(["-n", "add", "-net", &network, &ip_str])
        .output()
        .await?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn create_tun_linux(name: &str, ip: std::net::Ipv4Addr) -> Result<()> {
    use tokio::process::Command;

    // Create TUN device
    Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tun"])
        .output()
        .await?;

    // Set IP address
    let ip_str = format!("{}/24", ip);
    Command::new("ip")
        .args(["addr", "add", &ip_str, "dev", name])
        .output()
        .await?;

    // Bring interface up
    Command::new("ip")
        .args(["link", "set", "dev", name, "up"])
        .output()
        .await?;

    Ok(())
}

/// Disconnect from VPN (for background daemon)
async fn disconnect() -> Result<()> {
    // Try to connect to IPC socket
    #[cfg(unix)]
    {
        let socket_path = dirs::runtime_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("rift.sock");

        if !socket_path.exists() {
            println!("{} Rift is not running", "●".yellow());
            return Ok(());
        }

        // Send shutdown command via IPC
        // For now, just inform the user
        println!("{} To disconnect, press Ctrl+C in the rift connect terminal", "→".dimmed());
    }

    #[cfg(not(unix))]
    {
        println!("{} To disconnect, press Ctrl+C in the rift connect terminal", "→".dimmed());
    }

    Ok(())
}

/// Show connection status
async fn status(config_path: &PathBuf) -> Result<()> {
    use rift_core::config::Config;

    println!();
    println!("  {} {}", "Rift".cyan().bold(), "Status".dimmed());
    println!("  {}", "─".repeat(30).dimmed());

    // Check if config exists
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(_) => {
            println!("  {} Not configured", "●".yellow());
            println!();
            println!("  Run {} to set up", "rift init".cyan());
            println!();
            return Ok(());
        }
    };

    println!("  {} {}", "Node:".dimmed(), config.node.name);
    println!("  {} {}", "Beacon:".dimmed(), config.beacon.address);
    println!("  {} {}", "Interface:".dimmed(), config.network.interface_name);
    println!("  {} {}", "Peers:".dimmed(), config.peers.len());
    println!();

    // Try to check if daemon is running via IPC
    #[cfg(unix)]
    {
        let socket_path = dirs::runtime_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("rift.sock");

        if socket_path.exists() {
            println!("  {} {}", "Status:".dimmed(), "Connected".green());
        } else {
            println!("  {} {}", "Status:".dimmed(), "Disconnected".yellow());
            println!();
            println!("  Run {} to connect", "rift connect".cyan());
        }
    }

    #[cfg(not(unix))]
    {
        println!("  {} {}", "Status:".dimmed(), "Unknown".yellow());
    }

    println!();

    Ok(())
}

/// List connected peers
async fn peers() -> Result<()> {
    use rift_core::config::Config;

    let config_path = get_config_path(None);

    println!();
    println!("  {} {}", "Rift".cyan().bold(), "Peers".dimmed());
    println!("  {}", "─".repeat(50).dimmed());

    // Load config to get beacon address
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(_) => {
            println!("  {} Not configured. Run: {}", "●".yellow(), "rift init".cyan());
            println!();
            return Ok(());
        }
    };

    // Connect to beacon and list peers
    let beacon_addr: std::net::SocketAddr = match config.beacon.address.parse() {
        Ok(addr) => addr,
        Err(_) => {
            println!("  {} Invalid beacon address", "✗".red());
            return Ok(());
        }
    };

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(beacon_addr).await?;

    let list_msg = rift_core::protocol::Message::ListPeers;
    let data = serde_json::to_vec(&list_msg)?;
    socket.send(&data).await?;

    let mut buf = vec![0u8; 65535];
    let peers = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv(&mut buf)
    ).await {
        Ok(Ok(n)) => {
            match serde_json::from_slice::<rift_core::protocol::Message>(&buf[..n]) {
                Ok(rift_core::protocol::Message::PeerList(peers)) => peers,
                _ => vec![],
            }
        }
        _ => {
            println!("  {} Could not reach beacon", "✗".red());
            println!();
            return Ok(());
        }
    };

    if peers.is_empty() {
        println!("  {} No peers registered", "●".yellow());
    } else {
        println!("  {:<16} {:<20} {:<10}", "VIRTUAL IP".dimmed(), "NAME".dimmed(), "STATUS".dimmed());
        println!("  {}", "─".repeat(50).dimmed());
        for peer in &peers {
            let status = if peer.online {
                "online".green().to_string()
            } else {
                "offline".yellow().to_string()
            };
            println!("  {:<16} {:<20} {:<10}",
                peer.virtual_ip.to_string(),
                peer.name,
                status
            );
        }
    }
    println!();

    Ok(())
}
