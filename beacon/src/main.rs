use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

mod server;
mod discovery;
mod hole_punch;
mod relay;

use rift_core::config::BeaconServerConfig;
use server::BeaconServer;
use relay::{RelayManager, RelayServer};

#[derive(Parser, Debug)]
#[command(name = "beacon")]
#[command(about = "Rift mesh VPN beacon server")]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "beacon.toml")]
    config: PathBuf,

    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<SocketAddr>,

    /// Generate default config and exit
    #[arg(long)]
    init: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let args = Args::parse();

    // Generate default config if requested
    if args.init {
        let default_addr: SocketAddr = "0.0.0.0:7770".parse()?;
        let config = BeaconServerConfig::default_config(default_addr);
        config.save(&args.config)?;
        info!("Created default config at {:?}", args.config);
        return Ok(());
    }

    // Load config
    let mut config = if args.config.exists() {
        BeaconServerConfig::load(&args.config)?
    } else {
        info!("Config not found, using defaults. Run with --init to generate config file.");
        BeaconServerConfig::default_config("0.0.0.0:7770".parse()?)
    };

    // Override listen address if provided
    if let Some(addr) = args.listen {
        config.listen_addr = addr;
    }

    info!("Starting Rift Beacon on {}", config.listen_addr);

    // Create beacon server
    let server = BeaconServer::new(config.clone()).await?;

    // Start UDP relay server if enabled
    if config.enable_relay {
        let relay_addr = config.relay_addr();
        let relay_manager = server.relay_manager();

        let relay_server = RelayServer::bind(relay_addr, relay_manager).await?;
        info!("UDP relay server listening on {}", relay_addr);

        // Spawn relay server in background
        tokio::spawn(async move {
            if let Err(e) = relay_server.run().await {
                error!("Relay server error: {}", e);
            }
        });
    }

    // Run QUIC control server (blocking)
    server.run().await?;

    Ok(())
}
