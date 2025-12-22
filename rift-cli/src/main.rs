use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;

mod commands;

use commands::{init, status, peers, keys};

#[derive(Parser)]
#[command(name = "rift")]
#[command(author, version, about = "Rift - Peer-to-peer mesh VPN")]
#[command(propagate_version = true)]
struct Cli {
    /// Config file path
    #[arg(short, long, global = true, default_value = "rift.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Rift node
    Init {
        /// Node name
        #[arg(short, long)]
        name: String,

        /// Beacon server address (host:port)
        #[arg(short, long)]
        beacon: String,
    },

    /// Show node status
    Status,

    /// Manage peers
    #[command(subcommand)]
    Peer(PeerCommands),

    /// Key management
    #[command(subcommand)]
    Key(KeyCommands),

    /// Start the Rift daemon
    Up,

    /// Stop the Rift daemon
    Down,
}

#[derive(Subcommand)]
enum PeerCommands {
    /// List all known peers
    List,

    /// Add a peer by public key
    Add {
        /// Peer's public key (base64)
        #[arg(short, long)]
        key: String,

        /// Peer name
        #[arg(short, long)]
        name: String,

        /// Static endpoint (optional, for peers with public IPs)
        #[arg(short, long)]
        endpoint: Option<String>,
    },

    /// Remove a peer
    Remove {
        /// Peer name or public key prefix
        peer: String,
    },

    /// Show peer details
    Show {
        /// Peer name or public key prefix
        peer: String,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Show this node's public key
    Show,

    /// Generate a new keypair (warning: will change node identity)
    Generate {
        /// Force regeneration without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// Export keys for backup
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Import keys from backup
    Import {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up minimal logging for CLI
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .without_time()
        .init();

    match cli.command {
        Commands::Init { name, beacon } => {
            init::run(&cli.config, &name, &beacon)?;
        }
        Commands::Status => {
            status::run(&cli.config).await?;
        }
        Commands::Peer(cmd) => match cmd {
            PeerCommands::List => peers::list(&cli.config).await?,
            PeerCommands::Add { key, name, endpoint } => {
                peers::add(&cli.config, &key, &name, endpoint.as_deref())?;
            }
            PeerCommands::Remove { peer } => {
                peers::remove(&cli.config, &peer)?;
            }
            PeerCommands::Show { peer } => {
                peers::show(&cli.config, &peer).await?;
            }
        },
        Commands::Key(cmd) => match cmd {
            KeyCommands::Show => keys::show(&cli.config)?,
            KeyCommands::Generate { force } => keys::generate(&cli.config, force)?,
            KeyCommands::Export { output } => keys::export(&cli.config, &output)?,
            KeyCommands::Import { input } => keys::import(&cli.config, &input)?,
        },
        Commands::Up => {
            println!("{}", "Starting Rift daemon...".green());
            println!("Run: rift-node run -c {:?}", cli.config);
        }
        Commands::Down => {
            println!("{}", "Stopping Rift daemon...".yellow());
            // Would send signal to daemon
        }
    }

    Ok(())
}
