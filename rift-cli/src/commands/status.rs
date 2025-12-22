use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use rift_core::config::Config;

pub async fn run(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;

    println!("{}", "Rift Node Status".cyan().bold());
    println!();

    // Node info
    println!("{}", "Node:".white().bold());
    println!("  {} {}", "Name:".dimmed(), config.node.name);
    println!("  {} {}", "Interface:".dimmed(), config.network.interface_name);
    println!("  {} {}", "Virtual Network:".dimmed(), config.network.virtual_network);
    println!("  {} {}", "WireGuard Port:".dimmed(), config.network.wg_port);
    println!();

    // Beacon info
    println!("{}", "Beacon:".white().bold());
    println!("  {} {}", "Address:".dimmed(), config.beacon.address);
    // TODO: Ping beacon and show status
    println!("  {} {}", "Status:".dimmed(), "Unknown (daemon not running)".yellow());
    println!();

    // Peer summary
    println!("{}", "Peers:".white().bold());
    println!("  {} {}", "Authorized:".dimmed(), config.peers.len());
    // TODO: Query daemon for connected peer count
    println!("  {} {}", "Connected:".dimmed(), "Unknown (daemon not running)".yellow());
    println!();

    // Quick tips
    println!("{}", "Commands:".dimmed());
    println!("  {} - Start the daemon", "rift up".cyan());
    println!("  {} - List peers", "rift peer list".cyan());
    println!("  {} - Show public key", "rift key show".cyan());

    Ok(())
}

#[derive(Tabled)]
struct PeerRow {
    name: String,
    status: String,
    virtual_ip: String,
    endpoint: String,
    latency: String,
}
