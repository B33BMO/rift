use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled, settings::Style};

use rift_core::config::Config;
use rift_core::crypto::PublicKey;
use rift_core::peer::AuthorizedPeer;

#[derive(Tabled)]
struct PeerRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Public Key")]
    public_key: String,
    #[tabled(rename = "Endpoint")]
    endpoint: String,
}

pub async fn list(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;

    if config.peers.is_empty() {
        println!("{}", "No peers configured.".yellow());
        println!();
        println!("Add a peer with: {}", "rift peer add -k <public_key> -n <name>".cyan());
        return Ok(());
    }

    let rows: Vec<PeerRow> = config
        .peers
        .iter()
        .map(|p| PeerRow {
            name: p.name.clone(),
            public_key: truncate_key(&p.public_key),
            endpoint: p.endpoint.clone().unwrap_or_else(|| "dynamic".to_string()),
        })
        .collect();

    let table = Table::new(rows)
        .with(Style::rounded())
        .to_string();

    println!("{}", "Authorized Peers".cyan().bold());
    println!();
    println!("{}", table);
    println!();
    println!("{} {} peers configured", "Total:".dimmed(), config.peers.len());

    Ok(())
}

pub fn add(config_path: &Path, key: &str, name: &str, endpoint: Option<&str>) -> Result<()> {
    // Validate the public key
    let _ = PublicKey::from_base64(key)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    let mut config = Config::load(config_path)?;

    // Check if peer already exists
    if config.peers.iter().any(|p| p.public_key == key) {
        anyhow::bail!("Peer with this public key already exists");
    }

    if config.peers.iter().any(|p| p.name == name) {
        anyhow::bail!("Peer with name '{}' already exists", name);
    }

    // Add peer
    config.peers.push(AuthorizedPeer {
        public_key: key.to_string(),
        name: name.to_string(),
        endpoint: endpoint.map(String::from),
    });

    config.save(config_path)?;

    println!("{} Added peer '{}'", "Success!".green().bold(), name);
    println!();
    println!("  {} {}", "Name:".dimmed(), name);
    println!("  {} {}", "Key:".dimmed(), truncate_key(key));
    if let Some(ep) = endpoint {
        println!("  {} {}", "Endpoint:".dimmed(), ep);
    }
    println!();
    println!(
        "{}",
        "Restart the daemon for changes to take effect.".dimmed()
    );

    Ok(())
}

pub fn remove(config_path: &Path, peer: &str) -> Result<()> {
    let mut config = Config::load(config_path)?;

    let initial_len = config.peers.len();

    // Remove by name or key prefix
    config.peers.retain(|p| {
        p.name != peer && !p.public_key.starts_with(peer)
    });

    if config.peers.len() == initial_len {
        anyhow::bail!("No peer matching '{}' found", peer);
    }

    config.save(config_path)?;

    println!("{} Removed peer '{}'", "Success!".green().bold(), peer);

    Ok(())
}

pub async fn show(config_path: &Path, peer: &str) -> Result<()> {
    let config = Config::load(config_path)?;

    let found = config.peers.iter().find(|p| {
        p.name == peer || p.public_key.starts_with(peer)
    });

    match found {
        Some(p) => {
            println!("{}", "Peer Details".cyan().bold());
            println!();
            println!("  {} {}", "Name:".white().bold(), p.name);
            println!("  {} {}", "Public Key:".dimmed(), p.public_key);
            println!(
                "  {} {}",
                "Endpoint:".dimmed(),
                p.endpoint.as_deref().unwrap_or("dynamic")
            );
            println!();

            // TODO: Query daemon for live status
            println!("{}", "Live Status:".white().bold());
            println!("  {} {}", "Status:".dimmed(), "Unknown (daemon not running)".yellow());
        }
        None => {
            anyhow::bail!("No peer matching '{}' found", peer);
        }
    }

    Ok(())
}

fn truncate_key(key: &str) -> String {
    if key.len() > 16 {
        format!("{}...{}", &key[..8], &key[key.len()-8..])
    } else {
        key.to_string()
    }
}
