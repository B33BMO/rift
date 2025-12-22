use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use rift_core::config::Config;

pub fn run(config_path: &Path, name: &str, beacon: &str) -> Result<()> {
    if config_path.exists() {
        anyhow::bail!(
            "Config file already exists at {:?}. Remove it first or use a different path.",
            config_path
        );
    }

    println!("{}", "Initializing new Rift node...".cyan());

    // Create default config
    let mut config = Config::default_config(name, beacon);

    // Generate keypair
    let keypair = config.get_or_create_keypair()?;
    let public_key = keypair.public_key();

    // Save config
    config.save(config_path)?;

    println!();
    println!("{}", "Node initialized successfully!".green().bold());
    println!();
    println!("  {} {}", "Name:".dimmed(), name);
    println!("  {} {}", "Beacon:".dimmed(), beacon);
    println!("  {} {:?}", "Config:".dimmed(), config_path);
    println!();
    println!("{}", "Public Key:".cyan().bold());
    println!("  {}", public_key.to_base64());
    println!();
    println!(
        "{}",
        "Share this public key with peers who want to connect to you.".dimmed()
    );
    println!();
    println!("Next steps:");
    println!("  1. Share your public key with other Rift nodes");
    println!("  2. Add their public keys: {}", "rift peer add -k <key> -n <name>".cyan());
    println!("  3. Start the daemon: {}", "rift up".cyan());

    Ok(())
}
