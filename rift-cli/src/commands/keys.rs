use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use dialoguer::Confirm;

use rift_core::config::Config;
use rift_core::crypto::{KeyPair, ExportedKeyPair};

pub fn show(config_path: &Path) -> Result<()> {
    let mut config = Config::load(config_path)?;
    let keypair = config.get_or_create_keypair()?;

    // Save in case we generated a new key
    config.save(config_path)?;

    let public_key = keypair.public_key();

    println!("{}", "Node Public Key".cyan().bold());
    println!();
    println!("{}", public_key.to_base64());
    println!();
    println!("{} {}", "Fingerprint:".dimmed(), public_key.fingerprint());
    println!();
    println!(
        "{}",
        "Share this key with peers who want to connect to you.".dimmed()
    );

    Ok(())
}

pub fn generate(config_path: &Path, force: bool) -> Result<()> {
    let mut config = Config::load(config_path)?;

    if config.node.keys.is_some() && !force {
        let confirmed = Confirm::new()
            .with_prompt("This will replace your existing keypair. All peers will need your new public key. Continue?")
            .default(false)
            .interact()?;

        if !confirmed {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }

    // Generate new keypair
    let keypair = KeyPair::generate();
    config.node.keys = Some(keypair.export_private());
    config.save(config_path)?;

    let public_key = keypair.public_key();

    println!("{}", "New keypair generated!".green().bold());
    println!();
    println!("{}", "Public Key:".cyan());
    println!("{}", public_key.to_base64());
    println!();
    println!(
        "{}",
        "Important: Share this new public key with all your peers.".yellow()
    );

    Ok(())
}

pub fn export(config_path: &Path, output: &Path) -> Result<()> {
    let config = Config::load(config_path)?;

    let keys = config.node.keys.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No keys found in config"))?;

    let json = serde_json::to_string_pretty(keys)?;
    std::fs::write(output, json)?;

    println!("{} Keys exported to {:?}", "Success!".green().bold(), output);
    println!();
    println!(
        "{}",
        "Warning: This file contains your private keys. Keep it secure!".yellow()
    );

    Ok(())
}

pub fn import(config_path: &Path, input: &Path) -> Result<()> {
    let mut config = Config::load(config_path)?;

    // Confirm if keys already exist
    if config.node.keys.is_some() {
        let confirmed = Confirm::new()
            .with_prompt("This will replace your existing keypair. Continue?")
            .default(false)
            .interact()?;

        if !confirmed {
            println!("{}", "Aborted.".yellow());
            return Ok(());
        }
    }

    // Read and parse keys
    let json = std::fs::read_to_string(input)?;
    let keys: ExportedKeyPair = serde_json::from_str(&json)?;

    // Validate keys
    let keypair = KeyPair::import(&keys)?;
    let public_key = keypair.public_key();

    config.node.keys = Some(keys);
    config.save(config_path)?;

    println!("{} Keys imported!", "Success!".green().bold());
    println!();
    println!("{} {}", "Public Key:".dimmed(), public_key.fingerprint());

    Ok(())
}
