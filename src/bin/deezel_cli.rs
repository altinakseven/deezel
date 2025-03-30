//! Deezel CLI binary
//!
//! This is the main entry point for the deezel CLI.

use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use std::path::PathBuf;
use std::fs;
use std::io::Write;

use deezel::cli::{Cli, CliConfig, CliManager};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Parse command-line arguments
    let cli = Cli::parse();
    
    // Load or create config
    let config = load_or_create_config()?;
    
    // Create CLI manager
    let manager = CliManager::new(config);
    
    // Run CLI
    manager.run(cli).await?;
    
    Ok(())
}

/// Load or create CLI configuration
fn load_or_create_config() -> Result<CliConfig> {
    // Get config path
    let config_path = get_config_path()?;
    
    // Create parent directory if it doesn't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }
    
    // Check if config file exists
    if config_path.exists() {
        // Load config
        let config_str = fs::read_to_string(&config_path)
            .context("Failed to read config file")?;
        
        // Parse config
        let config: CliConfig = serde_json::from_str(&config_str)
            .context("Failed to parse config file")?;
        
        Ok(config)
    } else {
        // Create default config
        let config = CliConfig::default();
        
        // Save config
        let config_str = serde_json::to_string_pretty(&config)
            .context("Failed to serialize config")?;
        
        let mut file = fs::File::create(&config_path)
            .context("Failed to create config file")?;
        
        file.write_all(config_str.as_bytes())
            .context("Failed to write config file")?;
        
        Ok(config)
    }
}

/// Get config path
fn get_config_path() -> Result<PathBuf> {
    // Get home directory
    let home_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Failed to get home directory"))?;
    
    // Create config path
    let config_path = home_dir.join(".deezel").join("config.json");
    
    Ok(config_path)
}
