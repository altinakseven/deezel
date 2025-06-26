//! Wallet command handlers using the generic deezel runtime

use anyhow::Result;
use bitcoin::Address;
use deezel_core::runtime::DeezelRuntime;
use log::{info, error};
use serde_json::json;
use std::str::FromStr;

use crate::cli::WalletCommands;
use crate::ProductionRuntime;

pub async fn handle_wallet_command(
    mut runtime: ProductionRuntime,
    command: WalletCommands,
) -> Result<()> {
    match command {
        WalletCommands::Create { name, mnemonic, passphrase } => {
            create_wallet(&mut runtime, &name, mnemonic, passphrase).await
        }
        WalletCommands::List => {
            list_wallets(&runtime).await
        }
        WalletCommands::Load { name } => {
            load_wallet(&mut runtime, &name).await
        }
        WalletCommands::Balance { wallet } => {
            get_balance(&runtime, wallet).await
        }
        WalletCommands::Addresses { wallet, count } => {
            get_addresses(&runtime, wallet, count).await
        }
        WalletCommands::Utxos { wallet } => {
            get_utxos(&runtime, wallet).await
        }
        WalletCommands::Backup { name, output } => {
            backup_wallet(&runtime, &name, output).await
        }
        WalletCommands::Restore { input, name } => {
            restore_wallet(&mut runtime, &input, name).await
        }
    }
}

async fn create_wallet(
    runtime: &mut ProductionRuntime,
    name: &str,
    mnemonic: Option<String>,
    _passphrase: Option<String>,
) -> Result<()> {
    info!("Creating wallet: {}", name);
    
    runtime.create_wallet(name, mnemonic).await?;
    
    println!("✅ Wallet '{}' created successfully", name);
    println!("💡 Use 'deezel wallet load {}' to load this wallet", name);
    
    Ok(())
}

async fn list_wallets(runtime: &ProductionRuntime) -> Result<()> {
    info!("Listing wallets");
    
    let wallets = runtime.list_wallets().await?;
    
    if wallets.is_empty() {
        println!("No wallets found");
        println!("💡 Use 'deezel wallet create <name>' to create a new wallet");
    } else {
        println!("Available wallets:");
        for wallet in wallets {
            println!("  • {}", wallet);
        }
    }
    
    Ok(())
}

async fn load_wallet(runtime: &mut ProductionRuntime, name: &str) -> Result<()> {
    info!("Loading wallet: {}", name);
    
    runtime.load_wallet(name).await?;
    
    // Save the loaded wallet name in config
    let config = json!({
        "loaded_wallet": name,
        "loaded_at": chrono::Utc::now().to_rfc3339()
    });
    runtime.save_config("current_wallet", &config).await?;
    
    println!("✅ Wallet '{}' loaded successfully", name);
    
    Ok(())
}

async fn get_balance(runtime: &ProductionRuntime, wallet_name: Option<String>) -> Result<()> {
    let wallet = get_wallet_name(runtime, wallet_name).await?;
    info!("Getting balance for wallet: {}", wallet);
    
    // For now, we'll use a placeholder address since we need to integrate with the actual wallet
    // In a full implementation, this would get the wallet's addresses and sum their balances
    let placeholder_address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    let address = Address::from_str(placeholder_address)?
        .require_network(bitcoin::Network::Bitcoin)?;
    
    let balance = runtime.get_address_balance(&address).await?;
    
    println!("Wallet: {}", wallet);
    println!("Balance: {} sats ({:.8} BTC)", balance, balance as f64 / 100_000_000.0);
    
    Ok(())
}

async fn get_addresses(
    runtime: &ProductionRuntime,
    wallet_name: Option<String>,
    count: u32,
) -> Result<()> {
    let wallet = get_wallet_name(runtime, wallet_name).await?;
    info!("Getting {} addresses for wallet: {}", count, wallet);
    
    println!("Addresses for wallet '{}':", wallet);
    
    // Placeholder implementation - in a full version this would generate actual addresses
    for i in 0..count {
        println!("  {}: bc1q...address{}...", i, i);
    }
    
    println!("💡 Use these addresses to receive Bitcoin");
    
    Ok(())
}

async fn get_utxos(runtime: &ProductionRuntime, wallet_name: Option<String>) -> Result<()> {
    let wallet = get_wallet_name(runtime, wallet_name).await?;
    info!("Getting UTXOs for wallet: {}", wallet);
    
    // Placeholder implementation
    println!("UTXOs for wallet '{}':", wallet);
    println!("  (No UTXOs found)");
    println!("💡 Send Bitcoin to this wallet to see UTXOs here");
    
    Ok(())
}

async fn backup_wallet(
    runtime: &ProductionRuntime,
    name: &str,
    output: Option<String>,
) -> Result<()> {
    info!("Backing up wallet: {}", name);
    
    let backup_data = json!({
        "wallet_name": name,
        "backup_time": chrono::Utc::now().to_rfc3339(),
        "version": "0.1.0"
    });
    
    let output_path = output.unwrap_or_else(|| format!("{}_backup.json", name));
    let backup_json = serde_json::to_string_pretty(&backup_data)?;
    
    runtime.write_file(&output_path, backup_json.as_bytes()).await?;
    
    println!("✅ Wallet '{}' backed up to: {}", name, output_path);
    println!("🔒 Keep this backup file secure!");
    
    Ok(())
}

async fn restore_wallet(
    runtime: &mut ProductionRuntime,
    input: &str,
    name: Option<String>,
) -> Result<()> {
    info!("Restoring wallet from: {}", input);
    
    let backup_data = runtime.read_file(input).await?;
    let backup_json: serde_json::Value = serde_json::from_slice(&backup_data)?;
    
    let wallet_name = name.unwrap_or_else(|| {
        backup_json.get("wallet_name")
            .and_then(|v| v.as_str())
            .unwrap_or("restored_wallet")
            .to_string()
    });
    
    // In a full implementation, this would restore the actual wallet data
    runtime.create_wallet(&wallet_name, None).await?;
    
    println!("✅ Wallet restored as: {}", wallet_name);
    println!("💡 Use 'deezel wallet load {}' to load this wallet", wallet_name);
    
    Ok(())
}

async fn get_wallet_name(
    runtime: &ProductionRuntime,
    wallet_name: Option<String>,
) -> Result<String> {
    if let Some(name) = wallet_name {
        return Ok(name);
    }
    
    // Try to get the currently loaded wallet
    if let Ok(Some(config)) = runtime.load_config::<serde_json::Value>("current_wallet").await {
        if let Some(name) = config.get("loaded_wallet").and_then(|v| v.as_str()) {
            return Ok(name.to_string());
        }
    }
    
    error!("No wallet specified and no wallet currently loaded");
    anyhow::bail!("Please specify a wallet name with --wallet or load a wallet first");
}