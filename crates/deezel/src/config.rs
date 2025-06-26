//! Configuration command handlers using the generic deezel runtime

use anyhow::Result;
use deezel_core::runtime::DeezelRuntime;
use log::{info, error};
use serde_json::{json, Value};

use crate::cli::ConfigCommands;
use crate::ProductionRuntime;

pub async fn handle_config_command(
    mut runtime: ProductionRuntime,
    command: ConfigCommands,
) -> Result<()> {
    match command {
        ConfigCommands::Show => {
            show_config(&runtime).await
        }
        ConfigCommands::Set { key, value } => {
            set_config(&mut runtime, &key, &value).await
        }
        ConfigCommands::Get { key } => {
            get_config(&runtime, &key).await
        }
        ConfigCommands::Reset { force } => {
            reset_config(&mut runtime, force).await
        }
        ConfigCommands::Export { output } => {
            export_config(&runtime, &output).await
        }
        ConfigCommands::Import { input } => {
            import_config(&mut runtime, &input).await
        }
    }
}

async fn show_config(runtime: &ProductionRuntime) -> Result<()> {
    info!("Showing current configuration");
    
    println!("⚙️  Deezel Configuration");
    
    // Load main configuration
    if let Ok(Some(config)) = runtime.load_config::<Value>("deezel_config").await {
        println!("📋 Main Configuration:");
        print_config_section(&config, "  ");
    } else {
        println!("📋 Main Configuration: (not set)");
    }
    
    // Show current wallet
    if let Ok(Some(wallet_config)) = runtime.load_config::<Value>("current_wallet").await {
        if let Some(wallet_name) = wallet_config.get("loaded_wallet").and_then(|v| v.as_str()) {
            println!("💼 Current Wallet: {}", wallet_name);
            if let Some(loaded_at) = wallet_config.get("loaded_at").and_then(|v| v.as_str()) {
                println!("   Loaded at: {}", loaded_at);
            }
        }
    } else {
        println!("💼 Current Wallet: (none loaded)");
    }
    
    // Show deployment status
    if let Ok(Some(deploy_status)) = runtime.load_config::<Value>("deployment_status").await {
        if let Some(status) = deploy_status.get("status").and_then(|v| v.as_str()) {
            println!("🚀 Infrastructure: {}", status);
            if let Some(network) = deploy_status.get("network").and_then(|v| v.as_str()) {
                println!("   Network: {}", network);
            }
        }
    } else {
        println!("🚀 Infrastructure: not deployed");
    }
    
    Ok(())
}

async fn set_config(runtime: &mut ProductionRuntime, key: &str, value: &str) -> Result<()> {
    info!("Setting configuration: {} = {}", key, value);
    
    // Load existing configuration or create new
    let mut config = runtime.load_config::<Value>("deezel_config").await?
        .unwrap_or_else(|| json!({}));
    
    // Parse value as JSON if possible, otherwise treat as string
    let parsed_value = serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()));
    
    // Set the value using dot notation
    set_nested_value(&mut config, key, parsed_value)?;
    
    // Save updated configuration
    runtime.save_config("deezel_config", &config).await?;
    
    println!("✅ Configuration updated");
    println!("   {}: {}", key, value);
    
    Ok(())
}

async fn get_config(runtime: &ProductionRuntime, key: &str) -> Result<()> {
    info!("Getting configuration value for: {}", key);
    
    if let Ok(Some(config)) = runtime.load_config::<Value>("deezel_config").await {
        if let Some(value) = get_nested_value(&config, key) {
            println!("⚙️  Configuration Value");
            println!("   {}: {}", key, value);
        } else {
            println!("❌ Configuration key '{}' not found", key);
        }
    } else {
        println!("❌ No configuration found");
        println!("💡 Use 'deezel config set' to create configuration");
    }
    
    Ok(())
}

async fn reset_config(runtime: &mut ProductionRuntime, force: bool) -> Result<()> {
    info!("Resetting configuration (force: {})", force);
    
    if !force {
        println!("⚠️  This will reset all configuration to defaults!");
        println!("   Use --force to confirm this action");
        return Ok(());
    }
    
    println!("🔄 Resetting configuration to defaults");
    
    // Create default configuration
    let default_config = json!({
        "network": "regtest",
        "rpc": {
            "bitcoin_url": "http://bitcoinrpc:bitcoinrpc@localhost:8332",
            "metashrew_url": "http://localhost:8080",
            "timeout": 30
        },
        "wallet": {
            "default_fee_rate": 1.0,
            "max_fee": 10000
        },
        "alkanes": {
            "gas_limit": 1000000,
            "default_timeout": 30
        },
        "logging": {
            "level": "info",
            "file": "deezel.log"
        }
    });
    
    runtime.save_config("deezel_config", &default_config).await?;
    
    println!("✅ Configuration reset to defaults");
    println!("💡 Use 'deezel config show' to see the default configuration");
    
    Ok(())
}

async fn export_config(runtime: &ProductionRuntime, output: &str) -> Result<()> {
    info!("Exporting configuration to: {}", output);
    
    // Collect all configuration
    let mut export_data = json!({
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "version": "0.1.0"
    });
    
    // Add main configuration
    if let Ok(Some(config)) = runtime.load_config::<Value>("deezel_config").await {
        export_data["deezel_config"] = config;
    }
    
    // Add current wallet info (without sensitive data)
    if let Ok(Some(wallet_config)) = runtime.load_config::<Value>("current_wallet").await {
        export_data["current_wallet"] = wallet_config;
    }
    
    // Add deployment status
    if let Ok(Some(deploy_status)) = runtime.load_config::<Value>("deployment_status").await {
        export_data["deployment_status"] = deploy_status;
    }
    
    let export_json = serde_json::to_string_pretty(&export_data)?;
    runtime.write_file(output, export_json.as_bytes()).await?;
    
    println!("✅ Configuration exported");
    println!("📁 Output file: {}", output);
    println!("📊 Size: {} bytes", export_json.len());
    
    Ok(())
}

async fn import_config(runtime: &mut ProductionRuntime, input: &str) -> Result<()> {
    info!("Importing configuration from: {}", input);
    
    let import_data = runtime.read_file(input).await?;
    let import_json: Value = serde_json::from_slice(&import_data)?;
    
    println!("🔄 Importing configuration from: {}", input);
    
    // Import main configuration
    if let Some(config) = import_json.get("deezel_config") {
        runtime.save_config("deezel_config", config).await?;
        println!("  ✅ Main configuration imported");
    }
    
    // Import current wallet info
    if let Some(wallet_config) = import_json.get("current_wallet") {
        runtime.save_config("current_wallet", wallet_config).await?;
        println!("  ✅ Wallet configuration imported");
    }
    
    // Import deployment status
    if let Some(deploy_status) = import_json.get("deployment_status") {
        runtime.save_config("deployment_status", deploy_status).await?;
        println!("  ✅ Deployment status imported");
    }
    
    println!("✅ Configuration import completed");
    println!("💡 Use 'deezel config show' to verify the imported configuration");
    
    Ok(())
}

fn print_config_section(value: &Value, indent: &str) {
    match value {
        Value::Object(obj) => {
            for (key, val) in obj {
                match val {
                    Value::Object(_) => {
                        println!("{}{}: {{", indent, key);
                        print_config_section(val, &format!("{}  ", indent));
                        println!("{}}}", indent);
                    }
                    _ => {
                        println!("{}{}: {}", indent, key, format_config_value(val));
                    }
                }
            }
        }
        _ => {
            println!("{}{}", indent, format_config_value(value));
        }
    }
}

fn format_config_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(arr) => format!("[{} items]", arr.len()),
        Value::Object(obj) => format!("{{{}  keys}}", obj.len()),
    }
}

fn set_nested_value(config: &mut Value, key: &str, value: Value) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = config;
    
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last part - set the value
            if let Value::Object(obj) = current {
                obj.insert(part.to_string(), value);
                return Ok(());
            } else {
                anyhow::bail!("Cannot set value on non-object");
            }
        } else {
            // Intermediate part - navigate or create object
            if !current.is_object() {
                *current = json!({});
            }
            
            if let Value::Object(obj) = current {
                if !obj.contains_key(*part) {
                    obj.insert(part.to_string(), json!({}));
                }
                current = obj.get_mut(*part).unwrap();
            }
        }
    }
    
    Ok(())
}

fn get_nested_value<'a>(config: &'a Value, key: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = config;
    
    for part in parts {
        if let Value::Object(obj) = current {
            current = obj.get(part)?;
        } else {
            return None;
        }
    }
    
    Some(current)
}