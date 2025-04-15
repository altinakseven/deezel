//! Deezel CLI tool for interacting with Sandshrew RPC
//!
//! This binary provides command-line tools for interacting with the Sandshrew RPC API,
//! focusing on alkanes functionality as a replacement for oyl-sdk.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use log::{debug, error, info};
#[allow(unused_imports)]
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

// Import from our crate
use deezel_cli::rpc::{RpcClient, RpcConfig};
use deezel_cli::format_runestone;
use bdk::bitcoin::Transaction;
use bdk::bitcoin::consensus::encode::deserialize;
use hex;

/// Deezel CLI tool for interacting with Sandshrew RPC
#[derive(Parser, Debug)]
#[clap(author, version, about = "Deezel CLI tool for interacting with Sandshrew RPC")]
struct Args {
    /// Provider or RPC URL
    /// Can be a preset (mainnet, signet, localhost) or a full URL
    #[clap(short, long, default_value = "mainnet")]
    provider: String,

    /// Bitcoin RPC URL
    #[clap(long)]
    bitcoin_rpc_url: Option<String>,

    /// Sandshrew RPC URL
    #[clap(long)]
    sandshrew_rpc_url: Option<String>,

    /// Network magic values (p2sh_prefix:p2pkh_prefix:bech32_prefix)
    /// Example: "05:00:bc" for mainnet
    #[clap(long)]
    magic: Option<String>,

    /// Log level (error, warn, info, debug, trace)
    #[clap(long, default_value = "info")]
    log_level: String,

    /// Wallet path
    #[clap(long, default_value = "wallet.dat")]
    wallet_path: String,

    /// Subcommand
    #[clap(subcommand)]
    command: Commands,
}

/// Deezel CLI subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Metashrew commands
    Metashrew {
        /// Metashrew subcommand
        #[clap(subcommand)]
        command: MetashrewCommands,
    },
    /// Bitcoind commands
    Bitcoind {
        /// Bitcoind subcommand
        #[clap(subcommand)]
        command: BitcoindCommands,
    },
    /// Wallet information
    Walletinfo,
    /// Decode Runestone from transaction
    Runestone {
        /// Transaction ID or hex
        txid_or_hex: String,
    },
    /// Alkanes commands
    Alkanes {
        /// Alkanes subcommand
        #[clap(subcommand)]
        command: AlkanesCommands,
    },
}

/// Metashrew subcommands
#[derive(Subcommand, Debug)]
enum MetashrewCommands {
    /// Get the current block height from Metashrew
    Height,
}

/// Bitcoind subcommands
#[derive(Subcommand, Debug)]
enum BitcoindCommands {
    /// Get the current block count from Bitcoin Core
    Getblockcount,
}

/// Alkanes subcommands
#[derive(Subcommand, Debug)]
enum AlkanesCommands {
    /// Get bytecode for a smart contract
    Getbytecode {
        /// Contract ID (block:tx)
        contract_id: String,
    },
    /// Get protorunes by address
    Protorunesbyaddress {
        /// Bitcoin address
        address: String,
    },
    /// Get protorunes by outpoint
    Protorunesbyoutpoint {
        /// Outpoint (txid:vout)
        outpoint: String,
    },
    /// Get spendables by address
    Spendablesbyaddress {
        /// Bitcoin address
        address: String,
    },
    /// Trace a block
    Traceblock {
        /// Block height
        block_height: u64,
    },
    /// Trace a transaction
    Trace {
        /// Outpoint (txid:vout)
        outpoint: String,
    },
    /// Simulate a contract execution
    Simulate {
        /// Simulation parameters (block:tx:input1:input2...)
        params: String,
    },
    /// Get metadata for a contract
    Meta {
        /// Contract ID (block:tx)
        contract_id: String,
    },
}

/// Parse an outpoint string in the format "txid:vout"
fn parse_outpoint(outpoint: &str) -> Result<(String, u32)> {
    let parts: Vec<&str> = outpoint.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid outpoint format. Expected 'txid:vout'"));
    }
    
    let txid = parts[0].to_string();
    let vout = u32::from_str(parts[1])
        .context("Invalid vout. Expected a number")?;
    
    Ok((txid, vout))
}

/// Parse a contract ID string in the format "block:tx"
fn parse_contract_id(contract_id: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = contract_id.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid contract ID format. Expected 'block:tx'"));
    }
    
    let block = parts[0].to_string();
    let tx = parts[1].to_string();
    
    Ok((block, tx))
}

/// Parse simulation parameters in the format "block:tx:input1:input2..."
fn parse_simulation_params(params: &str) -> Result<(String, String, Vec<String>)> {
    let parts: Vec<&str> = params.split(':').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid simulation parameters. Expected at least 'block:tx'"));
    }
    
    let block = parts[0].to_string();
    let tx = parts[1].to_string();
    let inputs = parts[2..].iter().map(|s| s.to_string()).collect();
    
    Ok((block, tx, inputs))
}

/// Analyze a transaction for Runestone data
fn analyze_runestone_tx(tx: &Transaction) {
    // Use the enhanced format_runestone function
    match format_runestone(tx) {
        Ok(protostones) => {
            println!("Found {} protostones:", protostones.len());
            for (i, protostone) in protostones.iter().enumerate() {
                println!("Protostone {}: {:?}", i+1, protostone);
            }
        },
        Err(e) => {
            println!("Error decoding runestone: {}", e);
        }
    }
}

/// Decode a transaction from hex
fn decode_transaction_hex(hex_str: &str) -> Result<Transaction> {
    let tx_bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("Failed to decode transaction hex")?;
    
    let tx: Transaction = deserialize(&tx_bytes)
        .context("Failed to deserialize transaction")?;
    
    Ok(tx)
}


#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    // Determine network parameters based on provider and magic flags
    let network_params = if let Some(magic) = args.magic.as_ref() {
        deezel_cli::network::NetworkParams::from_magic(magic)
            .map_err(|e| anyhow!("Invalid magic value: {}", e))?
    } else {
        deezel_cli::network::NetworkParams::from_provider(&args.provider)
            .map_err(|e| anyhow!("Invalid provider: {}", e))?
    };

    // Determine RPC URLs based on provider
    let sandshrew_rpc_url = args.sandshrew_rpc_url.clone()
        .unwrap_or_else(|| deezel_cli::network::get_rpc_url(&args.provider));
    
    let bitcoin_rpc_url = args.bitcoin_rpc_url.clone()
        .unwrap_or_else(|| "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string());

    // Initialize wallet if needed for the command
    let wallet_manager = if matches!(args.command, Commands::Walletinfo) {
        let wallet_config = deezel_cli::wallet::WalletConfig {
            wallet_path: args.wallet_path.clone(),
            network: network_params.network,
            bitcoin_rpc_url: bitcoin_rpc_url.clone(),
            metashrew_rpc_url: sandshrew_rpc_url.clone(),
        };
        
        Some(Arc::new(
            deezel_cli::wallet::WalletManager::new(wallet_config)
                .await
                .context("Failed to initialize wallet manager")?
        ))
    } else {
        None
    };

    // Initialize RPC client
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: bitcoin_rpc_url.clone(),
        metashrew_rpc_url: sandshrew_rpc_url.clone(),
    };
    let rpc_client = RpcClient::new(rpc_config);

    match args.command {
        Commands::Metashrew { command } => match command {
            MetashrewCommands::Height => {
                let height = rpc_client.get_metashrew_height().await?;
                println!("{}", height);
            },
        },
        Commands::Bitcoind { command } => match command {
            BitcoindCommands::Getblockcount => {
                let count = rpc_client.get_block_count().await?;
                println!("{}", count);
            },
        },
        Commands::Walletinfo => {
            if let Some(wallet_manager) = wallet_manager {
                // Get wallet addresses for different address types
                println!("Wallet Addresses:");
                
                // Native SegWit (bech32)
                let native_segwit_address = wallet_manager.get_address().await?;
                println!("  Native SegWit (bech32): {}", native_segwit_address);
                
                // Try to sync wallet with blockchain, but don't fail if it doesn't work
                println!("\nAttempting to sync wallet with blockchain...");
                match wallet_manager.sync().await {
                    Ok(_) => println!("Sync successful."),
                    Err(e) => println!("Sync failed: {}. Using offline mode.", e),
                };
                
                // Get wallet balance
                match wallet_manager.get_balance().await {
                    Ok(balance) => {
                        println!("\nBitcoin Balance:");
                        println!("  Confirmed: {} sats", balance.confirmed);
                        println!("  Pending: {} sats", balance.trusted_pending + balance.untrusted_pending);
                        println!("  Total: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
                    },
                    Err(e) => println!("\nFailed to get balance: {}", e),
                };
                
                // Try to get alkanes balances
                println!("\nAlkanes Balances:");
                let address_str = wallet_manager.get_address().await?;
                match rpc_client.get_protorunes_by_address(&address_str).await {
                    Ok(protorunes) => {
                        if let Some(runes_array) = protorunes.as_array() {
                            if runes_array.is_empty() {
                                println!("  No alkanes tokens found");
                            } else {
                                for (i, rune) in runes_array.iter().enumerate() {
                                    if let Some(rune_obj) = rune.as_object() {
                                        let name = rune_obj.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                        let balance = rune_obj.get("balance").and_then(|v| v.as_str()).unwrap_or("0");
                                        println!("  {}: {} - {} units", i+1, name, balance);
                                    }
                                }
                            }
                        } else {
                            println!("  Failed to parse alkanes balances");
                        }
                    },
                    Err(e) => println!("  Failed to get alkanes balances: {}", e),
                };
            } else {
                return Err(anyhow!("Wallet manager not initialized"));
            }
        },
        Commands::Runestone { txid_or_hex } => {
            // Check if input is a transaction ID or hex
            if txid_or_hex.len() == 64 && txid_or_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                // Looks like a transaction ID, fetch from RPC
                println!("Fetching transaction {} from RPC...", txid_or_hex);
                let tx_hex = rpc_client.get_transaction_hex(&txid_or_hex).await
                    .context("Failed to fetch transaction from RPC")?;
                
                let tx = decode_transaction_hex(&tx_hex)?;
                analyze_runestone_tx(&tx);
            } else {
                // Assume it's transaction hex
                println!("Decoding transaction from hex...");
                let tx = decode_transaction_hex(&txid_or_hex)?;
                analyze_runestone_tx(&tx);
            }
        },
        Commands::Alkanes { command } => match command {
            AlkanesCommands::Getbytecode { contract_id } => {
                let (block, tx) = parse_contract_id(&contract_id)?;
                let bytecode = rpc_client.get_bytecode(&block, &tx).await?;
                println!("{}", bytecode);
            },
            AlkanesCommands::Protorunesbyaddress { address } => {
                let result = rpc_client.get_protorunes_by_address(&address).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            AlkanesCommands::Protorunesbyoutpoint { outpoint } => {
                let (txid, vout) = parse_outpoint(&outpoint)?;
                let result = rpc_client.get_protorunes_by_outpoint(&txid, vout).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            AlkanesCommands::Spendablesbyaddress { address } => {
                let result = rpc_client.get_spendables_by_address(&address).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            AlkanesCommands::Traceblock { block_height } => {
                let result = rpc_client.trace_block(block_height).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            AlkanesCommands::Trace { outpoint } => {
                let (txid, vout) = parse_outpoint(&outpoint)?;
                let result = rpc_client.trace_transaction(&txid, vout as usize).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            AlkanesCommands::Simulate { params } => {
                let (block, tx, inputs) = parse_simulation_params(&params)?;
                let result = rpc_client.simulate(&block, &tx, &inputs).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            AlkanesCommands::Meta { contract_id } => {
                let (block, tx) = parse_contract_id(&contract_id)?;
                let result = rpc_client.get_contract_meta(&block, &tx).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
        },
    }

    Ok(())
}
