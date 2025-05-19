//! Deezel CLI tool for interacting with Sandshrew RPC
//!
//! This binary provides command-line tools for interacting with the Sandshrew RPC API,
//! focusing on alkanes functionality as a replacement for oyl-sdk.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use log::{debug, error, info};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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

    /// Number of confirmations to wait for after broadcasting
    #[clap(long, default_value = "1")]
    confirmations: u64,

    /// Fee rate in satoshis per vbyte
    #[clap(long)]
    fee_rate: Option<f64>,

    /// Target number of confirmations for automatic fee estimation (1-1008)
    #[clap(long, default_value = "6")]
    fee_target_blocks: u16,

    /// Enable replace-by-fee (RBF) for transactions
    #[clap(long)]
    rbf: bool,

    /// Subcommand
    #[clap(subcommand)]
    command: Commands,
}

/// Transaction confirmation information
#[derive(Debug)]
struct ConfirmationInfo {
    /// Block hash in which transaction was confirmed 
    pub block_hash: String,
    /// Block height in which transaction was confirmed
    pub block_height: u64,
    /// Number of confirmations
    pub confirmations: u64,
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
    /// Execute a transaction with alkane operation
    Execute {
        /// Execute parameters in format "namespace,contract_id,opcode"
        #[clap(short, long, required = true)]
        execute: String,
        
        /// Input in format "id1,amount1,output1,id2,amount2,output2,..."
        #[clap(short, long)]
        input: Option<String>,
        
        /// Validate inputs only (don't execute transaction)
        #[clap(short, long)]
        validate: bool,
        
        /// Wait for confirmation after broadcasting
        #[clap(short, long)]
        wait_confirmation: bool,
    },
}

/// Parse an outpoint string in the format "txid:vout"
fn parse_outpoint(outpoint: &str) -> Result<(String, u32)> {
    let parts: Vec<&str> = outpoint.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid outpoint format. Expected 'txid:vout'"));
    }
    
    let txid = parts[0].to_string();
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid txid format. Expected 64 hex characters"));
    }
    
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
fn analyze_runestone_tx(tx: &Transaction) -> Result<()> {
    // Use the enhanced format_runestone function
    match format_runestone(tx) {
        Ok(protostones) => {
            println!("Found {} protostones:", protostones.len());
            for (i, protostone) in protostones.iter().enumerate() {
                println!("Protostone {}: {:?}", i+1, protostone);
            }
            Ok(())
        },
        Err(e) => {
            Err(anyhow!("Error decoding runestone: {}", e))
        }
    }
}

/// Decode a transaction from hex
fn decode_transaction_hex(hex_str: &str) -> Result<Transaction> {
    // Validate hex string
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit() || c == 'x' || c == '0') {
        return Err(anyhow!("Invalid hex string: Contains non-hex characters"));
    }
    
    let tx_bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("Failed to decode transaction hex")?;
    
    // Ensure minimum transaction size
    if tx_bytes.len() < 10 {
        return Err(anyhow!("Invalid transaction: Too small to be a valid transaction"));
    }
    
    let tx: Transaction = deserialize(&tx_bytes)
        .context("Failed to deserialize transaction")?;
    
    Ok(tx)
}

/// Wait for transaction confirmation
async fn wait_for_confirmation(rpc_client: &RpcClient, txid: &str, required_confirmations: u64) -> Result<ConfirmationInfo> {
    const POLL_INTERVAL: Duration = Duration::from_secs(10);
    const MAX_RETRIES: u32 = 30; // 5 minutes with 10 second interval
    
    info!("Waiting for {} confirmations for transaction {}", required_confirmations, txid);
    println!("Waiting for transaction to be confirmed (this may take several minutes)...");
    
    let mut retries = 0;
    
    loop {
        match rpc_client.get_transaction_confirmations(txid).await {
            Ok(tx_info) => {
                // Extract confirmation info from response
                let confirmations = tx_info.get("confirmations")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                
                if confirmations >= required_confirmations {
                    // Get block info
                    let block_hash = tx_info.get("blockhash")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Missing block hash in transaction info"))?
                        .to_string();
                    
                    let block_height = rpc_client.get_block_height(&block_hash).await?;
                    
                    return Ok(ConfirmationInfo {
                        block_hash,
                        block_height,
                        confirmations,
                    });
                }
                
                println!("Transaction has {} confirmations (waiting for {})", confirmations, required_confirmations);
            },
            Err(e) => {
                info!("Error checking transaction status: {}. Retrying...", e);
                println!("Waiting for transaction to be included in a block...");
            }
        }
        
        retries += 1;
        if retries > MAX_RETRIES {
            return Err(anyhow!("Timeout waiting for transaction confirmation after {} attempts", MAX_RETRIES));
        }
        
        tokio::time::sleep(POLL_INTERVAL).await;
    }
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
                                        let name = rune_obj.get("name")
                                            .and_then(|v| v.as_str())
                                            .ok_or_else(|| anyhow!("Missing or invalid rune name"))?;
                                        
                                        let balance = rune_obj.get("balance")
                                            .and_then(|v| v.as_str())
                                            .ok_or_else(|| anyhow!("Missing or invalid rune balance"))?;
                                        
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
                analyze_runestone_tx(&tx)?;
            } else {
                // Assume it's transaction hex
                println!("Decoding transaction from hex...");
                let tx = decode_transaction_hex(&txid_or_hex)?;
                analyze_runestone_tx(&tx)?;
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
            AlkanesCommands::Execute { execute, input, validate, wait_confirmation } => {
                // Need to initialize wallet manager for this command
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: args.wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                // Initialize transaction constructor
                // Get fee rate either from command line or estimate from network
                let fee_rate = if let Some(rate) = args.fee_rate {
                    println!("Using provided fee rate: {} sat/vbyte", rate);
                    rate
                } else {
                    // Estimate fee rate based on target confirmation blocks
                    let target_blocks = args.fee_target_blocks.clamp(1, 1008);
                    println!("Estimating fee rate for target {} blocks confirmation...", target_blocks);
                    match rpc_client.estimate_fee_rate(target_blocks).await {
                        Ok(rate) => {
                            println!("Estimated fee rate: {} sat/vbyte", rate);
                            rate
                        },
                        Err(e) => {
                            println!("Error estimating fee rate: {}", e);
                            println!("Falling back to default fee rate: 2.0 sat/vbyte");
                            2.0
                        }
                    }
                };

                let tx_config = deezel_cli::transaction::TransactionConfig {
                    network: network_params.network,
                    fee_rate,
                    max_inputs: 100,
                    max_outputs: 20,
                    enable_rbf: args.rbf,
                };
                
                let tx_constructor = deezel_cli::transaction::TransactionConstructor::new(
                    wallet_manager.clone(),
                    Arc::new(rpc_client.clone()),
                    tx_config
                );
                
                // Process execute parameters
                let full_input = if let Some(input_str) = input {
                    // Both execute and input provided, combine them
                    format!("{},{}", execute, input_str)
                } else {
                    // Only execute provided
                    execute.clone()
                };
                    
                if validate {
                    // Validate inputs if they were provided
                    if input.is_some() {
                        match tx_constructor.validate_inputs(&input.unwrap()).await {
                            Ok(valid) => {
                                if valid {
                                    println!("Inputs are valid for user's alkane holdings");
                                } else {
                                    println!("Inputs are NOT valid for user's alkane holdings");
                                }
                            },
                            Err(e) => println!("Error validating inputs: {}", e),
                        }
                    } else {
                        println!("No inputs provided to validate");
                    }
                } else {
                    // Execute the transaction
                    match tx_constructor.create_transaction_with_execute(&full_input).await {
                            Ok(tx) => {
                                println!("Transaction created successfully with execute parameters: {}", execute);
                                println!("Transaction details: {:#?}", tx);
                                
                                // Broadcast the signed transaction
                                info!("Broadcasting transaction to network");
                                match rpc_client.broadcast_transaction(&tx).await {
                                    Ok(txid) => {
                                        println!("Transaction broadcast successfully");
                                        println!("Transaction ID: {}", txid);
                                        
                                        // Wait for confirmation if requested
                                        if wait_confirmation {
                                            if let Ok(confirm) = wait_for_confirmation(&rpc_client, &txid, args.confirmations).await {
                                                println!("Transaction confirmed in block {} (height {})", 
                                                         confirm.block_hash, confirm.block_height);
                                                println!("Current confirmations: {}", confirm.confirmations);
                                            }
                                        }
                                    },
                                    Err(e) => println!("Error broadcasting transaction: {}", e),
                                }
                            },
                            Err(e) => println!("Error creating transaction: {}", e),
                        }
                    }
                }
            },
        },
    }

    Ok(())
}
