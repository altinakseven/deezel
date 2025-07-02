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
use deezel_cli::runestone_enhanced::format_runestone_with_decoded_messages;
use bdk::bitcoin::Transaction;
use bdk::bitcoin::consensus::encode::deserialize;
use hex;
use protorune_support::proto::protorune::OutpointResponse;

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

    /// Network name or magic values
    /// Supported networks: mainnet, testnet, signet, regtest, dogecoin, luckycoin, bellscoin
    /// Or custom magic format: p2sh_prefix:p2pkh_prefix:bech32_prefix (e.g., "05:00:bc")
    #[clap(long)]
    magic: Option<String>,

    /// Log level (error, warn, info, debug, trace)
    #[clap(long, default_value = "info")]
    log_level: String,

    /// Wallet path (will be network-specific if not explicitly provided)
    #[clap(long)]
    wallet_path: Option<String>,

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
    /// Wallet commands
    Wallet {
        /// Wallet subcommand
        #[clap(subcommand)]
        command: WalletCommands,
    },
    /// Wallet information (legacy command)
    Walletinfo,
    /// Decode Runestone from transaction
    Runestone {
        /// Transaction ID or hex
        txid_or_hex: String,
        /// Output raw JSON format (for scripting)
        #[clap(short, long)]
        raw: bool,
    },
    /// Alkanes commands
    Alkanes {
        /// Alkanes subcommand
        #[clap(subcommand)]
        command: AlkanesCommands,
    },
    /// View commands for querying blockchain data
    View {
        /// View subcommand
        #[clap(subcommand)]
        command: ViewCommands,
    },
    /// Inspect an alkane with advanced analysis capabilities
    InspectAlkane {
        /// Alkane ID in format block:tx (e.g., 2:0)
        alkane_id: String,
        /// Output WASM disassembly (WAT format)
        #[clap(long)]
        disasm: bool,
        /// Perform fuzzing analysis with metashrew-runtime
        #[clap(long)]
        fuzz: bool,
        /// Opcode ranges to fuzz (e.g., "0-999" or "0-999,2000-2500")
        #[clap(long)]
        fuzz_ranges: Option<String>,
        /// Extract metadata directly from WASM binary
        #[clap(long)]
        meta: bool,
        /// Compute SHA3 hash of the WASM bytecode
        #[clap(long)]
        codehash: bool,
        /// Output raw JSON format (for scripting)
        #[clap(short, long)]
        raw: bool,
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
    /// Generate blocks to an address (regtest only)
    Generatetoaddress {
        /// Number of blocks to generate
        #[clap(long)]
        nblocks: u32,
        /// Address to receive the block rewards
        #[clap(long)]
        address: String,
    },
}

/// Wallet subcommands
#[derive(Subcommand, Debug)]
enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Mnemonic phrase (if not provided, a new one will be generated)
        #[clap(long)]
        mnemonic: Option<String>,
        /// Passphrase for the wallet
        #[clap(long)]
        passphrase: Option<String>,
    },
    /// Restore wallet from mnemonic
    Restore {
        /// Mnemonic phrase
        mnemonic: String,
        /// Passphrase for the wallet
        #[clap(long)]
        passphrase: Option<String>,
    },
    /// Show wallet information
    Info,
    /// Get wallet addresses
    Addresses {
        /// Number of addresses to generate
        #[clap(long, default_value = "1")]
        count: u32,
    },
    /// Get wallet balance
    Balance,
    /// Send Bitcoin to an address
    Send {
        /// Recipient address
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Send all available Bitcoin to an address
    SendAll {
        /// Recipient address
        address: String,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Create a transaction (without broadcasting)
    CreateTx {
        /// Recipient address
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Sign a transaction
    SignTx {
        /// Transaction hex
        tx_hex: String,
    },
    /// Broadcast a transaction
    BroadcastTx {
        /// Transaction hex
        tx_hex: String,
    },
    /// List UTXOs
    Utxos,
    /// Freeze a UTXO
    FreezeUtxo {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
    },
    /// Unfreeze a UTXO
    UnfreezeUtxo {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
    },
    /// Show transaction history
    History {
        /// Maximum number of transactions to show
        #[clap(long, default_value = "50")]
        limit: usize,
    },
    /// Get transaction details
    TxDetails {
        /// Transaction ID
        txid: String,
    },
    /// Estimate fee rates
    EstimateFee {
        /// Recipient address
        address: String,
        /// Amount in satoshis
        amount: u64,
    },
    /// Get current fee rates
    FeeRates,
    /// Sync wallet with blockchain
    Sync,
    /// Backup wallet (show mnemonic)
    Backup,
}

/// Alkanes subcommands
#[derive(Subcommand, Debug)]
enum AlkanesCommands {
    /// Get metadata for a contract
    Meta {
        /// Contract ID (block:tx)
        contract_id: String,
    },
    
    // Enhanced alkanes commands
    /// Deploy a new smart contract
    DeployContract {
        /// Path to WASM contract file
        wasm_file: String,
        /// Calldata for contract deployment (comma-separated)
        #[clap(long)]
        calldata: String,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Execute a contract function
    Execute {
        /// Calldata for contract execution (comma-separated)
        #[clap(long)]
        calldata: String,
        /// Edicts for protostone (format: block:tx:amount:output)
        #[clap(long)]
        edicts: Option<String>,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Deploy a new alkanes token
    DeployToken {
        /// Token name
        #[clap(long)]
        name: String,
        /// Token symbol
        #[clap(long)]
        symbol: String,
        /// Token cap (maximum supply)
        #[clap(long)]
        cap: u64,
        /// Amount minted per mint operation
        #[clap(long)]
        amount_per_mint: u64,
        /// Reserve number for factory contract
        #[clap(long)]
        reserve_number: u64,
        /// Amount to premine
        #[clap(long)]
        premine: Option<u64>,
        /// Path to token image file
        #[clap(long)]
        image: Option<String>,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Send alkanes tokens
    SendToken {
        /// Token ID in format block:tx
        #[clap(long)]
        token: String,
        /// Amount to send
        #[clap(long)]
        amount: u64,
        /// Recipient address
        #[clap(long)]
        to: String,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Get alkanes balance
    Balance {
        /// Address to check (defaults to wallet address)
        #[clap(long)]
        address: Option<String>,
    },
    /// Get token information
    TokenInfo {
        /// Token ID in format block:tx
        token: String,
    },
    /// Create a new liquidity pool
    CreatePool {
        /// Calldata for pool creation (comma-separated)
        #[clap(long)]
        calldata: String,
        /// Tokens and amounts (format: block:tx:amount,block:tx:amount)
        #[clap(long)]
        tokens: String,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Add liquidity to a pool
    AddLiquidity {
        /// Calldata for liquidity addition (comma-separated)
        #[clap(long)]
        calldata: String,
        /// Tokens and amounts (format: block:tx:amount,block:tx:amount)
        #[clap(long)]
        tokens: String,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Remove liquidity from a pool
    RemoveLiquidity {
        /// Calldata for liquidity removal (comma-separated)
        #[clap(long)]
        calldata: String,
        /// LP token ID in format block:tx
        #[clap(long)]
        token: String,
        /// Amount of LP tokens to burn
        #[clap(long)]
        amount: u64,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Swap tokens in a pool
    Swap {
        /// Calldata for swap (comma-separated)
        #[clap(long)]
        calldata: String,
        /// Input token ID in format block:tx
        #[clap(long)]
        token: String,
        /// Amount to swap
        #[clap(long)]
        amount: u64,
        /// Fee rate in sat/vB
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    /// Simulate alkanes operation
    SimulateAdvanced {
        /// Target contract in format block:tx
        #[clap(long)]
        target: String,
        /// Inputs for simulation (comma-separated)
        #[clap(long)]
        inputs: String,
        /// Tokens for simulation (format: block:tx:amount,block:tx:amount)
        #[clap(long)]
        tokens: Option<String>,
        /// Decoder type (pool, factory, etc.)
        #[clap(long)]
        decoder: Option<String>,
    },
    /// Preview liquidity removal
    PreviewRemoveLiquidity {
        /// LP token ID in format block:tx
        #[clap(long)]
        token: String,
        /// Amount of LP tokens
        #[clap(long)]
        amount: u64,
    },
    /// Inspect an alkane with advanced analysis capabilities
    Inspect {
        /// Alkane ID in format block:tx (e.g., 2:0)
        alkane_id: String,
        /// Output WASM disassembly (WAT format)
        #[clap(long)]
        disasm: bool,
        /// Perform fuzzing analysis with wasmi runtime
        #[clap(long)]
        fuzz: bool,
        /// Opcode ranges to fuzz (e.g., "0-999" or "0-999,2000-2500")
        #[clap(long)]
        fuzz_ranges: Option<String>,
        /// Extract metadata directly from WASM binary
        #[clap(long)]
        meta: bool,
        /// Compute SHA3 hash of the WASM bytecode
        #[clap(long)]
        codehash: bool,
        /// Output raw JSON format (for scripting)
        #[clap(short, long)]
        raw: bool,
    },
}

/// Block tag for specifying which block to query
#[derive(Debug, Clone)]
enum BlockTag {
    Latest,
    Pending,
    Height(u64),
}

impl std::str::FromStr for BlockTag {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BlockTag::Latest),
            "pending" => Ok(BlockTag::Pending),
            _ => {
                let height = s.parse::<u64>()
                    .context("Block tag must be 'latest', 'pending', or a block height number")?;
                Ok(BlockTag::Height(height))
            }
        }
    }
}

/// View subcommands for querying blockchain data
#[derive(Subcommand, Debug)]
enum ViewCommands {
    /// Get bytecode for a smart contract
    Getbytecode {
        /// Contract ID (block:tx)
        contract_id: String,
        /// Block tag (latest, pending, or block height)
        #[clap(long, default_value = "latest")]
        block_tag: BlockTag,
    },
    /// Get block data
    Getblock {
        /// Block height
        height: u64,
        /// Block tag (latest, pending, or block height)
        #[clap(long, default_value = "latest")]
        block_tag: BlockTag,
    },
    /// Get protorunes by address
    Protorunesbyaddress {
        /// Bitcoin address
        address: String,
        /// Protocol tag
        #[clap(long, default_value = "1")]
        protocol_tag: u64,
        /// Block tag (latest, pending, or block height)
        #[clap(long, default_value = "latest")]
        block_tag: BlockTag,
    },
    /// Get transaction by ID
    Transactionbyid {
        /// Transaction ID
        txid: String,
        /// Block tag (latest, pending, or block height)
        #[clap(long, default_value = "latest")]
        block_tag: BlockTag,
    },
    /// Get spendables by address
    Spendablesbyaddress {
        /// Bitcoin address
        address: String,
        /// Block tag (latest, pending, or block height)
        #[clap(long, default_value = "latest")]
        block_tag: BlockTag,
    },
    /// Get protorunes by height
    Protorunesbyheight {
        /// Block height
        height: u64,
        /// Protocol tag
        #[clap(long, default_value = "1")]
        protocol_tag: u64,
    },
    /// Get protorunes by outpoint
    Protorunesbyoutpoint {
        /// Outpoint (txid:vout)
        outpoint: String,
        /// Protocol tag
        #[clap(long, default_value = "1")]
        protocol_tag: u64,
    },
    /// Trace a transaction
    Trace {
        /// Outpoint (txid:vout)
        outpoint: String,
        /// Output raw JSON format (for scripting)
        #[clap(short, long)]
        raw: bool,
    },
    /// Simulate a contract execution
    Simulate {
        /// Alkanes transfers (format: block:tx:amount,block:tx:amount,...)
        #[clap(long)]
        alkanes: Option<String>,
        /// Transaction hex
        #[clap(long)]
        transaction: String,
        /// Block height
        #[clap(long)]
        height: u64,
        /// Block hex
        #[clap(long)]
        block: String,
        /// Transaction index
        #[clap(long)]
        txindex: u32,
        /// Inputs (comma-separated)
        #[clap(long)]
        inputs: String,
        /// Output index
        #[clap(long)]
        vout: u32,
        /// Pointer
        #[clap(long)]
        pointer: u32,
        /// Refund pointer
        #[clap(long, name = "refund-pointer")]
        refund_pointer: u32,
        /// Block tag (latest, pending, or block height)
        #[clap(long, default_value = "latest")]
        block_tag: BlockTag,
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

/// Address information extracted from script
struct AddressInfo {
    address: String,
    script_type: String,
}

/// Extract address from script pubkey
fn extract_address_from_script(script: &bdk::bitcoin::ScriptBuf) -> Option<AddressInfo> {
    use bdk::bitcoin::Address;
    use bdk::bitcoin::Network;
    
    // Try to convert script to address
    if let Ok(address) = Address::from_script(script, Network::Bitcoin) {
        let script_type = if script.is_p2pkh() {
            "P2PKH (Legacy)".to_string()
        } else if script.is_p2sh() {
            "P2SH (Script Hash)".to_string()
        } else if script.is_v1_p2tr() {
            "P2TR (Taproot)".to_string()
        } else if script.is_witness_program() {
            "Witness Program (SegWit)".to_string()
        } else {
            "Unknown".to_string()
        };
        
        Some(AddressInfo {
            address: address.to_string(),
            script_type,
        })
    } else {
        None
    }
}

/// Analyze a transaction for Runestone data
fn analyze_runestone_tx(tx: &Transaction, raw_output: bool) {
    // Use the enhanced format_runestone_with_decoded_messages function
    match format_runestone_with_decoded_messages(tx) {
        Ok(result) => {
            if raw_output {
                // Raw JSON output for scripting
                println!("{}", serde_json::to_string_pretty(&result).unwrap_or_else(|_| "Error formatting result".to_string()));
            } else {
                // Human-readable styled output
                print_human_readable_runestone(tx, &result);
            }
        },
        Err(e) => {
            if raw_output {
                eprintln!("Error decoding runestone: {}", e);
            } else {
                println!("❌ Error decoding runestone: {}", e);
            }
        }
    }
}

/// Print human-readable, styled runestone information
fn print_human_readable_runestone(tx: &Transaction, result: &serde_json::Value) {
    println!("🔍 Transaction Analysis");
    println!("═══════════════════════");
    
    // Transaction basic info
    if let Some(txid) = result.get("transaction_id").and_then(|v| v.as_str()) {
        println!("📋 Transaction ID: {}", txid);
    }
    println!("🔢 Version: {}", tx.version);
    println!("🔒 Lock Time: {}", tx.lock_time);
    
    // Transaction inputs
    println!("\n📥 Inputs ({}):", tx.input.len());
    for (i, input) in tx.input.iter().enumerate() {
        println!("  {}. 🔗 {}:{}", i + 1, input.previous_output.txid, input.previous_output.vout);
        if !input.witness.is_empty() {
            println!("     📝 Witness: {} items", input.witness.len());
        }
    }
    
    // Transaction outputs
    println!("\n📤 Outputs ({}):", tx.output.len());
    for (i, output) in tx.output.iter().enumerate() {
        println!("  {}. 💰 {} sats", i, output.value);
        
        // Check if this is an OP_RETURN output
        if output.script_pubkey.is_op_return() {
            println!("     📜 OP_RETURN script ({} bytes)", output.script_pubkey.len());
            // Show OP_RETURN data in hex
            let op_return_bytes = output.script_pubkey.as_bytes();
            if op_return_bytes.len() > 2 {
                let data_bytes = &op_return_bytes[2..]; // Skip OP_RETURN and length byte
                let hex_data = hex::encode(data_bytes);
                println!("     📄 Data: {}", hex_data);
            }
        } else {
            // Try to extract address
            match extract_address_from_script(&output.script_pubkey) {
                Some(address_info) => {
                    println!("     🏠 {}: {}", address_info.script_type, address_info.address);
                }
                None => {
                    if output.script_pubkey.is_p2pkh() {
                        println!("     🏠 P2PKH (Legacy)");
                    } else if output.script_pubkey.is_p2sh() {
                        println!("     🏛️  P2SH (Script Hash)");
                    } else if output.script_pubkey.is_v1_p2tr() {
                        println!("     🌳 P2TR (Taproot)");
                    } else if output.script_pubkey.is_witness_program() {
                        println!("     ⚡ Witness Program (SegWit)");
                    } else {
                        println!("     📋 Script ({} bytes)", output.script_pubkey.len());
                    }
                }
            }
        }
    }
    
    // Protostones information
    if let Some(protostones) = result.get("protostones").and_then(|v| v.as_array()) {
        if protostones.is_empty() {
            println!("\n🚫 No protostones found in this transaction");
        } else {
            println!("\n🪨 Protostones Found: {}", protostones.len());
            println!("═══════════════════════");
            
            for (i, protostone) in protostones.iter().enumerate() {
                println!("\n🪨 Protostone #{}", i + 1);
                println!("───────────────────");
                
                // Protocol tag
                if let Some(protocol_tag) = protostone.get("protocol_tag").and_then(|v| v.as_u64()) {
                    let protocol_name = match protocol_tag {
                        1 => "ALKANES Metaprotocol",
                        _ => "Unknown Protocol",
                    };
                    println!("🏷️  Protocol: {} (tag: {})", protocol_name, protocol_tag);
                }
                
                // Message information
                if let Some(message_bytes) = protostone.get("message_bytes").and_then(|v| v.as_array()) {
                    println!("📨 Message ({} bytes):", message_bytes.len());
                    
                    // Show raw bytes
                    let bytes_str = message_bytes.iter()
                        .filter_map(|v| v.as_u64())
                        .map(|n| format!("{:02x}", n))
                        .collect::<Vec<_>>()
                        .join(" ");
                    println!("   📄 Raw bytes: {}", bytes_str);
                    
                    // Show decoded values
                    if let Some(message_decoded) = protostone.get("message_decoded").and_then(|v| v.as_array()) {
                        let decoded_str = message_decoded.iter()
                            .filter_map(|v| v.as_u64())
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        println!("   🔓 Decoded: [{}]", decoded_str);
                        
                        // Special handling for DIESEL tokens
                        if let Some(protocol_tag) = protostone.get("protocol_tag").and_then(|v| v.as_u64()) {
                            if protocol_tag == 1 && message_decoded.len() >= 3 {
                                if let (Some(first), Some(second), Some(third)) = (
                                    message_decoded[0].as_u64(),
                                    message_decoded[1].as_u64(),
                                    message_decoded[2].as_u64()
                                ) {
                                    if first == 2 && second == 0 && third == 77 {
                                        println!("   🔥 DIESEL Token Mint Detected!");
                                        println!("   ⚡ Cellpack: [2, 0, 77] (Standard DIESEL mint)");
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Edicts with tree view
                if let Some(edicts) = protostone.get("edicts").and_then(|v| v.as_array()) {
                    if !edicts.is_empty() {
                        println!("📋 Token Transfers ({}):", edicts.len());
                        for (j, edict) in edicts.iter().enumerate() {
                            if let Some(edict_obj) = edict.as_object() {
                                let id_block = edict_obj.get("id").and_then(|v| v.get("block")).and_then(|v| v.as_u64()).unwrap_or(0);
                                let id_tx = edict_obj.get("id").and_then(|v| v.get("tx")).and_then(|v| v.as_u64()).unwrap_or(0);
                                let amount = edict_obj.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                                let output_idx = edict_obj.get("output").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                                
                                let tree_symbol = if j == edicts.len() - 1 { "└─" } else { "├─" };
                                println!("   {} 🪙 Token {}:{}", tree_symbol, id_block, id_tx);
                                println!("   {}    💰 Amount: {} units", if j == edicts.len() - 1 { "  " } else { "│ " }, amount);
                                
                                // Show destination output details
                                if output_idx < tx.output.len() {
                                    let dest_output = &tx.output[output_idx];
                                    println!("   {}    🎯 → Output {}: {} sats",
                                        if j == edicts.len() - 1 { "  " } else { "│ " },
                                        output_idx, dest_output.value);
                                    
                                    if let Some(addr_info) = extract_address_from_script(&dest_output.script_pubkey) {
                                        println!("   {}       📍 {}",
                                            if j == edicts.len() - 1 { "  " } else { "│ " },
                                            addr_info.address);
                                    }
                                } else {
                                    println!("   {}    ❌ → Invalid output {}",
                                        if j == edicts.len() - 1 { "  " } else { "│ " },
                                        output_idx);
                                }
                            }
                        }
                    }
                }
                
                // Pointer and refund with output details
                if let Some(pointer) = protostone.get("pointer").and_then(|v| v.as_u64()) {
                    let pointer_idx = pointer as usize;
                    println!("👉 Pointer: output {}", pointer);
                    if pointer_idx < tx.output.len() {
                        let pointer_output = &tx.output[pointer_idx];
                        println!("   └─ 💰 {} sats", pointer_output.value);
                        if let Some(addr_info) = extract_address_from_script(&pointer_output.script_pubkey) {
                            println!("      📍 {}", addr_info.address);
                        }
                    }
                }
                
                if let Some(refund) = protostone.get("refund").and_then(|v| v.as_u64()) {
                    let refund_idx = refund as usize;
                    println!("💸 Refund: output {}", refund);
                    if refund_idx < tx.output.len() {
                        let refund_output = &tx.output[refund_idx];
                        println!("   └─ 💰 {} sats", refund_output.value);
                        if let Some(addr_info) = extract_address_from_script(&refund_output.script_pubkey) {
                            println!("      📍 {}", addr_info.address);
                        }
                    }
                }
            }
        }
    }
    
    println!("\n✅ Analysis complete!");
}

/// Decode a transaction from hex
fn decode_transaction_hex(hex_str: &str) -> Result<Transaction> {
    let tx_bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("Failed to decode transaction hex")?;
    
    let tx: Transaction = deserialize(&tx_bytes)
        .context("Failed to deserialize transaction")?;
    
    Ok(tx)
}

/// Expand tilde (~) in file paths to home directory
fn expand_tilde(path: &str) -> Result<String> {
    if path.starts_with("~/") {
        let home = std::env::var("HOME")
            .context("HOME environment variable not set")?;
        Ok(path.replacen("~", &home, 1))
    } else {
        Ok(path.to_string())
    }
}

/// Format Uint128 as a floating point number divided by 1e8
fn format_uint128_as_float(uint128: &protorune_support::proto::protorune::Uint128) -> String {
    // Convert Uint128 to u128
    let value = (uint128.hi as u128) << 64 | (uint128.lo as u128);
    
    // Special case: if the raw value is exactly 1, display as "1" (since 1 raw unit = 1 token)
    if value == 1 {
        return "1".to_string();
    }
    
    let float_value = value as f64 / 1e8;
    
    // Format with 4 decimal places or 4 significant figures if smaller
    if float_value >= 0.0001 {
        format!("{:.4}", float_value)
    } else if float_value > 0.0 {
        // For very small numbers, use scientific notation with 4 significant figures
        format!("{:.3e}", float_value)
    } else {
        "0.0000".to_string()
    }
}

/// Format OutpointResponse with pretty-printed BalanceSheet
fn format_outpoint_response(response: &OutpointResponse) -> String {
    let mut output = String::new();
    
    // Header
    output.push_str("🔍 Protorunes Outpoint Response\n");
    output.push_str("═══════════════════════════════\n\n");
    
    // Outpoint information
    if let Some(outpoint) = response.outpoint.as_ref() {
        output.push_str("📍 Outpoint Information:\n");
        let txid_hex = hex::encode(&outpoint.txid);
        output.push_str(&format!("   🆔 TXID: {}\n", txid_hex));
        output.push_str(&format!("   🔢 VOUT: {}\n", outpoint.vout));
    }
    
    // Output information
    if let Some(output_info) = response.output.as_ref() {
        output.push_str("\n📤 Output Information:\n");
        output.push_str(&format!("   💰 Value: {} sats\n", output_info.value));
        let scriptpubkey_hex = hex::encode(&output_info.script);
        output.push_str(&format!("   📜 ScriptPubKey: {}\n", scriptpubkey_hex));
    }
    
    // Block information
    output.push_str("\n🏗️ Block Information:\n");
    output.push_str(&format!("   📏 Height: {}\n", response.height));
    output.push_str(&format!("   🔢 TX Index: {}\n", response.txindex));
    
    // Balance sheet
    if let Some(balance_sheet) = response.balances.as_ref() {
        output.push_str("\n💰 Balance Sheet:\n");
        
        if balance_sheet.entries.is_empty() {
            output.push_str("   🚫 No rune balances found\n");
        } else {
            for (i, entry) in balance_sheet.entries.iter().enumerate() {
                let tree_symbol = if i == balance_sheet.entries.len() - 1 { "└─" } else { "├─" };
                
                output.push_str(&format!("   {} 🪙 Rune Entry #{}\n", tree_symbol, i + 1));
                
                // Rune information
                if let Some(rune) = entry.rune.as_ref() {
                    let continuation = if i == balance_sheet.entries.len() - 1 { "  " } else { "│ " };
                    output.push_str(&format!("   {}    🏷️ Name: {}\n", continuation, rune.name));
                    output.push_str(&format!("   {}    ✨ Symbol: {}\n", continuation, rune.symbol));
                    if let Some(rune_id) = rune.runeId.as_ref() {
                        let height = if let Some(h) = rune_id.height.as_ref() {
                            (h.hi as u128) << 64 | (h.lo as u128)
                        } else {
                            0
                        };
                        let txindex = if let Some(t) = rune_id.txindex.as_ref() {
                            (t.hi as u128) << 64 | (t.lo as u128)
                        } else {
                            0
                        };
                        output.push_str(&format!("   {}    🆔 ID: {}:{}\n", continuation, height, txindex));
                    }
                }
                
                // Balance information
                if let Some(balance) = entry.balance.as_ref() {
                    let continuation = if i == balance_sheet.entries.len() - 1 { "  " } else { "│ " };
                    let formatted_balance = format_uint128_as_float(balance);
                    output.push_str(&format!("   {}    💎 Balance: {} units\n", continuation, formatted_balance));
                }
            }
        }
    }
    
    output
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

    // Generate network-specific wallet path
    let wallet_path = if let Some(path) = args.wallet_path {
        expand_tilde(&path)?
    } else {
        let network_name = match network_params.network {
            bdk::bitcoin::Network::Bitcoin => "mainnet",
            bdk::bitcoin::Network::Testnet => "testnet",
            bdk::bitcoin::Network::Signet => "signet",
            bdk::bitcoin::Network::Regtest => "regtest",
            _ => "custom",
        };
        expand_tilde(&format!("~/.deezel/{}.dat", network_name))?
    };
    
    // Create wallet directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(&wallet_path).parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create wallet directory")?;
    }

    // Determine RPC URLs based on provider
    let sandshrew_rpc_url = args.sandshrew_rpc_url.clone()
        .unwrap_or_else(|| deezel_cli::network::get_rpc_url(&args.provider));
    
    let bitcoin_rpc_url = args.bitcoin_rpc_url.clone()
        .unwrap_or_else(|| "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string());

    // Initialize wallet if needed for the command (but not for wallet creation)
    let wallet_manager = if matches!(args.command, Commands::Walletinfo) ||
        matches!(args.command, Commands::Wallet { command: WalletCommands::Restore { .. } |
                                                            WalletCommands::Info |
                                                            WalletCommands::Addresses { .. } |
                                                            WalletCommands::Balance |
                                                            WalletCommands::Send { .. } |
                                                            WalletCommands::SendAll { .. } |
                                                            WalletCommands::CreateTx { .. } |
                                                            WalletCommands::SignTx { .. } |
                                                            WalletCommands::BroadcastTx { .. } |
                                                            WalletCommands::Utxos |
                                                            WalletCommands::FreezeUtxo { .. } |
                                                            WalletCommands::UnfreezeUtxo { .. } |
                                                            WalletCommands::History { .. } |
                                                            WalletCommands::TxDetails { .. } |
                                                            WalletCommands::EstimateFee { .. } |
                                                            WalletCommands::FeeRates |
                                                            WalletCommands::Sync |
                                                            WalletCommands::Backup }) {
       let wallet_config = deezel_cli::wallet::WalletConfig {
           wallet_path: wallet_path.clone(),
           network: network_params.network,
           bitcoin_rpc_url: bitcoin_rpc_url.clone(),
           metashrew_rpc_url: sandshrew_rpc_url.clone(),
           network_params: Some(network_params.to_protorune_params()),
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
            BitcoindCommands::Generatetoaddress { nblocks, address } => {
                let result = rpc_client.generate_to_address(nblocks, &address).await?;
                println!("Generated {} blocks to address {}", nblocks, address);
                if let Some(block_hashes) = result.as_array() {
                    println!("Block hashes:");
                    for (i, hash) in block_hashes.iter().enumerate() {
                        if let Some(hash_str) = hash.as_str() {
                            println!("  {}: {}", i + 1, hash_str);
                        }
                    }
                }
            },
        },
        Commands::Wallet { command } => {
            match command {
                WalletCommands::Create { mnemonic, passphrase } => {
                    // Handle wallet creation separately since we don't need an existing wallet manager
                        let wallet_config = deezel_cli::wallet::WalletConfig {
                            wallet_path: wallet_path.clone(),
                            network: network_params.network,
                            bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                            metashrew_rpc_url: sandshrew_rpc_url.clone(),
                            network_params: Some(network_params.to_protorune_params()),
                        };
                        
                        let new_wallet = deezel_cli::wallet::WalletManager::create_wallet(
                            wallet_config,
                            mnemonic.clone(),
                            passphrase.clone()
                        ).await?;
                        
                        println!("Wallet created successfully!");
                        if let Some(mnemonic) = new_wallet.get_mnemonic().await? {
                            println!("Mnemonic: {}", mnemonic);
                            println!("⚠️  IMPORTANT: Save this mnemonic phrase in a secure location!");
                        }
                        
                        let address = new_wallet.get_address().await?;
                        println!("First address: {}", address);
                },
                _ => {
                    // Handle all other wallet commands that require an existing wallet manager
                    if let Some(wallet_manager) = &wallet_manager {
                        match command {
                            WalletCommands::Create { .. } => unreachable!(), // Already handled above
                            WalletCommands::Restore { mnemonic, passphrase } => {
                                let wallet_config = deezel_cli::wallet::WalletConfig {
                                    wallet_path: wallet_path.clone(),
                                    network: network_params.network,
                                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                                    network_params: Some(network_params.to_protorune_params()),
                                };
                        
                        let restored_wallet = deezel_cli::wallet::WalletManager::restore_wallet(
                            wallet_config,
                            mnemonic.clone(),
                            passphrase.clone()
                        ).await?;
                        
                        println!("Wallet restored successfully!");
                        let address = restored_wallet.get_address().await?;
                        println!("First address: {}", address);
                    },
                    WalletCommands::Info => {
                        println!("Wallet Information:");
                        
                        // Get wallet addresses
                        let address = wallet_manager.get_address().await?;
                        println!("  Address: {}", address);
                        
                        // Get wallet balance
                        match wallet_manager.get_balance().await {
                            Ok(balance) => {
                                println!("  Balance:");
                                println!("    Confirmed: {} sats", balance.confirmed);
                                println!("    Pending: {} sats", balance.trusted_pending + balance.untrusted_pending);
                                println!("    Total: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
                            },
                            Err(e) => println!("  Failed to get balance: {}", e),
                        };
                        
                        // Get alkanes balances
                        println!("  Alkanes Balances:");
                        match rpc_client.get_protorunes_by_address(&address).await {
                            Ok(protorunes) => {
                                if let Some(runes_array) = protorunes.as_array() {
                                    if runes_array.is_empty() {
                                        println!("    No alkanes tokens found");
                                    } else {
                                        for (i, rune) in runes_array.iter().enumerate() {
                                            if let Some(rune_obj) = rune.as_object() {
                                                let name = rune_obj.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                                let balance = rune_obj.get("balance").and_then(|v| v.as_str()).unwrap_or("0");
                                                println!("    {}: {} - {} units", i+1, name, balance);
                                            }
                                        }
                                    }
                                } else {
                                    println!("    Failed to parse alkanes balances");
                                }
                            },
                            Err(e) => println!("    Failed to get alkanes balances: {}", e),
                        };
                    },
                    WalletCommands::Addresses { count } => {
                        let addresses = wallet_manager.get_addresses(count).await?;
                        println!("Generated {} addresses:", addresses.len());
                        for (i, address) in addresses.iter().enumerate() {
                            println!("  {}: {}", i + 1, address);
                        }
                    },
                    WalletCommands::Balance => {
                        match wallet_manager.get_balance().await {
                            Ok(balance) => {
                                println!("💰 Bitcoin Balance Summary:");
                                println!("═══════════════════════════");
                                println!("  ✅ Confirmed: {} sats", balance.confirmed);
                                println!("  ⏳ Pending: {} sats", balance.trusted_pending + balance.untrusted_pending);
                                println!("  📊 Total: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
                                
                                // Get and display individual UTXOs
                                println!("\n🔍 UTXO Details:");
                                println!("═══════════════");
                                match wallet_manager.get_utxos().await {
                                    Ok(utxos) => {
                                        if utxos.is_empty() {
                                            println!("  🚫 No UTXOs found");
                                        } else {
                                            for (i, utxo) in utxos.iter().enumerate() {
                                                let tree_symbol = if i == utxos.len() - 1 { "└─" } else { "├─" };
                                                let status_icon = if utxo.frozen { "🔒" } else { "🔓" };
                                                let confirmation_icon = "✅"; // All UTXOs from wallet should be confirmed
                                                
                                                println!("  {} {} UTXO #{}", tree_symbol, status_icon, i + 1);
                                                println!("  {}    🆔 {}:{}", if i == utxos.len() - 1 { "  " } else { "│ " }, utxo.txid, utxo.vout);
                                                println!("  {}    💰 {} sats", if i == utxos.len() - 1 { "  " } else { "│ " }, utxo.amount);
                                                println!("  {}    📍 {}", if i == utxos.len() - 1 { "  " } else { "│ " }, utxo.address);
                                                println!("  {}    {} Confirmed{}",
                                                    if i == utxos.len() - 1 { "  " } else { "│ " },
                                                    confirmation_icon,
                                                    if utxo.frozen { " [FROZEN]" } else { "" }
                                                );
                                            }
                                            
                                            println!("\n📈 Summary:");
                                            println!("  🔢 Total UTXOs: {}", utxos.len());
                                            let total_value: u64 = utxos.iter().map(|u| u.amount).sum();
                                            println!("  💎 Combined Value: {} sats", total_value);
                                            let frozen_count = utxos.iter().filter(|u| u.frozen).count();
                                            if frozen_count > 0 {
                                                println!("  🔒 Frozen UTXOs: {}", frozen_count);
                                            }
                                        }
                                    },
                                    Err(e) => println!("  ❌ Failed to get UTXO details: {}", e),
                                };
                            },
                            Err(e) => println!("❌ Failed to get balance: {}", e),
                        };
                    },
                    WalletCommands::Send { address, amount, fee_rate } => {
                        let params = deezel_cli::wallet::SendParams {
                            address: address.clone(),
                            amount: amount,
                            fee_rate: fee_rate.clone(),
                            send_all: false,
                        };
                        
                        match wallet_manager.send(params).await {
                            Ok(txid) => {
                                println!("Transaction sent successfully!");
                                println!("Transaction ID: {}", txid);
                            },
                            Err(e) => println!("Failed to send transaction: {}", e),
                        };
                    },
                    WalletCommands::SendAll { address, fee_rate } => {
                        let params = deezel_cli::wallet::SendParams {
                            address: address.clone(),
                            amount: 0, // Not used when send_all is true
                            fee_rate: fee_rate.clone(),
                            send_all: true,
                        };
                        
                        match wallet_manager.send(params).await {
                            Ok(txid) => {
                                println!("All funds sent successfully!");
                                println!("Transaction ID: {}", txid);
                            },
                            Err(e) => println!("Failed to send all funds: {}", e),
                        };
                    },
                    WalletCommands::CreateTx { address, amount, fee_rate } => {
                        let params = deezel_cli::wallet::SendParams {
                            address: address.clone(),
                            amount: amount,
                            fee_rate: fee_rate.clone(),
                            send_all: false,
                        };
                        
                        match wallet_manager.create_transaction(params).await {
                            Ok((tx, details)) => {
                                println!("Transaction created successfully!");
                                println!("Transaction ID: {}", tx.txid());
                                println!("Transaction hex: {}", hex::encode(bdk::bitcoin::consensus::serialize(&tx)));
                                println!("Fee: {} sats", details.fee.unwrap_or(0));
                            },
                            Err(e) => println!("Failed to create transaction: {}", e),
                        };
                    },
                    WalletCommands::SignTx { tx_hex } => {
                        // For now, just validate the transaction hex
                        match decode_transaction_hex(&tx_hex) {
                            Ok(tx) => {
                                println!("Transaction is valid:");
                                println!("  Transaction ID: {}", tx.txid());
                                println!("  Inputs: {}", tx.input.len());
                                println!("  Outputs: {}", tx.output.len());
                                println!("Note: Signing functionality requires wallet integration");
                            },
                            Err(e) => println!("Invalid transaction hex: {}", e),
                        };
                    },
                    WalletCommands::BroadcastTx { tx_hex } => {
                        match rpc_client.broadcast_transaction(&tx_hex).await {
                            Ok(txid) => {
                                println!("Transaction broadcast successfully!");
                                println!("Transaction ID: {}", txid);
                            },
                            Err(e) => println!("Failed to broadcast transaction: {}", e),
                        };
                    },
                    WalletCommands::Utxos => {
                        match wallet_manager.get_utxos().await {
                            Ok(utxos) => {
                                if utxos.is_empty() {
                                    println!("No UTXOs found");
                                } else {
                                    println!("UTXOs ({} total):", utxos.len());
                                    for utxo in utxos {
                                        println!("  {}:{} - {} sats ({}{})",
                                            utxo.txid,
                                            utxo.vout,
                                            utxo.amount,
                                            utxo.address,
                                            if utxo.frozen { " [FROZEN]" } else { "" }
                                        );
                                    }
                                }
                            },
                            Err(e) => println!("Failed to get UTXOs: {}", e),
                        };
                    },
                    WalletCommands::FreezeUtxo { txid, vout } => {
                        match wallet_manager.freeze_utxo(&txid, vout).await {
                            Ok(_) => println!("UTXO {}:{} frozen successfully", txid, vout),
                            Err(e) => println!("Failed to freeze UTXO: {}", e),
                        };
                    },
                    WalletCommands::UnfreezeUtxo { txid, vout } => {
                        match wallet_manager.unfreeze_utxo(&txid, vout).await {
                            Ok(_) => println!("UTXO {}:{} unfrozen successfully", txid, vout),
                            Err(e) => println!("Failed to unfreeze UTXO: {}", e),
                        };
                    },
                    WalletCommands::History { limit } => {
                        match wallet_manager.get_transaction_history(Some(limit)).await {
                            Ok(history) => {
                                if history.is_empty() {
                                    println!("No transaction history found");
                                } else {
                                    println!("Transaction History ({} transactions):", history.len());
                                    for tx in history {
                                        println!("  {} - {} sats ({}) - {} confirmations",
                                            tx.txid,
                                            tx.amount,
                                            tx.tx_type,
                                            tx.confirmations
                                        );
                                    }
                                }
                            },
                            Err(e) => println!("Failed to get transaction history: {}", e),
                        };
                    },
                    WalletCommands::TxDetails { txid } => {
                        match rpc_client.get_transaction_hex(&txid).await {
                            Ok(tx_hex) => {
                                match decode_transaction_hex(&tx_hex) {
                                    Ok(tx) => {
                                        println!("Transaction Details:");
                                        println!("  Transaction ID: {}", tx.txid());
                                        println!("  Version: {}", tx.version);
                                        println!("  Lock time: {}", tx.lock_time);
                                        println!("  Inputs: {}", tx.input.len());
                                        println!("  Outputs: {}", tx.output.len());
                                        
                                        for (i, output) in tx.output.iter().enumerate() {
                                            println!("    Output {}: {} sats", i, output.value);
                                        }
                                    },
                                    Err(e) => println!("Failed to decode transaction: {}", e),
                                }
                            },
                            Err(e) => println!("Failed to get transaction: {}", e),
                        };
                    },
                    WalletCommands::EstimateFee { address, amount } => {
                        let params = deezel_cli::wallet::SendParams {
                            address: address.clone(),
                            amount: amount,
                            fee_rate: None,
                            send_all: false,
                        };
                        
                        match wallet_manager.create_transaction(params).await {
                            Ok((_, details)) => {
                                println!("Fee estimate: {} sats", details.fee.unwrap_or(0));
                            },
                            Err(e) => println!("Failed to estimate fee: {}", e),
                        };
                    },
                    WalletCommands::FeeRates => {
                        match wallet_manager.estimate_fee_rate().await {
                            Ok(fee_rate) => {
                                println!("Current fee rate: {} sat/vB", fee_rate);
                            },
                            Err(e) => println!("Failed to get fee rates: {}", e),
                        };
                    },
                    WalletCommands::Sync => {
                        match wallet_manager.sync().await {
                            Ok(_) => println!("Wallet synced successfully"),
                            Err(e) => println!("Failed to sync wallet: {}", e),
                        };
                    },
                    WalletCommands::Backup => {
                        match wallet_manager.get_mnemonic().await {
                            Ok(Some(mnemonic)) => {
                                println!("Wallet Backup:");
                                println!("Mnemonic: {}", mnemonic);
                                println!("⚠️  IMPORTANT: Store this mnemonic phrase in a secure location!");
                            },
                            Ok(None) => println!("No mnemonic available for this wallet"),
                            Err(e) => println!("Failed to get mnemonic: {}", e),
                        };
                    },
                        }
                    } else {
                        return Err(anyhow!("Wallet manager not initialized"));
                    }
                }
            }
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
        Commands::Runestone { txid_or_hex, raw } => {
            // Check if input is a transaction ID or hex
            if txid_or_hex.len() == 64 && txid_or_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                // Looks like a transaction ID, fetch from RPC
                if !raw {
                    println!("🔍 Fetching transaction {} from RPC...", txid_or_hex);
                } else {
                    eprintln!("Fetching transaction {} from RPC...", txid_or_hex);
                }
                let tx_hex = rpc_client.get_transaction_hex(&txid_or_hex).await
                    .context("Failed to fetch transaction from RPC")?;
                
                let tx = decode_transaction_hex(&tx_hex)?;
                analyze_runestone_tx(&tx, raw);
            } else {
                // Assume it's transaction hex
                if !raw {
                    println!("🔍 Decoding transaction from hex...");
                } else {
                    eprintln!("Decoding transaction from hex...");
                }
                let tx = decode_transaction_hex(&txid_or_hex)?;
                analyze_runestone_tx(&tx, raw);
            }
        },
        Commands::Alkanes { command } => match command {
            AlkanesCommands::Meta { contract_id } => {
                let (block, tx) = parse_contract_id(&contract_id)?;
                let result = rpc_client.get_contract_meta(&block, &tx).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            
            // Enhanced alkanes commands
            AlkanesCommands::DeployContract { wasm_file, calldata, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let params = deezel_cli::alkanes::types::ContractDeployParams {
                    wasm_file: wasm_file.clone(),
                    calldata: deezel_cli::alkanes::contract::parse_calldata(&calldata),
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.contract.deploy_contract(params).await {
                    Ok(result) => {
                        println!("Contract deployed successfully!");
                        println!("Contract ID: {}:{}", result.contract_id.block, result.contract_id.tx);
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to deploy contract: {}", e),
                };
            },
            
            AlkanesCommands::Execute { calldata, edicts, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let parsed_edicts = if let Some(edicts_str) = edicts {
                    Some(deezel_cli::alkanes::contract::parse_edicts(&edicts_str)?)
                } else {
                    None
                };
                
                let params = deezel_cli::alkanes::types::ContractExecuteParams {
                    calldata: deezel_cli::alkanes::contract::parse_calldata(&calldata),
                    edicts: parsed_edicts,
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.contract.execute_contract(params).await {
                    Ok(result) => {
                        println!("Contract executed successfully!");
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to execute contract: {}", e),
                };
            },
            
            AlkanesCommands::DeployToken { name, symbol, cap, amount_per_mint, reserve_number, premine, image, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let params = deezel_cli::alkanes::types::TokenDeployParams {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    cap: cap,
                    amount_per_mint: amount_per_mint,
                    reserve_number: reserve_number,
                    premine: premine.clone(),
                    image: image.clone(),
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.token.deploy_token(params).await {
                    Ok(result) => {
                        println!("Token deployed successfully!");
                        println!("Token ID: {}:{}", result.token_id.block, result.token_id.tx);
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to deploy token: {}", e),
                };
            },
            
            AlkanesCommands::SendToken { token, amount, to, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_id = deezel_cli::alkanes::parse_alkane_id(&token)?;
                
                let params = deezel_cli::alkanes::types::TokenSendParams {
                    token: token_id,
                    amount: amount,
                    to: to.clone(),
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.token.send_token(params).await {
                    Ok(result) => {
                        println!("Token sent successfully!");
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to send token: {}", e),
                };
            },
            
            AlkanesCommands::Balance { address } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                match alkanes_manager.get_balance(address.as_deref()).await {
                    Ok(balances) => {
                        if balances.is_empty() {
                            println!("No alkanes tokens found");
                        } else {
                            println!("Alkanes Balances:");
                            for (i, balance) in balances.iter().enumerate() {
                                println!("  {}: {} ({}) - {} units (ID: {}:{})",
                                    i + 1,
                                    balance.name,
                                    balance.symbol,
                                    balance.balance,
                                    balance.alkane_id.block,
                                    balance.alkane_id.tx
                                );
                            }
                        }
                    },
                    Err(e) => println!("Failed to get alkanes balance: {}", e),
                };
            },
            
            AlkanesCommands::TokenInfo { token } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_id = deezel_cli::alkanes::parse_alkane_id(&token)?;
                
                match alkanes_manager.get_token_info(&token_id).await {
                    Ok(info) => {
                        println!("Token Information:");
                        println!("  Name: {}", info.name);
                        println!("  Symbol: {}", info.symbol);
                        println!("  Token ID: {}:{}", info.alkane_id.block, info.alkane_id.tx);
                        println!("  Total Supply: {}", info.total_supply);
                        println!("  Cap: {}", info.cap);
                        println!("  Amount per Mint: {}", info.amount_per_mint);
                        println!("  Minted: {}", info.minted);
                    },
                    Err(e) => println!("Failed to get token info: {}", e),
                };
            },
            
            AlkanesCommands::CreatePool { calldata, tokens, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_amounts = deezel_cli::alkanes::token::parse_token_amounts(&tokens)?;
                
                let params = deezel_cli::alkanes::types::PoolCreateParams {
                    calldata: deezel_cli::alkanes::contract::parse_calldata(&calldata),
                    tokens: token_amounts,
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.amm.create_pool(params).await {
                    Ok(result) => {
                        println!("Pool created successfully!");
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to create pool: {}", e),
                };
            },
            
            AlkanesCommands::AddLiquidity { calldata, tokens, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_amounts = deezel_cli::alkanes::token::parse_token_amounts(&tokens)?;
                
                let params = deezel_cli::alkanes::types::LiquidityAddParams {
                    calldata: deezel_cli::alkanes::contract::parse_calldata(&calldata),
                    tokens: token_amounts,
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.amm.add_liquidity(params).await {
                    Ok(result) => {
                        println!("Liquidity added successfully!");
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to add liquidity: {}", e),
                };
            },
            
            AlkanesCommands::RemoveLiquidity { calldata, token, amount, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_id = deezel_cli::alkanes::parse_alkane_id(&token)?;
                
                let params = deezel_cli::alkanes::types::LiquidityRemoveParams {
                    calldata: deezel_cli::alkanes::contract::parse_calldata(&calldata),
                    token: token_id,
                    amount: amount,
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.amm.remove_liquidity(params).await {
                    Ok(result) => {
                        println!("Liquidity removed successfully!");
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to remove liquidity: {}", e),
                };
            },
            
            AlkanesCommands::Swap { calldata, token, amount, fee_rate } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_id = deezel_cli::alkanes::parse_alkane_id(&token)?;
                
                let params = deezel_cli::alkanes::types::SwapParams {
                    calldata: deezel_cli::alkanes::contract::parse_calldata(&calldata),
                    token: token_id,
                    amount: amount,
                    fee_rate: fee_rate.clone(),
                };
                
                match alkanes_manager.amm.swap(params).await {
                    Ok(result) => {
                        println!("Swap executed successfully!");
                        println!("Transaction ID: {}", result.txid);
                        println!("Fee: {} sats", result.fee);
                    },
                    Err(e) => println!("Failed to execute swap: {}", e),
                };
            },
            
            AlkanesCommands::SimulateAdvanced { target, inputs, tokens, decoder } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let target_id = deezel_cli::alkanes::parse_alkane_id(&target)?;
                let parsed_inputs = deezel_cli::alkanes::simulation::parse_simulation_inputs(&inputs);
                
                let token_amounts = if let Some(tokens_str) = tokens {
                    Some(deezel_cli::alkanes::token::parse_token_amounts(&tokens_str)?)
                } else {
                    None
                };
                
                let params = deezel_cli::alkanes::types::SimulationParams {
                    target: target_id,
                    inputs: parsed_inputs,
                    tokens: token_amounts,
                    decoder: decoder.clone(),
                };
                
                match alkanes_manager.simulation.simulate_advanced(params).await {
                    Ok(result) => {
                        println!("Simulation Result:");
                        println!("{}", deezel_cli::alkanes::simulation::format_simulation_result(&result));
                    },
                    Err(e) => println!("Simulation failed: {}", e),
                };
            },
            
            AlkanesCommands::PreviewRemoveLiquidity { token, amount } => {
                // Initialize alkanes manager
                let wallet_config = deezel_cli::wallet::WalletConfig {
                    wallet_path: wallet_path.clone(),
                    network: network_params.network,
                    bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                    metashrew_rpc_url: sandshrew_rpc_url.clone(),
                    network_params: Some(network_params.to_protorune_params()),
                };
                
                let wallet_manager = Arc::new(
                    deezel_cli::wallet::WalletManager::new(wallet_config)
                        .await
                        .context("Failed to initialize wallet manager")?
                );
                
                let alkanes_manager = deezel_cli::alkanes::AlkanesManager::new(
                    Arc::new(rpc_client),
                    wallet_manager
                );
                
                let token_id = deezel_cli::alkanes::parse_alkane_id(&token)?;
                
                match alkanes_manager.amm.preview_remove_liquidity(&token_id, amount).await {
                    Ok(preview) => {
                        println!("Liquidity Removal Preview:");
                        println!("  LP Tokens to Burn: {}", preview.lp_tokens_burned);
                        println!("  Token A Amount: {}", preview.token_a_amount);
                        println!("  Token B Amount: {}", preview.token_b_amount);
                    },
                    Err(e) => println!("Failed to preview liquidity removal: {}", e),
                };
            },
            
            AlkanesCommands::Inspect { alkane_id, disasm, fuzz, fuzz_ranges, meta, codehash, raw } => {
                info!("Inspecting alkane: {}", alkane_id);
                
                // Parse alkane ID
                let parsed_alkane_id = deezel_cli::alkanes::parse_alkane_id(&alkane_id)?;
                
                // Initialize RPC client for inspector
                let inspector = deezel_cli::alkanes::inspector::AlkaneInspector::new(
                    Arc::new(rpc_client)
                ).context("Failed to initialize alkane inspector")?;
                
                // Perform inspection with requested analysis modes
                match inspector.inspect_alkane(&parsed_alkane_id, disasm, fuzz, fuzz_ranges.as_deref(), meta, codehash, raw).await {
                    Ok(_) => {
                        if !raw {
                            println!("Alkane inspection completed successfully");
                        }
                    },
                    Err(e) => {
                        if raw {
                            eprintln!("Alkane inspection failed: {}", e);
                        } else {
                            println!("Alkane inspection failed: {}", e);
                        }
                        std::process::exit(1);
                    }
                }
            },
        },
        Commands::View { command } => {
            // Convert BlockTag to string for RPC calls
            let block_tag_to_string = |tag: &BlockTag| -> String {
                match tag {
                    BlockTag::Latest => "latest".to_string(),
                    BlockTag::Pending => "pending".to_string(),
                    BlockTag::Height(h) => h.to_string(),
                }
            };

            match command {
                ViewCommands::Getbytecode { contract_id, block_tag } => {
                    let (block, tx) = parse_contract_id(&contract_id)?;
                    let tag_str = block_tag_to_string(&block_tag);
                    let bytecode = rpc_client.get_bytecode_with_tag(&block, &tx, &tag_str).await?;
                    println!("{}", bytecode);
                },
                ViewCommands::Getblock { height, block_tag } => {
                    let tag_str = block_tag_to_string(&block_tag);
                    let result = rpc_client.get_block(height, &tag_str).await?;
                    println!("{}", result);
                },
                ViewCommands::Protorunesbyaddress { address, protocol_tag, block_tag } => {
                    let tag_str = block_tag_to_string(&block_tag);
                    let result = rpc_client.get_protorunes_by_address_with_tags(&address, protocol_tag, &tag_str).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                ViewCommands::Transactionbyid { txid, block_tag } => {
                    let tag_str = block_tag_to_string(&block_tag);
                    let result = rpc_client.get_transaction_by_id(&txid, &tag_str).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                ViewCommands::Spendablesbyaddress { address, block_tag } => {
                    let tag_str = block_tag_to_string(&block_tag);
                    let result = rpc_client.get_spendables_by_address_with_tag(&address, &tag_str).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                ViewCommands::Protorunesbyheight { height, protocol_tag } => {
                    let result = rpc_client.get_protorunes_by_height(height, protocol_tag).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                ViewCommands::Protorunesbyoutpoint { outpoint, protocol_tag } => {
                    let (txid, vout) = parse_outpoint(&outpoint)?;
                    let result = rpc_client.get_protorunes_by_outpoint_with_protocol(&txid, vout, protocol_tag).await?;
                    println!("{}", format_outpoint_response(&result));
                },
                ViewCommands::Trace { outpoint, raw } => {
                    let (txid, vout) = parse_outpoint(&outpoint)?;
                    if raw {
                        let trace_json = rpc_client.trace_outpoint_json(&txid, vout).await?;
                        println!("{}", trace_json);
                    } else {
                        let trace_pretty = rpc_client.trace_outpoint_pretty(&txid, vout).await?;
                        println!("{}", trace_pretty);
                    }
                },
                ViewCommands::Simulate {
                    alkanes,
                    transaction,
                    height,
                    block,
                    txindex,
                    inputs,
                    vout,
                    pointer,
                    refund_pointer,
                    block_tag
                } => {
                    let tag_str = block_tag_to_string(&block_tag);
                    let result = rpc_client.simulate_detailed(
                        alkanes.as_deref(),
                        &transaction,
                        height,
                        &block,
                        txindex,
                        &inputs,
                        vout,
                        pointer,
                        refund_pointer,
                        &tag_str
                    ).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
            }
        },
        Commands::InspectAlkane { alkane_id, disasm, fuzz, fuzz_ranges, meta, codehash, raw } => {
            info!("Inspecting alkane: {}", alkane_id);
            
            // Parse alkane ID
            let parsed_alkane_id = deezel_cli::alkanes::parse_alkane_id(&alkane_id)?;
            
            // Initialize RPC client for inspector
            let inspector = deezel_cli::alkanes::inspector::AlkaneInspector::new(
                Arc::new(rpc_client)
            ).context("Failed to initialize alkane inspector")?;
            
            // Perform inspection with requested analysis modes
            match inspector.inspect_alkane(&parsed_alkane_id, disasm, fuzz, fuzz_ranges.as_deref(), meta, codehash, raw).await {
                Ok(_) => {
                    if !raw {
                        println!("Alkane inspection completed successfully");
                    }
                },
                Err(e) => {
                    if raw {
                        eprintln!("Alkane inspection failed: {}", e);
                    } else {
                        println!("Alkane inspection failed: {}", e);
                    }
                    std::process::exit(1);
                }
            }
        },
    }

    Ok(())
}
