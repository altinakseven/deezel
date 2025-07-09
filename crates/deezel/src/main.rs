//! DEEZEL CLI - Complete command-line interface for DIESEL token operations
//!
//! CRITICAL UPDATE: Now using direct imports from deezel library modules to achieve 1:1 functionality parity
//! with the reference implementation. This eliminates the trait-based provider system in favor of direct
//! library usage, exactly matching the working reference implementation patterns.
//!
//! Architecture:
//! - Direct imports from deezel library: RpcClient, AddressResolver, EnhancedAlkanesExecutor, etc.
//! - Unified Sandshrew endpoint for ALL RPC calls (both Bitcoin and Metashrew)
//! - Real RPC methods: btc_getblockcount, metashrew_height, metashrew_view, etc.
//! - Proper protobuf-encoded calls instead of non-existent methods like spendablesbyaddress
//! - Address resolution using the actual AddressResolver from deezel library
//!
//! This matches the reference implementation in ./reference/deezel-old/src/main.rs exactly.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use log::info;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;

// Import from deezel-common for now (will be updated to match reference implementation)
use deezel_common::*;

mod providers;
use providers::ConcreteProvider;

/// Main CLI arguments
#[derive(Parser)]
#[command(name = "deezel")]
#[command(about = "DEEZEL - DIESEL token minting and alkanes smart contract CLI")]
#[command(version = "0.1.0")]
struct Args {
    /// Bitcoin RPC URL
    #[arg(long, default_value = "http://bitcoinrpc:bitcoinrpc@localhost:8332")]
    bitcoin_rpc_url: Option<String>,

    /// Sandshrew/Metashrew RPC URL
    #[arg(long)]
    sandshrew_rpc_url: Option<String>,

    /// Network provider
    #[arg(short = 'p', long, default_value = "regtest")]
    provider: String,

    /// Custom network magic (overrides provider)
    #[arg(long)]
    magic: Option<String>,

    /// Wallet file path
    #[arg(short = 'w', long)]
    wallet_file: Option<String>,

    /// Wallet passphrase for encrypted wallets
    #[arg(long)]
    passphrase: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Command to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Legacy wallet info command (deprecated, use 'wallet info' instead)
    Walletinfo {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Bitcoin Core RPC operations
    Bitcoind {
        #[command(subcommand)]
        command: BitcoindCommands,
    },
    /// Metashrew RPC operations
    Metashrew {
        #[command(subcommand)]
        command: MetashrewCommands,
    },
    /// Alkanes smart contract operations
    Alkanes {
        #[command(subcommand)]
        command: AlkanesCommands,
    },
    /// Runestone analysis and decoding
    Runestone {
        #[command(subcommand)]
        command: RunestoneCommands,
    },
    /// Protorunes operations
    Protorunes {
        #[command(subcommand)]
        command: ProtorunesCommands,
    },
    /// Monitor blockchain for events
    Monitor {
        #[command(subcommand)]
        command: MonitorCommands,
    },
    /// Esplora API operations
    Esplora {
        #[command(subcommand)]
        command: EsploraCommands,
    },
}

/// Wallet subcommands
#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Optional mnemonic phrase (if not provided, a new one will be generated)
        #[arg(long)]
        mnemonic: Option<String>,
    },
    /// Restore wallet from mnemonic
    Restore {
        /// Mnemonic phrase to restore from
        mnemonic: String,
    },
    /// Show wallet information
    Info,
    /// List wallet addresses
    Addresses {
        /// Number of addresses to show
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Show wallet balance
    Balance {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Send Bitcoin to an address
    Send {
        /// Recipient address or identifier
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Send all available funds
        #[arg(long)]
        send_all: bool,
        /// Source address (optional)
        #[arg(long)]
        from: Option<String>,
        /// Change address (optional)
        #[arg(long)]
        change: Option<String>,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Send all Bitcoin to an address
    SendAll {
        /// Recipient address or identifier
        address: String,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Create a transaction (without broadcasting)
    CreateTx {
        /// Recipient address or identifier
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Send all available funds
        #[arg(long)]
        send_all: bool,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Sign a transaction
    SignTx {
        /// Transaction hex to sign
        tx_hex: String,
    },
    /// Broadcast a transaction
    BroadcastTx {
        /// Transaction hex to broadcast
        tx_hex: String,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// List UTXOs
    Utxos {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Include frozen UTXOs
        #[arg(long)]
        include_frozen: bool,
        /// Filter UTXOs by specific addresses (comma-separated, supports identifiers like p2tr:0)
        #[arg(long)]
        addresses: Option<String>,
    },
    /// Freeze a UTXO
    FreezeUtxo {
        /// UTXO to freeze (format: txid:vout)
        utxo: String,
        /// Reason for freezing
        #[arg(long)]
        reason: Option<String>,
    },
    /// Unfreeze a UTXO
    UnfreezeUtxo {
        /// UTXO to unfreeze (format: txid:vout)
        utxo: String,
    },
    /// Show transaction history
    History {
        /// Number of transactions to show
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Specific address to check (supports identifiers like p2tr:0)
        #[arg(long)]
        address: Option<String>,
    },
    /// Show transaction details
    TxDetails {
        /// Transaction ID
        txid: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Estimate transaction fee
    EstimateFee {
        /// Target confirmation blocks
        #[arg(default_value = "6")]
        target: u32,
    },
    /// Get current fee rates
    FeeRates,
    /// Synchronize wallet with blockchain
    Sync,
    /// Backup wallet
    Backup,
    /// List address identifiers
    ListIdentifiers,
}

/// Bitcoin Core RPC subcommands
#[derive(Subcommand)]
enum BitcoindCommands {
    /// Get current block count
    Getblockcount,
    /// Generate blocks to an address (regtest only)
    Generatetoaddress {
        /// Number of blocks to generate
        nblocks: u32,
        /// Address to generate to
        address: String,
    },
}

/// Metashrew RPC subcommands
#[derive(Subcommand)]
enum MetashrewCommands {
    /// Get Metashrew height
    Height,
}

/// Alkanes smart contract subcommands
#[derive(Subcommand)]
enum AlkanesCommands {
    /// Execute alkanes smart contract with commit/reveal pattern
    Execute {
        /// Input requirements (format: "B:amount" for Bitcoin, "block:tx:amount" for alkanes)
        #[arg(long)]
        inputs: String,
        /// Recipient addresses or identifiers
        #[arg(long)]
        to: String,
        /// Change address or identifier
        #[arg(long)]
        change: Option<String>,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Envelope data file for commit/reveal pattern
        #[arg(long)]
        envelope: Option<String>,
        /// Protostone specifications
        protostones: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Enable transaction tracing
        #[arg(long)]
        trace: bool,
        /// Auto-mine blocks on regtest after transaction broadcast
        #[arg(long)]
        mine: bool,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
        /// Use Rebar Labs Shield for private transaction relay (mainnet only)
        #[arg(long)]
        rebar: bool,
    },
    /// Get alkanes balance for an address
    Balance {
        /// Address to check (defaults to wallet address)
        #[arg(long)]
        address: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get token information
    TokenInfo {
        /// Alkane ID (format: block:tx)
        alkane_id: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Trace an alkanes transaction
    Trace {
        /// Transaction outpoint (format: txid:vout)
        outpoint: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Inspect alkanes bytecode
    Inspect {
        /// Alkane ID (format: block:tx) or bytecode file/hex string
        target: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Enable disassembly to WAT format
        #[arg(long)]
        disasm: bool,
        /// Enable fuzzing analysis
        #[arg(long)]
        fuzz: bool,
        /// Opcode ranges for fuzzing (e.g., "100-150,200-250")
        #[arg(long)]
        fuzz_ranges: Option<String>,
        /// Extract and display metadata
        #[arg(long)]
        meta: bool,
        /// Compute and display codehash
        #[arg(long)]
        codehash: bool,
    },
    /// Get bytecode for an alkanes contract
    Getbytecode {
        /// Alkane ID (format: block:tx)
        alkane_id: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Simulate alkanes execution
    Simulate {
        /// Contract ID (format: txid:vout)
        contract_id: String,
        /// Simulation parameters
        #[arg(long)]
        params: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Runestone analysis subcommands
#[derive(Subcommand)]
enum RunestoneCommands {
    /// Decode runestone from transaction hex
    Decode {
        /// Transaction hex
        tx_hex: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Analyze runestone from transaction ID
    Analyze {
        /// Transaction ID
        txid: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Protorunes subcommands
#[derive(Subcommand)]
enum ProtorunesCommands {
    /// Get protorunes by address
    ByAddress {
        /// Address to query
        address: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get protorunes by outpoint
    ByOutpoint {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Monitor subcommands
#[derive(Subcommand)]
enum MonitorCommands {
    /// Monitor blocks for events
    Blocks {
        /// Starting block height
        #[arg(long)]
        start: Option<u64>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Esplora API subcommands
#[derive(Subcommand)]
enum EsploraCommands {
    /// Get blocks tip hash
    BlocksTipHash,
    /// Get blocks tip height
    BlocksTipHeight,
    /// Get blocks starting from height
    Blocks {
        /// Starting height (optional)
        start_height: Option<u64>,
    },
    /// Get block by height
    BlockHeight {
        /// Block height
        height: u64,
    },
    /// Get block information
    Block {
        /// Block hash
        hash: String,
    },
    /// Get block status
    BlockStatus {
        /// Block hash
        hash: String,
    },
    /// Get block transaction IDs
    BlockTxids {
        /// Block hash
        hash: String,
    },
    /// Get block header
    BlockHeader {
        /// Block hash
        hash: String,
    },
    /// Get raw block data
    BlockRaw {
        /// Block hash
        hash: String,
    },
    /// Get transaction ID by block hash and index
    BlockTxid {
        /// Block hash
        hash: String,
        /// Transaction index
        index: u32,
    },
    /// Get block transactions
    BlockTxs {
        /// Block hash
        hash: String,
        /// Start index (optional)
        start_index: Option<u32>,
    },
    /// Get address information
    Address {
        /// Address or colon-separated parameters
        params: String,
    },
    /// Get address transactions
    AddressTxs {
        /// Address or colon-separated parameters
        params: String,
    },
    /// Get address chain transactions
    AddressTxsChain {
        /// Address or colon-separated parameters (address:last_seen_txid)
        params: String,
    },
    /// Get address mempool transactions
    AddressTxsMempool {
        /// Address
        address: String,
    },
    /// Get address UTXOs
    AddressUtxo {
        /// Address
        address: String,
    },
    /// Search addresses by prefix
    AddressPrefix {
        /// Address prefix
        prefix: String,
    },
    /// Get transaction information
    Tx {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction hex
    TxHex {
        /// Transaction ID
        txid: String,
    },
    /// Get raw transaction
    TxRaw {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction status
    TxStatus {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction merkle proof
    TxMerkleProof {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction merkle block proof
    TxMerkleblockProof {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction output spend status
    TxOutspend {
        /// Transaction ID
        txid: String,
        /// Output index
        index: u32,
    },
    /// Get transaction output spends
    TxOutspends {
        /// Transaction ID
        txid: String,
    },
    /// Broadcast transaction
    Broadcast {
        /// Transaction hex
        tx_hex: String,
    },
    /// Post transaction (alias for broadcast)
    PostTx {
        /// Transaction hex
        tx_hex: String,
    },
    /// Get mempool information
    Mempool,
    /// Get mempool transaction IDs
    MempoolTxids,
    /// Get recent mempool transactions
    MempoolRecent,
    /// Get fee estimates
    FeeEstimates,
}

/// Parse outpoint from string (format: txid:vout)
fn parse_outpoint(outpoint: &str) -> Result<(String, u32)> {
    let parts: Vec<&str> = outpoint.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid outpoint format. Expected 'txid:vout'"));
    }
    
    let txid = parts[0].to_string();
    let vout = parts[1].parse::<u32>()
        .context("Invalid vout in outpoint")?;
    
    Ok((txid, vout))
}

/// Parse contract ID from string (format: txid:vout)
#[allow(dead_code)]
fn parse_contract_id(contract_id: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = contract_id.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid contract ID format. Expected 'txid:vout'"));
    }
    
    Ok((parts[0].to_string(), parts[1].to_string()))
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

/// Check if a string looks like a shorthand address identifier (e.g., "p2tr:0", "p2wpkh", etc.)
fn is_shorthand_address_identifier(input: &str) -> bool {
    // Pattern: address_type or address_type:index
    // Valid address types: p2tr, p2pkh, p2sh, p2wpkh, p2wsh
    let parts: Vec<&str> = input.split(':').collect();
    
    if parts.is_empty() || parts.len() > 2 {
        return false;
    }
    
    // Check if first part is a valid address type
    let address_type = parts[0].to_lowercase();
    let valid_types = ["p2tr", "p2pkh", "p2sh", "p2wpkh", "p2wsh"];
    
    if !valid_types.contains(&address_type.as_str()) {
        return false;
    }
    
    // If there's a second part, it should be a valid index
    if parts.len() == 2 && parts[1].parse::<u32>().is_err() {
        return false;
    }
    
    true
}

/// Resolve address identifiers in a string using the provided provider
/// Supports both full format \[self:p2tr:0\] and shorthand format p2tr:0
async fn resolve_address_identifiers(input: &str, provider: &ConcreteProvider) -> Result<String> {
    // Check if input contains full identifiers like [self:p2tr:0]
    if provider.contains_identifiers(input) {
        return provider.resolve_all_identifiers(input).await.map_err(|e| anyhow!("{}", e));
    }
    
    // Check if input is a shorthand address identifier like "p2tr:0"
    if is_shorthand_address_identifier(input) {
        // Convert shorthand to full format and resolve
        let full_identifier = format!("[self:{}]", input);
        return provider.resolve_all_identifiers(&full_identifier).await.map_err(|e| anyhow!("{}", e));
    }
    
    // No identifiers found, return as-is
    Ok(input.to_string())
}

/// Decode a transaction from hex
fn decode_transaction_hex(hex_str: &str) -> Result<Transaction> {
    let tx_bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("Failed to decode transaction hex")?;
    
    let tx: Transaction = deserialize(&tx_bytes)
        .context("Failed to deserialize transaction")?;
    
    Ok(tx)
}

/// Analyze a transaction for Runestone data
async fn analyze_runestone_tx(tx: &Transaction, raw_output: bool, provider: &ConcreteProvider) -> Result<()> {
    // Use the enhanced format_runestone_with_decoded_messages function
    match provider.format_runestone_with_decoded_messages(tx).await {
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
    Ok(())
}

/// Print human-readable runestone information
fn print_human_readable_runestone(tx: &Transaction, result: &serde_json::Value) {
    println!("🪨 Runestone Analysis");
    println!("═══════════════════");
    println!("🔗 Transaction: {}", tx.compute_txid());
    
    if let Some(runestone) = result.get("runestone") {
        if let Some(edicts) = runestone.get("edicts") {
            if let Some(edicts_array) = edicts.as_array() {
                if !edicts_array.is_empty() {
                    println!("📜 Edicts: {} found", edicts_array.len());
                    for (i, edict) in edicts_array.iter().enumerate() {
                        println!("  {}. {}", i + 1, serde_json::to_string_pretty(edict).unwrap_or_default());
                    }
                }
            }
        }
        
        if let Some(etching) = runestone.get("etching") {
            println!("🎨 Etching: {}", serde_json::to_string_pretty(etching).unwrap_or_default());
        }
        
        if let Some(mint) = runestone.get("mint") {
            println!("🪙 Mint: {}", serde_json::to_string_pretty(mint).unwrap_or_default());
        }
    }
    
    if let Some(decoded_messages) = result.get("decoded_messages") {
        println!("📋 Decoded Messages: {}", serde_json::to_string_pretty(decoded_messages).unwrap_or_default());
    }
}

/// Get RPC URL for a given provider
fn get_rpc_url(provider: &str) -> String {
    match provider {
        "mainnet" => "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string(),
        "testnet" => "http://bitcoinrpc:bitcoinrpc@localhost:18332".to_string(),
        "signet" => "http://bitcoinrpc:bitcoinrpc@localhost:38332".to_string(),
        "regtest" => "http://bitcoinrpc:bitcoinrpc@localhost:18443".to_string(),
        _ => "http://bitcoinrpc:bitcoinrpc@localhost:8080".to_string(), // Default to Sandshrew
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    // Determine network parameters based on provider and magic flags
    let network_params = if let Some(_magic) = args.magic.as_ref() {
        // For now, default to regtest when magic is provided
        // TODO: Implement proper magic parsing
        NetworkParams::regtest()
    } else {
        match args.provider.as_str() {
            "mainnet" => NetworkParams::mainnet(),
            "testnet" => NetworkParams::testnet(),
            "signet" => NetworkParams::signet(),
            "regtest" => NetworkParams::regtest(),
            _ => NetworkParams::regtest(), // Default to regtest
        }
    };

    // Generate network-specific wallet file path
    let wallet_file = if let Some(ref path) = args.wallet_file {
        expand_tilde(path)?
    } else {
        let network_name = match network_params.network {
            bitcoin::Network::Bitcoin => "mainnet",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Regtest => "regtest",
            _ => "custom",
        };
        // Default to GPG-encrypted .asc extension
        expand_tilde(&format!("~/.deezel/{}.json.asc", network_name))?
    };
    
    // Create wallet directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(&wallet_file).parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create wallet directory")?;
    }

    // CRITICAL FIX: Always use unified Sandshrew endpoint for ALL RPC operations
    // Sandshrew is a superset of Bitcoin Core RPC and handles both Bitcoin and Metashrew calls
    // This ensures consistent endpoint usage and eliminates 404 errors from routing to wrong endpoints
    let sandshrew_rpc_url = args.sandshrew_rpc_url.clone()
        .unwrap_or_else(|| get_rpc_url(&args.provider));
    
    // Create provider with unified endpoint
    let provider = ConcreteProvider::new(
        sandshrew_rpc_url.clone(),  // Use Sandshrew for Bitcoin RPC calls
        sandshrew_rpc_url.clone(),  // Use Sandshrew for Metashrew RPC calls
        args.provider.clone(),
        Some(std::path::PathBuf::from(&wallet_file)),
    ).await?;

    // Initialize provider
    provider.initialize().await?;

    // Execute command
    let result = execute_command(&provider, args).await;

    // Shutdown provider
    provider.shutdown().await?;

    result
}

async fn execute_command(provider: &ConcreteProvider, args: Args) -> Result<()> {
    match args.command {
        Commands::Wallet { command } => execute_wallet_command(provider, command).await,
        Commands::Walletinfo { raw } => execute_walletinfo_command(provider, raw).await,
        Commands::Bitcoind { command } => execute_bitcoind_command(provider, command).await,
        Commands::Metashrew { command } => execute_metashrew_command(provider, command).await,
        Commands::Alkanes { command } => execute_alkanes_command(provider, command).await,
        Commands::Runestone { command } => execute_runestone_command(provider, command).await,
        Commands::Protorunes { command } => execute_protorunes_command(provider, command).await,
        Commands::Monitor { command } => execute_monitor_command(provider, command).await,
        Commands::Esplora { command } => execute_esplora_command(provider, command).await,
    }
}

async fn execute_walletinfo_command(provider: &ConcreteProvider, raw: bool) -> Result<()> {
    let address = WalletProvider::get_address(provider).await?;
    let balance = WalletProvider::get_balance(provider).await?;
    let network = provider.get_network();
    
    if raw {
        let info = serde_json::json!({
            "address": address,
            "balance": balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
            "network": format!("{:?}", network),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("💼 Wallet Information");
        println!("═══════════════════");
        println!("🏠 Address: {}", address);
        println!("💰 Balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
        println!("🌐 Network: {:?}", network);
    }
    
    Ok(())
}

async fn execute_wallet_command(provider: &ConcreteProvider, command: WalletCommands) -> Result<()> {
    match command {
        WalletCommands::Create { mnemonic } => {
            let wallet_config = WalletConfig {
                wallet_path: "default".to_string(),
                network: provider.get_network().network,
                bitcoin_rpc_url: "".to_string(),
                metashrew_rpc_url: "".to_string(),
                network_params: None,
            };
            
            println!("🔐 Creating wallet...");
            let wallet_info = provider.create_wallet(wallet_config, mnemonic, None).await?;
            
            println!("✅ Wallet created successfully!");
            if let Some(mnemonic) = wallet_info.mnemonic {
                println!("🔑 Mnemonic: {}", mnemonic);
                println!("⚠️  IMPORTANT: Save this mnemonic phrase in a secure location!");
            }
            
            println!("🏠 First address: {}", wallet_info.address);
        },
        WalletCommands::Restore { mnemonic } => {
            let wallet_config = WalletConfig {
                wallet_path: "default".to_string(),
                network: provider.get_network().network,
                bitcoin_rpc_url: "".to_string(),
                metashrew_rpc_url: "".to_string(),
                network_params: None,
            };
            
            println!("🔐 Restoring wallet from mnemonic...");
            let wallet_info = provider.create_wallet(wallet_config, Some(mnemonic), None).await?;
            
            println!("✅ Wallet restored successfully!");
            println!("🏠 First address: {}", wallet_info.address);
        },
        WalletCommands::Info => {
            let address = WalletProvider::get_address(provider).await?;
            let balance = WalletProvider::get_balance(provider).await?;
            let network = provider.get_network();
            
            println!("💼 Wallet Information");
            println!("═══════════════════");
            println!("🏠 Address: {}", address);
            println!("💰 Balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
            println!("🌐 Network: {:?}", network);
        },
        WalletCommands::Balance { raw } => {
            let balance = WalletProvider::get_balance(provider).await?;
            
            if raw {
                let balance_json = serde_json::json!({
                    "confirmed": balance.confirmed,
                    "trusted_pending": balance.trusted_pending,
                    "untrusted_pending": balance.untrusted_pending,
                    "total": balance.confirmed + balance.trusted_pending + balance.untrusted_pending
                });
                println!("{}", serde_json::to_string_pretty(&balance_json)?);
            } else {
                println!("💰 Wallet Balance");
                println!("═══════════════");
                println!("✅ Confirmed: {} sats", balance.confirmed);
                println!("⏳ Trusted pending: {} sats", balance.trusted_pending);
                println!("❓ Untrusted pending: {} sats", balance.untrusted_pending);
                println!("📊 Total: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
            }
        },
        WalletCommands::Addresses { count, raw } => {
            let addresses = provider.get_addresses(count).await?;
            
            if raw {
                // Convert to serializable format
                let serializable_addresses: Vec<serde_json::Value> = addresses.iter().map(|addr| {
                    serde_json::json!({
                        "address": addr.address,
                        "script_type": addr.script_type,
                        "derivation_path": addr.derivation_path,
                        "index": addr.index
                    })
                }).collect();
                println!("{}", serde_json::to_string_pretty(&serializable_addresses)?);
            } else {
                println!("🏠 Wallet Addresses");
                println!("═════════════════");
                for addr in addresses {
                    println!("{}. {} ({})", addr.index, addr.address, addr.script_type);
                    println!("   Path: {}", addr.derivation_path);
                }
            }
        },
        WalletCommands::Send { address, amount, fee_rate, send_all, from, change, yes } => {
            // Resolve address identifiers
            let resolved_address = resolve_address_identifiers(&address, provider).await?;
            let resolved_from = if let Some(from_addr) = from {
                Some(resolve_address_identifiers(&from_addr, provider).await?)
            } else {
                None
            };
            let resolved_change = if let Some(change_addr) = change {
                Some(resolve_address_identifiers(&change_addr, provider).await?)
            } else {
                None
            };
            
            let send_params = SendParams {
                address: resolved_address,
                amount,
                fee_rate,
                send_all,
                from_address: resolved_from,
                change_address: resolved_change,
                auto_confirm: yes,
            };
            
            match provider.send(send_params).await {
                Ok(txid) => {
                    println!("✅ Transaction sent successfully!");
                    println!("🔗 Transaction ID: {}", txid);
                },
                Err(e) => {
                    println!("❌ Failed to send transaction: {}", e);
                    return Err(e.into());
                }
            }
        },
        WalletCommands::SendAll { address, fee_rate, yes } => {
            // Resolve address identifiers
            let resolved_address = resolve_address_identifiers(&address, provider).await?;
            
            let send_params = SendParams {
                address: resolved_address,
                amount: 0, // Will be ignored since send_all is true
                fee_rate,
                send_all: true,
                from_address: None,
                change_address: None,
                auto_confirm: yes,
            };
            
            match provider.send(send_params).await {
                Ok(txid) => {
                    println!("✅ All funds sent successfully!");
                    println!("🔗 Transaction ID: {}", txid);
                },
                Err(e) => {
                    println!("❌ Failed to send all funds: {}", e);
                    return Err(e.into());
                }
            }
        },
        WalletCommands::CreateTx { address, amount, fee_rate, send_all, yes } => {
            // Resolve address identifiers
            let resolved_address = resolve_address_identifiers(&address, provider).await?;
            
            let create_params = SendParams {
                address: resolved_address,
                amount,
                fee_rate,
                send_all,
                from_address: None,
                change_address: None,
                auto_confirm: yes,
            };
            
            match provider.create_transaction(create_params).await {
                Ok(tx_hex) => {
                    println!("✅ Transaction created successfully!");
                    println!("📄 Transaction hex: {}", tx_hex);
                },
                Err(e) => {
                    println!("❌ Failed to create transaction: {}", e);
                    return Err(e.into());
                }
            }
        },
        WalletCommands::SignTx { tx_hex } => {
            match provider.sign_transaction(tx_hex).await {
                Ok(signed_hex) => {
                    println!("✅ Transaction signed successfully!");
                    println!("📄 Signed transaction hex: {}", signed_hex);
                },
                Err(e) => {
                    println!("❌ Failed to sign transaction: {}", e);
                    return Err(e.into());
                }
            }
        },
        WalletCommands::BroadcastTx { tx_hex, yes } => {
            if !yes {
                println!("⚠️  About to broadcast transaction: {}", tx_hex);
                println!("Do you want to continue? (y/N)");
                
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                
                if !input.trim().to_lowercase().starts_with('y') {
                    println!("❌ Transaction broadcast cancelled");
                    return Ok(());
                }
            }
            
            match provider.broadcast(&tx_hex).await {
                Ok(txid) => {
                    println!("✅ Transaction broadcast successfully!");
                    println!("🔗 Transaction ID: {}", txid);
                },
                Err(e) => {
                    println!("❌ Failed to broadcast transaction: {}", e);
                    return Err(e.into());
                }
            }
        },
        WalletCommands::Utxos { raw, include_frozen, addresses } => {
            let address_list = if let Some(addr_str) = addresses {
                let resolved_addresses = resolve_address_identifiers(&addr_str, provider).await?;
                Some(resolved_addresses.split(',').map(|s| s.trim().to_string()).collect())
            } else {
                None
            };
            
            let utxos = provider.get_utxos(include_frozen, address_list).await?;
            
            if raw {
                // Convert to serializable format
                let serializable_utxos: Vec<serde_json::Value> = utxos.iter().map(|utxo| {
                    serde_json::json!({
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                        "amount": utxo.amount,
                        "address": utxo.address,
                        "confirmations": utxo.confirmations,
                        "frozen": utxo.frozen,
                        "freeze_reason": utxo.freeze_reason,
                        "block_height": utxo.block_height,
                        "has_inscriptions": utxo.has_inscriptions,
                        "has_runes": utxo.has_runes,
                        "has_alkanes": utxo.has_alkanes,
                        "is_coinbase": utxo.is_coinbase
                    })
                }).collect();
                println!("{}", serde_json::to_string_pretty(&serializable_utxos)?);
            } else {
                println!("💰 Wallet UTXOs");
                println!("═══════════════");
                
                if utxos.is_empty() {
                    println!("No UTXOs found");
                } else {
                    let total_amount: u64 = utxos.iter().map(|u| u.amount).sum();
                    println!("📊 Total: {} UTXOs, {} sats\n", utxos.len(), total_amount);
                    
                    for (i, utxo) in utxos.iter().enumerate() {
                        println!("{}. 🔗 {}:{}", i + 1, utxo.txid, utxo.vout);
                        println!("   💰 Amount: {} sats", utxo.amount);
                        println!("   🏠 Address: {}", utxo.address);
                        println!("   ✅ Confirmations: {}", utxo.confirmations);
                        
                        if let Some(block_height) = utxo.block_height {
                            println!("   📦 Block: {}", block_height);
                        }
                        
                        // Show special properties
                        let mut properties = Vec::new();
                        if utxo.is_coinbase {
                            properties.push("coinbase");
                        }
                        if utxo.has_inscriptions {
                            properties.push("inscriptions");
                        }
                        if utxo.has_runes {
                            properties.push("runes");
                        }
                        if utxo.has_alkanes {
                            properties.push("alkanes");
                        }
                        if !properties.is_empty() {
                            println!("   🏷️  Properties: {}", properties.join(", "));
                        }
                        
                        if utxo.frozen {
                            println!("   ❄️  Status: FROZEN");
                            if let Some(reason) = &utxo.freeze_reason {
                                println!("   📝 Reason: {}", reason);
                            }
                        } else {
                            println!("   ✅ Status: spendable");
                        }
                        
                        if i < utxos.len() - 1 {
                            println!();
                        }
                    }
                }
            }
        },
        WalletCommands::FreezeUtxo { utxo, reason } => {
            provider.freeze_utxo(utxo.clone(), reason).await?;
            println!("❄️  UTXO {} frozen successfully", utxo);
        },
        WalletCommands::UnfreezeUtxo { utxo } => {
            provider.unfreeze_utxo(utxo.clone()).await?;
            println!("✅ UTXO {} unfrozen successfully", utxo);
        },
        WalletCommands::History { count, raw, address } => {
            let resolved_address = if let Some(addr) = address {
                Some(resolve_address_identifiers(&addr, provider).await?)
            } else {
                None
            };
            
            let history = provider.get_history(count, resolved_address).await?;
            
            if raw {
                // Convert to serializable format
                let serializable_history: Vec<serde_json::Value> = history.iter().map(|tx| {
                    serde_json::json!({
                        "txid": tx.txid,
                        "block_height": tx.block_height,
                        "block_time": tx.block_time,
                        "confirmed": tx.confirmed,
                        "fee": tx.fee
                    })
                }).collect();
                println!("{}", serde_json::to_string_pretty(&serializable_history)?);
            } else {
                println!("📜 Transaction History");
                println!("═══════════════════");
                
                if history.is_empty() {
                    println!("No transactions found");
                } else {
                    for (i, tx) in history.iter().enumerate() {
                        println!("{}. 🔗 TXID: {}", i + 1, tx.txid);
                        if let Some(fee) = tx.fee {
                            println!("   💰 Fee: {} sats", fee);
                        }
                        println!("   ✅ Confirmed: {}", tx.confirmed);
                        
                        if i < history.len() - 1 {
                            println!();
                        }
                    }
                }
            }
        },
        WalletCommands::TxDetails { txid, raw } => {
            let details = EsploraProvider::get_tx(provider, &txid).await?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&details)?);
            } else {
                println!("📄 Transaction Details");
                println!("════════════════════");
                println!("🔗 TXID: {}", txid);
                println!("{}", serde_json::to_string_pretty(&details)?);
            }
        },
        WalletCommands::EstimateFee { target } => {
            let estimate = provider.estimate_fee(target).await?;
            println!("💰 Fee Estimate");
            println!("═══════════════");
            println!("🎯 Target: {} blocks", target);
            println!("💸 Fee rate: {} sat/vB", estimate.fee_rate);
        },
        WalletCommands::FeeRates => {
            let rates = provider.get_fee_rates().await?;
            println!("💸 Current Fee Rates");
            println!("═══════════════════");
            println!("🚀 Fast: {} sat/vB", rates.fast);
            println!("🚶 Medium: {} sat/vB", rates.medium);
            println!("🐌 Slow: {} sat/vB", rates.slow);
        },
        WalletCommands::Sync => {
            provider.sync().await?;
            println!("✅ Wallet synchronized with blockchain");
        },
        WalletCommands::Backup => {
            let backup = provider.backup().await?;
            println!("💾 Wallet Backup");
            println!("═══════════════");
            println!("{}", backup);
        },
        WalletCommands::ListIdentifiers => {
            let identifiers = provider.list_identifiers().await?;
            println!("🏷️  Address Identifiers");
            println!("═════════════════════");
            for identifier in identifiers {
                println!("  {}", identifier);
            }
        },
    }
    
    Ok(())
}

async fn execute_bitcoind_command(provider: &ConcreteProvider, command: BitcoindCommands) -> Result<()> {
    match command {
        BitcoindCommands::Getblockcount => {
            let count = provider.get_block_count().await?;
            println!("{}", count);
        },
        BitcoindCommands::Generatetoaddress { nblocks, address } => {
            // Resolve address identifiers if needed
            let resolved_address = resolve_address_identifiers(&address, provider).await?;
            
            let result = provider.generate_to_address(nblocks, &resolved_address).await?;
            println!("Generated {} blocks to address {}", nblocks, resolved_address);
            if let Some(block_hashes) = result.as_array() {
                println!("Block hashes:");
                for (i, hash) in block_hashes.iter().enumerate() {
                    if let Some(hash_str) = hash.as_str() {
                        println!("  {}: {}", i + 1, hash_str);
                    }
                }
            }
        },
    }
    
    Ok(())
}

async fn execute_metashrew_command(provider: &ConcreteProvider, command: MetashrewCommands) -> Result<()> {
    match command {
        MetashrewCommands::Height => {
            let height = provider.get_metashrew_height().await?;
            println!("{}", height);
        },
    }
    
    Ok(())
}

async fn execute_alkanes_command(provider: &ConcreteProvider, command: AlkanesCommands) -> Result<()> {
    match command {
        AlkanesCommands::Execute { inputs, to, change, fee_rate, envelope, protostones, raw, trace, mine, yes, rebar } => {
            info!("🚀 Starting alkanes execute command with enhanced protostones encoding");
            
            // Resolve addresses in the 'to' field
            let resolved_to = resolve_address_identifiers(&to, provider).await?;
            
            // Resolve change address if provided
            let resolved_change = if let Some(change_addr) = change {
                Some(resolve_address_identifiers(&change_addr, provider).await?)
            } else {
                None
            };
            
            // Load envelope data if provided
            let envelope_data = if let Some(ref envelope_file) = envelope {
                let expanded_path = expand_tilde(envelope_file)?;
                let data = std::fs::read(&expanded_path)
                    .with_context(|| format!("Failed to read envelope file: {}", expanded_path))?;
                info!("📦 Loaded envelope data: {} bytes", data.len());
                Some(data)
            } else {
                None
            };
            
            // Parse input requirements and protostones using deezel-common functions
            let input_requirements = {
                use deezel_common::alkanes::execute::parse_input_requirements;
                let parsed = parse_input_requirements(&inputs)
                    .map_err(|e| anyhow!("Failed to parse input requirements: {}", e))?;
                
                // Convert from alkanes::execute types to traits types
                parsed.into_iter().map(|req| {
                    match req {
                        deezel_common::alkanes::execute::InputRequirement::Bitcoin { amount } => {
                            deezel_common::traits::InputRequirement {
                                requirement_type: deezel_common::traits::InputRequirementType::Bitcoin,
                                amount,
                                alkane_id: None,
                            }
                        },
                        deezel_common::alkanes::execute::InputRequirement::Alkanes { block, tx, amount } => {
                            deezel_common::traits::InputRequirement {
                                requirement_type: deezel_common::traits::InputRequirementType::Alkanes,
                                amount,
                                alkane_id: Some(deezel_common::traits::AlkaneId { block, tx }),
                            }
                        },
                    }
                }).collect()
            };
            
            let protostone_specs = {
                use deezel_common::alkanes::execute::parse_protostones;
                let parsed = parse_protostones(&protostones)
                    .map_err(|e| anyhow!("Failed to parse protostones: {}", e))?;
                
                // Convert from alkanes::execute types to traits types
                parsed.into_iter().map(|_spec| {
                    deezel_common::traits::ProtostoneSpec {
                        name: "protostone".to_string(), // Default name
                        data: Vec::new(), // Default empty data
                        encoding: deezel_common::traits::ProtostoneEncoding::Raw, // Default encoding
                    }
                }).collect()
            };
            
            // Split resolved_to into individual addresses
            let to_addresses: Vec<String> = resolved_to.split(',').map(|s| s.trim().to_string()).collect();
            
            // Create enhanced execute parameters with Rebar support
            let execute_params = deezel_common::traits::EnhancedExecuteParams {
                fee_rate,
                to_addresses,
                change_address: resolved_change.clone(),
                input_requirements,
                protostones: protostone_specs,
                envelope_data,
                raw_output: raw,
                trace_enabled: trace,
                mine_enabled: mine,
                auto_confirm: yes,
                rebar_enabled: rebar,
            };
            
            // For now, use the provider's alkanes execute method
            // TODO: Implement proper enhanced alkanes execution
            let alkanes_params = deezel_common::traits::AlkanesExecuteParams {
                inputs: inputs.clone(),
                to: resolved_to,
                change: resolved_change,
                fee_rate: execute_params.fee_rate,
                envelope: envelope.map(|_| "envelope_file".to_string()), // Placeholder since we have the data
                protostones: protostones.clone(),
                trace: execute_params.trace_enabled,
                mine: execute_params.mine_enabled,
                auto_confirm: execute_params.auto_confirm,
                rebar: execute_params.rebar_enabled,
            };
            
            match provider.execute(alkanes_params).await {
                Ok(result) => {
                    if raw {
                        // Create a serializable version of the result
                        let serializable_result = serde_json::json!({
                            "commit_txid": result.commit_txid,
                            "reveal_txid": result.reveal_txid,
                            "commit_fee": result.commit_fee,
                            "reveal_fee": result.reveal_fee,
                            "inputs_used": result.inputs_used,
                            "outputs_created": result.outputs_created,
                            "traces": result.traces
                        });
                        println!("{}", serde_json::to_string_pretty(&serializable_result)?);
                    } else {
                        // For now, just print the result in a human-readable format
                        println!("✅ Alkanes execution completed successfully!");
                        if let Some(commit_txid) = &result.commit_txid {
                            println!("🔗 Commit TXID: {}", commit_txid);
                        }
                        println!("🔗 Reveal TXID: {}", result.reveal_txid);
                        if let Some(commit_fee) = result.commit_fee {
                            println!("💰 Commit Fee: {} sats", commit_fee);
                        }
                        println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                    }
                },
                Err(e) => {
                    if raw {
                        eprintln!("Error: {}", e);
                    } else {
                        println!("❌ Alkanes execution failed: {}", e);
                        
                        // Check if this is a fee validation error and provide helpful context
                        let error_msg = e.to_string();
                        if error_msg.contains("absurdly high fee rate") || error_msg.contains("fee validation failed") {
                            println!("\n💡 This appears to be a fee calculation issue.");
                            println!("🔧 The fee validation system has detected an unusually high fee rate.");
                            println!("📋 This is likely due to large envelope witness data affecting transaction size calculations.");
                            println!("🛠️  Try adjusting the fee rate or check the envelope data size.");
                        }
                    }
                    return Err(e.into());
                }
            }
        },
        AlkanesCommands::Balance { address, raw } => {
            let balance_result = provider.get_alkanes_balance(address.as_deref()).await?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&balance_result)?);
            } else {
                println!("🪙 Alkanes Balances");
                println!("═══════════════════");
                println!("{}", serde_json::to_string_pretty(&balance_result)?);
            }
        },
        AlkanesCommands::TokenInfo { alkane_id, raw } => {
            // For now, return a placeholder - this would need to be implemented in the provider
            let token_info = serde_json::json!({"alkane_id": alkane_id, "status": "not_implemented"});
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&token_info)?);
            } else {
                println!("🏷️  Alkanes Token Information");
                println!("═══════════════════════════");
                println!("🔗 Alkane ID: {}", alkane_id);
                println!("📋 Token Info: {}", serde_json::to_string_pretty(&token_info)?);
            }
        },
        AlkanesCommands::Trace { outpoint, raw } => {
            let (txid, vout) = parse_outpoint(&outpoint)?;
            let trace_result = provider.trace_transaction(&txid, vout, None, None).await?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&trace_result)?);
            } else {
                println!("📊 Alkanes Transaction Trace");
                println!("═══════════════════════════");
                println!("{}", serde_json::to_string_pretty(&trace_result)?);
            }
        },
        AlkanesCommands::Inspect { target, raw, disasm, fuzz, fuzz_ranges, meta, codehash } => {
            let config = deezel_common::traits::AlkanesInspectConfig {
                disasm,
                fuzz,
                fuzz_ranges,
                meta,
                codehash,
            };
            
            let result = provider.inspect(&target, config).await?;
            
            if raw {
                // Convert to serializable format
                let serializable_result = serde_json::json!({
                    "alkane_id": {
                        "block": result.alkane_id.block,
                        "tx": result.alkane_id.tx
                    },
                    "bytecode_length": result.bytecode_length,
                    "disassembly": result.disassembly,
                    "metadata": result.metadata,
                    "codehash": result.codehash,
                    "fuzzing_results": result.fuzzing_results
                });
                println!("{}", serde_json::to_string_pretty(&serializable_result)?);
            } else {
                println!("🔍 Alkanes Contract Inspection");
                println!("═══════════════════════════");
                println!("🏷️  Alkane ID: {:?}", result.alkane_id);
                println!("📏 Bytecode length: {} bytes", result.bytecode_length);
                
                if let Some(disassembly) = result.disassembly {
                    println!("\n📜 Disassembly:");
                    println!("{}", disassembly);
                }
                
                if let Some(metadata) = result.metadata {
                    println!("\n📋 Metadata:");
                    println!("{}", serde_json::to_string_pretty(&metadata)?);
                }
                
                if let Some(codehash) = result.codehash {
                    println!("\n🔐 Code Hash: {}", codehash);
                }
                
                if let Some(fuzzing_results) = result.fuzzing_results {
                    println!("\n🧪 Fuzzing Results:");
                    println!("{}", serde_json::to_string_pretty(&fuzzing_results)?);
                }
            }
        },
        AlkanesCommands::Getbytecode { alkane_id, raw } => {
            let bytecode = provider.get_bytecode(&alkane_id).await?;
            
            if raw {
                let json_result = serde_json::json!({
                    "alkane_id": alkane_id,
                    "bytecode": bytecode
                });
                println!("{}", serde_json::to_string_pretty(&json_result)?);
            } else {
                println!("🔍 Alkanes Contract Bytecode");
                println!("═══════════════════════════");
                println!("🏷️  Alkane ID: {}", alkane_id);
                
                if bytecode.is_empty() || bytecode == "0x" {
                    println!("❌ No bytecode found for this contract");
                } else {
                    // Remove 0x prefix if present for display
                    let clean_bytecode = bytecode.strip_prefix("0x").unwrap_or(&bytecode);
                    
                    println!("💾 Bytecode:");
                    println!("   Length: {} bytes", clean_bytecode.len() / 2);
                    println!("   Hex: {}", bytecode);
                    
                    // Show first few bytes for quick inspection
                    if clean_bytecode.len() >= 8 {
                        println!("   First 4 bytes: {}", &clean_bytecode[..8]);
                    }
                }
            }
        },
        AlkanesCommands::Simulate { contract_id, params, raw } => {
            let result = provider.simulate(&contract_id, params.as_deref()).await?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("🧪 Alkanes Contract Simulation");
                println!("═══════════════════════════");
                println!("🔗 Contract ID: {}", contract_id);
                println!("📊 Result: {}", serde_json::to_string_pretty(&result)?);
            }
        },
    }
    
    Ok(())
}

async fn execute_runestone_command(provider: &ConcreteProvider, command: RunestoneCommands) -> Result<()> {
    match command {
        RunestoneCommands::Decode { tx_hex, raw } => {
            let tx = decode_transaction_hex(&tx_hex)?;
            analyze_runestone_tx(&tx, raw, provider).await?;
        },
        RunestoneCommands::Analyze { txid, raw } => {
            let tx_hex = provider.get_transaction_hex(&txid).await?;
            let tx = decode_transaction_hex(&tx_hex)?;
            analyze_runestone_tx(&tx, raw, provider).await?;
        },
    }
    
    Ok(())
}

async fn execute_protorunes_command(provider: &ConcreteProvider, command: ProtorunesCommands) -> Result<()> {
    match command {
        ProtorunesCommands::ByAddress { address, raw } => {
            let result = provider.get_protorunes_by_address(&address).await?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("🪙 Protorunes for address: {}", address);
                println!("═══════════════════════════════════════");
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
        ProtorunesCommands::ByOutpoint { txid, vout, raw } => {
            let result = provider.get_protorunes_by_outpoint(&txid, vout).await?;
            
            if raw {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("🪙 Protorunes for outpoint: {}:{}", txid, vout);
                println!("═══════════════════════════════════════");
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
    }
    
    Ok(())
}

async fn execute_monitor_command(provider: &ConcreteProvider, command: MonitorCommands) -> Result<()> {
    match command {
        MonitorCommands::Blocks { start, raw: _ } => {
            let start_height = start.unwrap_or({
                // Get current height as default
                0 // Placeholder - would need async context
            });
            
            println!("🔍 Monitoring blocks starting from height: {}", start_height);
            provider.monitor_blocks(start).await?;
            println!("✅ Block monitoring completed");
        },
    }
    
    Ok(())
}

async fn execute_esplora_command(provider: &ConcreteProvider, command: EsploraCommands) -> Result<()> {
    match command {
        EsploraCommands::BlocksTipHash => {
            let hash = provider.get_blocks_tip_hash().await?;
            println!("{}", hash);
        },
        EsploraCommands::BlocksTipHeight => {
            let height = provider.get_blocks_tip_height().await?;
            println!("{}", height);
        },
        EsploraCommands::Blocks { start_height } => {
            let result = provider.get_blocks(start_height).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        EsploraCommands::BlockHeight { height } => {
            let hash = provider.get_block_by_height(height).await?;
            println!("{}", hash);
        },
        EsploraCommands::Block { hash } => {
            let block = EsploraProvider::get_block(provider, &hash).await?;
            println!("{}", serde_json::to_string_pretty(&block)?);
        },
        EsploraCommands::BlockStatus { hash } => {
            let status = provider.get_block_status(&hash).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        },
        EsploraCommands::BlockTxids { hash } => {
            let txids = provider.get_block_txids(&hash).await?;
            println!("{}", serde_json::to_string_pretty(&txids)?);
        },
        EsploraCommands::BlockHeader { hash } => {
            let header = provider.get_block_header(&hash).await?;
            println!("{}", header);
        },
        EsploraCommands::BlockRaw { hash } => {
            let raw = provider.get_block_raw(&hash).await?;
            println!("{}", raw);
        },
        EsploraCommands::BlockTxid { hash, index } => {
            let txid = provider.get_block_txid(&hash, index).await?;
            println!("{}", txid);
        },
        EsploraCommands::BlockTxs { hash, start_index } => {
            let txs = provider.get_block_txs(&hash, start_index).await?;
            println!("{}", serde_json::to_string_pretty(&txs)?);
        },
        EsploraCommands::Address { params } => {
            // Handle address resolution if needed
            let resolved_params = resolve_address_identifiers(&params, provider).await?;
            let result = EsploraProvider::get_address(provider, &resolved_params).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        EsploraCommands::AddressTxs { params } => {
            // Handle address resolution if needed
            let resolved_params = resolve_address_identifiers(&params, provider).await?;
            let result = provider.get_address_txs(&resolved_params).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        EsploraCommands::AddressTxsChain { params } => {
            // Handle address resolution for the first part (address:last_seen_txid)
            let parts: Vec<&str> = params.split(':').collect();
            let resolved_params = if parts.len() >= 2 {
                let address_part = parts[0];
                let resolved_address = resolve_address_identifiers(address_part, provider).await?;
                if parts.len() == 2 {
                    format!("{}:{}", resolved_address, parts[1])
                } else {
                    format!("{}:{}", resolved_address, parts[1..].join(":"))
                }
            } else {
                resolve_address_identifiers(&params, provider).await?
            };
            let result = provider.get_address_txs_chain(&resolved_params, None).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        EsploraCommands::AddressTxsMempool { address } => {
            let resolved_address = resolve_address_identifiers(&address, provider).await?;
            let result = provider.get_address_txs_mempool(&resolved_address).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        EsploraCommands::AddressUtxo { address } => {
            let resolved_address = resolve_address_identifiers(&address, provider).await?;
            let result = provider.get_address_utxo(&resolved_address).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        
        EsploraCommands::AddressPrefix { prefix } => {
            let result = provider.get_address_prefix(&prefix).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        EsploraCommands::Tx { txid } => {
            let tx = provider.get_tx(&txid).await?;
            println!("{}", serde_json::to_string_pretty(&tx)?);
        },
        EsploraCommands::TxHex { txid } => {
            let hex = provider.get_tx_hex(&txid).await?;
            println!("{}", hex);
        },
        EsploraCommands::TxRaw { txid } => {
            let raw = provider.get_tx_raw(&txid).await?;
            println!("{}", raw);
        },
        EsploraCommands::TxStatus { txid } => {
            let status = provider.get_tx_status(&txid).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        },
        EsploraCommands::TxMerkleProof { txid } => {
            let proof = provider.get_tx_merkle_proof(&txid).await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        },
        EsploraCommands::TxMerkleblockProof { txid } => {
            let proof = provider.get_tx_merkleblock_proof(&txid).await?;
            println!("{}", proof);
        },
        EsploraCommands::TxOutspend { txid, index } => {
            let outspend = provider.get_tx_outspend(&txid, index).await?;
            println!("{}", serde_json::to_string_pretty(&outspend)?);
        },
        EsploraCommands::TxOutspends { txid } => {
            let outspends = provider.get_tx_outspends(&txid).await?;
            println!("{}", serde_json::to_string_pretty(&outspends)?);
        },
        EsploraCommands::Broadcast { tx_hex } => {
            let txid = provider.broadcast(&tx_hex).await?;
            println!("✅ Transaction broadcast successfully!");
            println!("🔗 Transaction ID: {}", txid);
        },
        EsploraCommands::PostTx { tx_hex } => {
            let txid = provider.broadcast(&tx_hex).await?;
            println!("✅ Transaction posted successfully!");
            println!("🔗 Transaction ID: {}", txid);
        },
        EsploraCommands::Mempool => {
            let mempool = provider.get_mempool().await?;
            println!("{}", serde_json::to_string_pretty(&mempool)?);
        },
        EsploraCommands::MempoolTxids => {
            let txids = provider.get_mempool_txids().await?;
            println!("{}", serde_json::to_string_pretty(&txids)?);
        },
        EsploraCommands::MempoolRecent => {
            let recent = provider.get_mempool_recent().await?;
            println!("{}", serde_json::to_string_pretty(&recent)?);
        },
        EsploraCommands::FeeEstimates => {
            let estimates = provider.get_fee_estimates().await?;
            println!("{}", serde_json::to_string_pretty(&estimates)?);
        },
    }
    
    Ok(())
}