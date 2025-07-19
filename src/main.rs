//! DEEZEL CLI - Complete command-line interface for DIESEL token operations
//!
//! This is the main binary for the deezel project, providing comprehensive
//! functionality for Bitcoin wallet operations, alkanes smart contracts,
//! runestone analysis, and blockchain monitoring.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use log::info;
use std::str::FromStr;
use std::sync::Arc;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use serde_json;

// Import all necessary modules from the deezel library
use deezel::{
    RpcClient, AddressResolver,
    runestone_enhanced::format_runestone_with_decoded_messages,
    alkanes::{
        execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams, parse_input_requirements, parse_protostones},
        AlkanesManager,
    },
};
use deezel::rpc::RpcConfig;
mod build_contracts;

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
    wallet_passphrase: Option<String>,

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
    /// Build contracts
    BuildContracts,
    /// Deploy contracts
    Deploy {
        #[command(subcommand)]
        command: DeployCommands,
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
        /// Wallet passphrase
        #[arg(long)]
        wallet_passphrase: Option<String>,
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

/// Deploy subcommands
#[derive(Subcommand)]
enum DeployCommands {
    /// Deploy an AMM contract
    Amm {
        /// Path to the wasm file to deploy
        #[arg(long, default_value = "out/amm.wasm")]
        wasm_file: String,
        #[arg(short = 'y', long)]
        yes: bool,
        /// Calldata for the deployment
        calldata: Vec<String>,
    },
    /// Deploy a Free Mint contract
    FreeMint {
        /// Path to the wasm file to deploy
        #[arg(long, default_value = "out/free_mint.wasm")]
        wasm_file: String,
        #[arg(short = 'y', long)]
        yes: bool,
        /// Calldata for the deployment
        calldata: Vec<String>,
    },
    /// Deploy a Vault Factory contract
    VaultFactory {
        /// Path to the wasm file to deploy
        #[arg(long, default_value = "out/vault_factory.wasm")]
        wasm_file: String,
        #[arg(short = 'y', long)]
        yes: bool,
        /// Calldata for the deployment
        calldata: Vec<String>,
    },
}

/// Block tag for monitoring
#[derive(Debug, Clone)]
enum BlockTag {
    Height(()),
    Latest,
}

impl FromStr for BlockTag {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "latest" => Ok(BlockTag::Latest),
            _ => {
                let _height = s.parse::<u64>()
                    .context("Invalid block height")?;
                Ok(BlockTag::Height(()))
            }
        }
    }
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
fn parse_contract_id(contract_id: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = contract_id.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid contract ID format. Expected 'txid:vout'"));
    }
    
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Parse simulation parameters
fn parse_simulation_params(_params: &str) -> Result<(String, String, Vec<String>)> {
    // Placeholder implementation
    Ok((
        "default_method".to_string(),
        "default_input".to_string(),
        vec!["default_arg".to_string()]
    ))
}

/// Parse address ranges for monitoring
fn _parse_address_ranges(ranges_str: &str) -> Result<Vec<(String, Vec<u32>)>> {
    let mut ranges = Vec::new();
    
    for range_str in ranges_str.split(',') {
        let parts: Vec<&str> = range_str.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid address range format. Expected 'address:start-end'"));
        }
        
        let address = parts[0].to_string();
        let range_parts: Vec<&str> = parts[1].split('-').collect();
        
        if range_parts.len() == 1 {
            // Single index
            let index = range_parts[0].parse::<u32>()
                .context("Invalid address index")?;
            ranges.push((address, vec![index]));
        } else if range_parts.len() == 2 {
            // Range
            let start = range_parts[0].parse::<u32>()
                .context("Invalid start index")?;
            let end = range_parts[1].parse::<u32>()
                .context("Invalid end index")?;
            let indices: Vec<u32> = (start..=end).collect();
            ranges.push((address, indices));
        } else {
            return Err(anyhow!("Invalid range format"));
        }
    }
    
    Ok(ranges)
}

/// Check if a string is a raw Bitcoin address (not an identifier)
fn _is_raw_bitcoin_address(addr: &str) -> bool {
    // Simple heuristic: if it doesn't contain '[' or ':', it's probably a raw address
    !addr.contains('[') && !addr.contains(':')
}

/// Get derivation path for address type
fn _get_derivation_path(address_type: &str, network: bitcoin::Network, index: u32) -> String {
    match address_type.to_lowercase().as_str() {
        "p2pkh" => format!("m/44'/{}'/{}'/{}/{}", 
                          if network == bitcoin::Network::Bitcoin { 0 } else { 1 }, 
                          0, 0, index),
        "p2sh" => format!("m/49'/{}'/{}'/{}/{}", 
                         if network == bitcoin::Network::Bitcoin { 0 } else { 1 }, 
                         0, 0, index),
        "p2wpkh" => format!("m/84'/{}'/{}'/{}/{}", 
                           if network == bitcoin::Network::Bitcoin { 0 } else { 1 }, 
                           0, 0, index),
        "p2tr" => format!("m/86'/{}'/{}'/{}/{}", 
                         if network == bitcoin::Network::Bitcoin { 0 } else { 1 }, 
                         0, 0, index),
        _ => format!("m/84'/{}'/{}'/{}/{}", 
                    if network == bitcoin::Network::Bitcoin { 0 } else { 1 }, 
                    0, 0, index),
    }
}

/// Address information for display
struct _AddressInfo {
    address: String,
    script_type: String,
}

/// Extract address from script pubkey
fn _extract_address_from_script(script: &bitcoin::ScriptBuf) -> Option<_AddressInfo> {
    use bitcoin::Address;
    use bitcoin::Network;
    
    // Try to convert script to address
    if let Ok(address) = Address::from_script(script, Network::Bitcoin) {
        let script_type = if script.is_p2pkh() {
            "P2PKH (Legacy)".to_string()
        } else if script.is_p2sh() {
            "P2SH (Script Hash)".to_string()
        } else if script.is_p2tr() {
            "P2TR (Taproot)".to_string()
        } else if script.is_witness_program() {
            "Witness Program (SegWit)".to_string()
        } else {
            "Unknown".to_string()
        };
        
        Some(_AddressInfo {
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
                // Human-readable styled output - use the public function from runestone_enhanced
                deezel::runestone_enhanced::print_human_readable_runestone(tx, &result);
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

/// Resolve address identifiers in a string using the provided wallet manager
/// Supports both full format [self:p2tr:0] and shorthand format p2tr:0
async fn resolve_address_identifiers(input: &str, wallet_manager: Option<&Arc<deezel::wallet::WalletManager>>) -> Result<String> {
    // Check if input contains full identifiers like [self:p2tr:0]
    if AddressResolver::contains_identifiers(input) {
        let resolver = if let Some(wm) = wallet_manager {
            AddressResolver::with_wallet(Arc::clone(wm))
        } else {
            return Err(anyhow!("Address identifiers found but no wallet manager available. Please ensure wallet is loaded."));
        };
        return resolver.resolve_all_identifiers(input).await;
    }
    
    // Check if input is a shorthand address identifier like "p2tr:0"
    if is_shorthand_address_identifier(input) {
        let wallet_manager = wallet_manager.ok_or_else(|| {
            anyhow!("Address identifier found but no wallet manager available. Please ensure wallet is loaded.")
        })?;
        
        // Directly parse and resolve the shorthand identifier
        let parts: Vec<&str> = input.split(':').collect();
        let address_type_str = parts[0];
        let index = if parts.len() > 1 {
            parts[1].parse::<u32>().context("Invalid index in shorthand identifier")?
        } else {
            0
        };

        return wallet_manager.get_address_of_type_at_index(address_type_str, index, false).await;
    }
    
    // No identifiers found, return as-is
    Ok(input.to_string())
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
    if parts.len() == 2 {
        if parts[1].parse::<u32>().is_err() {
            return false;
        }
    }
    
    true
}

/// Helper function to load an existing wallet with proper error handling
async fn load_wallet_manager(
    wallet_file: &str,
    network_params: &deezel::network::NetworkParams,
    sandshrew_rpc_url: &str,
    passphrase: Option<&str>
) -> Result<Arc<deezel::wallet::WalletManager>> {
    // Check if wallet file exists first
    let wallet_path = std::path::Path::new(wallet_file);
    if !wallet_path.exists() {
        return Err(anyhow!("Wallet file not found at {}. Please create a wallet first using 'deezel wallet create'", wallet_file));
    }
    
    let wallet_config = deezel::wallet::WalletConfig {
        wallet_path: wallet_file.to_string(),
        network: network_params.network,
        bitcoin_rpc_url: sandshrew_rpc_url.to_string(), // FIXED: Use Sandshrew for all RPC calls
        metashrew_rpc_url: sandshrew_rpc_url.to_string(),
        network_params: Some(network_params.to_protorune_params()),
    };
    
    // Journal: Updated wallet config to use sandshrew_rpc_url for both bitcoin_rpc_url and
    // metashrew_rpc_url to ensure consistent endpoint usage throughout the wallet operations
    
    // Use passphrase-aware wallet loading if passphrase is provided
    let wallet_manager = if let Some(passphrase) = passphrase {
        deezel::wallet::WalletManager::load_with_passphrase(wallet_config, passphrase)
            .await
            .context("Failed to load wallet with passphrase")?
    } else {
        deezel::wallet::WalletManager::new(wallet_config)
            .await
            .context("Failed to load wallet. If the wallet is encrypted with a passphrase, use --passphrase option")?
    };
    
    Ok(Arc::new(wallet_manager))
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
        deezel::network::NetworkParams::from_magic(magic)
            .map_err(|e| anyhow!("Invalid magic value: {}", e))?
    } else {
        deezel::network::NetworkParams::from_provider(&args.provider)
            .map_err(|e| anyhow!("Invalid provider: {}", e))?
    };

    // Generate network-specific wallet file path
    let wallet_file = if let Some(path) = args.wallet_file {
        expand_tilde(&path)?
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
        .unwrap_or_else(|| deezel::network::get_rpc_url(&args.provider));
    
    // Journal: Updated RPC URL handling to ALWAYS use the unified Sandshrew endpoint for both
    // bitcoin_rpc_url and metashrew_rpc_url. This eliminates the routing confusion where btc_*
    // methods were going to a separate Bitcoin RPC endpoint that might not exist or be accessible.
    
    // Initialize RPC client with unified endpoint
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: sandshrew_rpc_url.clone(),  // Use Sandshrew for Bitcoin RPC calls
        metashrew_rpc_url: sandshrew_rpc_url.clone(), // Use Sandshrew for Metashrew RPC calls
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));

    // Initialize wallet if needed for the command (but not for wallet creation)
    let wallet_manager = if matches!(args.command, Commands::Walletinfo { .. }) ||
        matches!(args.command, Commands::Wallet { command: WalletCommands::Restore { .. } |
                                                            WalletCommands::Info |
                                                            WalletCommands::Addresses { wallet_passphrase: _, .. } |
                                                            WalletCommands::Balance { .. } |
                                                            WalletCommands::Send { .. } |
                                                            WalletCommands::SendAll { .. } |
                                                            WalletCommands::CreateTx { .. } |
                                                            WalletCommands::SignTx { .. } |
                                                            WalletCommands::BroadcastTx { .. } |
                                                            WalletCommands::Utxos { .. } |
                                                            WalletCommands::FreezeUtxo { .. } |
                                                            WalletCommands::UnfreezeUtxo { .. } |
                                                            WalletCommands::History { .. } |
                                                            WalletCommands::TxDetails { .. } |
                                                            WalletCommands::EstimateFee { .. } |
                                                            WalletCommands::FeeRates |
                                                            WalletCommands::Sync |
                                                            WalletCommands::Backup |
                                                            WalletCommands::ListIdentifiers }) ||
        matches!(args.command, Commands::Alkanes { command: AlkanesCommands::Execute { .. } |
                                                             AlkanesCommands::Balance { .. } }) ||
       matches!(args.command, Commands::Deploy { .. }) {
        // FIXED: Only load wallet for alkanes commands that actually need it (Execute and Balance)
        // Commands like TokenInfo, Trace, Inspect, Getbytecode, and Simulate work with RPC client only
        let wallet_manager = load_wallet_manager(
            &wallet_file,
            &network_params,
            &sandshrew_rpc_url,
            args.wallet_passphrase.as_deref()
        ).await?;
        
        Some(wallet_manager)
    } else {
        None
    };

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
                // Load the wallet manager to resolve the address
                let wm = load_wallet_manager(
                    &wallet_file,
                    &network_params,
                    &sandshrew_rpc_url,
                    args.wallet_passphrase.as_deref(),
                )
                .await
                .context("Failed to load wallet for generatetoaddress")?;

                // Resolve address identifiers
                let resolved_address = resolve_address_identifiers(&address, Some(&wm)).await?;

                let result = rpc_client.generate_to_address(nblocks, &resolved_address).await?;
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
        },
        Commands::Wallet { command } => {
            match command {
                WalletCommands::Create { mnemonic } => {
                    // Handle wallet creation with GPG encryption support
                    let wallet_config = deezel::wallet::WalletConfig {
                        wallet_path: wallet_file.clone(),
                        network: network_params.network,
                        bitcoin_rpc_url: sandshrew_rpc_url.clone(), // FIXED: Use Sandshrew for all RPC calls
                        metashrew_rpc_url: sandshrew_rpc_url.clone(),
                        network_params: Some(network_params.to_protorune_params()),
                    };
                    
                    // Journal: Updated wallet creation config to use sandshrew_rpc_url consistently
                    // for both bitcoin_rpc_url and metashrew_rpc_url
                    
                    // Determine encryption mode based on file extension and passphrase
                    let use_gpg = wallet_file.ends_with(".asc");
                    let interactive_mode = args.wallet_passphrase.is_none();
                    
                    if use_gpg && interactive_mode {
                        println!("🔐 Creating GPG-encrypted wallet (interactive mode)...");
                        println!("📝 You will be prompted to enter GPG encryption details.");
                    } else if use_gpg && !interactive_mode {
                        println!("🔐 Creating GPG-encrypted wallet (non-interactive mode)...");
                    } else {
                        println!("🔒 Creating PBKDF2-encrypted wallet...");
                    }
                    
                    let new_wallet = deezel::wallet::WalletManager::create_wallet(
                        wallet_config,
                        mnemonic.clone(),
                        args.wallet_passphrase.clone()
                    ).await?;
                    
                    println!("✅ Wallet created successfully!");
                    if let Some(mnemonic) = new_wallet.get_mnemonic().await? {
                        println!("🔑 Mnemonic: {}", mnemonic);
                        println!("⚠️  IMPORTANT: Save this mnemonic phrase in a secure location!");
                    }
                    
                    let address = new_wallet.get_address().await?;
                    println!("🏠 First address: {}", address);
                    println!("💾 Wallet saved to: {}", wallet_file);
                },
                WalletCommands::Info => {
                    if let Some(wm) = &wallet_manager {
                        let address = wm.get_address().await?;
                        let balance = wm.get_balance().await?;
                        let network = wm.get_network();
                        
                        println!("💼 Wallet Information");
                        println!("═══════════════════");
                        println!("🏠 Address: {}", address);
                        println!("💰 Balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
                        println!("🌐 Network: {:?}", network);
                        println!("📁 File: {}", wallet_file);
                    }
                },
                WalletCommands::Send { address, amount, fee_rate, send_all, from, change, yes } => {
                    if let Some(wm) = &wallet_manager {
                        // Resolve address identifiers
                        let resolved_address = resolve_address_identifiers(&address, Some(wm)).await?;
                        let resolved_from = if let Some(from_addr) = from {
                            Some(resolve_address_identifiers(&from_addr, Some(wm)).await?)
                        } else {
                            None
                        };
                        let resolved_change = if let Some(change_addr) = change {
                            Some(resolve_address_identifiers(&change_addr, Some(wm)).await?)
                        } else {
                            None
                        };
                        
                        let send_params = deezel::wallet::SendParams {
                            address: resolved_address,
                            amount,
                            fee_rate,
                            send_all,
                            from_address: resolved_from,
                            change_address: resolved_change,
                            auto_confirm: yes,
                        };
                        
                        match wm.send(send_params).await {
                            Ok(txid) => {
                                println!("✅ Transaction sent successfully!");
                                println!("🔗 Transaction ID: {}", txid);
                            },
                            Err(e) => {
                                println!("❌ Failed to send transaction: {}", e);
                                return Err(e);
                            }
                        }
                    }
                },
                WalletCommands::SendAll { address, fee_rate, yes } => {
                    if let Some(wm) = &wallet_manager {
                        // Resolve address identifiers
                        let resolved_address = resolve_address_identifiers(&address, Some(wm)).await?;
                        
                        let send_params = deezel::wallet::SendParams {
                            address: resolved_address,
                            amount: 0, // Will be ignored since send_all is true
                            fee_rate,
                            send_all: true,
                            from_address: None,
                            change_address: None,
                            auto_confirm: yes,
                        };
                        
                        match wm.send(send_params).await {
                            Ok(txid) => {
                                println!("✅ All funds sent successfully!");
                                println!("🔗 Transaction ID: {}", txid);
                            },
                            Err(e) => {
                                println!("❌ Failed to send all funds: {}", e);
                                return Err(e);
                            }
                        }
                    }
                },
                WalletCommands::Utxos { raw, include_frozen, addresses } => {
                    if let Some(wm) = &wallet_manager {
                        // Handle address filtering
                        let utxos = if let Some(addresses_str) = addresses {
                            // Parse and resolve addresses
                            let address_list: Vec<String> = addresses_str.split(',')
                                .map(|addr| addr.trim().to_string())
                                .collect();
                            
                            let mut all_utxos = Vec::new();
                            for address in address_list {
                                // Resolve address identifiers (supports p2tr:0, etc.)
                                let resolved_address = resolve_address_identifiers(&address, Some(wm)).await?;
                                
                                // Get UTXOs for this specific address
                                let address_utxos = wm.get_enriched_utxos_for_address(&resolved_address).await?;
                                all_utxos.extend(address_utxos);
                            }
                            all_utxos
                        } else {
                            // Get UTXOs for all wallet addresses
                            wm.get_enriched_utxos().await?
                        };
                        
                        // Filter by frozen status if needed
                        let filtered_utxos: Vec<_> = if include_frozen {
                            utxos
                        } else {
                            utxos.into_iter().filter(|u| !u.utxo.frozen).collect()
                        };
                        
                        if raw {
                            // Raw JSON output
                            let json_utxos: Vec<serde_json::Value> = filtered_utxos.iter().map(|enriched_utxo| {
                                serde_json::json!({
                                    "txid": enriched_utxo.utxo.txid,
                                    "vout": enriched_utxo.utxo.vout,
                                    "amount": enriched_utxo.utxo.amount,
                                    "address": enriched_utxo.utxo.address,
                                    "confirmations": enriched_utxo.utxo.confirmations,
                                    "frozen": enriched_utxo.utxo.frozen,
                                    "freeze_reason": enriched_utxo.freeze_reason,
                                    "block_height": enriched_utxo.block_height,
                                    "has_inscriptions": enriched_utxo.has_inscriptions,
                                    "has_runes": enriched_utxo.has_runes,
                                    "has_alkanes": enriched_utxo.has_alkanes,
                                    "is_coinbase": enriched_utxo.is_coinbase
                                })
                            }).collect();
                            println!("{}", serde_json::to_string_pretty(&json_utxos)?);
                        } else {
                            // Human-readable output
                            println!("💰 Wallet UTXOs");
                            println!("═══════════════");
                            
                            if filtered_utxos.is_empty() {
                                println!("No UTXOs found");
                            } else {
                                let total_amount: u64 = filtered_utxos.iter().map(|u| u.utxo.amount).sum();
                                println!("📊 Total: {} UTXOs, {} sats\n", filtered_utxos.len(), total_amount);
                                
                                for (i, enriched_utxo) in filtered_utxos.iter().enumerate() {
                                    let utxo = &enriched_utxo.utxo;
                                    println!("{}. 🔗 {}:{}", i + 1, utxo.txid, utxo.vout);
                                    println!("   💰 Amount: {} sats", utxo.amount);
                                    println!("   🏠 Address: {}", utxo.address);
                                    println!("   ✅ Confirmations: {}", utxo.confirmations);
                                    
                                    if let Some(block_height) = enriched_utxo.block_height {
                                        println!("   📦 Block: {}", block_height);
                                    }
                                    
                                    // Show special properties
                                    let mut properties = Vec::new();
                                    if enriched_utxo.is_coinbase {
                                        properties.push("coinbase");
                                    }
                                    if enriched_utxo.has_inscriptions {
                                        properties.push("inscriptions");
                                    }
                                    if enriched_utxo.has_runes {
                                        properties.push("runes");
                                    }
                                    if enriched_utxo.has_alkanes {
                                        properties.push("alkanes");
                                    }
                                    if !properties.is_empty() {
                                        println!("   🏷️  Properties: {}", properties.join(", "));
                                    }
                                    
                                    if utxo.frozen {
                                        println!("   ❄️  Status: FROZEN");
                                        if let Some(reason) = &enriched_utxo.freeze_reason {
                                            println!("   📝 Reason: {}", reason);
                                        }
                                    } else {
                                        println!("   ✅ Status: spendable");
                                    }
                                    
                                    if i < filtered_utxos.len() - 1 {
                                        println!();
                                    }
                                }
                            }
                        }
                    }
                },
                WalletCommands::History { count, raw, address } => {
                    if let Some(wm) = &wallet_manager {
                        // Determine which address to check
                        let target_address = if let Some(addr) = address {
                            // Resolve address identifiers (supports p2tr:0, etc.)
                            resolve_address_identifiers(&addr, Some(wm)).await?
                        } else {
                            // Use default wallet address
                            wm.get_address().await?
                        };
                        
                        // Get transaction history using esplora API
                        match rpc_client._call("esplora_address::txs", serde_json::json!([target_address])).await {
                            Ok(result) => {
                                if let Some(txs_array) = result.as_array() {
                                    // Limit to requested count
                                    let limited_txs: Vec<_> = txs_array.iter().take(count as usize).collect();
                                    
                                    if raw {
                                        // Raw JSON output
                                        println!("{}", serde_json::to_string_pretty(&limited_txs)?);
                                    } else {
                                        // Human-readable output
                                        println!("📜 Transaction History for {}", target_address);
                                        println!("═══════════════════════════════════════════════");
                                        
                                        if limited_txs.is_empty() {
                                            println!("No transactions found");
                                        } else {
                                            println!("📊 Showing {} of {} transactions\n", limited_txs.len(), txs_array.len());
                                            
                                            for (i, tx) in limited_txs.iter().enumerate() {
                                                if let Some(tx_obj) = tx.as_object() {
                                                    println!("{}. 🔗 TXID: {}", i + 1,
                                                        tx_obj.get("txid").and_then(|v| v.as_str()).unwrap_or("unknown"));
                                                    
                                                    if let Some(status) = tx_obj.get("status").and_then(|v| v.as_object()) {
                                                        if let Some(confirmed) = status.get("confirmed").and_then(|v| v.as_bool()) {
                                                            if confirmed {
                                                                if let Some(block_height) = status.get("block_height").and_then(|v| v.as_u64()) {
                                                                    println!("   📦 Block: {}", block_height);
                                                                }
                                                                if let Some(block_time) = status.get("block_time").and_then(|v| v.as_u64()) {
                                                                    // Convert timestamp to readable format
                                                                    if let Some(datetime) = chrono::DateTime::from_timestamp(block_time as i64, 0) {
                                                                        println!("   🕐 Time: {}", datetime.format("%Y-%m-%d %H:%M:%S UTC"));
                                                                    }
                                                                }
                                                                println!("   ✅ Status: Confirmed");
                                                            } else {
                                                                println!("   ⏳ Status: Unconfirmed");
                                                            }
                                                        }
                                                    }
                                                    
                                                    // Show fee if available
                                                    if let Some(fee) = tx_obj.get("fee").and_then(|v| v.as_u64()) {
                                                        println!("   💰 Fee: {} sats", fee);
                                                    }
                                                    
                                                    // Show input/output counts
                                                    if let Some(vin) = tx_obj.get("vin").and_then(|v| v.as_array()) {
                                                        if let Some(vout) = tx_obj.get("vout").and_then(|v| v.as_array()) {
                                                            println!("   📥 Inputs: {}, 📤 Outputs: {}", vin.len(), vout.len());
                                                        }
                                                    }
                                                    
                                                    if i < limited_txs.len() - 1 {
                                                        println!();
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    if raw {
                                        println!("{}", serde_json::to_string_pretty(&result)?);
                                    } else {
                                        println!("❌ Unexpected response format from esplora API");
                                    }
                                }
                            },
                            Err(e) => {
                                if raw {
                                    let error_result = serde_json::json!({
                                        "error": e.to_string(),
                                        "address": target_address
                                    });
                                    println!("{}", serde_json::to_string_pretty(&error_result)?);
                                } else {
                                    println!("❌ Failed to get transaction history for address {}", target_address);
                                    println!("Error: {}", e);
                                }
                                return Err(e);
                            }
                        }
                    }
                },
                WalletCommands::Addresses { count, raw, .. } => {
                    if let Some(wm) = &wallet_manager {
                        let addresses = wm.get_addresses(count).await?;
                        if raw {
                            println!("{}", serde_json::to_string_pretty(&addresses)?);
                        } else {
                            println!("🏠 Wallet Addresses");
                            println!("══════════════════");
                            for (i, address) in addresses.iter().enumerate() {
                                println!("{}. {}", i, address.get("address").unwrap());
                            }
                        }
                    }
                },
                _ => {
                    println!("Other wallet commands not yet implemented");
                }
            }
        },
        Commands::Alkanes { command } => {
            match command {
                // Commands that work with RPC client only (no wallet needed)
                AlkanesCommands::Getbytecode { alkane_id, raw } => {
                    // Parse alkane ID
                    let alkane_parts: Vec<&str> = alkane_id.split(':').collect();
                    if alkane_parts.len() != 2 {
                        return Err(anyhow!("Invalid alkane ID format. Expected 'block:tx'"));
                    }
                    
                    let block = alkane_parts[0];
                    let tx = alkane_parts[1];
                    
                    // Get bytecode using RPC client (no wallet needed)
                    match rpc_client.get_bytecode(block, tx).await {
                        Ok(bytecode) => {
                            if raw {
                                // Output raw JSON for scripting
                                let json_result = serde_json::json!({
                                    "alkane_id": alkane_id,
                                    "block": block,
                                    "tx": tx,
                                    "bytecode": bytecode
                                });
                                println!("{}", serde_json::to_string_pretty(&json_result)?);
                            } else {
                                // Human-readable output
                                println!("🔍 Alkanes Contract Bytecode");
                                println!("═══════════════════════════");
                                println!("🏷️  Alkane ID: {}", alkane_id);
                                println!("📦 Block: {}", block);
                                println!("🔗 Transaction: {}", tx);
                                println!();
                                
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
                                    
                                    // Try to identify common patterns
                                    if clean_bytecode.starts_with("6080604052") {
                                        println!("   🔍 Pattern: Looks like Solidity bytecode (starts with common constructor pattern)");
                                    } else if clean_bytecode.starts_with("fe") {
                                        println!("   🔍 Pattern: Starts with INVALID opcode (0xfe)");
                                    } else if clean_bytecode.starts_with("60") {
                                        println!("   🔍 Pattern: Starts with PUSH opcode");
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            if raw {
                                let error_result = serde_json::json!({
                                    "error": e.to_string(),
                                    "alkane_id": alkane_id,
                                    "block": block,
                                    "tx": tx
                                });
                                println!("{}", serde_json::to_string_pretty(&error_result)?);
                            } else {
                                println!("❌ Failed to get bytecode for alkane {}:{}", block, tx);
                                println!("Error: {}", e);
                            }
                            return Err(e);
                        }
                    }
                },
                AlkanesCommands::TokenInfo { alkane_id, raw } => {
                    // Parse alkane ID
                    let alkane_parts: Vec<&str> = alkane_id.split(':').collect();
                    if alkane_parts.len() != 2 {
                        return Err(anyhow!("Invalid alkane ID format. Expected 'block:tx'"));
                    }
                    
                    let block = alkane_parts[0];
                    let tx = alkane_parts[1];
                    
                    // Get contract metadata using RPC client (no wallet needed)
                    match rpc_client.get_contract_meta(block, tx).await {
                        Ok(metadata) => {
                            if raw {
                                println!("{}", serde_json::to_string_pretty(&metadata)?);
                            } else {
                                println!("🏷️  Alkanes Token Information");
                                println!("═══════════════════════════");
                                println!("🔗 Alkane ID: {}", alkane_id);
                                println!("📦 Block: {}", block);
                                println!("🔗 Transaction: {}", tx);
                                println!("📋 Metadata: {}", serde_json::to_string_pretty(&metadata)?);
                            }
                        },
                        Err(e) => {
                            if raw {
                                let error_result = serde_json::json!({
                                    "error": e.to_string(),
                                    "alkane_id": alkane_id
                                });
                                println!("{}", serde_json::to_string_pretty(&error_result)?);
                            } else {
                                println!("❌ Failed to get token info for alkane {}", alkane_id);
                                println!("Error: {}", e);
                            }
                            return Err(e);
                        }
                    }
                },
                AlkanesCommands::Trace { outpoint, raw } => {
                    // Parse outpoint format (txid:vout)
                    let (txid, vout) = parse_outpoint(&outpoint)?;
                    
                    // Trace transaction using RPC client (no wallet needed)
                    match rpc_client.trace_outpoint_pretty(&txid, vout).await {
                        Ok(trace_output) => {
                            if raw {
                                // For raw output, use JSON format
                                match rpc_client.trace_outpoint_json(&txid, vout).await {
                                    Ok(json_output) => println!("{}", json_output),
                                    Err(e) => {
                                        let error_result = serde_json::json!({
                                            "error": e.to_string(),
                                            "outpoint": outpoint,
                                            "txid": txid,
                                            "vout": vout
                                        });
                                        println!("{}", serde_json::to_string_pretty(&error_result)?);
                                        return Err(e);
                                    }
                                }
                            } else {
                                println!("{}", trace_output);
                            }
                        },
                        Err(e) => {
                            if raw {
                                let error_result = serde_json::json!({
                                    "error": e.to_string(),
                                    "outpoint": outpoint,
                                    "txid": txid,
                                    "vout": vout
                                });
                                println!("{}", serde_json::to_string_pretty(&error_result)?);
                            } else {
                                println!("❌ Failed to trace transaction {}", outpoint);
                                println!("Error: {}", e);
                            }
                            return Err(e);
                        }
                    }
                },
                AlkanesCommands::Inspect { target, raw, disasm, fuzz, fuzz_ranges, meta, codehash } => {
                    // Create alkane inspector
                    let inspector = deezel::alkanes::inspector::AlkaneInspector::new(Arc::clone(&rpc_client))?;
                    
                    // Check if target is an alkane ID (format: block:tx) or bytecode
                    if target.contains(':') && !target.starts_with("0x") {
                        // Parse as alkane ID
                        let alkane_parts: Vec<&str> = target.split(':').collect();
                        if alkane_parts.len() != 2 {
                            return Err(anyhow!("Invalid alkane ID format. Expected 'block:tx'"));
                        }
                        
                        let block: u64 = alkane_parts[0].parse()
                            .context("Invalid block number in alkane ID")?;
                        let tx: u64 = alkane_parts[1].parse()
                            .context("Invalid transaction number in alkane ID")?;
                        
                        let alkane_id = deezel::alkanes::types::AlkaneId { block, tx };
                        
                        // Perform inspection with specified flags
                        inspector.inspect_alkane(
                            &alkane_id,
                            disasm,
                            fuzz,
                            fuzz_ranges.as_deref(),
                            meta,
                            codehash,
                            raw
                        ).await?;
                    } else {
                        // Handle as bytecode file or hex string (legacy mode)
                        if raw {
                            let result = serde_json::json!({
                                "target": target,
                                "analysis": "Direct bytecode inspection not yet implemented. Use alkane ID format (block:tx) for full inspection."
                            });
                            println!("{}", serde_json::to_string_pretty(&result)?);
                        } else {
                            println!("🔍 Alkanes Bytecode Inspection");
                            println!("═══════════════════════════");
                            println!("📄 Target: {}", target);
                            println!("⚠️  Direct bytecode inspection not yet implemented.");
                            println!("💡 Use alkane ID format (block:tx) for full inspection with --fuzz, --meta, --disasm, --codehash flags.");
                        }
                    }
                },
                AlkanesCommands::Simulate { contract_id, params, raw } => {
                    // Simulate contract execution (no wallet needed)
                    let (block, tx) = parse_contract_id(&contract_id)?;
                    let _simulation_params = if let Some(p) = params {
                        parse_simulation_params(&p)?
                    } else {
                        ("default_method".to_string(), "default_input".to_string(), vec!["default_arg".to_string()])
                    };
                    
                    // This is a placeholder - actual implementation would use RPC simulation
                    if raw {
                        let result = serde_json::json!({
                            "contract_id": contract_id,
                            "block": block,
                            "tx": tx,
                            "simulation": "Contract simulation not yet implemented"
                        });
                        println!("{}", serde_json::to_string_pretty(&result)?);
                    } else {
                        println!("🧪 Alkanes Contract Simulation");
                        println!("═══════════════════════════");
                        println!("🔗 Contract ID: {}", contract_id);
                        println!("📦 Block: {}", block);
                        println!("🔗 Transaction: {}", tx);
                        println!("⚠️  Simulation not yet implemented");
                    }
                },
                
                // Commands that require wallet access
                AlkanesCommands::Execute { .. } | AlkanesCommands::Balance { .. } => {
                    // For alkanes commands that need wallet access
                    let wm = wallet_manager.as_ref().ok_or_else(|| anyhow!("Wallet required for this alkanes operation"))?;
                    
                    match command {
                AlkanesCommands::Execute {
                    inputs,
                    to,
                    change,
                    fee_rate,
                    envelope,
                    protostones,
                    raw,
                    trace,
                    mine,
                    yes
                } => {
                    info!("🚀 Starting alkanes execute command");
                    
                    // Parse input requirements
                    let input_requirements = parse_input_requirements(&inputs)?;
                    info!("📥 Parsed {} input requirements", input_requirements.len());
                    
                    // Resolve addresses in the 'to' field
                    let resolved_to = resolve_address_identifiers(&to, Some(wm)).await?;
                    let to_addresses: Vec<String> = resolved_to.split(',')
                        .map(|addr| addr.trim().to_string())
                        .collect();
                    info!("📤 Resolved {} recipient addresses", to_addresses.len());
                    
                    // Resolve change address if provided
                    let resolved_change = if let Some(change_addr) = change {
                        Some(resolve_address_identifiers(&change_addr, Some(wm)).await?)
                    } else {
                        None
                    };
                    
                    // Parse protostones
                    let protostone_specs = parse_protostones(&protostones)?;
                    info!("🪨 Parsed {} protostone specifications", protostone_specs.len());
                    
                    // Load envelope data if provided
                    let envelope_data = if let Some(envelope_file) = envelope {
                        let expanded_path = expand_tilde(&envelope_file)?;
                        let data = std::fs::read(&expanded_path)
                            .with_context(|| format!("Failed to read envelope file: {}", expanded_path))?;
                        info!("📦 Loaded envelope data: {} bytes", data.len());
                        Some(data)
                    } else {
                        None
                    };
                    
                    // Create enhanced execute parameters
                    let execute_params = EnhancedExecuteParams {
                        fee_rate,
                        to_addresses,
                        change_address: resolved_change,
                        input_requirements,
                        protostones: protostone_specs,
                        envelope_data,
                        raw_output: raw,
                        trace_enabled: trace,
                        mine_enabled: mine,
                        auto_confirm: yes,
                    };
                    
                    // Create enhanced alkanes executor
                    let executor = EnhancedAlkanesExecutor::new(Arc::clone(&rpc_client), Arc::clone(wm));
                    
                    // Execute the alkanes transaction
                    match executor.execute(execute_params).await {
                        Ok(result) => {
                            if raw {
                                // Output raw JSON for scripting
                                let json_result = serde_json::json!({
                                    "commit_txid": result.commit_txid,
                                    "reveal_txid": result.reveal_txid,
                                    "commit_fee": result.commit_fee,
                                    "reveal_fee": result.reveal_fee,
                                    "inputs_used": result.inputs_used,
                                    "outputs_created": result.outputs_created,
                                    "traces": result.traces
                                });
                                println!("{}", serde_json::to_string_pretty(&json_result)?);
                            } else {
                                // Human-readable output
                                println!("\n🎉 Alkanes execution completed successfully!");
                                
                                if let Some(commit_txid) = result.commit_txid {
                                    println!("🔗 Commit TXID: {}", commit_txid);
                                    if let Some(commit_fee) = result.commit_fee {
                                        println!("💰 Commit Fee: {} sats", commit_fee);
                                    }
                                }
                                
                                println!("🔗 Reveal TXID: {}", result.reveal_txid);
                                println!("💰 Reveal Fee: {} sats", result.reveal_fee);
                                
                                if let Some(traces) = result.traces {
                                    println!("\n📊 Transaction Traces:");
                                    for (i, trace) in traces.iter().enumerate() {
                                        println!("  Trace {}: {}", i + 1, trace);
                                    }
                                }
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
                            return Err(e);
                        }
                    }
                },
                AlkanesCommands::Balance { address, raw } => {
                    let alkanes_manager = AlkanesManager::new(Arc::clone(&rpc_client), Arc::clone(wm));
                    let balances = alkanes_manager.get_balance(address.as_deref()).await?;
                    
                    if raw {
                        println!("{}", serde_json::to_string_pretty(&balances)?);
                    } else {
                        println!("🪙 Alkanes Balances");
                        println!("═══════════════════");
                        
                        if balances.is_empty() {
                            println!("No alkanes tokens found");
                        } else {
                            for balance in balances {
                                println!("🏷️  {}: {} {}",
                                        balance.name,
                                        balance.balance,
                                        balance.symbol);
                                println!("   ID: {}:{}", balance.alkane_id.block, balance.alkane_id.tx);
                            }
                        }
                    }
                },
                AlkanesCommands::Trace { outpoint, raw } => {
                    // Parse outpoint format (txid:vout)
                    let (txid, vout) = parse_outpoint(&outpoint)?;
                    
                    let alkanes_manager = AlkanesManager::new(Arc::clone(&rpc_client), Arc::clone(wm));
                    let trace_result = alkanes_manager.trace_transaction(&txid, vout).await?;
                    
                    if raw {
                        println!("{}", serde_json::to_string_pretty(&trace_result)?);
                    } else {
                        println!("📊 Alkanes Transaction Trace");
                        println!("═══════════════════════════");
                        println!("{}", serde_json::to_string_pretty(&trace_result)?);
                    }
                },
                _ => {
                    println!("Alkanes command not yet implemented");
                }
                    }
                }
            }
        },
        Commands::Runestone { command } => match command {
            RunestoneCommands::Decode { tx_hex, raw } => {
                let tx = decode_transaction_hex(&tx_hex)?;
                analyze_runestone_tx(&tx, raw);
            },
            RunestoneCommands::Analyze { txid, raw } => {
                let tx_hex = rpc_client.get_transaction_hex(&txid).await?;
                let tx = decode_transaction_hex(&tx_hex)?;
                analyze_runestone_tx(&tx, raw);
            },
        },
        Commands::Protorunes { command } => match command {
            ProtorunesCommands::ByAddress { address, raw } => {
                let result = rpc_client.get_protorunes_by_address(&address).await?;
                
                if raw {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    println!("🪙 Protorunes for address: {}", address);
                    println!("═══════════════════════════════════════");
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
            },
            ProtorunesCommands::ByOutpoint { txid, vout, raw } => {
                let result = rpc_client.get_protorunes_by_outpoint(&txid, vout).await?;
                
                if raw {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    println!("🪙 Protorunes for outpoint: {}:{}", txid, vout);
                    println!("═══════════════════════════════════════");
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
            },
        },
        Commands::Monitor { command } => match command {
            MonitorCommands::Blocks { start, raw: _ } => {
                let start_height = start.unwrap_or_else(|| {
                    // Get current height as default
                    0 // Placeholder - would need async context
                });
                
                println!("🔍 Monitoring blocks starting from height: {}", start_height);
                println!("⚠️  Block monitoring not yet implemented");
            },
        },
        Commands::Esplora { command } => {
            match command {
                EsploraCommands::BlocksTipHash => {
                    let result = rpc_client._call("esplora_blocks:tip:hash", serde_json::json!([])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::BlocksTipHeight => {
                    let result = rpc_client._call("esplora_blocks:tip:height", serde_json::json!([])).await?;
                    println!("{}", result.as_u64().unwrap_or(0));
                },
                EsploraCommands::Blocks { start_height } => {
                    let params = if let Some(height) = start_height {
                        serde_json::json!([height])
                    } else {
                        serde_json::json!([])
                    };
                    let result = rpc_client._call("esplora_blocks", params).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::BlockHeight { height } => {
                    let result = rpc_client._call("esplora_block:height", serde_json::json!([height])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::Block { hash } => {
                    let result = rpc_client._call("esplora_block", serde_json::json!([hash])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::BlockStatus { hash } => {
                    let result = rpc_client._call("esplora_block::status", serde_json::json!([hash])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::BlockTxids { hash } => {
                    let result = rpc_client._call("esplora_block::txids", serde_json::json!([hash])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::BlockHeader { hash } => {
                    let result = rpc_client._call("esplora_block::header", serde_json::json!([hash])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::BlockRaw { hash } => {
                    let result = rpc_client._call("esplora_block::raw", serde_json::json!([hash])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::BlockTxid { hash, index } => {
                    let result = rpc_client._call("esplora_block::txid", serde_json::json!([hash, index])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::BlockTxs { hash, start_index } => {
                    let params = if let Some(index) = start_index {
                        serde_json::json!([hash, index])
                    } else {
                        serde_json::json!([hash])
                    };
                    let result = rpc_client._call("esplora_block::txs", params).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::Address { params } => {
                    // Handle address resolution if needed
                    let resolved_params = resolve_address_identifiers(&params, wallet_manager.as_ref()).await?;
                    let result = rpc_client._call("esplora_address", serde_json::json!([resolved_params])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::AddressTxs { params } => {
                    // Handle address resolution if needed
                    let resolved_params = resolve_address_identifiers(&params, wallet_manager.as_ref()).await?;
                    let result = rpc_client._call("esplora_address::txs", serde_json::json!([resolved_params])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::AddressTxsChain { params } => {
                    // Handle address resolution for the first part (address:last_seen_txid)
                    let parts: Vec<&str> = params.split(':').collect();
                    if parts.len() >= 2 {
                        let address_part = parts[0];
                        let resolved_address = resolve_address_identifiers(address_part, wallet_manager.as_ref()).await?;
                        let resolved_params = if parts.len() == 2 {
                            format!("{}:{}", resolved_address, parts[1])
                        } else {
                            format!("{}:{}", resolved_address, parts[1..].join(":"))
                        };
                        let result = rpc_client._call("esplora_address::txs:chain", serde_json::json!([resolved_params])).await?;
                        println!("{}", serde_json::to_string_pretty(&result)?);
                    } else {
                        let resolved_params = resolve_address_identifiers(&params, wallet_manager.as_ref()).await?;
                        let result = rpc_client._call("esplora_address::txs:chain", serde_json::json!([resolved_params])).await?;
                        println!("{}", serde_json::to_string_pretty(&result)?);
                    }
                },
                EsploraCommands::AddressTxsMempool { address } => {
                    let resolved_address = resolve_address_identifiers(&address, wallet_manager.as_ref()).await?;
                    let result = rpc_client._call("esplora_address::txs:mempool", serde_json::json!([resolved_address])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::AddressUtxo { address } => {
                    let resolved_address = resolve_address_identifiers(&address, wallet_manager.as_ref()).await?;
                    let result = rpc_client._call("esplora_address::utxo", serde_json::json!([resolved_address])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::AddressPrefix { prefix } => {
                    let result = rpc_client._call("esplora_address:prefix", serde_json::json!([prefix])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::Tx { txid } => {
                    let result = rpc_client._call("esplora_tx", serde_json::json!([txid])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::TxHex { txid } => {
                    let result = rpc_client._call("esplora_tx::hex", serde_json::json!([txid])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::TxRaw { txid } => {
                    let result = rpc_client._call("esplora_tx::raw", serde_json::json!([txid])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::TxStatus { txid } => {
                    let result = rpc_client._call("esplora_tx::status", serde_json::json!([txid])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::TxMerkleProof { txid } => {
                    let result = rpc_client._call("esplora_tx::merkle:proof", serde_json::json!([txid])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::TxMerkleblockProof { txid } => {
                    let result = rpc_client._call("esplora_tx::merkleblock:proof", serde_json::json!([txid])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::TxOutspend { txid, index } => {
                    let result = rpc_client._call("esplora_tx::outspend", serde_json::json!([txid, index])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::TxOutspends { txid } => {
                    let result = rpc_client._call("esplora_tx::outspends", serde_json::json!([txid])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::Broadcast { tx_hex } => {
                    let result = rpc_client._call("esplora_broadcast", serde_json::json!([tx_hex])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::PostTx { tx_hex } => {
                    let result = rpc_client._call("esplora_tx", serde_json::json!([tx_hex])).await?;
                    println!("{}", result.as_str().unwrap_or(""));
                },
                EsploraCommands::Mempool => {
                    let result = rpc_client._call("esplora_mempool", serde_json::json!([])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::MempoolTxids => {
                    let result = rpc_client._call("esplora_mempool::txids", serde_json::json!([])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::MempoolRecent => {
                    let result = rpc_client._call("esplora_mempool::recent", serde_json::json!([])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                EsploraCommands::FeeEstimates => {
                    let result = rpc_client._call("esplora_fee:estimates", serde_json::json!([])).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
            }
        },
        Commands::Walletinfo { raw } => {
            if let Some(wm) = &wallet_manager {
                let address = wm.get_address().await?;
                let balance = wm.get_balance().await?;
                let network = wm.get_network();
                
                if raw {
                    let info = serde_json::json!({
                        "address": address,
                        "balance": balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
                        "network": format!("{:?}", network),
                        "wallet_file": wallet_file
                    });
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else {
                    println!("💼 Wallet Information");
                    println!("═══════════════════");
                    println!("🏠 Address: {}", address);
                    println!("💰 Balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
                    println!("🌐 Network: {:?}", network);
                    println!("📁 File: {}", wallet_file);
                }
            }
        },
        Commands::BuildContracts => {
            build_contracts::build()?;
        },
        Commands::Deploy { command } => {
            match command {
                DeployCommands::Amm { wasm_file, yes, calldata } => {
                    let wm = wallet_manager.ok_or_else(|| anyhow!("Wallet required for deployment"))?;
                    let deployer = deezel::deploy::ContractDeployer::new(rpc_client.clone(), wm);
                    deployer.deploy(&wasm_file, calldata, yes).await?;
                }
                DeployCommands::FreeMint { wasm_file, yes, calldata } => {
                    let wm = wallet_manager.ok_or_else(|| anyhow!("Wallet required for deployment"))?;
                    let deployer = deezel::deploy::ContractDeployer::new(rpc_client.clone(), wm);
                    deployer.deploy(&wasm_file, calldata, yes).await?;
                }
                DeployCommands::VaultFactory { wasm_file, yes, calldata } => {
                    let wm = wallet_manager.ok_or_else(|| anyhow!("Wallet required for deployment"))?;
                    let deployer = deezel::deploy::ContractDeployer::new(rpc_client.clone(), wm);
                    deployer.deploy(&wasm_file, calldata, yes).await?;
                }
            }
        }
    }

    Ok(())
}