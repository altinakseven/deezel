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
    let wallet_manager = if matches!(args.command, Commands::Walletinfo | Commands::Wallet { .. }) {
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
        Commands::Wallet { command } => {
            if let Some(wallet_manager) = &wallet_manager {
                match command {
                    WalletCommands::Create { mnemonic, passphrase } => {
                        let wallet_config = deezel_cli::wallet::WalletConfig {
                            wallet_path: args.wallet_path.clone(),
                            network: network_params.network,
                            bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                            metashrew_rpc_url: sandshrew_rpc_url.clone(),
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
                    WalletCommands::Restore { mnemonic, passphrase } => {
                        let wallet_config = deezel_cli::wallet::WalletConfig {
                            wallet_path: args.wallet_path.clone(),
                            network: network_params.network,
                            bitcoin_rpc_url: bitcoin_rpc_url.clone(),
                            metashrew_rpc_url: sandshrew_rpc_url.clone(),
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
                                println!("Bitcoin Balance:");
                                println!("  Confirmed: {} sats", balance.confirmed);
                                println!("  Pending: {} sats", balance.trusted_pending + balance.untrusted_pending);
                                println!("  Total: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
                            },
                            Err(e) => println!("Failed to get balance: {}", e),
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
            AlkanesCommands::Meta { contract_id } => {
                let (block, tx) = parse_contract_id(&contract_id)?;
                let result = rpc_client.get_contract_meta(&block, &tx).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            },
            
            // Enhanced alkanes commands
            AlkanesCommands::DeployContract { wasm_file, calldata, fee_rate } => {
                // Initialize alkanes manager
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
            
            AlkanesCommands::Inspect { alkane_id, disasm, fuzz, fuzz_ranges, meta } => {
                info!("Inspecting alkane: {}", alkane_id);
                
                // Parse alkane ID
                let parsed_alkane_id = deezel_cli::alkanes::parse_alkane_id(&alkane_id)?;
                
                // Initialize RPC client for inspector
                let inspector = deezel_cli::alkanes::inspector::AlkaneInspector::new(
                    Arc::new(rpc_client)
                ).context("Failed to initialize alkane inspector")?;
                
                // Perform inspection with requested analysis modes
                match inspector.inspect_alkane(&parsed_alkane_id, disasm, fuzz, fuzz_ranges.as_deref(), meta).await {
                    Ok(_) => {
                        println!("Alkane inspection completed successfully");
                    },
                    Err(e) => {
                        println!("Alkane inspection failed: {}", e);
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
                    println!("{}", serde_json::to_string_pretty(&result)?);
                },
                ViewCommands::Trace { outpoint } => {
                    let (txid, vout) = parse_outpoint(&outpoint)?;
                    let result = rpc_client.trace_outpoint(&txid, vout).await?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
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
        Commands::InspectAlkane { alkane_id, disasm, fuzz, fuzz_ranges, meta } => {
            info!("Inspecting alkane: {}", alkane_id);
            
            // Parse alkane ID
            let parsed_alkane_id = deezel_cli::alkanes::parse_alkane_id(&alkane_id)?;
            
            // Initialize RPC client for inspector
            let inspector = deezel_cli::alkanes::inspector::AlkaneInspector::new(
                Arc::new(rpc_client)
            ).context("Failed to initialize alkane inspector")?;
            
            // Perform inspection with requested analysis modes
            match inspector.inspect_alkane(&parsed_alkane_id, disasm, fuzz, fuzz_ranges.as_deref(), meta).await {
                Ok(_) => {
                    println!("Alkane inspection completed successfully");
                },
                Err(e) => {
                    println!("Alkane inspection failed: {}", e);
                    std::process::exit(1);
                }
            }
        },
    }

    Ok(())
}
