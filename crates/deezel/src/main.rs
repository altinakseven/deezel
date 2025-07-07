//! Deezel CLI - Bitcoin alkanes inspector and wallet
//!
//! This is the CLI wrapper that implements the deezel-common traits
//! to provide the same functionality as the original deezel CLI.
//!
//! Architecture:
//! - Uses deezel-common for all business logic via trait abstractions
//! - Implements concrete providers for real-world usage
//! - Maintains 1-to-1 CLI compatibility with original deezel

use anyhow::Result;
use clap::{Parser, Subcommand};
use deezel_common::*;
use std::path::PathBuf;

mod providers;
use providers::ConcreteProvider;

#[derive(Parser)]
#[command(name = "deezel")]
#[command(about = "Bitcoin alkanes inspector and wallet")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Bitcoin RPC URL
    #[arg(long, default_value = "http://bitcoinrpc:bitcoinrpc@localhost:8332")]
    bitcoin_rpc_url: String,
    
    /// Metashrew RPC URL
    #[arg(long, default_value = "http://localhost:8080")]
    metashrew_rpc_url: String,
    
    /// Network (mainnet, testnet, signet, regtest)
    #[arg(long, default_value = "regtest")]
    network: String,
    
    /// Wallet directory
    #[arg(long)]
    wallet_dir: Option<PathBuf>,
    
    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Bitcoin RPC operations
    Bitcoind {
        #[command(subcommand)]
        command: BitcoindCommands,
    },
    /// Metashrew RPC operations
    Metashrew {
        #[command(subcommand)]
        command: MetashrewCommands,
    },
    /// Alkanes operations
    Alkanes {
        #[command(subcommand)]
        command: AlkanesCommands,
    },
    /// Runestone operations
    Runestone {
        #[command(subcommand)]
        command: RunestoneCommands,
    },
    /// Protorunes operations
    Protorunes {
        #[command(subcommand)]
        command: ProtorunesCommands,
    },
    /// Monitor operations
    Monitor {
        #[command(subcommand)]
        command: MonitorCommands,
    },
    /// Esplora operations
    Esplora {
        #[command(subcommand)]
        command: EsploraCommands,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Wallet name
        name: String,
        /// Use existing mnemonic
        #[arg(long)]
        mnemonic: Option<String>,
        /// Passphrase for wallet encryption
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Load existing wallet
    Load {
        /// Wallet name
        name: String,
        /// Passphrase for wallet decryption
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Get wallet balance
    Balance,
    /// Get receiving address
    Address,
    /// Get multiple addresses
    Addresses {
        /// Number of addresses to generate
        #[arg(default_value = "5")]
        count: u32,
    },
    /// Send transaction
    Send {
        /// Destination address or identifier
        to: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f64>,
    },
    /// List UTXOs
    Utxos {
        /// Include frozen UTXOs
        #[arg(long)]
        include_frozen: bool,
        /// Filter by addresses
        #[arg(long)]
        addresses: Option<Vec<String>>,
    },
    /// Get transaction history
    History {
        /// Number of transactions
        #[arg(default_value = "10")]
        count: u32,
        /// Filter by address
        #[arg(long)]
        address: Option<String>,
    },
    /// Sync wallet with blockchain
    Sync,
    /// Backup wallet
    Backup,
    /// Get mnemonic
    Mnemonic,
}

#[derive(Subcommand)]
enum BitcoindCommands {
    /// Get block count
    BlockCount,
    /// Generate blocks to address
    Generate {
        /// Number of blocks
        blocks: u32,
        /// Target address
        address: String,
    },
    /// Get transaction
    GetTx {
        /// Transaction ID
        txid: String,
    },
    /// Get block
    GetBlock {
        /// Block hash
        hash: String,
    },
    /// Send raw transaction
    SendRawTx {
        /// Transaction hex
        tx_hex: String,
    },
}

#[derive(Subcommand)]
enum MetashrewCommands {
    /// Get metashrew height
    Height,
    /// Get contract metadata
    ContractMeta {
        /// Block hash
        block: String,
        /// Transaction hash
        tx: String,
    },
    /// Trace outpoint
    Trace {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
    },
    /// Get spendables by address
    Spendables {
        /// Address
        address: String,
    },
}

#[derive(Subcommand)]
enum AlkanesCommands {
    /// Execute alkanes transaction
    Execute {
        /// Contract ID (block:tx)
        contract_id: String,
        /// Calldata
        #[arg(long)]
        calldata: Option<String>,
        /// Input requirements
        #[arg(long)]
        inputs: Option<String>,
        /// Output target
        #[arg(long)]
        output: Option<String>,
        /// Fee rate
        #[arg(long)]
        fee_rate: Option<f64>,
    },
    /// Get alkanes balance
    Balance {
        /// Address (optional, uses wallet address if not provided)
        #[arg(long)]
        address: Option<String>,
    },
    /// Inspect alkanes contract
    Inspect {
        /// Target (contract ID or transaction)
        target: String,
        /// Show disassembly
        #[arg(long)]
        disasm: bool,
        /// Show metadata
        #[arg(long)]
        metadata: bool,
        /// Run fuzzing
        #[arg(long)]
        fuzz: bool,
        /// Fuzzing iterations
        #[arg(long, default_value = "1000")]
        fuzz_iterations: u32,
        /// Opcode ranges for fuzzing
        #[arg(long)]
        opcode_ranges: Option<String>,
    },
    /// Trace alkanes outpoint
    Trace {
        /// Outpoint (txid:vout)
        outpoint: String,
    },
    /// Simulate alkanes contract
    Simulate {
        /// Contract ID
        contract_id: String,
        /// Parameters
        #[arg(long)]
        params: Option<String>,
    },
}

#[derive(Subcommand)]
enum RunestoneCommands {
    /// Decode runestone from transaction
    Decode {
        /// Transaction ID
        txid: String,
    },
    /// Analyze runestone
    Analyze {
        /// Transaction ID
        txid: String,
    },
}

#[derive(Subcommand)]
enum ProtorunesCommands {
    /// Get protorunes by address
    ByAddress {
        /// Address
        address: String,
    },
    /// Get protorunes by outpoint
    ByOutpoint {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
    },
}

#[derive(Subcommand)]
enum MonitorCommands {
    /// Start monitoring blocks
    Start {
        /// Starting block height
        #[arg(long)]
        start: Option<u64>,
    },
    /// Get block events
    Events {
        /// Block height
        height: u64,
    },
}

#[derive(Subcommand)]
enum EsploraCommands {
    /// Get tip height
    TipHeight,
    /// Get block by height
    Block {
        /// Block height
        height: u64,
    },
    /// Get address info
    Address {
        /// Address
        address: String,
    },
    /// Get transaction
    Tx {
        /// Transaction ID
        txid: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    
    // Create provider with CLI configuration
    let provider = ConcreteProvider::new(
        cli.bitcoin_rpc_url.clone(),
        cli.metashrew_rpc_url.clone(),
        cli.network.clone(),
        cli.wallet_dir.clone(),
    ).await?;
    
    // Initialize provider
    provider.initialize().await?;
    
    // Execute command
    let result = execute_command(&provider, cli).await;
    
    // Shutdown provider
    provider.shutdown().await?;
    
    result
}

async fn execute_command(provider: &ConcreteProvider, cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Wallet { command } => execute_wallet_command(provider, command).await,
        Commands::Bitcoind { command } => execute_bitcoind_command(provider, command).await,
        Commands::Metashrew { command } => execute_metashrew_command(provider, command).await,
        Commands::Alkanes { command } => execute_alkanes_command(provider, command).await,
        Commands::Runestone { command } => execute_runestone_command(provider, command).await,
        Commands::Protorunes { command } => execute_protorunes_command(provider, command).await,
        Commands::Monitor { command } => execute_monitor_command(provider, command).await,
        Commands::Esplora { command } => execute_esplora_command(provider, command).await,
    }
}

async fn execute_wallet_command(provider: &ConcreteProvider, command: WalletCommands) -> Result<()> {
    let wallet_config = deezel_common::wallet::WalletConfig {
        wallet_path: provider.get_wallet_config().wallet_path,
        network: provider.get_wallet_config().network,
        bitcoin_rpc_url: provider.get_wallet_config().bitcoin_rpc_url,
        metashrew_rpc_url: provider.get_wallet_config().metashrew_rpc_url,
        network_params: None,
    };
    let wallet = deezel_common::wallet::WalletManager::new(provider.clone(), wallet_config);
    
    match command {
        WalletCommands::Create { name, mnemonic, passphrase } => {
            let mut config = provider.get_wallet_config();
            config.wallet_path = name;
            let wallet_info = provider.create_wallet(config, mnemonic, passphrase).await?;
            println!("Created wallet with address: {}", wallet_info.address);
            if let Some(mnemonic) = wallet_info.mnemonic {
                println!("Mnemonic: {}", mnemonic);
            }
        }
        WalletCommands::Load { name, passphrase } => {
            let mut config = provider.get_wallet_config();
            config.wallet_path = name;
            let wallet_info = provider.load_wallet(config, passphrase).await?;
            println!("Loaded wallet with address: {}", wallet_info.address);
        }
        WalletCommands::Balance => {
            let balance = wallet.get_balance().await?;
            println!("Confirmed: {} sats", balance.confirmed);
            println!("Trusted pending: {} sats", balance.trusted_pending);
            println!("Untrusted pending: {} sats", balance.untrusted_pending);
        }
        WalletCommands::Address => {
            let address = wallet.get_address().await?;
            println!("{}", address);
        }
        WalletCommands::Addresses { count } => {
            let addresses = wallet.get_addresses(count).await?;
            for addr in addresses {
                println!("{}: {}", addr.index, addr.address);
            }
        }
        WalletCommands::Send { to, amount, fee_rate } => {
            let params = deezel_common::wallet::SendParams {
                address: to,
                amount,
                fee_rate: fee_rate.map(|f| f as f32),
                send_all: false,
                from_address: None,
                change_address: None,
                auto_confirm: false,
            };
            let txid = wallet.send(params).await?;
            println!("Transaction sent: {}", txid);
        }
        WalletCommands::Utxos { include_frozen: _, addresses: _ } => {
            let utxos = wallet.get_utxos().await?;
            for utxo in utxos {
                println!("{}:{} - {} sats ({})", utxo.txid, utxo.vout, utxo.amount, utxo.address);
            }
        }
        WalletCommands::History { count, address } => {
            let history = wallet.get_history(count, address).await?;
            for tx in history {
                println!("{}: {} (confirmed: {})", tx.txid, tx.fee.unwrap_or(0), tx.confirmed);
            }
        }
        WalletCommands::Sync => {
            wallet.sync().await?;
            println!("Wallet synced");
        }
        WalletCommands::Backup => {
            let backup = wallet.backup().await?;
            println!("Backup: {}", backup);
        }
        WalletCommands::Mnemonic => {
            if let Some(mnemonic) = wallet.get_mnemonic().await? {
                println!("{}", mnemonic);
            } else {
                println!("No mnemonic available");
            }
        }
    }
    
    Ok(())
}

async fn execute_bitcoind_command(provider: &ConcreteProvider, command: BitcoindCommands) -> Result<()> {
    match command {
        BitcoindCommands::BlockCount => {
            let count = provider.get_block_count().await?;
            println!("{}", count);
        }
        BitcoindCommands::Generate { blocks, address } => {
            let result = provider.generate_to_address(blocks, &address).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        BitcoindCommands::GetTx { txid } => {
            let tx_hex = provider.get_transaction_hex(&txid).await?;
            println!("{}", tx_hex);
        }
        BitcoindCommands::GetBlock { hash } => {
            let block = deezel_common::BitcoinRpcProvider::get_block(provider, &hash).await?;
            println!("{}", serde_json::to_string_pretty(&block)?);
        }
        BitcoindCommands::SendRawTx { tx_hex } => {
            let txid = provider.send_raw_transaction(&tx_hex).await?;
            println!("{}", txid);
        }
    }
    
    Ok(())
}

async fn execute_metashrew_command(provider: &ConcreteProvider, command: MetashrewCommands) -> Result<()> {
    match command {
        MetashrewCommands::Height => {
            let height = provider.get_metashrew_height().await?;
            println!("{}", height);
        }
        MetashrewCommands::ContractMeta { block, tx } => {
            let meta = provider.get_contract_meta(&block, &tx).await?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }
        MetashrewCommands::Trace { txid, vout } => {
            let trace = provider.trace_outpoint(&txid, vout).await?;
            println!("{}", serde_json::to_string_pretty(&trace)?);
        }
        MetashrewCommands::Spendables { address } => {
            let spendables = provider.get_spendables_by_address(&address).await?;
            println!("{}", serde_json::to_string_pretty(&spendables)?);
        }
    }
    
    Ok(())
}

async fn execute_alkanes_command(provider: &ConcreteProvider, command: AlkanesCommands) -> Result<()> {
    let alkanes = deezel_common::alkanes::AlkanesManager::new(provider.clone());
    
    match command {
        AlkanesCommands::Execute { contract_id, calldata, inputs, output, fee_rate } => {
            let params = AlkanesExecuteParams {
                inputs: inputs.unwrap_or_default(),
                to: output.unwrap_or_default(),
                change: None,
                fee_rate: fee_rate.map(|f| f as f32),
                envelope: Some(contract_id),
                protostones: calldata.unwrap_or_default(),
                trace: false,
                mine: false,
                auto_confirm: false,
            };
            let result = alkanes.execute(params).await?;
            println!("Reveal transaction: {}", result.reveal_txid);
            if let Some(commit_txid) = result.commit_txid {
                println!("Commit transaction: {}", commit_txid);
            }
        }
        AlkanesCommands::Balance { address } => {
            let balances = alkanes.get_balance(address.as_deref()).await?;
            for balance in balances {
                println!("{} ({}): {} - {:?}", balance.name, balance.symbol, balance.balance, balance.alkane_id);
            }
        }
        AlkanesCommands::Inspect { target, disasm, metadata, fuzz, fuzz_iterations: _, opcode_ranges } => {
            let config = AlkanesInspectConfig {
                disasm,
                fuzz,
                fuzz_ranges: opcode_ranges,
                meta: metadata,
                codehash: true,
            };
            let result = alkanes.inspect(&target, config).await?;
            
            println!("Alkane ID: {:?}", result.alkane_id);
            println!("Bytecode length: {} bytes", result.bytecode_length);
            
            if let Some(disassembly) = result.disassembly {
                println!("\nDisassembly:\n{}", disassembly);
            }
            
            if let Some(metadata) = result.metadata {
                println!("\nMetadata:\n{}", serde_json::to_string_pretty(&metadata)?);
            }
            
            if let Some(fuzzing_results) = result.fuzzing_results {
                println!("\nFuzzing Results:\n{}", serde_json::to_string_pretty(&fuzzing_results)?);
            }
        }
        AlkanesCommands::Trace { outpoint } => {
            let trace = alkanes.trace(&outpoint).await?;
            println!("{}", serde_json::to_string_pretty(&trace)?);
        }
        AlkanesCommands::Simulate { contract_id, params } => {
            let result = alkanes.simulate(&contract_id, params.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    
    Ok(())
}

async fn execute_runestone_command(provider: &ConcreteProvider, command: RunestoneCommands) -> Result<()> {
    let _runestone_manager = deezel_common::runestone::RunestoneManager::new(provider.clone());
    
    match command {
        RunestoneCommands::Decode { txid } => {
            // Get transaction and decode runestone
            let tx_hex = provider.get_transaction_hex(&txid).await?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(tx_hex)?)?;
            let decoded = provider.decode_runestone(&tx).await?;
            println!("{}", serde_json::to_string_pretty(&decoded)?);
        }
        RunestoneCommands::Analyze { txid } => {
            let analysis = provider.analyze_runestone(&txid).await?;
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
    }
    
    Ok(())
}

async fn execute_protorunes_command(provider: &ConcreteProvider, command: ProtorunesCommands) -> Result<()> {
    match command {
        ProtorunesCommands::ByAddress { address } => {
            let protorunes = provider.get_protorunes_by_address(&address).await?;
            println!("{}", serde_json::to_string_pretty(&protorunes)?);
        }
        ProtorunesCommands::ByOutpoint { txid, vout } => {
            let protorunes = provider.get_protorunes_by_outpoint(&txid, vout).await?;
            println!("{}", serde_json::to_string_pretty(&protorunes)?);
        }
    }
    
    Ok(())
}

async fn execute_monitor_command(provider: &ConcreteProvider, command: MonitorCommands) -> Result<()> {
    let mut monitor = deezel_common::monitor::BlockMonitor::new(provider.clone());
    
    match command {
        MonitorCommands::Start { start } => {
            monitor.monitor_blocks(start).await?;
            println!("Monitoring started");
        }
        MonitorCommands::Events { height } => {
            let events = monitor.get_block_events(height).await?;
            for event in events {
                println!("{}: {} at block {}", event.event_type, event.txid, event.block_height);
            }
        }
    }
    
    Ok(())
}

async fn execute_esplora_command(provider: &ConcreteProvider, command: EsploraCommands) -> Result<()> {
    match command {
        EsploraCommands::TipHeight => {
            let height = provider.get_blocks_tip_height().await?;
            println!("{}", height);
        }
        EsploraCommands::Block { height } => {
            let hash = provider.get_block_by_height(height).await?;
            let block = deezel_common::EsploraProvider::get_block(provider, &hash).await?;
            println!("{}", serde_json::to_string_pretty(&block)?);
        }
        EsploraCommands::Address { address } => {
            let info = EsploraProvider::get_address(provider, &address).await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        EsploraCommands::Tx { txid } => {
            let tx = provider.get_tx(&txid).await?;
            println!("{}", serde_json::to_string_pretty(&tx)?);
        }
    }
    
    Ok(())
}