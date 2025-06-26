//! Deezel CLI - Bitcoin wallet tool for automated DIESEL token minting and management
//! 
//! This is the main CLI application that uses the generic deezel runtime with
//! filesystem-based adapters for production use.

use anyhow::Result;
use clap::{Parser, Subcommand};
use deezel_adapters::filesystem::{FilesystemWalletStorage, FilesystemConfigStorage, FilesystemAdapter};
use deezel_adapters::http_rpc::{HttpRpcClient, HttpBlockchainClient};
use deezel_adapters::wasmtime_runtime::WasmtimeRuntime;
use deezel_core::runtime::DeezelRuntime;
use bitcoin::Network;
use log::{info, error};

mod cli;
mod config;
mod wallet;
mod transaction;
mod alkanes;
mod deployment;

use cli::{WalletCommands, TransactionCommands, AlkanesCommands, DeployCommands, ConfigCommands};

type ProductionRuntime = DeezelRuntime<
    FilesystemWalletStorage,
    FilesystemConfigStorage,
    HttpRpcClient,
    HttpBlockchainClient,
    FilesystemAdapter,
    WasmtimeRuntime,
>;

#[derive(Parser)]
#[command(name = "deezel")]
#[command(about = "A Bitcoin wallet CLI tool for automated DIESEL token minting and management")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Network to use (mainnet, testnet, regtest)
    #[arg(long, default_value = "regtest")]
    network: String,
    
    /// Configuration directory
    #[arg(long)]
    config_dir: Option<String>,
    
    /// Bitcoin RPC URL
    #[arg(long, default_value = "http://bitcoinrpc:bitcoinrpc@localhost:8332")]
    bitcoin_rpc_url: String,
    
    /// Metashrew RPC URL
    #[arg(long, default_value = "http://localhost:8080")]
    metashrew_rpc_url: String,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Wallet management commands
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Transaction operations
    Transaction {
        #[command(subcommand)]
        command: TransactionCommands,
    },
    /// Alkanes contract operations
    Alkanes {
        #[command(subcommand)]
        command: AlkanesCommands,
    },
    /// Deployment and infrastructure commands
    Deploy {
        #[command(subcommand)]
        command: DeployCommands,
    },
    /// Show configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
    
    info!("Starting Deezel CLI v0.1.0");
    
    // Parse network
    let network = match cli.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            error!("Invalid network: {}. Use mainnet, testnet, regtest, or signet", cli.network);
            std::process::exit(1);
        }
    };
    
    // Create runtime with filesystem adapters
    let runtime = create_production_runtime(&cli, network).await?;
    
    // Execute command
    match cli.command {
        Commands::Wallet { command } => {
            wallet::handle_wallet_command(runtime, command).await?;
        }
        Commands::Transaction { command } => {
            transaction::handle_transaction_command(runtime, command).await?;
        }
        Commands::Alkanes { command } => {
            alkanes::handle_alkanes_command(runtime, command).await?;
        }
        Commands::Deploy { command } => {
            deployment::handle_deploy_command(runtime, command).await?;
        }
        Commands::Config { command } => {
            config::handle_config_command(runtime, command).await?;
        }
    }
    
    Ok(())
}

async fn create_production_runtime(cli: &Cli, network: Network) -> Result<ProductionRuntime> {
    info!("Initializing production runtime with network: {:?}", network);
    
    // Determine config directory
    let config_dir = cli.config_dir.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|home| home.join(".deezel").to_string_lossy().to_string())
            .unwrap_or_else(|| ".deezel".to_string())
    });
    
    info!("Using config directory: {}", config_dir);
    
    // Create adapters
    let wallet_storage = FilesystemWalletStorage::new(config_dir.clone().into());
    let config_storage = FilesystemConfigStorage::new(config_dir.clone().into());
    
    let rpc_client = HttpRpcClient::new(
        cli.metashrew_rpc_url.clone(),
        5000, // 5 second timeout
    );
    
    let blockchain_client = HttpBlockchainClient::new(
        cli.bitcoin_rpc_url.clone(),
        5000, // 5 second timeout
    );
    let filesystem = FilesystemAdapter::new(config_dir.clone().into());
    let wasm_runtime = WasmtimeRuntime::new()?;
    
    // Create runtime config
    let runtime_config = deezel_core::runtime::DeezelRuntimeConfig {
        network: deezel_core::traits::NetworkConfig {
            network,
            rpc_url: cli.bitcoin_rpc_url.clone(),
            esplora_url: None,
            metashrew_url: Some(cli.metashrew_rpc_url.clone()),
        },
        wallet: deezel_core::traits::WalletConfig {
            name: "default".to_string(),
            network,
            descriptor: None,
            mnemonic_path: None,
        },
        rpc: deezel_core::traits::RpcConfig {
            bitcoin_rpc_url: cli.bitcoin_rpc_url.clone(),
            ord_rpc_url: None,
            esplora_url: None,
            metashrew_url: Some(cli.metashrew_rpc_url.clone()),
            timeout_ms: 5000,
            max_retries: 3,
        },
        alkanes: deezel_core::traits::AlkanesConfig {
            wasm_cache_dir: format!("{}/wasm_cache", config_dir),
            max_memory: 64 * 1024 * 1024, // 64MB
            execution_timeout_ms: 30000,
            enable_simulation: true,
        },
    };
    
    // Create runtime
    let runtime = DeezelRuntime::new(
        wallet_storage,
        config_storage,
        rpc_client,
        blockchain_client,
        filesystem,
        wasm_runtime,
        runtime_config,
    );
    
    info!("Production runtime initialized successfully");
    Ok(runtime)
}