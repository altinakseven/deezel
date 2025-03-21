use anyhow::{Context, Result, anyhow};
use clap::Parser;
use log::{info, warn, error, debug};

mod wallet;
mod monitor;
mod transaction;
mod rpc;
mod runestone;

/// A Bitcoin wallet CLI tool for automated DIESEL token minting and management
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Bitcoin RPC URL
    #[clap(long, default_value = "http://bitcoinrpc:bitcoinrpc@localhost:8332")]
    bitcoin_rpc_url: String,

    /// Metashrew RPC URL
    #[clap(long, default_value = "http://localhost:8080")]
    metashrew_rpc_url: String,

    /// Wallet file path
    #[clap(long, default_value = "wallet.dat")]
    wallet_path: String,

    /// Log level (error, warn, info, debug, trace)
    #[clap(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    info!("Starting deezel - DIESEL token minting and management tool");
    info!("Bitcoin RPC URL: {}", args.bitcoin_rpc_url);
    info!("Metashrew RPC URL: {}", args.metashrew_rpc_url);
    info!("Wallet path: {}", args.wallet_path);

    // Initialize RPC client
    let rpc_config = rpc::RpcConfig {
        bitcoin_rpc_url: args.bitcoin_rpc_url.clone(),
        metashrew_rpc_url: args.metashrew_rpc_url.clone(),
    };
    let rpc_client = std::sync::Arc::new(rpc::RpcClient::new(rpc_config));
    
    // Verify RPC connections
    info!("Verifying RPC connections...");
    
    // Check Bitcoin RPC
    match rpc_client.get_block_count().await {
        Ok(height) => info!("Bitcoin RPC connection successful. Current height: {}", height),
        Err(e) => {
            error!("Failed to connect to Bitcoin RPC: {}", e);
            return Err(anyhow!("Bitcoin RPC connection failed"));
        }
    }
    
    // Check Metashrew RPC
    match rpc_client.get_metashrew_height().await {
        Ok(height) => info!("Metashrew RPC connection successful. Current height: {}", height),
        Err(e) => {
            error!("Failed to connect to Metashrew RPC: {}", e);
            return Err(anyhow!("Metashrew RPC connection failed"));
        }
    }
    
    // Initialize wallet
    let wallet_config = wallet::WalletConfig {
        wallet_path: args.wallet_path.clone(),
        network: bdk::bitcoin::Network::Testnet, // TODO: Make configurable
        bitcoin_rpc_url: args.bitcoin_rpc_url.clone(),
        metashrew_rpc_url: args.metashrew_rpc_url.clone(),
    };
    
    let wallet_manager = std::sync::Arc::new(
        wallet::WalletManager::new(wallet_config).await
            .context("Failed to initialize wallet manager")?
    );
    
    // Sync wallet with blockchain
    wallet_manager.sync().await
        .context("Failed to sync wallet with blockchain")?;
    
    // Get a new address
    let address = wallet_manager.get_address().await
        .context("Failed to get wallet address")?;
    
    info!("Wallet address: {}", address);
    
    // Save wallet state
    wallet_manager.save().await
        .context("Failed to save wallet state")?;
    
    // Initialize RPC client
    let rpc_config = rpc::RpcConfig {
        bitcoin_rpc_url: args.bitcoin_rpc_url.clone(),
        metashrew_rpc_url: args.metashrew_rpc_url.clone(),
    };
    let rpc_client = std::sync::Arc::new(rpc::RpcClient::new(rpc_config));
    
    // Initialize block monitor
    let monitor_config = monitor::BlockMonitorConfig::default();
    let block_monitor = monitor::BlockMonitor::new(
        std::sync::Arc::clone(&rpc_client),
        monitor_config
    );
    
    // Initialize transaction constructor
    let tx_config = transaction::TransactionConfig {
        network: bdk::bitcoin::Network::Testnet, // TODO: Make configurable
        fee_rate: 1.0, // 1 sat/vbyte
        max_inputs: 100,
        max_outputs: 20,
    };
    let tx_constructor = transaction::TransactionConstructor::new(
        std::sync::Arc::clone(&wallet_manager),
        std::sync::Arc::clone(&rpc_client),
        tx_config
    );
    
    // Start monitoring for new blocks
    block_monitor.start().await
        .context("Failed to start block monitor")?;
    
    info!("Initialization complete. Running...");
    
    // Test DIESEL token minting
    if let Err(e) = test_diesel_minting(&tx_constructor).await {
        error!("Failed to test DIESEL token minting: {}", e);
    }
    
    // Get event receiver for block events
    let event_sender = block_monitor.get_event_receiver().await;
    
    // Main loop
    loop {
        // This will be replaced with actual block monitoring and token minting logic
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        info!("Waiting for new blocks...");
        
        // TODO: Implement proper event handling
        // For now, just log that we're waiting for events
    }
}

/// Test DIESEL token minting
async fn test_diesel_minting(tx_constructor: &transaction::TransactionConstructor) -> Result<()> {
    info!("Testing DIESEL token minting...");
    
    // Create a DIESEL token minting transaction
    let tx = tx_constructor.create_minting_transaction().await
        .context("Failed to create DIESEL token minting transaction")?;
    
    // In a real implementation, we would broadcast the transaction
    // For now, just log the transaction details
    info!("Created DIESEL token minting transaction: {}", tx.txid());
    debug!("Transaction details: {:?}", tx);
    
    // Simulate broadcasting the transaction
    // tx_constructor.broadcast_transaction(&tx).await?;
    
    info!("DIESEL token minting test completed successfully");
    Ok(())
}
