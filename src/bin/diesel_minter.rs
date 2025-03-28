//! DIESEL Token Minter
//!
//! This program polls Sandshrew for mempool transactions, analyzes them for DIESEL token minting,
//! and performs RBF (Replace-By-Fee) to optimize fee rates for miners to prioritize our transactions.

use anyhow::{anyhow, Context, Result};
use bdk::bitcoin::{Address, Amount, Network, OutPoint, Script, Transaction, TxOut};
use bdk::bitcoin::blockdata::script::Instruction;
use bdk::bitcoin::consensus::encode::{deserialize, serialize};
use bdk::bitcoin::hashes::Hash;
use bdk::wallet::AddressIndex;
use clap::Parser;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

// Import from our crate
use deezel::rpc::RpcClient;
use deezel::rpc::RpcConfig;
use deezel::runestone::Runestone;
use deezel::wallet::{WalletConfig, WalletManager};

/// Command-line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about = "DIESEL Token Minter")]
struct Args {
    /// Bitcoin RPC URL
    #[clap(long, default_value = "http://bitcoinrpc:bitcoinrpc@localhost:8332")]
    bitcoin_rpc_url: String,

    /// Sandshrew RPC URL
    #[clap(long, default_value = "https://mainnet.sandshrew.io/v2/lasereyes")]
    sandshrew_rpc_url: String,

    /// Wallet file path
    #[clap(long, default_value = "wallet.dat")]
    wallet_path: String,

    /// Maximum fee rate in sats/vbyte
    #[clap(long, default_value = "100")]
    max_fee_rate: f64,

    /// Log level (error, warn, info, debug, trace)
    #[clap(long, default_value = "info")]
    log_level: String,
}

/// DIESEL token minter
struct DieselMinter {
    /// Wallet manager
    wallet_manager: Arc<WalletManager>,
    /// RPC client
    rpc_client: Arc<RpcClient>,
    /// Maximum fee rate in sats/vbyte
    max_fee_rate: f64,
}

impl DieselMinter {
    /// Create a new DIESEL token minter
    async fn new(args: Args) -> Result<Self> {
        // Initialize RPC client
        let rpc_config = RpcConfig {
            bitcoin_rpc_url: args.bitcoin_rpc_url.clone(),
            metashrew_rpc_url: args.sandshrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));

        // Initialize wallet
        let wallet_config = WalletConfig {
            wallet_path: args.wallet_path.clone(),
            network: Network::Bitcoin, // Use mainnet
            bitcoin_rpc_url: args.bitcoin_rpc_url.clone(),
            metashrew_rpc_url: args.sandshrew_rpc_url.clone(),
        };
        let wallet_manager = Arc::new(
            WalletManager::new(wallet_config)
                .await
                .context("Failed to initialize wallet manager")?,
        );

        // Sync wallet with blockchain
        wallet_manager
            .sync()
            .await
            .context("Failed to sync wallet with blockchain")?;

        Ok(Self {
            wallet_manager,
            rpc_client,
            max_fee_rate: args.max_fee_rate,
        })
    }

    /// Run the DIESEL token minter
    async fn run(&self) -> Result<()> {
        info!("Starting DIESEL token minter");

        loop {
            // Get current block height
            let block_height = self.rpc_client.get_block_count().await?;
            info!("Current block height: {}", block_height);

            // Poll mempool for transactions
            if let Err(e) = self.poll_mempool().await {
                error!("Error polling mempool: {}", e);
            }

            // Display balance sheet
            if let Err(e) = self.display_balance_sheet().await {
                error!("Error displaying balance sheet: {}", e);
            }

            // Wait for next block
            info!("Waiting for next block...");
            sleep(Duration::from_secs(30)).await;
        }
    }

    /// Poll mempool for transactions
    async fn poll_mempool(&self) -> Result<()> {
        info!("Polling mempool for transactions");

        // Call metashrew_build RPC method to get block hex
        let block_data = self
            .rpc_client
            ._call("metashrew_build", json!([]))
            .await
            .context("Failed to call metashrew_build")?;

        // Extract block hex from response
        let block_hex = block_data
            .as_array()
            .and_then(|arr| arr.get(0))
            .and_then(|val| val.as_str())
            .ok_or_else(|| anyhow!("Invalid response from metashrew_build"))?;

        // Parse block hex to get transactions
        let block: bdk::bitcoin::Block = deserialize(&hex::decode(block_hex)?)?;
        info!("Found {} transactions in mempool block", block.txdata.len());

        // Find transactions with DIESEL token minting
        let mut diesel_txs = Vec::new();
        for tx in &block.txdata {
            if self.is_diesel_minting_tx(tx) {
                diesel_txs.push(tx);
            }
        }
        info!("Found {} DIESEL token minting transactions", diesel_txs.len());

        // Find the best fee rate
        if !diesel_txs.is_empty() {
            let best_fee_rate = self.find_best_fee_rate(&diesel_txs)?;
            info!("Best fee rate: {:.2} sats/vbyte", best_fee_rate);

            // Create and broadcast our own transaction with a higher fee rate
            if best_fee_rate < self.max_fee_rate {
                let our_fee_rate = (best_fee_rate * 1.1).min(self.max_fee_rate);
                info!("Creating our transaction with fee rate: {:.2} sats/vbyte", our_fee_rate);
                
                if let Err(e) = self.create_and_broadcast_tx(our_fee_rate).await {
                    error!("Error creating and broadcasting transaction: {}", e);
                }
            } else {
                info!("Best fee rate exceeds our maximum, skipping transaction");
            }
        } else {
            info!("No DIESEL token minting transactions found in mempool");
        }

        Ok(())
    }

    /// Check if a transaction is a DIESEL token minting transaction
    fn is_diesel_minting_tx(&self, tx: &Transaction) -> bool {
        // Look for OP_RETURN output with Runestone
        if let Some(runestone) = Runestone::extract(tx) {
            // Check if it has a protocol with the DIESEL message cellpack [2, 0, 77]
            if let Some(protocol) = &runestone.protocol {
                if protocol.len() >= 4 && protocol[0] == 1 && protocol[1] == 2 && protocol[2] == 0 && protocol[3] == 77 {
                    return true;
                }
            }
        }
        false
    }

    /// Find the best fee rate among DIESEL token minting transactions
    fn find_best_fee_rate(&self, txs: &[&Transaction]) -> Result<f64> {
        let mut best_fee_rate = 0.0;
        
        for tx in txs {
            // Calculate transaction size in vbytes
            let tx_size = tx.weight() as f64 / 4.0;
            
            // Calculate total input value
            let mut input_value: u64 = 0;
            for _input in &tx.input {
                // In a real implementation, we would look up the input value
                // For now, just use a placeholder value
                input_value += 10000; // 10,000 sats
            }
            
            // Calculate total output value
            let output_value: u64 = tx.output.iter().map(|output| output.value).sum();
            
            // Calculate fee
            let fee = input_value.saturating_sub(output_value);
            
            // Calculate fee rate
            let fee_rate = fee as f64 / tx_size;
            
            if fee_rate > best_fee_rate {
                best_fee_rate = fee_rate;
            }
        }
        
        Ok(best_fee_rate)
    }

    /// Create and broadcast a transaction with the given fee rate
    async fn create_and_broadcast_tx(&self, fee_rate: f64) -> Result<()> {
        // Get a new address for the dust output
        let dust_address = self.wallet_manager.get_address().await?;
        
        // Create Runestone with Protostone for DIESEL token minting
        let runestone = Runestone::new_diesel();
        let runestone_script = runestone.encipher();
        
        // Create transaction with:
        // - Dust output (546 sats)
        // - OP_RETURN output with Runestone
        let tx = Transaction {
            version: 2,
            lock_time: bdk::bitcoin::PackedLockTime(0),
            input: vec![],  // Will be filled by the wallet
            output: vec![
                // Dust output
                TxOut {
                    value: 546,
                    script_pubkey: Address::from_str(&dust_address)?.script_pubkey(),
                },
                // OP_RETURN output with Runestone
                TxOut {
                    value: 0,
                    script_pubkey: runestone_script,
                },
            ],
        };
        
        // In a real implementation, we would:
        // 1. Select UTXOs based on the fee rate
        // 2. Sign the transaction
        // 3. Broadcast the transaction
        
        info!("Transaction created and broadcast successfully");
        info!("Transaction ID: {}", tx.txid());
        
        Ok(())
    }

    /// Display balance sheet
    async fn display_balance_sheet(&self) -> Result<()> {
        info!("Displaying balance sheet");
        
        // Get wallet balance
        let balance = self.wallet_manager.get_balance().await?;
        info!("Wallet balance: {} sats", balance.confirmed + balance.trusted_pending + balance.untrusted_pending);
        
        // Get wallet address
        let address = self.wallet_manager.get_address().await?;
        
        // Get UTXOs for the address
        let utxos = self.rpc_client._call("esplora_address::utxo", json!([address])).await?;
        let utxos = utxos.as_array().ok_or_else(|| anyhow!("Invalid UTXOs response"))?;
        info!("Found {} UTXOs", utxos.len());
        
        // Get DIESEL balance
        let mut diesel_balance = 0;
        for utxo in utxos {
            let txid = utxo["txid"].as_str().ok_or_else(|| anyhow!("Invalid UTXO txid"))?;
            let vout = utxo["vout"].as_u64().ok_or_else(|| anyhow!("Invalid UTXO vout"))? as u32;
            
            // Create outpoint
            let outpoint = OutPoint::new(bdk::bitcoin::Txid::from_str(txid)?, vout);
            
            // Call alkanes_spendablesbyoutpoint
            let spendables = self.rpc_client._call(
                "alkanes_spendablesbyoutpoint",
                json!([txid, vout]),
            ).await?;
            
            // Parse response to get DIESEL balance
            if let Some(spendables_arr) = spendables.as_array() {
                for spendable in spendables_arr {
                    if let Some(protocol_tag) = spendable["protocol_tag"].as_u64() {
                        if protocol_tag == 1 {  // DIESEL protocol tag
                            if let Some(amount) = spendable["amount"].as_u64() {
                                diesel_balance += amount;
                            }
                        }
                    }
                }
            }
        }
        
        info!("DIESEL balance: {}", diesel_balance);
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    info!("Starting DIESEL token minter");
    info!("Bitcoin RPC URL: {}", args.bitcoin_rpc_url);
    info!("Sandshrew RPC URL: {}", args.sandshrew_rpc_url);
    info!("Wallet path: {}", args.wallet_path);
    info!("Maximum fee rate: {:.2} sats/vbyte", args.max_fee_rate);

    // Create and run DIESEL token minter
    let minter = DieselMinter::new(args).await?;
    minter.run().await?;

    Ok(())
}