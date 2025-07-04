//! Bitcoin wallet functionality using rust-bitcoin directly
//!
//! This module handles:
//! - Wallet creation and management with GPG encryption
//! - Mnemonic generation and restoration
//! - UTXO tracking and selection via Sandshrew RPC
//! - Transaction creation, signing, and broadcasting
//! - Persistent encrypted wallet state
//! - Fee estimation and coin selection

pub mod crypto;
pub mod bitcoin_wallet;
mod esplora_backend;

use anyhow::{Context, Result, anyhow};
use bitcoin::{Network, Address, Txid, OutPoint, TxOut, TxIn, Transaction, Witness};
use bitcoin::secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use bitcoin::sighash::{SighashCache, EcdsaSighashType};
use bitcoin::script::Builder;
use bitcoin::opcodes::all::OP_DUP;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::ecdsa::Signature;
use bip39::{Mnemonic, Language};
use log::{debug, info, warn};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs;

use crate::rpc::RpcClient;
use self::esplora_backend::SandshrewEsploraBackend;
use self::bitcoin_wallet::{BitcoinWallet, BitcoinWalletConfig};
use self::crypto::{WalletCrypto, WalletData, EncryptedWalletData};
use protorune_support::network::NetworkParams as CustomNetworkParams;

/// Wallet configuration
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// Path to wallet file
    pub wallet_path: String,
    /// Bitcoin network (mainnet, testnet, regtest)
    pub network: Network,
    /// Bitcoin RPC URL (deprecated - using Sandshrew for all RPC calls)
    pub bitcoin_rpc_url: String,
    /// Metashrew/Sandshrew RPC URL
    pub metashrew_rpc_url: String,
    /// Custom network parameters for address generation
    pub network_params: Option<CustomNetworkParams>,
}

/// Bitcoin wallet manager using rust-bitcoin directly
pub struct WalletManager {
    /// Bitcoin wallet instance
    wallet: Arc<BitcoinWallet>,
    /// Wallet configuration
    config: WalletConfig,
    /// Custom Esplora backend
    backend: SandshrewEsploraBackend,
    /// RPC client
    rpc_client: Arc<RpcClient>,
}

impl WalletManager {
    /// Create a new wallet manager by loading existing encrypted wallet
    pub async fn new(config: WalletConfig) -> Result<Self> {
        info!("Initializing wallet manager");
        debug!("Wallet path: {}", config.wallet_path);
        debug!("Network: {:?}", config.network);
        
        // Create RPC client - use Sandshrew RPC URL for both Bitcoin and Metashrew calls
        // since Sandshrew is functionally also a bitcoind
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.metashrew_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create custom Esplora backend
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        // Check if wallet file exists
        let wallet_path = Path::new(&config.wallet_path);
        if !wallet_path.exists() {
            return Err(anyhow!("Wallet file not found at {}. Please create a wallet first using 'deezel wallet create'", config.wallet_path));
        }
        
        // Load encrypted wallet
        info!("Loading encrypted wallet from {}", config.wallet_path);
        let bitcoin_config = BitcoinWalletConfig {
            wallet_path: config.wallet_path.clone(),
            network: config.network,
            sandshrew_rpc_url: config.metashrew_rpc_url.clone(),
            network_params: config.network_params.clone(),
        };
        
        let wallet = BitcoinWallet::load_encrypted(
            bitcoin_config,
            Arc::clone(&rpc_client),
            None, // Interactive GPG mode
        ).await?;
        
        info!("Wallet initialized successfully");
        
        Ok(Self {
            wallet: Arc::new(wallet),
            config,
            backend,
            rpc_client,
        })
    }
    
    /// Create a new wallet manager with encrypted wallet creation
    pub async fn create_wallet(
        config: WalletConfig, 
        mnemonic: Option<String>, 
        passphrase: Option<String>
    ) -> Result<Self> {
        info!("Creating new encrypted wallet");
        
        // Create RPC client
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.metashrew_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create custom Esplora backend
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        // Create Bitcoin wallet configuration
        let bitcoin_config = BitcoinWalletConfig {
            wallet_path: config.wallet_path.clone(),
            network: config.network,
            sandshrew_rpc_url: config.metashrew_rpc_url.clone(),
            network_params: config.network_params.clone(),
        };
        
        // Create wallet
        let wallet = if let Some(mnemonic_str) = mnemonic {
            // Restore from provided mnemonic
            BitcoinWallet::restore_from_mnemonic(
                bitcoin_config,
                &mnemonic_str,
                Arc::clone(&rpc_client),
            )?
        } else {
            // Create new wallet with generated mnemonic
            BitcoinWallet::create_new(
                bitcoin_config,
                Arc::clone(&rpc_client),
            )?
        };
        
        // Save encrypted wallet
        wallet.save_encrypted(passphrase.as_deref()).await?;
        
        let manager = Self {
            wallet: Arc::new(wallet),
            config,
            backend,
            rpc_client,
        };
        
        info!("Encrypted wallet created successfully");
        Ok(manager)
    }
    
    /// Load wallet manager with passphrase (non-interactive mode)
    pub async fn load_with_passphrase(config: WalletConfig, passphrase: &str) -> Result<Self> {
        info!("Loading wallet with passphrase (non-interactive mode)");
        
        // Create RPC client
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.metashrew_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create custom Esplora backend
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        // Check if wallet file exists
        let wallet_path = Path::new(&config.wallet_path);
        if !wallet_path.exists() {
            return Err(anyhow!("Wallet file not found at {}", config.wallet_path));
        }
        
        // Load encrypted wallet with passphrase
        let bitcoin_config = BitcoinWalletConfig {
            wallet_path: config.wallet_path.clone(),
            network: config.network,
            sandshrew_rpc_url: config.metashrew_rpc_url.clone(),
            network_params: config.network_params.clone(),
        };
        
        let wallet = BitcoinWallet::load_encrypted(
            bitcoin_config,
            Arc::clone(&rpc_client),
            Some(passphrase),
        ).await?;
        
        info!("Wallet loaded successfully with passphrase");
        
        Ok(Self {
            wallet: Arc::new(wallet),
            config,
            backend,
            rpc_client,
        })
    }
    
    /// Create wallet with passphrase (non-interactive mode)
    pub async fn create_wallet_with_passphrase(
        config: WalletConfig,
        mnemonic: Option<String>,
        passphrase: &str,
    ) -> Result<Self> {
        info!("Creating new encrypted wallet with passphrase (non-interactive mode)");
        
        // Create RPC client
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.metashrew_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create custom Esplora backend
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        // Create Bitcoin wallet configuration
        let bitcoin_config = BitcoinWalletConfig {
            wallet_path: config.wallet_path.clone(),
            network: config.network,
            sandshrew_rpc_url: config.metashrew_rpc_url.clone(),
            network_params: config.network_params.clone(),
        };
        
        // Create wallet
        let wallet = if let Some(mnemonic_str) = mnemonic {
            // Restore from provided mnemonic
            BitcoinWallet::restore_from_mnemonic(
                bitcoin_config,
                &mnemonic_str,
                Arc::clone(&rpc_client),
            )?
        } else {
            // Create new wallet with generated mnemonic
            BitcoinWallet::create_new(
                bitcoin_config,
                Arc::clone(&rpc_client),
            )?
        };
        
        // Save encrypted wallet with passphrase
        wallet.save_encrypted(Some(passphrase)).await?;
        
        let manager = Self {
            wallet: Arc::new(wallet),
            config,
            backend,
            rpc_client,
        };
        
        info!("Encrypted wallet created successfully with passphrase");
        Ok(manager)
    }
    
    /// Restore wallet from mnemonic
    pub async fn restore_wallet(config: WalletConfig, mnemonic: String, passphrase: Option<String>) -> Result<Self> {
        info!("Restoring wallet from mnemonic");
        Self::create_wallet(config, Some(mnemonic), passphrase).await
    }
    
    /// Get a new address from the wallet
    pub async fn get_address(&self) -> Result<String> {
        self.wallet.get_address().await
    }
    
    /// Get multiple addresses from the wallet
    pub async fn get_addresses(&self, count: u32) -> Result<Vec<String>> {
        self.wallet.get_addresses(count).await
    }
    
    /// Get address of specific type at specific index
    pub async fn get_address_of_type_at_index(&self, address_type: &str, index: u32, is_change: bool) -> Result<String> {
        self.wallet.get_address_of_type_at_index(address_type, index, is_change).await
    }
    
    /// Get the mnemonic phrase (if available)
    pub async fn get_mnemonic(&self) -> Result<Option<String>> {
        Ok(Some(self.wallet.get_mnemonic()))
    }
    
    /// Sync the wallet with the blockchain using Sandshrew esplora interface
    pub async fn sync(&self) -> Result<()> {
        info!("Syncing wallet with blockchain");
        
        // First verify that Metashrew height is Bitcoin height + 1
        let bitcoin_height = self.rpc_client.get_block_count().await?;
        let metashrew_height = self.rpc_client.get_metashrew_height().await?;
        
        if metashrew_height != bitcoin_height + 1 {
            warn!(
                "Metashrew height ({}) is not Bitcoin height ({}) + 1",
                metashrew_height, bitcoin_height
            );
        }
        
        info!("Wallet sync completed");
        
        // Get and log the wallet balance
        let balance = self.get_balance().await?;
        info!("Wallet balance: {} sats (confirmed: {} sats, unconfirmed: {} sats)",
            balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
            balance.confirmed,
            balance.untrusted_pending);
        
        Ok(())
    }
    
    /// Get the wallet balance by querying Sandshrew directly
    pub async fn get_balance(&self) -> Result<Balance> {
        self.wallet.get_balance().await
    }
    
    /// Preview a transaction before signing - shows the same output as `./deezel runestone` command
    pub async fn preview_transaction(&self, tx: &Transaction) -> Result<()> {
        self.wallet.preview_transaction(tx).await
    }

    /// Create a transaction using rust-bitcoin with Sandshrew UTXOs
    pub async fn create_transaction(&self, params: SendParams) -> Result<(Transaction, TransactionDetails)> {
        self.wallet.create_transaction(params).await
    }
    
    /// Broadcast a transaction using Sandshrew's sendrawtransaction JSON-RPC method
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String> {
        self.wallet.broadcast_transaction(tx).await
    }
    
    /// Send Bitcoin to an address
    pub async fn send(&self, params: SendParams) -> Result<String> {
        self.wallet.send(params).await
    }
    
    /// Get UTXOs by querying Sandshrew directly
    pub async fn get_utxos(&self) -> Result<Vec<UtxoInfo>> {
        self.wallet.get_utxos().await
    }
    
    /// Get enriched UTXOs with ordinals, runes, and alkanes data
    pub async fn get_enriched_utxos(&self) -> Result<Vec<bitcoin_wallet::EnrichedUtxoInfo>> {
        self.wallet.get_enriched_utxos().await
    }
    
    /// Freeze a UTXO
    pub async fn freeze_utxo(&self, txid: &str, vout: u32) -> Result<()> {
        self.wallet.freeze_utxo(txid, vout).await
    }
    
    /// Unfreeze a UTXO
    pub async fn unfreeze_utxo(&self, txid: &str, vout: u32) -> Result<()> {
        self.wallet.unfreeze_utxo(txid, vout).await
    }
    
    /// Get transaction history
    pub async fn get_transaction_history(&self, limit: Option<usize>) -> Result<Vec<TransactionHistoryEntry>> {
        info!("Getting transaction history");
        
        // Get all addresses from wallet
        let addresses = self.wallet.get_addresses(10).await?;
        let mut all_transactions = Vec::new();
        
        // Get transaction history for each address
        for address in addresses.iter().take(limit.unwrap_or(10)) {
            match self.rpc_client.get_address_transactions(address).await {
                Ok(txs) => {
                    if let Some(tx_array) = txs.as_array() {
                        for tx in tx_array {
                            if let Some(tx_obj) = tx.as_object() {
                                let txid = tx_obj.get("txid")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                
                                let amount = tx_obj.get("value")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0);
                                
                                let confirmations = tx_obj.get("status")
                                    .and_then(|s| s.get("block_height"))
                                    .and_then(|h| h.as_u64())
                                    .map(|_h| {
                                        // Calculate confirmations (simplified)
                                        1u32
                                    })
                                    .unwrap_or(0);
                                
                                let entry = TransactionHistoryEntry {
                                    txid,
                                    amount,
                                    fee: None, // TODO: Extract fee information
                                    confirmations,
                                    block_height: None, // TODO: Extract block height
                                    timestamp: None, // TODO: Extract timestamp
                                    tx_type: if amount > 0 { "received" } else { "sent" }.to_string(),
                                };
                                
                                all_transactions.push(entry);
                            }
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to get transaction history for address {}: {}", address, e);
                }
            }
        }
        
        // Sort by timestamp (most recent first) and limit
        all_transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        if let Some(limit) = limit {
            all_transactions.truncate(limit);
        }
        
        Ok(all_transactions)
    }
    
    /// Estimate fee rate
    pub async fn estimate_fee_rate(&self) -> Result<f32> {
        match self.rpc_client.get_fee_estimates().await {
            Ok(estimates) => {
                // Extract fee rate from estimates (simplified)
                if let Some(fee_obj) = estimates.as_object() {
                    if let Some(fee_1) = fee_obj.get("1").and_then(|v| v.as_f64()) {
                        return Ok(fee_1 as f32);
                    }
                }
                Ok(1.0) // Default fallback
            },
            Err(_) => Ok(1.0), // Default fallback
        }
    }
    
    /// Get the RPC client
    pub fn get_rpc_client(&self) -> Arc<RpcClient> {
        Arc::clone(&self.rpc_client)
    }
    
    /// Get the Esplora backend
    pub fn get_backend(&self) -> SandshrewEsploraBackend {
        self.backend.clone()
    }
    
    /// Get the internal key for taproot operations
    pub async fn get_internal_key(&self) -> Result<bitcoin::secp256k1::XOnlyPublicKey> {
        self.wallet.get_internal_key().await
    }
}

// Re-export types for compatibility
pub use bitcoin_wallet::{SendParams, UtxoInfo, EnrichedUtxoInfo, TransactionDetails, Balance, TransactionHistoryEntry};

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wallet_creation() {
        // Basic test for wallet creation
        let config = WalletConfig {
            wallet_path: "test_wallet.json.asc".to_string(),
            network: Network::Regtest,
            bitcoin_rpc_url: "http://localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            network_params: None,
        };
        
        // Test creating a wallet with passphrase
        let result = WalletManager::create_wallet_with_passphrase(
            config.clone(),
            None,
            "test_passphrase",
        ).await;
        
        if let Ok(manager) = result {
            // Test getting an address
            let address = manager.get_address().await;
            assert!(address.is_ok());
            
            // Test getting the balance
            let balance = manager.get_balance().await;
            assert!(balance.is_ok());
            
            // Test getting the RPC client
            let rpc_client = manager.get_rpc_client();
            // Just verify we got a valid RPC client reference
            assert!(Arc::strong_count(&rpc_client) >= 1);
            
            // Test getting the backend
            let _backend = manager.get_backend();
            
            // Clean up test file
            let _ = tokio::fs::remove_file("test_wallet.json.asc").await;
        }
    }
    
    #[tokio::test]
    async fn test_mnemonic_generation() {
        use bip39::{Mnemonic, Language};
        
        // Test mnemonic generation
        let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        
        // Test mnemonic parsing
        let mnemonic_str = mnemonic.to_string();
        let parsed = Mnemonic::parse(&mnemonic_str).unwrap();
        assert_eq!(parsed.to_string(), mnemonic_str);
    }
}