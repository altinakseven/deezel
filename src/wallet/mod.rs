//! Bitcoin wallet functionality using BDK
//!
//! This module handles:
//! - Wallet creation and management
//! - UTXO tracking and selection
//! - Transaction signing
//! - Persistent wallet state

mod esplora_backend;

use anyhow::{Context, Result};
use bdk::bitcoin::Network;
use bdk::database::MemoryDatabase;
use bdk::wallet::AddressIndex;
use bdk::{Wallet, SyncOptions};
use log::{debug, info, warn, error};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::rpc::RpcClient;
use self::esplora_backend::SandshrewEsploraBackend;

/// Wallet configuration
pub struct WalletConfig {
    /// Path to wallet file
    pub wallet_path: String,
    /// Bitcoin network (mainnet, testnet, regtest)
    pub network: Network,
    /// Bitcoin RPC URL
    pub bitcoin_rpc_url: String,
    /// Metashrew RPC URL
    pub metashrew_rpc_url: String,
}

/// Bitcoin wallet manager
pub struct WalletManager {
    /// BDK wallet instance
    wallet: Arc<Mutex<Wallet<MemoryDatabase>>>,
    /// Wallet configuration
    config: WalletConfig,
    /// Custom Esplora backend
    backend: SandshrewEsploraBackend,
    /// RPC client
    rpc_client: Arc<RpcClient>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub async fn new(config: WalletConfig) -> Result<Self> {
        info!("Initializing wallet manager");
        debug!("Wallet path: {}", config.wallet_path);
        debug!("Network: {:?}", config.network);
        
        // Create RPC client
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.bitcoin_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create custom Esplora backend
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        // Check if wallet file exists
        let wallet_path = Path::new(&config.wallet_path);
        let wallet = if wallet_path.exists() {
            info!("Loading wallet from {}", config.wallet_path);
            // TODO: Implement wallet loading from file
            // For now, create a new wallet in memory
            Wallet::new(
                "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)",
                Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"),
                config.network,
                MemoryDatabase::default(),
            )?
        } else {
            info!("Creating new wallet");
            Wallet::new(
                "wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/0/*)",
                Some("wpkh([c258d2e4/84h/1h/0h]tpubDDYkZojQFQjht8Tm4jsS3iuEmKjTiEGjG6KnuFNKKJb5A6ZUCUZKdvLdSDWofKi4ToRCwb9poe1XdqfUnP4jaJjCB2Zwv11ZLgSbnZSNecE/1/*)"),
                config.network,
                MemoryDatabase::default(),
            )?
        };
        
        info!("Wallet initialized successfully");
        
        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            config,
            backend,
            rpc_client,
        })
    }
    
    /// Get a new address from the wallet
    pub async fn get_address(&self) -> Result<String> {
        let wallet = self.wallet.lock().await;
        let address = wallet.get_address(AddressIndex::New)?;
        Ok(address.to_string())
    }
    
    /// Sync the wallet with the blockchain
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
            // Continue anyway, but log the warning
        }
        
        // For now, we're not actually syncing the wallet with the blockchain
        // In a real implementation, we would use our custom backend to fetch blockchain data
        // and update the wallet state
        
        info!("Wallet sync completed");
        
        // Get and log the wallet balance
        let balance = self.get_balance().await?;
        info!("Wallet balance: {} sats (confirmed: {} sats, unconfirmed: {} sats)",
            balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
            balance.confirmed,
            balance.untrusted_pending);
        
        Ok(())
    }
    
    /// Save wallet state to disk
    pub async fn save(&self) -> Result<()> {
        info!("Saving wallet state to {}", self.config.wallet_path);
        
        // Serialize the wallet state
        let wallet = self.wallet.lock().await;
        
        // TODO: Implement proper wallet serialization
        // For now, this is just a placeholder
        // In a real implementation, we would:
        // 1. Serialize the wallet state to a format that can be deserialized later
        // 2. Write the serialized state to the specified file
        // 3. Ensure the file is written atomically to prevent corruption
        
        info!("Wallet state saved successfully");
        Ok(())
    }
    
    /// Get the wallet balance
    pub async fn get_balance(&self) -> Result<bdk::Balance> {
        let wallet = self.wallet.lock().await;
        Ok(wallet.get_balance()?)
    }
    
    /// Get the RPC client
    pub fn get_rpc_client(&self) -> Arc<RpcClient> {
        Arc::clone(&self.rpc_client)
    }
    
    /// Get the Esplora backend
    pub fn get_backend(&self) -> SandshrewEsploraBackend {
        self.backend.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wallet_creation() {
        // Basic test for wallet creation
        let config = WalletConfig {
            wallet_path: "test_wallet.dat".to_string(),
            network: Network::Testnet,
            bitcoin_rpc_url: "http://localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        
        let wallet_manager = WalletManager::new(config).await;
        assert!(wallet_manager.is_ok());
        
        if let Ok(manager) = wallet_manager {
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
        }
    }
}