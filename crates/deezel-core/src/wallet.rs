//! Generic wallet management

use anyhow::Result;
use bitcoin::Network;
use serde::{Serialize, Deserialize};
use crate::traits::{WalletStorageLike, ConfigStorageLike};

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub name: String,
    #[serde(with = "crate::traits::network_serde")]
    pub network: Network,
    pub descriptor: Option<String>,
    pub mnemonic_path: Option<String>,
}

/// Wallet management errors
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Wallet not found: {0}")]
    NotFound(String),
    
    #[error("Wallet already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Generic wallet manager
pub struct WalletManager<WS, CS>
where
    WS: WalletStorageLike,
    CS: ConfigStorageLike,
{
    wallet_storage: WS,
    config_storage: CS,
}

impl<WS, CS> WalletManager<WS, CS>
where
    WS: WalletStorageLike,
    CS: ConfigStorageLike,
{
    pub fn new(wallet_storage: WS, config_storage: CS) -> Self {
        Self {
            wallet_storage,
            config_storage,
        }
    }
    
    pub async fn create_wallet(&mut self, config: WalletConfig) -> Result<(), WalletError> {
        // Check if wallet already exists
        let exists = self.wallet_storage.wallet_exists(&config.name).await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))?;
            
        if exists {
            return Err(WalletError::AlreadyExists(config.name));
        }
        
        // Save wallet configuration
        self.config_storage.save_config(&format!("wallet_{}", config.name), &config).await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))?;
        
        // Create empty wallet data
        let wallet_data = b""; // Placeholder
        self.wallet_storage.save_wallet(&config.name, wallet_data).await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))?;
        
        Ok(())
    }
    
    pub async fn load_wallet(&self, name: &str) -> Result<Option<Vec<u8>>, WalletError> {
        self.wallet_storage.load_wallet(name).await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))
    }
    
    pub async fn list_wallets(&self) -> Result<Vec<String>, WalletError> {
        self.wallet_storage.list_wallets().await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))
    }
    
    pub async fn delete_wallet(&mut self, name: &str) -> Result<(), WalletError> {
        self.wallet_storage.delete_wallet(name).await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))?;
            
        self.config_storage.delete_config(&format!("wallet_{}", name)).await
            .map_err(|e| WalletError::Storage(format!("{:?}", e)))?;
        
        Ok(())
    }
}