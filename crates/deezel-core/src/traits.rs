//! Core traits for generic deezel operations
//!
//! This module defines the fundamental traits that enable deezel to work with
//! different backends in a generic way, following the same patterns as metashrew-runtime.

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Block, Transaction, Txid, Address, Network};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Trait for atomic batch operations
///
/// Similar to metashrew's BatchLike, this enables collecting multiple operations
/// into a single atomic batch.
pub trait BatchLike {
    /// Add a key-value pair to the batch
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V);
    
    /// Mark a key for deletion in the batch
    fn delete<K: AsRef<[u8]>>(&mut self, key: K);
    
    /// Create a new empty batch
    fn default() -> Self;
}

/// Generic trait for wallet storage backends
///
/// This abstracts wallet data persistence to enable different storage backends:
/// - CLI: File-based storage (wallet.dat, etc.)
/// - Web: Browser localStorage/IndexedDB
/// - Test: In-memory storage
#[async_trait]
pub trait WalletStorageLike {
    type Error: std::fmt::Debug + Send + Sync + std::error::Error + 'static;
    type Batch: BatchLike;

    /// Save wallet data
    async fn save_wallet(&mut self, name: &str, data: &[u8]) -> Result<(), Self::Error>;
    
    /// Load wallet data
    async fn load_wallet(&self, name: &str) -> Result<Option<Vec<u8>>, Self::Error>;
    
    /// List available wallets
    async fn list_wallets(&self) -> Result<Vec<String>, Self::Error>;
    
    /// Delete a wallet
    async fn delete_wallet(&mut self, name: &str) -> Result<(), Self::Error>;
    
    /// Check if wallet exists
    async fn wallet_exists(&self, name: &str) -> Result<bool, Self::Error>;
    
    /// Create a batch for atomic operations
    fn create_batch(&self) -> Self::Batch;
    
    /// Write a batch atomically
    async fn write_batch(&mut self, batch: Self::Batch) -> Result<(), Self::Error>;
}

/// Generic trait for configuration storage
///
/// Abstracts configuration persistence across different environments.
#[async_trait]
pub trait ConfigStorageLike {
    type Error: std::fmt::Debug + Send + Sync + std::error::Error + 'static;

    /// Save configuration
    async fn save_config<T: Serialize + Send + Sync>(&mut self, key: &str, config: &T) -> Result<(), Self::Error>;
    
    /// Load configuration
    async fn load_config<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, Self::Error>;
    
    /// Delete configuration
    async fn delete_config(&mut self, key: &str) -> Result<(), Self::Error>;
    
    /// List configuration keys
    async fn list_configs(&self) -> Result<Vec<String>, Self::Error>;
}

/// Generic trait for RPC client operations
///
/// This abstracts RPC calls to enable different implementations:
/// - CLI: HTTP requests via reqwest
/// - Web: Fetch API calls
/// - Test: Mock responses
#[async_trait]
pub trait RpcClientLike {
    type Error: std::fmt::Debug + Send + Sync + std::error::Error + 'static;

    /// Make a JSON-RPC call
    async fn call_rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Self::Error>;
    
    /// Get current block height
    async fn get_block_height(&self) -> Result<u64, Self::Error>;
    
    /// Get transaction by ID
    async fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, Self::Error>;
    
    /// Broadcast transaction
    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid, Self::Error>;
    
    /// Get address balance
    async fn get_address_balance(&self, address: &Address) -> Result<u64, Self::Error>;
    
    /// Get address UTXOs
    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<serde_json::Value>, Self::Error>;
}

/// Generic trait for blockchain data access
///
/// Abstracts blockchain queries for different data sources.
#[async_trait]
pub trait BlockchainClientLike {
    type Error: std::fmt::Debug + Send + Sync + std::error::Error + 'static;

    /// Get block by height
    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Self::Error>;
    
    /// Get block by hash
    async fn get_block_by_hash(&self, hash: &str) -> Result<Option<Block>, Self::Error>;
    
    /// Get current tip height
    async fn get_tip_height(&self) -> Result<u64, Self::Error>;
    
    /// Get fee estimates
    async fn get_fee_estimates(&self) -> Result<HashMap<String, f64>, Self::Error>;
}

/// Generic trait for filesystem operations
///
/// Abstracts file operations to enable different implementations:
/// - CLI: Standard filesystem operations
/// - Web: Browser File API or virtual filesystem
/// - Test: In-memory filesystem
#[async_trait]
pub trait FilesystemLike {
    type Error: std::fmt::Debug + Send + Sync + std::error::Error + 'static;

    /// Read file contents
    async fn read_file(&self, path: &str) -> Result<Vec<u8>, Self::Error>;
    
    /// Write file contents
    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<(), Self::Error>;
    
    /// Check if file exists
    async fn file_exists(&self, path: &str) -> Result<bool, Self::Error>;
    
    /// Create directory
    async fn create_dir(&self, path: &str) -> Result<(), Self::Error>;
    
    /// List directory contents
    async fn list_dir(&self, path: &str) -> Result<Vec<String>, Self::Error>;
    
    /// Delete file
    async fn delete_file(&self, path: &str) -> Result<(), Self::Error>;
    
    /// Get file metadata
    async fn file_metadata(&self, path: &str) -> Result<FileMetadata, Self::Error>;
}

/// File metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub modified: u64, // Unix timestamp
    pub is_dir: bool,
}

/// Generic trait for WASM runtime operations
///
/// Abstracts WASM execution for alkanes inspection and simulation.
#[async_trait]
pub trait WasmRuntimeLike {
    type Error: std::fmt::Debug + Send + Sync + std::error::Error + 'static;

    /// Load WASM module from bytes
    async fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<(), Self::Error>;
    
    /// Execute WASM function
    async fn execute_function(&mut self, name: &str, args: &[u8]) -> Result<Vec<u8>, Self::Error>;
    
    /// Get exported functions
    async fn get_exports(&self) -> Result<Vec<String>, Self::Error>;
    
    /// Set memory limits
    fn set_memory_limit(&mut self, limit: usize);
    
    /// Set execution timeout
    fn set_timeout(&mut self, timeout_ms: u64);
}

/// Result type for atomic operations
#[derive(Debug, Clone)]
pub struct AtomicResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub error: Option<String>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(with = "network_serde")]
    pub network: Network,
    pub rpc_url: String,
    pub esplora_url: Option<String>,
    pub metashrew_url: Option<String>,
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub name: String,
    #[serde(with = "network_serde")]
    pub network: Network,
    pub descriptor: Option<String>,
    pub mnemonic_path: Option<String>,
}

/// Custom serde module for Network
pub mod network_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let network_str = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        };
        serializer.serialize_str(network_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(serde::de::Error::custom(format!("Unknown network: {}", s))),
        }
    }
}

/// RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub bitcoin_rpc_url: String,
    pub ord_rpc_url: Option<String>,
    pub esplora_url: Option<String>,
    pub metashrew_url: Option<String>,
    pub timeout_ms: u64,
    pub max_retries: u32,
}

/// Alkanes configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesConfig {
    pub wasm_cache_dir: String,
    pub max_memory: usize,
    pub execution_timeout_ms: u64,
    pub enable_simulation: bool,
}