//! Trait abstractions for platform-agnostic functionality
//!
//! This module defines the core traits that allow deezel-common to work
//! across different environments (native, WASM, testing) by abstracting
//! away platform-specific operations.
//!
//! The trait system is designed to support the complete deezel functionality:
//! - Wallet operations (create, send, balance, UTXOs, etc.)
//! - Bitcoin Core RPC operations
//! - Metashrew/Sandshrew RPC operations  
//! - Alkanes smart contract operations
//! - Runestone analysis
//! - Protorunes operations
//! - Block monitoring
//! - Esplora API operations
//! - Address resolution
//! - Network abstraction

use crate::Result;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use bitcoin::{Network, Transaction, ScriptBuf};

/// Trait for making JSON-RPC calls
///
/// This abstraction allows different implementations for different environments:
/// - Native: Uses reqwest for HTTP calls
/// - WASM: Uses fetch API
/// - Testing: Uses mocks
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait JsonRpcProvider: Send + Sync {
    /// Make a JSON-RPC call to the specified URL
    async fn call(
        &self,
        url: &str,
        method: &str,
        params: JsonValue,
        id: u64,
    ) -> Result<JsonValue>;
    
    /// Get bytecode for an alkane contract (convenience method)
    async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String>;
    
    /// Get the timeout for requests (in seconds)
    fn timeout_seconds(&self) -> u64 {
        600 // Default 10 minutes
    }
    
    /// Check if the provider supports a specific URL scheme
    fn supports_url(&self, url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }
}

/// Trait for making JSON-RPC calls (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait JsonRpcProvider {
    /// Make a JSON-RPC call to the specified URL
    async fn call(
        &self,
        url: &str,
        method: &str,
        params: JsonValue,
        id: u64,
    ) -> Result<JsonValue>;
    
    /// Get bytecode for an alkane contract (convenience method)
    async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String>;
    
    /// Get the timeout for requests (in seconds)
    fn timeout_seconds(&self) -> u64 {
        600 // Default 10 minutes
    }
    
    /// Check if the provider supports a specific URL scheme
    fn supports_url(&self, url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }
}

/// Trait for storage operations (reading/writing files, configuration, etc.)
///
/// This abstraction allows different implementations:
/// - Native: Uses std::fs for file operations
/// - WASM: Uses localStorage/IndexedDB
/// - Testing: Uses in-memory storage
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait StorageProvider: Send + Sync {
    /// Read data from storage
    async fn read(&self, key: &str) -> Result<Vec<u8>>;
    
    /// Write data to storage
    async fn write(&self, key: &str, data: &[u8]) -> Result<()>;
    
    /// Check if a key exists in storage
    async fn exists(&self, key: &str) -> Result<bool>;
    
    /// Delete data from storage
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// List all keys with a given prefix
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>>;
    
    /// Get the storage type identifier
    fn storage_type(&self) -> &'static str;
}

/// Trait for storage operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait StorageProvider {
    /// Read data from storage
    async fn read(&self, key: &str) -> Result<Vec<u8>>;
    
    /// Write data to storage
    async fn write(&self, key: &str, data: &[u8]) -> Result<()>;
    
    /// Check if a key exists in storage
    async fn exists(&self, key: &str) -> Result<bool>;
    
    /// Delete data from storage
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// List all keys with a given prefix
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>>;
    
    /// Get the storage type identifier
    fn storage_type(&self) -> &'static str;
}

/// Trait for network operations beyond JSON-RPC
///
/// This handles general HTTP requests, file downloads, etc.
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait NetworkProvider: Send + Sync {
    /// Make an HTTP GET request
    async fn get(&self, url: &str) -> Result<Vec<u8>>;
    
    /// Make an HTTP POST request
    async fn post(&self, url: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>>;
    
    /// Download a file from a URL
    async fn download(&self, url: &str) -> Result<Vec<u8>> {
        self.get(url).await
    }
    
    /// Check if a URL is reachable
    async fn is_reachable(&self, url: &str) -> bool;
    
    /// Get the user agent string
    fn user_agent(&self) -> &str {
        "deezel-common/0.1.0"
    }
}

/// Trait for network operations beyond JSON-RPC (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait NetworkProvider {
    /// Make an HTTP GET request
    async fn get(&self, url: &str) -> Result<Vec<u8>>;
    
    /// Make an HTTP POST request
    async fn post(&self, url: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>>;
    
    /// Download a file from a URL
    async fn download(&self, url: &str) -> Result<Vec<u8>> {
        self.get(url).await
    }
    
    /// Check if a URL is reachable
    async fn is_reachable(&self, url: &str) -> bool;
    
    /// Get the user agent string
    fn user_agent(&self) -> &str {
        "deezel-common/0.1.0"
    }
}

/// Trait for cryptographic operations
///
/// This allows different crypto implementations for different environments
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait CryptoProvider: Send + Sync {
    /// Generate random bytes
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>>;
    
    /// Hash data with SHA256
    fn sha256(&self, data: &[u8]) -> Result<[u8; 32]>;
    
    /// Hash data with SHA3-256 (Keccak256)
    fn sha3_256(&self, data: &[u8]) -> Result<[u8; 32]>;
    
    /// Encrypt data with AES-GCM
    async fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data with AES-GCM
    async fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    
    /// Derive key using PBKDF2
    async fn pbkdf2_derive(&self, password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Result<Vec<u8>>;
}

/// Trait for cryptographic operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait CryptoProvider {
    /// Generate random bytes
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>>;
    
    /// Hash data with SHA256
    fn sha256(&self, data: &[u8]) -> Result<[u8; 32]>;
    
    /// Hash data with SHA3-256 (Keccak256)
    fn sha3_256(&self, data: &[u8]) -> Result<[u8; 32]>;
    
    /// Encrypt data with AES-GCM
    async fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data with AES-GCM
    async fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    
    /// Derive key using PBKDF2
    async fn pbkdf2_derive(&self, password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Result<Vec<u8>>;
}

/// Trait for time operations
///
/// This abstracts time-related operations for different environments
#[cfg(not(feature = "web-compat"))]
pub trait TimeProvider: Send + Sync {
    /// Get current Unix timestamp in seconds
    fn now_secs(&self) -> u64;
    
    /// Get current Unix timestamp in milliseconds
    fn now_millis(&self) -> u64;
    
    /// Sleep for the specified duration (in milliseconds)
    fn sleep_ms(&self, ms: u64) -> impl std::future::Future<Output = ()> + Send;
}

/// Trait for time operations (WASM version without Send + Sync)
#[cfg(feature = "web-compat")]
pub trait TimeProvider {
    /// Get current Unix timestamp in seconds
    fn now_secs(&self) -> u64;
    
    /// Get current Unix timestamp in milliseconds
    fn now_millis(&self) -> u64;
    
    /// Sleep for the specified duration (in milliseconds)
    fn sleep_ms(&self, ms: u64) -> impl std::future::Future<Output = ()>;
}

/// Trait for logging operations
///
/// This allows different logging implementations
#[cfg(not(feature = "web-compat"))]
pub trait LogProvider: Send + Sync {
    /// Log a debug message
    fn debug(&self, message: &str);
    
    /// Log an info message
    fn info(&self, message: &str);
    
    /// Log a warning message
    fn warn(&self, message: &str);
    
    /// Log an error message
    fn error(&self, message: &str);
    
    /// Check if debug logging is enabled
    fn is_debug_enabled(&self) -> bool {
        true
    }
}

/// Trait for logging operations (WASM version without Send + Sync)
#[cfg(feature = "web-compat")]
pub trait LogProvider {
    /// Log a debug message
    fn debug(&self, message: &str);
    
    /// Log an info message
    fn info(&self, message: &str);
    
    /// Log a warning message
    fn warn(&self, message: &str);
    
    /// Log an error message
    fn error(&self, message: &str);
    
    /// Check if debug logging is enabled
    fn is_debug_enabled(&self) -> bool {
        true
    }
}

/// Trait for wallet operations
///
/// This abstracts all wallet functionality for cross-platform use
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait WalletProvider: Send + Sync {
    /// Create a new wallet
    async fn create_wallet(&self, config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Load an existing wallet
    async fn load_wallet(&self, config: WalletConfig, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Get wallet balance
    async fn get_balance(&self) -> Result<WalletBalance>;
    
    /// Get wallet address
    async fn get_address(&self) -> Result<String>;
    
    /// Get multiple addresses
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>>;
    
    /// Send Bitcoin transaction
    async fn send(&self, params: SendParams) -> Result<String>;
    
    /// Get UTXOs
    async fn get_utxos(&self, include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>>;
    
    /// Get transaction history
    async fn get_history(&self, count: u32, address: Option<String>) -> Result<Vec<TransactionInfo>>;
    
    /// Freeze/unfreeze UTXO
    async fn freeze_utxo(&self, utxo: String, reason: Option<String>) -> Result<()>;
    async fn unfreeze_utxo(&self, utxo: String) -> Result<()>;
    
    /// Create transaction without broadcasting
    async fn create_transaction(&self, params: SendParams) -> Result<String>;
    
    /// Sign transaction
    async fn sign_transaction(&self, tx_hex: String) -> Result<String>;
    
    /// Broadcast transaction
    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String>;
    
    /// Estimate fee
    async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate>;
    
    /// Get current fee rates
    async fn get_fee_rates(&self) -> Result<FeeRates>;
    
    /// Synchronize wallet
    async fn sync(&self) -> Result<()>;
    
    /// Backup wallet
    async fn backup(&self) -> Result<String>;
    
    /// Get mnemonic
    async fn get_mnemonic(&self) -> Result<Option<String>>;
    
    /// Get network
    fn get_network(&self) -> Network;
    
    /// Get internal key for wallet
    async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey>;
    
    /// Sign PSBT
    async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt>;
    
    /// Get keypair for wallet
    async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair>;
}

/// Trait for wallet operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait WalletProvider {
    /// Create a new wallet
    async fn create_wallet(&self, config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Load an existing wallet
    async fn load_wallet(&self, config: WalletConfig, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Get wallet balance
    async fn get_balance(&self) -> Result<WalletBalance>;
    
    /// Get wallet address
    async fn get_address(&self) -> Result<String>;
    
    /// Get multiple addresses
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>>;
    
    /// Send Bitcoin transaction
    async fn send(&self, params: SendParams) -> Result<String>;
    
    /// Get UTXOs
    async fn get_utxos(&self, include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>>;
    
    /// Get transaction history
    async fn get_history(&self, count: u32, address: Option<String>) -> Result<Vec<TransactionInfo>>;
    
    /// Freeze/unfreeze UTXO
    async fn freeze_utxo(&self, utxo: String, reason: Option<String>) -> Result<()>;
    async fn unfreeze_utxo(&self, utxo: String) -> Result<()>;
    
    /// Create transaction without broadcasting
    async fn create_transaction(&self, params: SendParams) -> Result<String>;
    
    /// Sign transaction
    async fn sign_transaction(&self, tx_hex: String) -> Result<String>;
    
    /// Broadcast transaction
    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String>;
    
    /// Estimate fee
    async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate>;
    
    /// Get current fee rates
    async fn get_fee_rates(&self) -> Result<FeeRates>;
    
    /// Synchronize wallet
    async fn sync(&self) -> Result<()>;
    
    /// Backup wallet
    async fn backup(&self) -> Result<String>;
    
    /// Get mnemonic
    async fn get_mnemonic(&self) -> Result<Option<String>>;
    
    /// Get network
    fn get_network(&self) -> Network;
    
    /// Get internal key for wallet
    async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey>;
    
    /// Sign PSBT
    async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt>;
    
    /// Get keypair for wallet
    async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair>;
}

/// Wallet configuration
#[derive(Debug, Clone)]
pub struct WalletConfig {
    pub wallet_path: String,
    pub network: Network,
    pub bitcoin_rpc_url: String,
    pub metashrew_rpc_url: String,
    pub network_params: Option<NetworkParams>,
}

/// Wallet information
#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub address: String,
    pub network: Network,
    pub mnemonic: Option<String>,
}

/// Wallet balance information
#[derive(Debug, Clone)]
pub struct WalletBalance {
    pub confirmed: u64,
    pub trusted_pending: u64,
    pub untrusted_pending: u64,
}

/// Address information
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub script_type: String,
    pub derivation_path: String,
    pub index: u32,
}

/// Send transaction parameters
#[derive(Debug, Clone)]
pub struct SendParams {
    pub address: String,
    pub amount: u64,
    pub fee_rate: Option<f32>,
    pub send_all: bool,
    pub from_address: Option<String>,
    pub change_address: Option<String>,
    pub auto_confirm: bool,
}

/// UTXO information
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub confirmations: u32,
    pub frozen: bool,
    pub freeze_reason: Option<String>,
    pub block_height: Option<u64>,
    pub has_inscriptions: bool,
    pub has_runes: bool,
    pub has_alkanes: bool,
    pub is_coinbase: bool,
}

/// Transaction information
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub txid: String,
    pub block_height: Option<u64>,
    pub block_time: Option<u64>,
    pub confirmed: bool,
    pub fee: Option<u64>,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

/// Transaction input
#[derive(Debug, Clone)]
pub struct TransactionInput {
    pub txid: String,
    pub vout: u32,
    pub address: Option<String>,
    pub amount: Option<u64>,
}

/// Transaction output
#[derive(Debug, Clone)]
pub struct TransactionOutput {
    pub address: Option<String>,
    pub amount: u64,
    pub script: ScriptBuf,
}

/// Fee estimate
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub fee_rate: f32,
    pub target_blocks: u32,
}

/// Fee rates
#[derive(Debug, Clone)]
pub struct FeeRates {
    pub fast: f32,
    pub medium: f32,
    pub slow: f32,
}

/// Network parameters
#[derive(Debug, Clone)]
pub struct NetworkParams {
    pub network: Network,
    pub magic: [u8; 4],
    pub default_port: u16,
    pub rpc_port: u16,
    pub bech32_hrp: String,
}

/// Trait for address resolution
///
/// This handles address identifiers like p2tr:0, [self:p2wpkh:1], etc.
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait AddressResolver: Send + Sync {
    /// Resolve address identifiers in a string
    async fn resolve_all_identifiers(&self, input: &str) -> Result<String>;
    
    /// Check if string contains identifiers
    fn contains_identifiers(&self, input: &str) -> bool;
    
    /// Get address for specific type and index
    async fn get_address(&self, address_type: &str, index: u32) -> Result<String>;
    
    /// List available address identifiers
    async fn list_identifiers(&self) -> Result<Vec<String>>;
}

/// Trait for address resolution (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait AddressResolver {
    /// Resolve address identifiers in a string
    async fn resolve_all_identifiers(&self, input: &str) -> Result<String>;
    
    /// Check if string contains identifiers
    fn contains_identifiers(&self, input: &str) -> bool;
    
    /// Get address for specific type and index
    async fn get_address(&self, address_type: &str, index: u32) -> Result<String>;
    
    /// List available address identifiers
    async fn list_identifiers(&self) -> Result<Vec<String>>;
}

/// Trait for Bitcoin Core RPC operations
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait BitcoinRpcProvider: Send + Sync {
    /// Get current block count
    async fn get_block_count(&self) -> Result<u64>;
    
    /// Generate blocks to address (regtest only)
    async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<JsonValue>;
    
    /// Get transaction hex
    async fn get_transaction_hex(&self, txid: &str) -> Result<String>;
    
    /// Get block by hash
    async fn get_block(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block hash by height
    async fn get_block_hash(&self, height: u64) -> Result<String>;
    
    /// Send raw transaction
    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String>;
    
    /// Get mempool info
    async fn get_mempool_info(&self) -> Result<JsonValue>;
    
    /// Estimate smart fee
    async fn estimate_smart_fee(&self, target: u32) -> Result<JsonValue>;
    
    /// Get Esplora blocks tip height
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64>;
    
    /// Trace transaction
    async fn trace_transaction(&self, txid: &str, vout: u32, block: Option<&str>, tx: Option<&str>) -> Result<serde_json::Value>;
}

/// Trait for Bitcoin Core RPC operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait BitcoinRpcProvider {
    /// Get current block count
    async fn get_block_count(&self) -> Result<u64>;
    
    /// Generate blocks to address (regtest only)
    async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<JsonValue>;
    
    /// Get transaction hex
    async fn get_transaction_hex(&self, txid: &str) -> Result<String>;
    
    /// Get block by hash
    async fn get_block(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block hash by height
    async fn get_block_hash(&self, height: u64) -> Result<String>;
    
    /// Send raw transaction
    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String>;
    
    /// Get mempool info
    async fn get_mempool_info(&self) -> Result<JsonValue>;
    
    /// Estimate smart fee
    async fn estimate_smart_fee(&self, target: u32) -> Result<JsonValue>;
    
    /// Get Esplora blocks tip height
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64>;
    
    /// Trace transaction
    async fn trace_transaction(&self, txid: &str, vout: u32, block: Option<&str>, tx: Option<&str>) -> Result<serde_json::Value>;
}

/// Trait for Metashrew/Sandshrew RPC operations
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait MetashrewRpcProvider: Send + Sync {
    /// Get Metashrew height
    async fn get_metashrew_height(&self) -> Result<u64>;
    
    /// Get contract metadata
    async fn get_contract_meta(&self, block: &str, tx: &str) -> Result<JsonValue>;
    
    /// Trace transaction outpoint
    async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue>;
    
    /// Get spendables by address
    async fn get_spendables_by_address(&self, address: &str) -> Result<JsonValue>;
    
    /// Get protorunes by address
    async fn get_protorunes_by_address(&self, address: &str) -> Result<JsonValue>;
    
    /// Get protorunes by outpoint
    async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue>;
}

/// Trait for Metashrew/Sandshrew RPC operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait MetashrewRpcProvider {
    /// Get Metashrew height
    async fn get_metashrew_height(&self) -> Result<u64>;
    
    /// Get contract metadata
    async fn get_contract_meta(&self, block: &str, tx: &str) -> Result<JsonValue>;
    
    /// Trace transaction outpoint
    async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue>;
    
    /// Get spendables by address
    async fn get_spendables_by_address(&self, address: &str) -> Result<JsonValue>;
    
    /// Get protorunes by address
    async fn get_protorunes_by_address(&self, address: &str) -> Result<JsonValue>;
    
    /// Get protorunes by outpoint
    async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue>;
}

/// Trait for Esplora API operations
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait EsploraProvider: Send + Sync {
    /// Get blocks tip hash
    async fn get_blocks_tip_hash(&self) -> Result<String>;
    
    /// Get blocks tip height
    async fn get_blocks_tip_height(&self) -> Result<u64>;
    
    /// Get blocks starting from height
    async fn get_blocks(&self, start_height: Option<u64>) -> Result<JsonValue>;
    
    /// Get block by height
    async fn get_block_by_height(&self, height: u64) -> Result<String>;
    
    /// Get block information
    async fn get_block(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block status
    async fn get_block_status(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block transaction IDs
    async fn get_block_txids(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block header
    async fn get_block_header(&self, hash: &str) -> Result<String>;
    
    /// Get raw block data
    async fn get_block_raw(&self, hash: &str) -> Result<String>;
    
    /// Get transaction ID by block hash and index
    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String>;
    
    /// Get block transactions
    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<JsonValue>;
    
    /// Get address information
    async fn get_address(&self, address: &str) -> Result<JsonValue>;
    
    /// Get address transactions
    async fn get_address_txs(&self, address: &str) -> Result<JsonValue>;
    
    /// Get address chain transactions
    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<JsonValue>;
    
    /// Get address mempool transactions
    async fn get_address_txs_mempool(&self, address: &str) -> Result<JsonValue>;
    
    /// Get address UTXOs
    async fn get_address_utxo(&self, address: &str) -> Result<JsonValue>;
    
    /// Search addresses by prefix
    async fn get_address_prefix(&self, prefix: &str) -> Result<JsonValue>;
    
    /// Get transaction information
    async fn get_tx(&self, txid: &str) -> Result<JsonValue>;
    
    /// Get transaction hex
    async fn get_tx_hex(&self, txid: &str) -> Result<String>;
    
    /// Get raw transaction
    async fn get_tx_raw(&self, txid: &str) -> Result<String>;
    
    /// Get transaction status
    async fn get_tx_status(&self, txid: &str) -> Result<JsonValue>;
    
    /// Get transaction merkle proof
    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<JsonValue>;
    
    /// Get transaction merkle block proof
    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String>;
    
    /// Get transaction output spend status
    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<JsonValue>;
    
    /// Get transaction output spends
    async fn get_tx_outspends(&self, txid: &str) -> Result<JsonValue>;
    
    /// Broadcast transaction
    async fn broadcast(&self, tx_hex: &str) -> Result<String>;
    
    /// Get mempool information
    async fn get_mempool(&self) -> Result<JsonValue>;
    
    /// Get mempool transaction IDs
    async fn get_mempool_txids(&self) -> Result<JsonValue>;
    
    /// Get recent mempool transactions
    async fn get_mempool_recent(&self) -> Result<JsonValue>;
    
    /// Get fee estimates
    async fn get_fee_estimates(&self) -> Result<JsonValue>;
}

/// Trait for Esplora API operations (web-compat version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait EsploraProvider {
    /// Get blocks tip hash
    async fn get_blocks_tip_hash(&self) -> Result<String>;
    
    /// Get blocks tip height
    async fn get_blocks_tip_height(&self) -> Result<u64>;
    
    /// Get blocks starting from height
    async fn get_blocks(&self, start_height: Option<u64>) -> Result<JsonValue>;
    
    /// Get block by height
    async fn get_block_by_height(&self, height: u64) -> Result<String>;
    
    /// Get block information
    async fn get_block(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block status
    async fn get_block_status(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block transaction IDs
    async fn get_block_txids(&self, hash: &str) -> Result<JsonValue>;
    
    /// Get block header
    async fn get_block_header(&self, hash: &str) -> Result<String>;
    
    /// Get raw block data
    async fn get_block_raw(&self, hash: &str) -> Result<String>;
    
    /// Get transaction ID by block hash and index
    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String>;
    
    /// Get block transactions
    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<JsonValue>;
    
    /// Get address information
    async fn get_address(&self, address: &str) -> Result<JsonValue>;
    
    /// Get address transactions
    async fn get_address_txs(&self, address: &str) -> Result<JsonValue>;
    
    /// Get address chain transactions
    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<JsonValue>;
    
    /// Get address mempool transactions
    async fn get_address_txs_mempool(&self, address: &str) -> Result<JsonValue>;
    
    /// Get address UTXOs
    async fn get_address_utxo(&self, address: &str) -> Result<JsonValue>;
    
    /// Search addresses by prefix
    async fn get_address_prefix(&self, prefix: &str) -> Result<JsonValue>;
    
    /// Get transaction information
    async fn get_tx(&self, txid: &str) -> Result<JsonValue>;
    
    /// Get transaction hex
    async fn get_tx_hex(&self, txid: &str) -> Result<String>;
    
    /// Get raw transaction
    async fn get_tx_raw(&self, txid: &str) -> Result<String>;
    
    /// Get transaction status
    async fn get_tx_status(&self, txid: &str) -> Result<JsonValue>;
    
    /// Get transaction merkle proof
    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<JsonValue>;
    
    /// Get transaction merkle block proof
    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String>;
    
    /// Get transaction output spend status
    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<JsonValue>;
    
    /// Get transaction output spends
    async fn get_tx_outspends(&self, txid: &str) -> Result<JsonValue>;
    
    /// Broadcast transaction
    async fn broadcast(&self, tx_hex: &str) -> Result<String>;
    
    /// Get mempool information
    async fn get_mempool(&self) -> Result<JsonValue>;
    
    /// Get mempool transaction IDs
    async fn get_mempool_txids(&self) -> Result<JsonValue>;
    
    /// Get recent mempool transactions
    async fn get_mempool_recent(&self) -> Result<JsonValue>;
    
    /// Get fee estimates
    async fn get_fee_estimates(&self) -> Result<JsonValue>;
}

/// Trait for runestone operations
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait RunestoneProvider: Send + Sync {
    /// Decode runestone from transaction
    async fn decode_runestone(&self, tx: &Transaction) -> Result<JsonValue>;
    
    /// Format runestone with decoded messages
    async fn format_runestone_with_decoded_messages(&self, tx: &Transaction) -> Result<JsonValue>;
    
    /// Analyze runestone from transaction ID
    async fn analyze_runestone(&self, txid: &str) -> Result<JsonValue>;
}

/// Trait for runestone operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait RunestoneProvider {
    /// Decode runestone from transaction
    async fn decode_runestone(&self, tx: &Transaction) -> Result<JsonValue>;
    
    /// Format runestone with decoded messages
    async fn format_runestone_with_decoded_messages(&self, tx: &Transaction) -> Result<JsonValue>;
    
    /// Analyze runestone from transaction ID
    async fn analyze_runestone(&self, txid: &str) -> Result<JsonValue>;
}

/// Trait for alkanes operations
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait AlkanesProvider: Send + Sync {
    /// Execute alkanes smart contract
    async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult>;
    
    /// Get alkanes balance
    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>>;
    
    /// Get token information
    async fn get_token_info(&self, alkane_id: &str) -> Result<JsonValue>;
    
    /// Trace alkanes transaction
    async fn trace(&self, outpoint: &str) -> Result<JsonValue>;
    
    /// Inspect alkanes bytecode
    async fn inspect(&self, target: &str, config: AlkanesInspectConfig) -> Result<AlkanesInspectResult>;
    
    /// Get bytecode for alkanes contract
    async fn get_bytecode(&self, alkane_id: &str) -> Result<String>;
    
    /// Simulate alkanes execution
    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue>;
}

/// Trait for alkanes operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait AlkanesProvider {
    /// Execute alkanes smart contract
    async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult>;
    
    /// Get alkanes balance
    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>>;
    
    /// Get token information
    async fn get_token_info(&self, alkane_id: &str) -> Result<JsonValue>;
    
    /// Trace alkanes transaction
    async fn trace(&self, outpoint: &str) -> Result<JsonValue>;
    
    /// Inspect alkanes bytecode
    async fn inspect(&self, target: &str, config: AlkanesInspectConfig) -> Result<AlkanesInspectResult>;
    
    /// Get bytecode for alkanes contract
    async fn get_bytecode(&self, alkane_id: &str) -> Result<String>;
    
    /// Simulate alkanes execution
    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue>;
}

/// Alkanes execute parameters
#[derive(Debug, Clone)]
pub struct AlkanesExecuteParams {
    pub inputs: String,
    pub to: String,
    pub change: Option<String>,
    pub fee_rate: Option<f32>,
    pub envelope: Option<String>,
    pub protostones: String,
    pub trace: bool,
    pub mine: bool,
    pub auto_confirm: bool,
    pub rebar: bool,
}

/// Alkanes execute result
#[derive(Debug, Clone)]
pub struct AlkanesExecuteResult {
    pub commit_txid: Option<String>,
    pub reveal_txid: String,
    pub commit_fee: Option<u64>,
    pub reveal_fee: u64,
    pub inputs_used: Vec<String>,
    pub outputs_created: Vec<String>,
    pub traces: Option<Vec<String>>,
}

/// Alkanes balance
#[derive(Debug, Clone)]
pub struct AlkanesBalance {
    pub name: String,
    pub symbol: String,
    pub balance: u128,
    pub alkane_id: AlkaneId,
}

/// Alkane ID
#[derive(Debug, Clone)]
pub struct AlkaneId {
    pub block: u64,
    pub tx: u64,
}

/// Alkanes inspect configuration
#[derive(Debug, Clone)]
pub struct AlkanesInspectConfig {
    pub disasm: bool,
    pub fuzz: bool,
    pub fuzz_ranges: Option<String>,
    pub meta: bool,
    pub codehash: bool,
}

/// Alkanes inspect result
#[derive(Debug, Clone)]
pub struct AlkanesInspectResult {
    pub alkane_id: AlkaneId,
    pub bytecode_length: usize,
    pub disassembly: Option<String>,
    pub metadata: Option<AlkaneMetadata>,
    pub codehash: Option<String>,
    pub fuzzing_results: Option<FuzzingResults>,
}

/// Alkane metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlkaneMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub methods: Vec<AlkaneMethod>,
}

/// Alkane method
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlkaneMethod {
    pub name: String,
    pub opcode: u128,
    pub params: Vec<String>,
    pub returns: String,
}

/// Fuzzing results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FuzzingResults {
    pub total_opcodes_tested: usize,
    pub opcodes_filtered_out: usize,
    pub successful_executions: usize,
    pub failed_executions: usize,
    pub implemented_opcodes: Vec<u128>,
    pub opcode_results: Vec<ExecutionResult>,
}

/// Combined provider trait that includes all functionality (WASM version without Send + Sync)
///
/// This is the main trait that implementations should provide for WASM targets
#[async_trait(?Send)]
#[cfg(target_arch = "wasm32")]
pub trait DeezelProvider:
    JsonRpcProvider +
    StorageProvider +
    NetworkProvider +
    CryptoProvider +
    TimeProvider +
    LogProvider +
    WalletProvider +
    AddressResolver +
    BitcoinRpcProvider +
    MetashrewRpcProvider +
    EsploraProvider +
    RunestoneProvider +
    AlkanesProvider +
    MonitorProvider +
    Clone
{
    /// Get provider name/type
    fn provider_name(&self) -> &str;
    
    /// Initialize the provider
    async fn initialize(&self) -> Result<()>;
    
    /// Shutdown the provider
    async fn shutdown(&self) -> Result<()>;
}

/// Execution result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_value: Option<i32>,
    pub return_data: Vec<u8>,
    pub error: Option<String>,
    pub execution_time_micros: u128,
    pub opcode: u128,
    pub host_calls: Vec<HostCall>,
}

/// Host call
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostCall {
    pub function_name: String,
    pub parameters: Vec<String>,
    pub result: String,
    pub timestamp_micros: u128,
}

/// Trait for monitoring operations
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait MonitorProvider: Send + Sync {
    /// Monitor blocks for events
    async fn monitor_blocks(&self, start: Option<u64>) -> Result<()>;
    
    /// Get block events
    async fn get_block_events(&self, height: u64) -> Result<Vec<BlockEvent>>;
}

/// Trait for monitoring operations (WASM version without Send + Sync)
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait MonitorProvider {
    /// Monitor blocks for events
    async fn monitor_blocks(&self, start: Option<u64>) -> Result<()>;
    
    /// Get block events
    async fn get_block_events(&self, height: u64) -> Result<Vec<BlockEvent>>;
}

/// Block event
#[derive(Debug, Clone)]
pub struct BlockEvent {
    pub event_type: String,
    pub block_height: u64,
    pub txid: String,
    pub data: JsonValue,
}

/// Combined provider trait that includes all functionality
///
/// This is the main trait that implementations should provide
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait DeezelProvider:
    JsonRpcProvider +
    StorageProvider +
    NetworkProvider +
    CryptoProvider +
    TimeProvider +
    LogProvider +
    WalletProvider +
    AddressResolver +
    BitcoinRpcProvider +
    MetashrewRpcProvider +
    EsploraProvider +
    RunestoneProvider +
    AlkanesProvider +
    MonitorProvider +
    Clone +
    Send +
    Sync
{
    /// Get provider name/type
    fn provider_name(&self) -> &str;
    
    /// Initialize the provider
    async fn initialize(&self) -> Result<()>;
    
    /// Shutdown the provider
    async fn shutdown(&self) -> Result<()>;
}

/// Combined provider trait that includes all functionality (web-compat version without Send + Sync)
///
/// This is the main trait that implementations should provide for web-compatible targets
#[async_trait(?Send)]
#[cfg(feature = "web-compat")]
pub trait DeezelProvider:
    JsonRpcProvider +
    StorageProvider +
    NetworkProvider +
    CryptoProvider +
    TimeProvider +
    LogProvider +
    WalletProvider +
    AddressResolver +
    BitcoinRpcProvider +
    MetashrewRpcProvider +
    EsploraProvider +
    RunestoneProvider +
    AlkanesProvider +
    MonitorProvider +
    Clone
{
    /// Get provider name/type
    fn provider_name(&self) -> &str;
    
    /// Initialize the provider
    async fn initialize(&self) -> Result<()>;
    
    /// Shutdown the provider
    async fn shutdown(&self) -> Result<()>;
}