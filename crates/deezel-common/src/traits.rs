//! Trait abstractions for platform-agnostic functionality
//
// This module defines the core traits that allow deezel-common to work
// across different environments (native, WASM, testing) by abstracting
// away platform-specific operations.
//
// The trait system is designed to support the complete deezel functionality:
// - Wallet operations (create, send, balance, UTXOs, etc.)
// - Bitcoin Core RPC operations
// - Metashrew/Sandshrew RPC operations  
// - Alkanes smart contract operations
// - Runestone analysis
// - Protorunes operations
// - Block monitoring
// - Esplora API operations
// - Address resolution
// - Network abstraction

use crate::Result;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use bitcoin::{Network, Transaction, ScriptBuf};
use crate::ord::{
    AddressInfo as OrdAddressInfo, Block as OrdBlock, Blocks as OrdBlocks, Children as OrdChildren,
    Inscription as OrdInscription, Inscriptions as OrdInscriptions, Output as OrdOutput,
    ParentInscriptions as OrdParents, SatResponse as OrdSat, RuneInfo as OrdRuneInfo,
    Runes as OrdRunes, TxInfo as OrdTxInfo,
};
use crate::alkanes::types::{EnhancedExecuteParams, EnhancedExecuteResult};
use alkanes_support::proto::alkanes as alkanes_pb;
use protorune_support::proto::protorune as protorune_pb;

#[cfg(not(target_arch = "wasm32"))]
use std::{vec::Vec, boxed::Box, string::String};
#[cfg(target_arch = "wasm32")]
use alloc::{vec::Vec, boxed::Box, string::String};

/// Trait for making JSON-RPC calls
#[async_trait(?Send)]
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
#[async_trait(?Send)]
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
#[async_trait(?Send)]
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
#[async_trait(?Send)]
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

/// Trait for PGP operations
#[async_trait(?Send)]
pub trait PgpProvider {
    /// Generate a new PGP key pair
    async fn generate_keypair(&self, user_id: &str, passphrase: Option<&str>) -> Result<PgpKeyPair>;
    
    /// Import a PGP key from armored text
    async fn import_key(&self, armored_key: &str) -> Result<PgpKey>;
    
    /// Export a PGP key to armored text
    async fn export_key(&self, key: &PgpKey, include_private: bool) -> Result<String>;
    
    /// Encrypt data with PGP
    async fn encrypt(&self, data: &[u8], recipient_keys: &[PgpKey], armor: bool) -> Result<Vec<u8>>;
    
    /// Decrypt data with PGP
    async fn decrypt(&self, encrypted_data: &[u8], private_key: &PgpKey, passphrase: Option<&str>) -> Result<Vec<u8>>;
    
    /// Sign data with PGP
    async fn sign(&self, data: &[u8], private_key: &PgpKey, passphrase: Option<&str>, armor: bool) -> Result<Vec<u8>>;
    
    /// Verify a PGP signature
    async fn verify(&self, data: &[u8], signature: &[u8], public_key: &PgpKey) -> Result<bool>;
    
    /// Encrypt and sign data
    async fn encrypt_and_sign(&self, data: &[u8], recipient_keys: &[PgpKey], signing_key: &PgpKey, passphrase: Option<&str>, armor: bool) -> Result<Vec<u8>>;
    
    /// Decrypt and verify data
    async fn decrypt_and_verify(&self, encrypted_data: &[u8], private_key: &PgpKey, sender_public_key: &PgpKey, passphrase: Option<&str>) -> Result<PgpDecryptResult>;
    
    /// List keys in keyring
    async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>>;
    
    /// Get key by ID or fingerprint
    async fn get_key(&self, identifier: &str) -> Result<Option<PgpKey>>;
    
    /// Delete key from keyring
    async fn delete_key(&self, identifier: &str) -> Result<()>;
    
    /// Change key passphrase
    async fn change_passphrase(&self, key: &PgpKey, old_passphrase: Option<&str>, new_passphrase: Option<&str>) -> Result<PgpKey>;
}

/// Trait for time operations
pub trait TimeProvider {
    /// Get current Unix timestamp in seconds
    fn now_secs(&self) -> u64;
    
    /// Get current Unix timestamp in milliseconds
    fn now_millis(&self) -> u64;
    
    /// Sleep for the specified duration (in milliseconds)
    fn sleep_ms(&self, ms: u64) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()>>>;
}

/// Trait for logging operations
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
#[async_trait(?Send)]
pub trait WalletProvider {
    /// Create a new wallet
    async fn create_wallet(&self, config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Load an existing wallet
    async fn load_wallet(&self, config: WalletConfig, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Get wallet balance
    async fn get_balance(&self, addresses: Option<Vec<String>>) -> Result<WalletBalance>;
    
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
    
    /// Freeze a UTXO
    async fn freeze_utxo(&self, utxo: String, reason: Option<String>) -> Result<()>;
    
    /// Unfreeze a UTXO
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

    /// Set the passphrase for the wallet
    fn set_passphrase(&mut self, passphrase: Option<String>);
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletBalance {
    pub confirmed: u64,
    pub pending: i64,
}

/// Address information
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub script_type: String,
    pub derivation_path: String,
    pub index: u32,
    pub used: bool,
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
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub script_pubkey: Option<ScriptBuf>,
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

/// PGP key pair (public and private key)
#[derive(Debug, Clone)]
pub struct PgpKeyPair {
    pub public_key: PgpKey,
    pub private_key: PgpKey,
    pub fingerprint: String,
    pub key_id: String,
}

/// PGP key (can be public or private)
#[derive(Debug, Clone)]
pub struct PgpKey {
    pub key_data: Vec<u8>,
    pub is_private: bool,
    pub fingerprint: String,
    pub key_id: String,
    pub user_ids: Vec<String>,
    pub creation_time: u64,
    pub expiration_time: Option<u64>,
    pub algorithm: PgpAlgorithm,
}

/// PGP algorithm information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PgpAlgorithm {
    pub public_key_algorithm: String,
    pub symmetric_algorithm: Option<String>,
    pub hash_algorithm: Option<String>,
    pub compression_algorithm: Option<String>,
}

/// PGP key information for listing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PgpKeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub user_ids: Vec<String>,
    pub is_private: bool,
    pub creation_time: u64,
    pub expiration_time: Option<u64>,
    pub algorithm: String,
    pub key_size: Option<u32>,
    pub is_expired: bool,
    pub is_revoked: bool,
}

/// Result of PGP decrypt and verify operation
#[derive(Debug, Clone)]
pub struct PgpDecryptResult {
    pub data: Vec<u8>,
    pub signature_valid: bool,
    pub signer_key_id: Option<String>,
    pub signature_time: Option<u64>,
}

/// PGP operation parameters
#[derive(Debug, Clone)]
pub struct PgpEncryptParams {
    pub data: Vec<u8>,
    pub recipient_keys: Vec<PgpKey>,
    pub armor: bool,
    pub compression: Option<String>,
    pub cipher: Option<String>,
}

/// PGP signing parameters
#[derive(Debug, Clone)]
pub struct PgpSignParams {
    pub data: Vec<u8>,
    pub signing_key: PgpKey,
    pub passphrase: Option<String>,
    pub armor: bool,
    pub detached: bool,
    pub hash_algorithm: Option<String>,
}


/// Trait for address resolution
#[async_trait(?Send)]
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

/// Trait for dynamic address derivation from master public keys
#[async_trait(?Send)]
pub trait KeystoreProvider {
    /// Derive addresses dynamically from master public key
    async fn derive_addresses(&self, master_public_key: &str, network: Network, script_types: &[&str], start_index: u32, count: u32) -> Result<Vec<KeystoreAddress>>;
    
    /// Get default addresses for display (first 5 of each type for given network)
    async fn get_default_addresses(&self, master_public_key: &str, network: Network) -> Result<Vec<KeystoreAddress>>;
    
    /// Parse address range specification (e.g., "p2tr:0-1000", "p2sh:0-500")
    fn parse_address_range(&self, range_spec: &str) -> Result<(String, u32, u32)>;
    
    /// Get keystore info from master public key
    async fn get_keystore_info(&self, master_public_key: &str, master_fingerprint: &str, created_at: u64, version: &str) -> Result<KeystoreInfo>;
}

/// Address information for keystore operations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeystoreAddress {
    /// The Bitcoin address
    pub address: String,
    /// Derivation path used to generate this address
    pub derivation_path: String,
    /// Index in the derivation sequence
    pub index: u32,
    /// Script type (P2WPKH, P2TR, etc.)
    pub script_type: String,
    /// Network name (optional, for display purposes)
    pub network: Option<String>,
}

/// Summary information about a keystore
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeystoreInfo {
    pub master_public_key: String,
    pub master_fingerprint: String,
    pub created_at: u64,
    pub version: String,
}

/// Trait for Bitcoin Core RPC operations
#[async_trait(?Send)]
pub trait BitcoinRpcProvider {
    /// Get current block count
    async fn get_block_count(&self) -> Result<u64>;
    
    /// Generate blocks to address (regtest only)
    async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<JsonValue>;

    /// Get a new address from the node's wallet
    async fn get_new_address(&self) -> Result<JsonValue>;
    
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

/// Trait for bitcoind RPC operations using bitcoincore_rpc_json types

/// Trait for Metashrew/Sandshrew RPC operations
#[async_trait(?Send)]
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
#[async_trait(?Send)]
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
    async fn get_address_info(&self, address: &str) -> Result<JsonValue>;
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
#[async_trait(?Send)]
pub trait RunestoneProvider {
    /// Decode runestone from transaction
    async fn decode_runestone(&self, tx: &Transaction) -> Result<JsonValue>;
    
    /// Format runestone with decoded messages
    async fn format_runestone_with_decoded_messages(&self, tx: &Transaction) -> Result<JsonValue>;
    
    /// Analyze runestone from transaction ID
    async fn analyze_runestone(&self, txid: &str) -> Result<JsonValue>;
}

/// Trait for ord operations
#[async_trait(?Send)]
pub trait OrdProvider {
    /// Get inscription by ID
    async fn get_inscription(&self, inscription_id: &str) -> Result<OrdInscription>;
    
    /// Get inscriptions for a block
    async fn get_inscriptions_in_block(&self, block_hash: &str) -> Result<OrdInscriptions>;
    /// Get address information
    async fn get_ord_address_info(&self, address: &str) -> Result<OrdAddressInfo>;
    /// Get block information
    async fn get_block_info(&self, query: &str) -> Result<OrdBlock>;
    /// Get latest block count
    async fn get_ord_block_count(&self) -> Result<u64>;
    /// Get latest blocks
    async fn get_ord_blocks(&self) -> Result<OrdBlocks>;
    /// Get children of an inscription
    async fn get_children(&self, inscription_id: &str, page: Option<u32>) -> Result<OrdChildren>;
    /// Get inscription content
    async fn get_content(&self, inscription_id: &str) -> Result<Vec<u8>>;
    /// Get all inscriptions
    async fn get_inscriptions(&self, page: Option<u32>) -> Result<OrdInscriptions>;
    /// Get output information
    async fn get_output(&self, output: &str) -> Result<OrdOutput>;
    /// Get parents of an inscription
    async fn get_parents(&self, inscription_id: &str, page: Option<u32>) -> Result<OrdParents>;
    /// Get rune information
    async fn get_rune(&self, rune: &str) -> Result<OrdRuneInfo>;
    /// Get all runes
    async fn get_runes(&self, page: Option<u32>) -> Result<OrdRunes>;
    /// Get sat information
    async fn get_sat(&self, sat: u64) -> Result<OrdSat>;
    /// Get transaction information
    async fn get_tx_info(&self, txid: &str) -> Result<OrdTxInfo>;
}

/// Trait for alkanes operations
#[async_trait(?Send)]
pub trait AlkanesProvider {
    /// Execute alkanes smart contract
    async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult>;
    async fn protorunes_by_address(&self, address: &str) -> Result<JsonValue>;
    async fn protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<protorune_pb::OutpointResponse>;
    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue>;
    async fn trace(&self, outpoint: &str) -> Result<alkanes_pb::Trace>;
    async fn get_block(&self, height: u64) -> Result<alkanes_pb::BlockResponse>;
    async fn sequence(&self, txid: &str, vout: u32) -> Result<JsonValue>;
    async fn spendables_by_address(&self, address: &str) -> Result<JsonValue>;
    async fn trace_block(&self, height: u64) -> Result<alkanes_pb::Trace>;
    async fn get_bytecode(&self, alkane_id: &str) -> Result<String>;
    async fn inspect(&self, target: &str, config: crate::alkanes::AlkanesInspectConfig) -> Result<crate::alkanes::AlkanesInspectResult>;
    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<crate::alkanes::AlkaneBalance>>;
}

/// Trait for monitoring operations
#[async_trait(?Send)]
pub trait MonitorProvider {
    /// Monitor blocks for events
    async fn monitor_blocks(&self, start: Option<u64>) -> Result<()>;
    
    /// Get block events
    async fn get_block_events(&self, height: u64) -> Result<Vec<BlockEvent>>;
}

/// Block event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockEvent {
    pub event_type: String,
    pub block_height: u64,
    pub txid: String,
    pub data: JsonValue,
}

/// Combined provider trait that includes all functionality
#[async_trait(?Send)]
pub trait DeezelProvider:
    JsonRpcProvider +
    StorageProvider +
    NetworkProvider +
    CryptoProvider +
    PgpProvider +
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
    KeystoreProvider +
    OrdProvider
{
    /// Get provider name/type
    fn provider_name(&self) -> &str;

    /// Create a boxed, clonable version of the provider
    fn clone_box(&self) -> Box<dyn DeezelProvider>;
    
    /// Initialize the provider
    async fn initialize(&self) -> Result<()>;
    
    /// Shutdown the provider
    async fn shutdown(&self) -> Result<()>;
}

impl Clone for Box<dyn DeezelProvider> {
   fn clone(&self) -> Self {
       self.clone_box()
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> JsonRpcProvider for Box<T> {
   async fn call(&self, url: &str, method: &str, params: serde_json::Value, id: u64) -> Result<serde_json::Value> {
       (**self).call(url, method, params, id).await
   }
   async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String> {
       <Self as JsonRpcProvider>::get_bytecode(self, block, tx).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> StorageProvider for Box<T> {
   async fn read(&self, key: &str) -> Result<Vec<u8>> {
       (**self).read(key).await
   }
   async fn write(&self, key: &str, data: &[u8]) -> Result<()> {
       (**self).write(key, data).await
   }
   async fn exists(&self, key: &str) -> Result<bool> {
       (**self).exists(key).await
   }
   async fn delete(&self, key: &str) -> Result<()> {
       (**self).delete(key).await
   }
   async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
       (**self).list_keys(prefix).await
   }
   fn storage_type(&self) -> &'static str {
       (**self).storage_type()
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> NetworkProvider for Box<T> {
   async fn get(&self, url: &str) -> Result<Vec<u8>> {
       (**self).get(url).await
   }
   async fn post(&self, url: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>> {
       (**self).post(url, body, content_type).await
   }
   async fn is_reachable(&self, url: &str) -> bool {
       (**self).is_reachable(url).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> CryptoProvider for Box<T> {
   fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
       (**self).random_bytes(len)
   }
   fn sha256(&self, data: &[u8]) -> Result<[u8; 32]> {
       (**self).sha256(data)
   }
   fn sha3_256(&self, data: &[u8]) -> Result<[u8; 32]> {
       (**self).sha3_256(data)
   }
   async fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
       (**self).encrypt_aes_gcm(data, key, nonce).await
   }
   async fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
       (**self).decrypt_aes_gcm(data, key, nonce).await
   }
   async fn pbkdf2_derive(&self, password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Result<Vec<u8>> {
       (**self).pbkdf2_derive(password, salt, iterations, key_len).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> PgpProvider for Box<T> {
   async fn generate_keypair(&self, user_id: &str, passphrase: Option<&str>) -> Result<PgpKeyPair> {
       (**self).generate_keypair(user_id, passphrase).await
   }
   async fn import_key(&self, armored_key: &str) -> Result<PgpKey> {
       (**self).import_key(armored_key).await
   }
   async fn export_key(&self, key: &PgpKey, include_private: bool) -> Result<String> {
       (**self).export_key(key, include_private).await
   }
   async fn encrypt(&self, data: &[u8], recipient_keys: &[PgpKey], armor: bool) -> Result<Vec<u8>> {
       (**self).encrypt(data, recipient_keys, armor).await
   }
   async fn decrypt(&self, encrypted_data: &[u8], private_key: &PgpKey, passphrase: Option<&str>) -> Result<Vec<u8>> {
       (**self).decrypt(encrypted_data, private_key, passphrase).await
   }
   async fn sign(&self, data: &[u8], private_key: &PgpKey, passphrase: Option<&str>, armor: bool) -> Result<Vec<u8>> {
       (**self).sign(data, private_key, passphrase, armor).await
   }
   async fn verify(&self, data: &[u8], signature: &[u8], public_key: &PgpKey) -> Result<bool> {
       (**self).verify(data, signature, public_key).await
   }
   async fn encrypt_and_sign(&self, data: &[u8], recipient_keys: &[PgpKey], signing_key: &PgpKey, passphrase: Option<&str>, armor: bool) -> Result<Vec<u8>> {
       (**self).encrypt_and_sign(data, recipient_keys, signing_key, passphrase, armor).await
   }
   async fn decrypt_and_verify(&self, encrypted_data: &[u8], private_key: &PgpKey, sender_public_key: &PgpKey, passphrase: Option<&str>) -> Result<PgpDecryptResult> {
       (**self).decrypt_and_verify(encrypted_data, private_key, sender_public_key, passphrase).await
   }
   async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>> {
       (**self).list_pgp_keys().await
   }
   async fn get_key(&self, identifier: &str) -> Result<Option<PgpKey>> {
       (**self).get_key(identifier).await
   }
   async fn delete_key(&self, identifier: &str) -> Result<()> {
       (**self).delete_key(identifier).await
   }
   async fn change_passphrase(&self, key: &PgpKey, old_passphrase: Option<&str>, new_passphrase: Option<&str>) -> Result<PgpKey> {
       (**self).change_passphrase(key, old_passphrase, new_passphrase).await
   }
}

impl<T: DeezelProvider + ?Sized> TimeProvider for Box<T> {
   fn now_secs(&self) -> u64 {
       (**self).now_secs()
   }
   fn now_millis(&self) -> u64 {
       (**self).now_millis()
   }
   fn sleep_ms(&self, ms: u64) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()>>> {
       (**self).sleep_ms(ms)
   }
}

impl<T: DeezelProvider + ?Sized> LogProvider for Box<T> {
   fn debug(&self, message: &str) {
       (**self).debug(message)
   }
   fn info(&self, message: &str) {
       (**self).info(message)
   }
   fn warn(&self, message: &str) {
       (**self).warn(message)
   }
   fn error(&self, message: &str) {
       (**self).error(message)
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> WalletProvider for Box<T> {
   async fn create_wallet(&self, config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<WalletInfo> {
       (**self).create_wallet(config, mnemonic, passphrase).await
   }
   async fn load_wallet(&self, config: WalletConfig, passphrase: Option<String>) -> Result<WalletInfo> {
       (**self).load_wallet(config, passphrase).await
   }
   async fn get_balance(&self, addresses: Option<Vec<String>>) -> Result<WalletBalance> {
       WalletProvider::get_balance(&**self, addresses).await
   }
   async fn get_address(&self) -> Result<String> {
       <Self as WalletProvider>::get_address(self).await
   }
   async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>> {
       (**self).get_addresses(count).await
   }
   async fn send(&self, params: SendParams) -> Result<String> {
       (**self).send(params).await
   }
   async fn get_utxos(&self, include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>> {
       (**self).get_utxos(include_frozen, addresses).await
   }
   async fn get_history(&self, count: u32, address: Option<String>) -> Result<Vec<TransactionInfo>> {
       (**self).get_history(count, address).await
   }
   async fn freeze_utxo(&self, utxo: String, reason: Option<String>) -> Result<()> {
       (**self).freeze_utxo(utxo, reason).await
   }
   async fn unfreeze_utxo(&self, utxo: String) -> Result<()> {
       (**self).unfreeze_utxo(utxo).await
   }
   async fn create_transaction(&self, params: SendParams) -> Result<String> {
       (**self).create_transaction(params).await
   }
   async fn sign_transaction(&self, tx_hex: String) -> Result<String> {
       (**self).sign_transaction(tx_hex).await
   }
   async fn broadcast_transaction(&self, tx_hex: String) -> Result<String> {
       (**self).broadcast_transaction(tx_hex).await
   }
   async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate> {
       (**self).estimate_fee(target).await
   }
   async fn get_fee_rates(&self) -> Result<FeeRates> {
       (**self).get_fee_rates().await
   }
   async fn sync(&self) -> Result<()> {
       (**self).sync().await
   }
   async fn backup(&self) -> Result<String> {
       (**self).backup().await
   }
   async fn get_mnemonic(&self) -> Result<Option<String>> {
       (**self).get_mnemonic().await
   }
   fn get_network(&self) -> bitcoin::Network {
       (**self).get_network()
   }
   async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey> {
       (**self).get_internal_key().await
   }
   async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt> {
       (**self).sign_psbt(psbt).await
   }
   async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
       (**self).get_keypair().await
   }
   fn set_passphrase(&mut self, passphrase: Option<String>) {
       (**self).set_passphrase(passphrase)
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> AddressResolver for Box<T> {
   async fn resolve_all_identifiers(&self, input: &str) -> Result<String> {
       (**self).resolve_all_identifiers(input).await
   }
   fn contains_identifiers(&self, input: &str) -> bool {
       (**self).contains_identifiers(input)
   }
   async fn get_address(&self, address_type: &str, index: u32) -> Result<String> {
       <Self as AddressResolver>::get_address(self, address_type, index).await
   }
   async fn list_identifiers(&self) -> Result<Vec<String>> {
       (**self).list_identifiers().await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> BitcoinRpcProvider for Box<T> {
   async fn get_block_count(&self) -> Result<u64> {
       (**self).get_block_count().await
   }
   async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<serde_json::Value> {
       (**self).generate_to_address(nblocks, address).await
   }
   async fn get_new_address(&self) -> Result<JsonValue> {
       (**self).get_new_address().await
   }
   async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
       (**self).get_transaction_hex(txid).await
   }
   async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
       <Self as BitcoinRpcProvider>::get_block(self, hash).await
   }
   async fn get_block_hash(&self, height: u64) -> Result<String> {
       <T as BitcoinRpcProvider>::get_block_hash(self, height).await
   }
   async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String> {
       <T as BitcoinRpcProvider>::send_raw_transaction(self, tx_hex).await
   }
   async fn get_mempool_info(&self) -> Result<serde_json::Value> {
       <T as BitcoinRpcProvider>::get_mempool_info(self).await
   }
   async fn estimate_smart_fee(&self, target: u32) -> Result<serde_json::Value> {
       (**self).estimate_smart_fee(target).await
   }
   async fn get_esplora_blocks_tip_height(&self) -> Result<u64> {
       (**self).get_esplora_blocks_tip_height().await
   }
   async fn trace_transaction(&self, txid: &str, vout: u32, block: Option<&str>, tx: Option<&str>) -> Result<serde_json::Value> {
       (**self).trace_transaction(txid, vout, block, tx).await
   }
}


#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> MetashrewRpcProvider for Box<T> {
   async fn get_metashrew_height(&self) -> Result<u64> {
       (**self).get_metashrew_height().await
   }
   async fn get_contract_meta(&self, block: &str, tx: &str) -> Result<serde_json::Value> {
       (**self).get_contract_meta(block, tx).await
   }
   async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<serde_json::Value> {
       (**self).trace_outpoint(txid, vout).await
   }
   async fn get_spendables_by_address(&self, address: &str) -> Result<serde_json::Value> {
       (**self).get_spendables_by_address(address).await
   }
   async fn get_protorunes_by_address(&self, address: &str) -> Result<serde_json::Value> {
       (**self).get_protorunes_by_address(address).await
   }
   async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<serde_json::Value> {
       (**self).get_protorunes_by_outpoint(txid, vout).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> EsploraProvider for Box<T> {
   async fn get_blocks_tip_hash(&self) -> Result<String> {
       (**self).get_blocks_tip_hash().await
   }
   async fn get_blocks_tip_height(&self) -> Result<u64> {
       (**self).get_blocks_tip_height().await
   }
   async fn get_blocks(&self, start_height: Option<u64>) -> Result<serde_json::Value> {
       (**self).get_blocks(start_height).await
   }
   async fn get_block_by_height(&self, height: u64) -> Result<String> {
       (**self).get_block_by_height(height).await
   }
   async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
       <Self as EsploraProvider>::get_block(self, hash).await
   }
   async fn get_block_status(&self, hash: &str) -> Result<serde_json::Value> {
       (**self).get_block_status(hash).await
   }
   async fn get_block_txids(&self, hash: &str) -> Result<serde_json::Value> {
       (**self).get_block_txids(hash).await
   }
   async fn get_block_header(&self, hash: &str) -> Result<String> {
       <T as EsploraProvider>::get_block_header(self, hash).await
   }
   async fn get_block_raw(&self, hash: &str) -> Result<String> {
       (**self).get_block_raw(hash).await
   }
   async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
       (**self).get_block_txid(hash, index).await
   }
   async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<serde_json::Value> {
       (**self).get_block_txs(hash, start_index).await
   }
   async fn get_address(&self, address: &str) -> Result<serde_json::Value> {
       <Self as EsploraProvider>::get_address(self, address).await
   }
   async fn get_address_info(&self, address: &str) -> Result<serde_json::Value> {
       (**self).get_address_info(address).await
   }
   async fn get_address_txs(&self, address: &str) -> Result<serde_json::Value> {
       (**self).get_address_txs(address).await
   }
   async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<serde_json::Value> {
       (**self).get_address_txs_chain(address, last_seen_txid).await
   }
   async fn get_address_txs_mempool(&self, address: &str) -> Result<serde_json::Value> {
       (**self).get_address_txs_mempool(address).await
   }
   async fn get_address_utxo(&self, address: &str) -> Result<serde_json::Value> {
       (**self).get_address_utxo(address).await
   }
   async fn get_address_prefix(&self, prefix: &str) -> Result<serde_json::Value> {
       (**self).get_address_prefix(prefix).await
   }
   async fn get_tx(&self, txid: &str) -> Result<serde_json::Value> {
       (**self).get_tx(txid).await
   }
   async fn get_tx_hex(&self, txid: &str) -> Result<String> {
       (**self).get_tx_hex(txid).await
   }
   async fn get_tx_raw(&self, txid: &str) -> Result<String> {
       (**self).get_tx_raw(txid).await
   }
   async fn get_tx_status(&self, txid: &str) -> Result<serde_json::Value> {
       (**self).get_tx_status(txid).await
   }
   async fn get_tx_merkle_proof(&self, txid: &str) -> Result<serde_json::Value> {
       (**self).get_tx_merkle_proof(txid).await
   }
   async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
       (**self).get_tx_merkleblock_proof(txid).await
   }
   async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<serde_json::Value> {
       (**self).get_tx_outspend(txid, index).await
   }
   async fn get_tx_outspends(&self, txid: &str) -> Result<serde_json::Value> {
       (**self).get_tx_outspends(txid).await
   }
   async fn broadcast(&self, tx_hex: &str) -> Result<String> {
       (**self).broadcast(tx_hex).await
   }
   async fn get_mempool(&self) -> Result<serde_json::Value> {
       (**self).get_mempool().await
   }
   async fn get_mempool_txids(&self) -> Result<serde_json::Value> {
       (**self).get_mempool_txids().await
   }
   async fn get_mempool_recent(&self) -> Result<serde_json::Value> {
       (**self).get_mempool_recent().await
   }
   async fn get_fee_estimates(&self) -> Result<serde_json::Value> {
       (**self).get_fee_estimates().await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> RunestoneProvider for Box<T> {
   async fn decode_runestone(&self, tx: &bitcoin::Transaction) -> Result<serde_json::Value> {
       (**self).decode_runestone(tx).await
   }
   async fn format_runestone_with_decoded_messages(&self, tx: &bitcoin::Transaction) -> Result<serde_json::Value> {
       (**self).format_runestone_with_decoded_messages(tx).await
   }
   async fn analyze_runestone(&self, txid: &str) -> Result<serde_json::Value> {
       (**self).analyze_runestone(txid).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> OrdProvider for Box<T> {
    async fn get_inscription(&self, inscription_id: &str) -> Result<OrdInscription> {
        (**self).get_inscription(inscription_id).await
    }

    async fn get_inscriptions_in_block(&self, block_hash: &str) -> Result<OrdInscriptions> {
        (**self).get_inscriptions_in_block(block_hash).await
    }
    async fn get_ord_address_info(&self, address: &str) -> Result<OrdAddressInfo> {
        (**self).get_ord_address_info(address).await
    }
    async fn get_block_info(&self, query: &str) -> Result<OrdBlock> {
        (**self).get_block_info(query).await
    }
    async fn get_ord_block_count(&self) -> Result<u64> {
        (**self).get_ord_block_count().await
    }
    async fn get_ord_blocks(&self) -> Result<OrdBlocks> {
        (**self).get_ord_blocks().await
    }
    async fn get_children(&self, inscription_id: &str, page: Option<u32>) -> Result<OrdChildren> {
        (**self).get_children(inscription_id, page).await
    }
    async fn get_content(&self, inscription_id: &str) -> Result<Vec<u8>> {
        (**self).get_content(inscription_id).await
    }
    async fn get_inscriptions(&self, page: Option<u32>) -> Result<OrdInscriptions> {
        (**self).get_inscriptions(page).await
    }
    async fn get_output(&self, output: &str) -> Result<OrdOutput> {
        (**self).get_output(output).await
    }
    async fn get_parents(&self, inscription_id: &str, page: Option<u32>) -> Result<OrdParents> {
        (**self).get_parents(inscription_id, page).await
    }
    async fn get_rune(&self, rune: &str) -> Result<OrdRuneInfo> {
        (**self).get_rune(rune).await
    }
    async fn get_runes(&self, page: Option<u32>) -> Result<OrdRunes> {
        (**self).get_runes(page).await
    }
    async fn get_sat(&self, sat: u64) -> Result<OrdSat> {
        (**self).get_sat(sat).await
    }
    async fn get_tx_info(&self, txid: &str) -> Result<OrdTxInfo> {
        (**self).get_tx_info(txid).await
    }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> AlkanesProvider for Box<T> {
    async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        (**self).execute(params).await
    }
    async fn protorunes_by_address(&self, address: &str) -> Result<JsonValue> {
        (**self).protorunes_by_address(address).await
    }
    async fn protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<protorune_pb::OutpointResponse> {
        AlkanesProvider::protorunes_by_outpoint(&**self, txid, vout).await
    }
    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue> {
        (**self).simulate(contract_id, params).await
    }
    async fn trace(&self, outpoint: &str) -> Result<alkanes_pb::Trace> {
        (**self).trace(outpoint).await
    }
    async fn get_block(&self, height: u64) -> Result<alkanes_pb::BlockResponse> {
        AlkanesProvider::get_block(&**self, height).await
    }
    async fn sequence(&self, txid: &str, vout: u32) -> Result<JsonValue> {
        (**self).sequence(txid, vout).await
    }
    async fn spendables_by_address(&self, address: &str) -> Result<JsonValue> {
        (**self).spendables_by_address(address).await
    }
    async fn trace_block(&self, height: u64) -> Result<alkanes_pb::Trace> {
        (**self).trace_block(height).await
    }
    async fn get_bytecode(&self, alkane_id: &str) -> Result<String> {
        AlkanesProvider::get_bytecode(&**self, alkane_id).await
    }
    async fn inspect(&self, target: &str, config: crate::alkanes::AlkanesInspectConfig) -> Result<crate::alkanes::AlkanesInspectResult> {
        (**self).inspect(target, config).await
    }
    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<crate::alkanes::AlkaneBalance>> {
        AlkanesProvider::get_balance(&**self, address).await
    }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> MonitorProvider for Box<T> {
   async fn monitor_blocks(&self, start: Option<u64>) -> Result<()> {
       (**self).monitor_blocks(start).await
   }
   async fn get_block_events(&self, height: u64) -> Result<Vec<BlockEvent>> {
       (**self).get_block_events(height).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> KeystoreProvider for Box<T> {
   async fn derive_addresses(&self, master_public_key: &str, network: Network, script_types: &[&str], start_index: u32, count: u32) -> Result<Vec<KeystoreAddress>> {
       (**self).derive_addresses(master_public_key, network, script_types, start_index, count).await
   }
   async fn get_default_addresses(&self, master_public_key: &str, network: Network) -> Result<Vec<KeystoreAddress>> {
       (**self).get_default_addresses(master_public_key, network).await
   }
   fn parse_address_range(&self, range_spec: &str) -> Result<(String, u32, u32)> {
       (**self).parse_address_range(range_spec)
   }
   async fn get_keystore_info(&self, master_public_key: &str, master_fingerprint: &str, created_at: u64, version: &str) -> Result<KeystoreInfo> {
       (**self).get_keystore_info(master_public_key, master_fingerprint, created_at, version).await
   }
}

#[async_trait(?Send)]
impl<T: DeezelProvider + ?Sized> DeezelProvider for Box<T> {
   fn provider_name(&self) -> &str {
       (**self).provider_name()
   }
   fn clone_box(&self) -> Box<dyn DeezelProvider> {
       (**self).clone_box()
   }
   async fn initialize(&self) -> Result<()> {
       (**self).initialize().await
   }
   async fn shutdown(&self) -> Result<()> {
       (**self).shutdown().await
   }
}

/// Trait for system-level wallet operations, corresponding to CLI commands
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemWallet {
   /// Execute a wallet command
   async fn execute_wallet_command(&self, command: crate::commands::WalletCommands) -> Result<()>;
   /// Execute the legacy walletinfo command
   async fn execute_walletinfo_command(&self, raw: bool) -> Result<()>;
}

/// Trait for system-level Bitcoin Core RPC operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemBitcoind {
   /// Execute a bitcoind command
   async fn execute_bitcoind_command(&self, command: crate::commands::BitcoindCommands) -> Result<()>;
}

/// Trait for system-level Metashrew RPC operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemMetashrew {
   /// Execute a metashrew command
   async fn execute_metashrew_command(&self, command: crate::commands::MetashrewCommands) -> Result<()>;
}

/// Trait for system-level Alkanes operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemAlkanes {
   /// Execute an alkanes command
   async fn execute_alkanes_command(&self, command: crate::commands::AlkanesCommands) -> Result<()>;
}

/// Trait for system-level Runestone operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemRunestone {
   /// Execute a runestone command
   async fn execute_runestone_command(&self, command: crate::commands::RunestoneCommands) -> Result<()>;
}

/// Trait for system-level Protorunes operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemProtorunes {
   /// Execute a protorunes command
   async fn execute_protorunes_command(&self, command: crate::commands::ProtorunesCommands) -> Result<()>;
}

/// Trait for system-level monitoring operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemMonitor {
   /// Execute a monitor command
   async fn execute_monitor_command(&self, command: crate::commands::MonitorCommands) -> Result<()>;
}

/// Trait for system-level Esplora operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemEsplora {
   /// Execute an esplora command
   async fn execute_esplora_command(&self, command: crate::commands::EsploraCommands) -> Result<()>;
}

/// Trait for system-level PGP operations
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait SystemPgp {
   /// Execute a PGP command
   async fn execute_pgp_command(&self, command: crate::commands::PgpCommands) -> Result<()>;
}

/// Combined system trait that includes all system-level functionality
#[cfg(not(target_arch = "wasm32"))]
#[async_trait(?Send)]
pub trait System:
   SystemWallet +
   SystemBitcoind +
   SystemMetashrew +
   SystemAlkanes +
   SystemRunestone +
   SystemProtorunes +
   SystemMonitor +
   SystemEsplora +
   SystemPgp +
   Send + Sync
{
   /// Get the underlying provider
   fn provider(&self) -> &dyn DeezelProvider;
}