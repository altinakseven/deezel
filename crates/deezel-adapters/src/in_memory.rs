//! In-memory adapter implementations for testing
//!
//! These adapters provide in-memory implementations of all deezel-core traits,
//! following the same patterns as metashrew's MemStoreAdapter.

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Address, Block, Transaction, Txid, Network};
use deezel_core::traits::{
    WalletStorageLike, ConfigStorageLike, RpcClientLike, BlockchainClientLike,
    FilesystemLike, WasmRuntimeLike, BatchLike, FileMetadata
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::{Error, ErrorKind};

/// In-memory batch for atomic operations
#[derive(Clone, Default)]
pub struct InMemoryBatch {
    operations: Vec<BatchOperation>,
}

#[derive(Clone)]
enum BatchOperation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

impl BatchLike for InMemoryBatch {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) {
        self.operations.push(BatchOperation::Put(
            key.as_ref().to_vec(),
            value.as_ref().to_vec(),
        ));
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) {
        self.operations.push(BatchOperation::Delete(key.as_ref().to_vec()));
    }

    fn default() -> Self {
        Self {
            operations: Vec::new(),
        }
    }
}

/// In-memory wallet storage adapter
#[derive(Clone, Default)]
pub struct InMemoryWalletStorage {
    wallets: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryWalletStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_data(data: HashMap<String, Vec<u8>>) -> Self {
        Self {
            wallets: Arc::new(Mutex::new(data)),
        }
    }

    /// Get a snapshot of all wallet data (useful for testing)
    pub fn get_all_data(&self) -> HashMap<String, Vec<u8>> {
        self.wallets.lock().unwrap().clone()
    }

    /// Clear all wallet data (useful for testing)
    pub fn clear(&mut self) {
        self.wallets.lock().unwrap().clear();
    }
}

#[async_trait]
impl WalletStorageLike for InMemoryWalletStorage {
    type Error = Error;
    type Batch = InMemoryBatch;

    async fn save_wallet(&mut self, name: &str, data: &[u8]) -> Result<(), Self::Error> {
        let mut wallets = self.wallets.lock().unwrap();
        wallets.insert(name.to_string(), data.to_vec());
        Ok(())
    }

    async fn load_wallet(&self, name: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.get(name).cloned())
    }

    async fn list_wallets(&self) -> Result<Vec<String>, Self::Error> {
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.keys().cloned().collect())
    }

    async fn delete_wallet(&mut self, name: &str) -> Result<(), Self::Error> {
        let mut wallets = self.wallets.lock().unwrap();
        wallets.remove(name);
        Ok(())
    }

    async fn wallet_exists(&self, name: &str) -> Result<bool, Self::Error> {
        let wallets = self.wallets.lock().unwrap();
        Ok(wallets.contains_key(name))
    }

    fn create_batch(&self) -> Self::Batch {
        <InMemoryBatch as BatchLike>::default()
    }

    async fn write_batch(&mut self, batch: Self::Batch) -> Result<(), Self::Error> {
        let mut wallets = self.wallets.lock().unwrap();
        for operation in batch.operations {
            match operation {
                BatchOperation::Put(key, value) => {
                    let key_str = String::from_utf8(key)
                        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid key"))?;
                    wallets.insert(key_str, value);
                }
                BatchOperation::Delete(key) => {
                    let key_str = String::from_utf8(key)
                        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid key"))?;
                    wallets.remove(&key_str);
                }
            }
        }
        Ok(())
    }
}

/// In-memory config storage adapter
#[derive(Clone, Default)]
pub struct InMemoryConfigStorage {
    configs: Arc<Mutex<HashMap<String, serde_json::Value>>>,
}

impl InMemoryConfigStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.configs.lock().unwrap().clear();
    }
}

#[async_trait]
impl ConfigStorageLike for InMemoryConfigStorage {
    type Error = Error;

    async fn save_config<T: Serialize + Send + Sync>(&mut self, key: &str, config: &T) -> Result<(), Self::Error> {
        let value = serde_json::to_value(config)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        let mut configs = self.configs.lock().unwrap();
        configs.insert(key.to_string(), value);
        Ok(())
    }

    async fn load_config<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>, Self::Error> {
        let configs = self.configs.lock().unwrap();
        if let Some(value) = configs.get(key) {
            let config = serde_json::from_value(value.clone())
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    async fn delete_config(&mut self, key: &str) -> Result<(), Self::Error> {
        let mut configs = self.configs.lock().unwrap();
        configs.remove(key);
        Ok(())
    }

    async fn list_configs(&self) -> Result<Vec<String>, Self::Error> {
        let configs = self.configs.lock().unwrap();
        Ok(configs.keys().cloned().collect())
    }
}

/// In-memory RPC client adapter
#[derive(Clone, Default)]
pub struct InMemoryRpcClient {
    responses: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    transactions: Arc<Mutex<HashMap<Txid, Transaction>>>,
    balances: Arc<Mutex<HashMap<String, u64>>>,
}

impl InMemoryRpcClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a mock response for a specific RPC method
    pub fn set_response(&mut self, method: &str, response: serde_json::Value) {
        let mut responses = self.responses.lock().unwrap();
        responses.insert(method.to_string(), response);
    }

    /// Set a mock transaction
    pub fn set_transaction(&mut self, txid: Txid, tx: Transaction) {
        let mut transactions = self.transactions.lock().unwrap();
        transactions.insert(txid, tx);
    }

    /// Set a mock balance for an address
    pub fn set_balance(&mut self, address: &str, balance: u64) {
        let mut balances = self.balances.lock().unwrap();
        balances.insert(address.to_string(), balance);
    }
}

#[async_trait]
impl RpcClientLike for InMemoryRpcClient {
    type Error = Error;

    async fn call_rpc(&self, method: &str, _params: serde_json::Value) -> Result<serde_json::Value, Self::Error> {
        let responses = self.responses.lock().unwrap();
        responses.get(method)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("No mock response for method: {}", method)))
    }

    async fn get_block_height(&self) -> Result<u64, Self::Error> {
        let responses = self.responses.lock().unwrap();
        if let Some(height) = responses.get("getblockcount") {
            height.as_u64()
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid block height"))
        } else {
            Ok(800000) // Default test height
        }
    }

    async fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, Self::Error> {
        let transactions = self.transactions.lock().unwrap();
        Ok(transactions.get(txid).cloned())
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid, Self::Error> {
        let txid = tx.compute_txid();
        let mut transactions = self.transactions.lock().unwrap();
        transactions.insert(txid, tx.clone());
        Ok(txid)
    }

    async fn get_address_balance(&self, address: &Address) -> Result<u64, Self::Error> {
        let balances = self.balances.lock().unwrap();
        Ok(balances.get(&address.to_string()).copied().unwrap_or(0))
    }

    async fn get_address_utxos(&self, _address: &Address) -> Result<Vec<serde_json::Value>, Self::Error> {
        Ok(vec![]) // Return empty UTXOs for testing
    }
}

/// In-memory blockchain client adapter
#[derive(Clone, Default)]
pub struct InMemoryBlockchainClient {
    blocks: Arc<Mutex<HashMap<u64, Block>>>,
    block_hashes: Arc<Mutex<HashMap<String, Block>>>,
    tip_height: Arc<Mutex<u64>>,
}

impl InMemoryBlockchainClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a mock block at a specific height
    pub fn set_block(&mut self, height: u64, block: Block) {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.insert(height, block.clone());
        
        let mut block_hashes = self.block_hashes.lock().unwrap();
        block_hashes.insert(block.block_hash().to_string(), block);
        
        let mut tip_height = self.tip_height.lock().unwrap();
        if height > *tip_height {
            *tip_height = height;
        }
    }
}

#[async_trait]
impl BlockchainClientLike for InMemoryBlockchainClient {
    type Error = Error;

    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Self::Error> {
        let blocks = self.blocks.lock().unwrap();
        Ok(blocks.get(&height).cloned())
    }

    async fn get_block_by_hash(&self, hash: &str) -> Result<Option<Block>, Self::Error> {
        let block_hashes = self.block_hashes.lock().unwrap();
        Ok(block_hashes.get(hash).cloned())
    }

    async fn get_tip_height(&self) -> Result<u64, Self::Error> {
        let tip_height = self.tip_height.lock().unwrap();
        Ok(*tip_height)
    }

    async fn get_fee_estimates(&self) -> Result<HashMap<String, f64>, Self::Error> {
        let mut estimates = HashMap::new();
        estimates.insert("1".to_string(), 10.0);
        estimates.insert("6".to_string(), 5.0);
        estimates.insert("144".to_string(), 1.0);
        Ok(estimates)
    }
}

/// In-memory filesystem adapter
#[derive(Clone, Default)]
pub struct InMemoryFilesystem {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    metadata: Arc<Mutex<HashMap<String, FileMetadata>>>,
}

impl InMemoryFilesystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.files.lock().unwrap().clear();
        self.metadata.lock().unwrap().clear();
    }
}

#[async_trait]
impl FilesystemLike for InMemoryFilesystem {
    type Error = Error;

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, Self::Error> {
        let files = self.files.lock().unwrap();
        files.get(path)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("File not found: {}", path)))
    }

    async fn write_file(&self, path: &str, contents: &[u8]) -> Result<(), Self::Error> {
        let mut files = self.files.lock().unwrap();
        files.insert(path.to_string(), contents.to_vec());
        
        let mut metadata = self.metadata.lock().unwrap();
        metadata.insert(path.to_string(), FileMetadata {
            size: contents.len() as u64,
            modified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_dir: false,
        });
        
        Ok(())
    }

    async fn file_exists(&self, path: &str) -> Result<bool, Self::Error> {
        let files = self.files.lock().unwrap();
        Ok(files.contains_key(path))
    }

    async fn create_dir(&self, _path: &str) -> Result<(), Self::Error> {
        // In-memory filesystem doesn't need directory creation
        Ok(())
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<String>, Self::Error> {
        let files = self.files.lock().unwrap();
        let prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };
        
        let entries: Vec<String> = files.keys()
            .filter(|key| key.starts_with(&prefix))
            .map(|key| key.strip_prefix(&prefix).unwrap_or(key).to_string())
            .collect();
            
        Ok(entries)
    }

    async fn delete_file(&self, path: &str) -> Result<(), Self::Error> {
        let mut files = self.files.lock().unwrap();
        files.remove(path);
        
        let mut metadata = self.metadata.lock().unwrap();
        metadata.remove(path);
        
        Ok(())
    }

    async fn file_metadata(&self, path: &str) -> Result<FileMetadata, Self::Error> {
        let metadata = self.metadata.lock().unwrap();
        metadata.get(path)
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("File not found: {}", path)))
    }
}

/// In-memory WASM runtime adapter
#[derive(Default)]
pub struct InMemoryWasmRuntime {
    modules: HashMap<String, Vec<u8>>,
    responses: HashMap<String, Vec<u8>>,
    memory_limit: usize,
    timeout_ms: u64,
}

impl InMemoryWasmRuntime {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            responses: HashMap::new(),
            memory_limit: 64 * 1024 * 1024, // 64MB default
            timeout_ms: 30000, // 30 seconds default
        }
    }

    /// Set a mock response for a specific function
    pub fn set_function_response(&mut self, function: &str, response: Vec<u8>) {
        self.responses.insert(function.to_string(), response);
    }
}

#[async_trait]
impl WasmRuntimeLike for InMemoryWasmRuntime {
    type Error = Error;

    async fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<(), Self::Error> {
        // Store the module bytes (in a real implementation, we'd compile it)
        self.modules.insert("current".to_string(), wasm_bytes.to_vec());
        Ok(())
    }

    async fn execute_function(&mut self, name: &str, _args: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // Return mock response if available
        if let Some(response) = self.responses.get(name) {
            Ok(response.clone())
        } else {
            // Default response
            Ok(b"mock_response".to_vec())
        }
    }

    async fn get_exports(&self) -> Result<Vec<String>, Self::Error> {
        // Return mock exports
        Ok(vec![
            "execute".to_string(),
            "simulate".to_string(),
            "meta".to_string(),
        ])
    }

    fn set_memory_limit(&mut self, limit: usize) {
        self.memory_limit = limit;
    }

    fn set_timeout(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms;
    }
}