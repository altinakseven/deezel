//! Generic DeezelRuntime that works with any adapter backends
//!
//! This module provides the main [`DeezelRuntime`] struct that executes deezel
//! operations using injected adapters, following the same patterns as metashrew-runtime.

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Address, Network, Transaction, Txid};
use std::sync::Arc;

use crate::traits::{
    WalletStorageLike, ConfigStorageLike, RpcClientLike, BlockchainClientLike,
    FilesystemLike, WasmRuntimeLike, NetworkConfig, WalletConfig, RpcConfig, AlkanesConfig
};

/// Configuration for DeezelRuntime
#[derive(Debug, Clone)]
pub struct DeezelRuntimeConfig {
    pub network: NetworkConfig,
    pub wallet: WalletConfig,
    pub rpc: RpcConfig,
    pub alkanes: AlkanesConfig,
}

/// Generic DeezelRuntime that works with any storage and RPC backends
///
/// This is the main execution engine that performs deezel operations using
/// injected adapters. It's generic over all backend types, enabling flexible
/// deployment scenarios from CLI to web applications.
///
/// # Type Parameters
///
/// - `WS`: Wallet storage backend implementing [`WalletStorageLike`]
/// - `CS`: Config storage backend implementing [`ConfigStorageLike`]
/// - `RC`: RPC client backend implementing [`RpcClientLike`]
/// - `BC`: Blockchain client backend implementing [`BlockchainClientLike`]
/// - `FS`: Filesystem backend implementing [`FilesystemLike`]
/// - `WR`: WASM runtime backend implementing [`WasmRuntimeLike`]
pub struct DeezelRuntime<WS, CS, RC, BC, FS, WR>
where
    WS: WalletStorageLike + Send + Sync + 'static,
    CS: ConfigStorageLike + Send + Sync + 'static,
    RC: RpcClientLike + Send + Sync + 'static,
    BC: BlockchainClientLike + Send + Sync + 'static,
    FS: FilesystemLike + Send + Sync + 'static,
    WR: WasmRuntimeLike + Send + Sync + 'static,
{
    /// Wallet storage adapter
    pub wallet_storage: Arc<tokio::sync::Mutex<WS>>,
    
    /// Configuration storage adapter
    pub config_storage: Arc<tokio::sync::Mutex<CS>>,
    
    /// RPC client adapter
    pub rpc_client: Arc<RC>,
    
    /// Blockchain client adapter
    pub blockchain_client: Arc<BC>,
    
    /// Filesystem adapter
    pub filesystem: Arc<FS>,
    
    /// WASM runtime adapter
    pub wasm_runtime: Arc<tokio::sync::Mutex<WR>>,
    
    /// Runtime configuration
    pub config: DeezelRuntimeConfig,
}

impl<WS, CS, RC, BC, FS, WR> DeezelRuntime<WS, CS, RC, BC, FS, WR>
where
    WS: WalletStorageLike + Send + Sync + 'static,
    CS: ConfigStorageLike + Send + Sync + 'static,
    RC: RpcClientLike + Send + Sync + 'static,
    BC: BlockchainClientLike + Send + Sync + 'static,
    FS: FilesystemLike + Send + Sync + 'static,
    WR: WasmRuntimeLike + Send + Sync + 'static,
{
    /// Create a new DeezelRuntime with injected adapters
    pub fn new(
        wallet_storage: WS,
        config_storage: CS,
        rpc_client: RC,
        blockchain_client: BC,
        filesystem: FS,
        wasm_runtime: WR,
        config: DeezelRuntimeConfig,
    ) -> Self {
        Self {
            wallet_storage: Arc::new(tokio::sync::Mutex::new(wallet_storage)),
            config_storage: Arc::new(tokio::sync::Mutex::new(config_storage)),
            rpc_client: Arc::new(rpc_client),
            blockchain_client: Arc::new(blockchain_client),
            filesystem: Arc::new(filesystem),
            wasm_runtime: Arc::new(tokio::sync::Mutex::new(wasm_runtime)),
            config,
        }
    }

    /// Initialize the runtime and load configuration
    pub async fn initialize(&mut self) -> Result<()> {
        log::info!("Initializing DeezelRuntime for network: {:?}", self.config.network.network);
        
        // Ensure wallet storage is ready
        let wallet_exists = {
            let storage = self.wallet_storage.lock().await;
            storage.wallet_exists(&self.config.wallet.name).await
                .map_err(|e| anyhow::anyhow!("Failed to check wallet existence: {:?}", e))?
        };
        
        if !wallet_exists {
            log::info!("Wallet '{}' does not exist, will need to be created", self.config.wallet.name);
        }
        
        // Test RPC connectivity
        let block_height = self.rpc_client.get_block_height().await
            .map_err(|e| anyhow::anyhow!("Failed to connect to RPC: {:?}", e))?;
        
        log::info!("Connected to blockchain at height: {}", block_height);
        
        Ok(())
    }

    /// Create a new wallet
    pub async fn create_wallet(&mut self, name: &str, mnemonic: Option<String>) -> Result<()> {
        log::info!("Creating wallet: {}", name);
        
        // Generate or use provided mnemonic
        let wallet_data = if let Some(mnemonic) = mnemonic {
            // Use provided mnemonic
            mnemonic.as_bytes().to_vec()
        } else {
            // Generate new mnemonic (simplified for now)
            b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_vec()
        };
        
        let mut storage = self.wallet_storage.lock().await;
        storage.save_wallet(name, &wallet_data).await
            .map_err(|e| anyhow::anyhow!("Failed to save wallet: {:?}", e))?;
        
        log::info!("Wallet '{}' created successfully", name);
        Ok(())
    }

    /// Load an existing wallet
    pub async fn load_wallet(&self, name: &str) -> Result<Vec<u8>> {
        log::debug!("Loading wallet: {}", name);
        
        let storage = self.wallet_storage.lock().await;
        let wallet_data = storage.load_wallet(name).await
            .map_err(|e| anyhow::anyhow!("Failed to load wallet: {:?}", e))?;
        
        wallet_data.ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))
    }

    /// List available wallets
    pub async fn list_wallets(&self) -> Result<Vec<String>> {
        let storage = self.wallet_storage.lock().await;
        storage.list_wallets().await
            .map_err(|e| anyhow::anyhow!("Failed to list wallets: {:?}", e))
    }

    /// Get current blockchain height
    pub async fn get_blockchain_height(&self) -> Result<u64> {
        self.blockchain_client.get_tip_height().await
            .map_err(|e| anyhow::anyhow!("Failed to get blockchain height: {:?}", e))
    }

    /// Get address balance
    pub async fn get_address_balance(&self, address: &Address) -> Result<u64> {
        self.rpc_client.get_address_balance(address).await
            .map_err(|e| anyhow::anyhow!("Failed to get address balance: {:?}", e))
    }

    /// Broadcast transaction
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid> {
        log::info!("Broadcasting transaction: {}", tx.compute_txid());
        
        self.rpc_client.broadcast_transaction(tx).await
            .map_err(|e| anyhow::anyhow!("Failed to broadcast transaction: {:?}", e))
    }

    /// Execute alkanes WASM module
    pub async fn execute_alkanes(&mut self, wasm_bytes: &[u8], function: &str, args: &[u8]) -> Result<Vec<u8>> {
        log::debug!("Executing alkanes function: {}", function);
        
        let mut wasm_runtime = self.wasm_runtime.lock().await;
        
        // Load the WASM module
        wasm_runtime.load_module(wasm_bytes).await
            .map_err(|e| anyhow::anyhow!("Failed to load WASM module: {:?}", e))?;
        
        // Execute the function
        wasm_runtime.execute_function(function, args).await
            .map_err(|e| anyhow::anyhow!("Failed to execute WASM function: {:?}", e))
    }

    /// Save configuration
    pub async fn save_config<T: serde::Serialize + Send + Sync>(&mut self, key: &str, config: &T) -> Result<()> {
        let mut storage = self.config_storage.lock().await;
        storage.save_config(key, config).await
            .map_err(|e| anyhow::anyhow!("Failed to save config: {:?}", e))
    }

    /// Load configuration
    pub async fn load_config<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let storage = self.config_storage.lock().await;
        storage.load_config(key).await
            .map_err(|e| anyhow::anyhow!("Failed to load config: {:?}", e))
    }

    /// Read file from filesystem
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.filesystem.read_file(path).await
            .map_err(|e| anyhow::anyhow!("Failed to read file: {:?}", e))
    }

    /// Write file to filesystem
    pub async fn write_file(&self, path: &str, contents: &[u8]) -> Result<()> {
        self.filesystem.write_file(path, contents).await
            .map_err(|e| anyhow::anyhow!("Failed to write file: {:?}", e))
    }

    /// Create a mock in-memory metashrew for testing
    pub async fn create_mock_metashrew(&mut self) -> Result<()> {
        log::info!("Creating mock in-memory metashrew runtime");
        
        // This would initialize an in-memory metashrew instance
        // using the alkanes-rs build and test block generation
        // For now, this is a placeholder
        
        Ok(())
    }

    /// Process a test block through the mock metashrew
    pub async fn process_test_block(&mut self, block_data: &[u8], height: u32) -> Result<()> {
        log::debug!("Processing test block at height: {}", height);
        
        // This would feed the block data into the mock metashrew
        // and execute the alkanes-rs indexer
        // For now, this is a placeholder
        
        Ok(())
    }
}

/// Builder for DeezelRuntime to make construction easier
pub struct DeezelRuntimeBuilder<WS, CS, RC, BC, FS, WR> {
    wallet_storage: Option<WS>,
    config_storage: Option<CS>,
    rpc_client: Option<RC>,
    blockchain_client: Option<BC>,
    filesystem: Option<FS>,
    wasm_runtime: Option<WR>,
    config: Option<DeezelRuntimeConfig>,
}

impl<WS, CS, RC, BC, FS, WR> DeezelRuntimeBuilder<WS, CS, RC, BC, FS, WR>
where
    WS: WalletStorageLike + Send + Sync + 'static,
    CS: ConfigStorageLike + Send + Sync + 'static,
    RC: RpcClientLike + Send + Sync + 'static,
    BC: BlockchainClientLike + Send + Sync + 'static,
    FS: FilesystemLike + Send + Sync + 'static,
    WR: WasmRuntimeLike + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            wallet_storage: None,
            config_storage: None,
            rpc_client: None,
            blockchain_client: None,
            filesystem: None,
            wasm_runtime: None,
            config: None,
        }
    }

    pub fn wallet_storage(mut self, storage: WS) -> Self {
        self.wallet_storage = Some(storage);
        self
    }

    pub fn config_storage(mut self, storage: CS) -> Self {
        self.config_storage = Some(storage);
        self
    }

    pub fn rpc_client(mut self, client: RC) -> Self {
        self.rpc_client = Some(client);
        self
    }

    pub fn blockchain_client(mut self, client: BC) -> Self {
        self.blockchain_client = Some(client);
        self
    }

    pub fn filesystem(mut self, fs: FS) -> Self {
        self.filesystem = Some(fs);
        self
    }

    pub fn wasm_runtime(mut self, runtime: WR) -> Self {
        self.wasm_runtime = Some(runtime);
        self
    }

    pub fn config(mut self, config: DeezelRuntimeConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn build(self) -> Result<DeezelRuntime<WS, CS, RC, BC, FS, WR>> {
        Ok(DeezelRuntime::new(
            self.wallet_storage.ok_or_else(|| anyhow::anyhow!("Wallet storage not provided"))?,
            self.config_storage.ok_or_else(|| anyhow::anyhow!("Config storage not provided"))?,
            self.rpc_client.ok_or_else(|| anyhow::anyhow!("RPC client not provided"))?,
            self.blockchain_client.ok_or_else(|| anyhow::anyhow!("Blockchain client not provided"))?,
            self.filesystem.ok_or_else(|| anyhow::anyhow!("Filesystem not provided"))?,
            self.wasm_runtime.ok_or_else(|| anyhow::anyhow!("WASM runtime not provided"))?,
            self.config.ok_or_else(|| anyhow::anyhow!("Config not provided"))?,
        ))
    }
}