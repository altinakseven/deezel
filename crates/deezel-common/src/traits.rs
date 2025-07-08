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

use crate::{Result, ToString, format};
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use bitcoin::{Network, Transaction, ScriptBuf};

#[cfg(not(target_arch = "wasm32"))]
use std::{vec, vec::Vec, boxed::Box, string::String, future::Future};
#[cfg(target_arch = "wasm32")]
use alloc::{vec, vec::Vec, boxed::Box, string::String};
#[cfg(target_arch = "wasm32")]
use core::future::Future;

/// Trait for making JSON-RPC calls
///
/// This abstraction allows different implementations for different environments:
/// - **Native**: Uses reqwest for HTTP calls with full TLS support
/// - **WASM**: Uses fetch API for browser compatibility
/// - **Testing**: Uses mocks for deterministic testing
///
/// The trait provides a unified interface for all JSON-RPC operations including
/// Bitcoin Core RPC, Metashrew/Sandshrew RPC, and custom protocol calls.
///
/// # Examples
///
/// ```rust,no_run
/// use deezel_common::*;
/// use serde_json::json;
///
/// async fn example_rpc_call<P: JsonRpcProvider>(provider: &P) -> Result<()> {
///     let params = json!(["getblockcount"]);
///     let result = provider.call(
///         "http://localhost:8332",
///         "getblockcount",
///         params,
///         1
///     ).await?;
///     println!("Block count: {}", result);
///     Ok(())
/// }
/// ```
///
/// # Implementation Notes
///
/// - All implementations should handle authentication (Basic Auth, API keys)
/// - Timeout handling is implementation-specific but should respect `timeout_seconds()`
/// - Error responses should be properly parsed and converted to [`DeezelError::JsonRpc`]
/// - Large responses should be handled efficiently (streaming when possible)
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait JsonRpcProvider: Send + Sync {
    /// Make a JSON-RPC call to the specified URL
    ///
    /// This is the core method for all RPC operations. It handles the JSON-RPC
    /// protocol formatting, HTTP transport, and response parsing.
    ///
    /// # Arguments
    ///
    /// * `url` - The RPC endpoint URL (e.g., "http://localhost:8332")
    /// * `method` - The RPC method name (e.g., "getblockcount", "metashrew_height")
    /// * `params` - Method parameters as a JSON value (array or object)
    /// * `id` - Request ID for matching responses (should be unique per request)
    ///
    /// # Returns
    ///
    /// Returns the `result` field from the JSON-RPC response on success.
    ///
    /// # Errors
    ///
    /// - [`DeezelError::JsonRpc`] - For JSON-RPC protocol errors
    /// - [`DeezelError::Network`] - For network/transport errors
    /// - [`DeezelError::Serialization`] - For JSON parsing errors
    async fn call(
        &self,
        url: &str,
        method: &str,
        params: JsonValue,
        id: u64,
    ) -> Result<JsonValue>;
    
    /// Get bytecode for an alkane contract (convenience method)
    ///
    /// This is a specialized method for retrieving WASM bytecode from alkanes
    /// contracts. It's a convenience wrapper around the `metashrew_view` RPC call.
    ///
    /// # Arguments
    ///
    /// * `block` - Block number where the contract was deployed
    /// * `tx` - Transaction index within the block
    ///
    /// # Returns
    ///
    /// Returns the contract bytecode as a hexadecimal string.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<P: JsonRpcProvider>(provider: &P) -> Result<()> {
    /// let bytecode = provider.get_bytecode("123", "456").await?;
    /// println!("Contract bytecode: {}", bytecode);
    /// # Ok(())
    /// # }
    /// ```
    async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String>;
    
    /// Get the timeout for requests (in seconds)
    ///
    /// Returns the maximum time to wait for RPC responses. Implementations
    /// should respect this timeout to prevent hanging operations.
    ///
    /// # Default Implementation
    ///
    /// Returns 600 seconds (10 minutes) by default, which is suitable for
    /// most blockchain operations including large block downloads.
    fn timeout_seconds(&self) -> u64 {
        600 // Default 10 minutes
    }
    
    /// Check if the provider supports a specific URL scheme
    ///
    /// This method allows callers to verify URL compatibility before
    /// attempting RPC calls. Useful for validation and error prevention.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to check for support
    ///
    /// # Returns
    ///
    /// `true` if the URL scheme is supported, `false` otherwise.
    ///
    /// # Default Implementation
    ///
    /// Supports HTTP and HTTPS URLs by default.
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
/// This abstraction allows different storage implementations across environments:
/// - **Native**: Uses std::fs for file operations with full filesystem access
/// - **WASM**: Uses localStorage/IndexedDB for browser-based persistence
/// - **Testing**: Uses in-memory storage for deterministic testing
///
/// The trait provides a key-value interface that can store arbitrary binary data,
/// making it suitable for wallet files, configuration, cache data, and temporary storage.
///
/// # Examples
///
/// ## Basic Storage Operations
///
/// ```rust,no_run
/// use deezel_common::*;
///
/// async fn storage_example<S: StorageProvider>(storage: &S) -> Result<()> {
///     // Write configuration data
///     let config_data = b"{'network': 'bitcoin', 'fee_rate': 1.0}";
///     storage.write("wallet_config", config_data).await?;
///
///     // Check if data exists
///     if storage.exists("wallet_config").await? {
///         // Read the data back
///         let data = storage.read("wallet_config").await?;
///         println!("Config: {}", String::from_utf8_lossy(&data));
///     }
///
///     // List all wallet-related keys
///     let wallet_keys = storage.list_keys("wallet_").await?;
///     for key in wallet_keys {
///         println!("Found wallet key: {}", key);
///     }
///
///     Ok(())
/// }
/// ```
///
/// ## Wallet File Management
///
/// ```rust,no_run
/// # use deezel_common::*;
/// # async fn wallet_storage_example<S: StorageProvider>(storage: &S) -> Result<()> {
/// // Store encrypted wallet data
/// let wallet_data = b"encrypted_wallet_content";
/// storage.write("wallets/main.dat", wallet_data).await?;
///
/// // Store wallet metadata
/// let metadata = b"{'created': '2024-01-01', 'network': 'bitcoin'}";
/// storage.write("wallets/main.meta", metadata).await?;
///
/// // List all wallet files
/// let wallet_files = storage.list_keys("wallets/").await?;
/// println!("Found {} wallet files", wallet_files.len());
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Notes
///
/// - Keys should be treated as case-sensitive paths
/// - Binary data is supported for all storage backends
/// - Implementations should handle concurrent access safely
/// - Storage may be persistent or ephemeral depending on the backend
/// - Error handling should distinguish between missing keys and storage failures
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait StorageProvider: Send + Sync {
    /// Read data from storage
    ///
    /// Retrieves binary data associated with the given key. This is the primary
    /// method for loading stored data such as wallet files, configuration, or cache.
    ///
    /// # Arguments
    ///
    /// * `key` - Storage key identifier (treated as a path-like string)
    ///
    /// # Returns
    ///
    /// Returns the stored data as a byte vector.
    ///
    /// # Errors
    ///
    /// - [`DeezelError::Storage`] - If the key doesn't exist or storage is inaccessible
    /// - [`DeezelError::Io`] - For filesystem-related errors (native implementation)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<S: StorageProvider>(storage: &S) -> Result<()> {
    /// let wallet_data = storage.read("wallets/main.dat").await?;
    /// println!("Loaded {} bytes of wallet data", wallet_data.len());
    /// # Ok(())
    /// # }
    /// ```
    async fn read(&self, key: &str) -> Result<Vec<u8>>;
    
    /// Write data to storage
    ///
    /// Stores binary data under the specified key. If the key already exists,
    /// the data will be overwritten. Creates any necessary directory structure.
    ///
    /// # Arguments
    ///
    /// * `key` - Storage key identifier
    /// * `data` - Binary data to store
    ///
    /// # Errors
    ///
    /// - [`DeezelError::Storage`] - If storage is full or inaccessible
    /// - [`DeezelError::Io`] - For filesystem-related errors
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<S: StorageProvider>(storage: &S) -> Result<()> {
    /// let config = serde_json::json!({"network": "bitcoin"});
    /// let config_bytes = config.to_string().into_bytes();
    /// storage.write("config.json", &config_bytes).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn write(&self, key: &str, data: &[u8]) -> Result<()>;
    
    /// Check if a key exists in storage
    ///
    /// Tests whether data is stored under the given key without reading the data.
    /// This is more efficient than attempting to read when you only need to check existence.
    ///
    /// # Arguments
    ///
    /// * `key` - Storage key to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the key exists, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<S: StorageProvider>(storage: &S) -> Result<()> {
    /// if !storage.exists("wallet.dat").await? {
    ///     println!("No wallet found, creating new one...");
    ///     // Create new wallet logic here
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn exists(&self, key: &str) -> Result<bool>;
    
    /// Delete data from storage
    ///
    /// Removes the data associated with the given key. If the key doesn't exist,
    /// this operation should succeed silently (idempotent behavior).
    ///
    /// # Arguments
    ///
    /// * `key` - Storage key to delete
    ///
    /// # Errors
    ///
    /// - [`DeezelError::Storage`] - If storage is inaccessible
    /// - [`DeezelError::Io`] - For filesystem-related errors
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<S: StorageProvider>(storage: &S) -> Result<()> {
    /// // Clean up temporary files
    /// storage.delete("temp/transaction.dat").await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete(&self, key: &str) -> Result<()>;
    
    /// List all keys with a given prefix
    ///
    /// Returns all storage keys that start with the specified prefix.
    /// Useful for discovering related files or implementing directory-like operations.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Key prefix to search for (can be empty to list all keys)
    ///
    /// # Returns
    ///
    /// Returns a vector of all matching keys.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<S: StorageProvider>(storage: &S) -> Result<()> {
    /// // Find all wallet files
    /// let wallet_keys = storage.list_keys("wallets/").await?;
    /// for key in wallet_keys {
    ///     println!("Found wallet: {}", key);
    /// }
    ///
    /// // Find all configuration files
    /// let config_keys = storage.list_keys("config").await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>>;
    
    /// Get the storage type identifier
    ///
    /// Returns a string identifying the storage backend type. Useful for
    /// debugging, logging, and feature detection.
    ///
    /// # Returns
    ///
    /// Returns a static string identifying the storage type.
    ///
    /// # Common Values
    ///
    /// - `"filesystem"` - Native filesystem storage
    /// - `"localStorage"` - Browser localStorage
    /// - `"indexedDB"` - Browser IndexedDB
    /// - `"memory"` - In-memory storage (testing)
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
/// This trait handles general HTTP operations that complement the JSON-RPC functionality,
/// providing a unified interface for network communication across different environments:
/// - **Native**: Uses reqwest with full HTTP/HTTPS support and connection pooling
/// - **WASM**: Uses fetch API for browser compatibility with CORS handling
/// - **Testing**: Uses mocks for deterministic network testing
///
/// The trait supports common HTTP operations needed for blockchain applications,
/// including API calls, file downloads, and connectivity testing.
///
/// # Examples
///
/// ## Basic HTTP Operations
///
/// ```rust,no_run
/// use deezel_common::*;
///
/// async fn network_example<N: NetworkProvider>(network: &N) -> Result<()> {
///     // Download blockchain data
///     let block_data = network.get("https://blockstream.info/api/block/latest").await?;
///     println!("Downloaded {} bytes", block_data.len());
///
///     // Post transaction data
///     let tx_hex = "01000000...";
///     let response = network.post(
///         "https://blockstream.info/api/tx",
///         tx_hex.as_bytes(),
///         "text/plain"
///     ).await?;
///
///     // Check if service is available
///     if network.is_reachable("https://mempool.space").await {
///         println!("Mempool.space is reachable");
///     }
///
///     Ok(())
/// }
/// ```
///
/// ## File Download and Caching
///
/// ```rust,no_run
/// # use deezel_common::*;
/// # async fn download_example<N: NetworkProvider>(network: &N) -> Result<()> {
/// // Download and cache blockchain data
/// let url = "https://raw.githubusercontent.com/bitcoin/bitcoin/master/chainparams.cpp";
/// let chainparams = network.download(url).await?;
///
/// // Process the downloaded data
/// let content = String::from_utf8_lossy(&chainparams);
/// println!("Downloaded {} characters of chainparams", content.len());
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Notes
///
/// - All implementations should handle HTTPS/TLS properly
/// - Timeout handling should be consistent with JSON-RPC operations
/// - User agent should identify the deezel client appropriately
/// - Error responses should be properly categorized (network vs. HTTP errors)
/// - Large downloads should be handled efficiently (streaming when possible)
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait NetworkProvider: Send + Sync {
    /// Make an HTTP GET request
    ///
    /// Performs an HTTP GET request to the specified URL and returns the response body.
    /// This is the primary method for fetching data from web APIs and services.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to request (must include protocol: http:// or https://)
    ///
    /// # Returns
    ///
    /// Returns the response body as a byte vector.
    ///
    /// # Errors
    ///
    /// - [`DeezelError::Network`] - For network connectivity issues
    /// - [`DeezelError::Http`] - For HTTP protocol errors (4xx, 5xx status codes)
    /// - [`DeezelError::Timeout`] - If the request times out
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<N: NetworkProvider>(network: &N) -> Result<()> {
    /// // Fetch current Bitcoin price
    /// let response = network.get("https://api.coindesk.com/v1/bpi/currentprice.json").await?;
    /// let price_data = String::from_utf8_lossy(&response);
    /// println!("Price data: {}", price_data);
    /// # Ok(())
    /// # }
    /// ```
    async fn get(&self, url: &str) -> Result<Vec<u8>>;
    
    /// Make an HTTP POST request
    ///
    /// Performs an HTTP POST request with the specified body and content type.
    /// Used for submitting data to APIs, broadcasting transactions, and form submissions.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to post to
    /// * `body` - Request body as bytes
    /// * `content_type` - MIME type of the request body
    ///
    /// # Returns
    ///
    /// Returns the response body as a byte vector.
    ///
    /// # Common Content Types
    ///
    /// - `"application/json"` - For JSON API calls
    /// - `"text/plain"` - For raw transaction hex
    /// - `"application/x-www-form-urlencoded"` - For form data
    /// - `"application/octet-stream"` - For binary data
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<N: NetworkProvider>(network: &N) -> Result<()> {
    /// // Submit transaction to mempool
    /// let tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeebf0f0b0121000000000";
    /// let response = network.post(
    ///     "https://blockstream.info/api/tx",
    ///     tx_hex.as_bytes(),
    ///     "text/plain"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn post(&self, url: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>>;
    
    /// Download a file from a URL
    ///
    /// Convenience method for downloading files. This is equivalent to making a GET request
    /// but may include optimizations for large file downloads in some implementations.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the file to download
    ///
    /// # Returns
    ///
    /// Returns the file content as a byte vector.
    ///
    /// # Default Implementation
    ///
    /// The default implementation simply calls [`get()`](Self::get), but implementations
    /// may override this for better handling of large files or progress tracking.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<N: NetworkProvider>(network: &N) -> Result<()> {
    /// // Download blockchain snapshot
    /// let snapshot = network.download("https://example.com/blockchain-snapshot.dat").await?;
    /// println!("Downloaded {} MB snapshot", snapshot.len() / 1024 / 1024);
    /// # Ok(())
    /// # }
    /// ```
    async fn download(&self, url: &str) -> Result<Vec<u8>> {
        self.get(url).await
    }
    
    /// Check if a URL is reachable
    ///
    /// Tests connectivity to a URL without downloading the full response.
    /// Useful for health checks and service discovery.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to test for reachability
    ///
    /// # Returns
    ///
    /// Returns `true` if the URL is reachable (responds with any HTTP status),
    /// `false` if there are network connectivity issues.
    ///
    /// # Implementation Notes
    ///
    /// - Should use HEAD requests when possible to minimize bandwidth
    /// - Should have a reasonable timeout (shorter than normal requests)
    /// - HTTP error responses (4xx, 5xx) should still return `true` (server is reachable)
    /// - Only network-level failures should return `false`
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<N: NetworkProvider>(network: &N) -> Result<()> {
    /// // Check multiple Bitcoin services
    /// let services = [
    ///     "https://blockstream.info",
    ///     "https://mempool.space",
    ///     "https://blockchain.info"
    /// ];
    ///
    /// for service in &services {
    ///     if network.is_reachable(service).await {
    ///         println!("{} is available", service);
    ///     } else {
    ///         println!("{} is unreachable", service);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn is_reachable(&self, url: &str) -> bool;
    
    /// Get the user agent string
    ///
    /// Returns the User-Agent header value used for HTTP requests.
    /// This helps identify deezel clients in server logs and analytics.
    ///
    /// # Returns
    ///
    /// Returns the user agent string.
    ///
    /// # Default Implementation
    ///
    /// Returns `"deezel-common/0.1.0"` by default, but implementations may
    /// customize this to include more specific version or platform information.
    ///
    /// # Example User Agents
    ///
    /// - `"deezel-common/0.1.0"` - Basic identification
    /// - `"deezel-cli/1.0.0 (deezel-common/0.1.0)"` - CLI application
    /// - `"deezel-web/1.0.0 (deezel-common/0.1.0; WASM)"` - Web application
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
    fn sleep_ms(&self, ms: u64) -> impl Future<Output = ()>;
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
/// This trait abstracts all wallet functionality for cross-platform use, providing
/// a unified interface for Bitcoin wallet operations across different environments:
/// - **Native**: Full BDK-based wallet with file storage
/// - **WASM**: Browser-based wallet using localStorage and Web Crypto API
/// - **Browser Wallets**: Integration with injected wallet extensions (Unisat, Xverse, etc.)
///
/// The trait covers the complete wallet lifecycle from creation to transaction management,
/// with support for multiple address types, UTXO management, and advanced features like
/// PSBT signing and fee estimation.
///
/// # Examples
///
/// ## Basic Wallet Operations
///
/// ```rust,no_run
/// use deezel_common::*;
/// use bitcoin::Network;
///
/// async fn wallet_example<P: WalletProvider>(provider: &P) -> Result<()> {
///     // Get wallet balance
///     let balance = provider.get_balance().await?;
///     println!("Balance: {} sats", balance.confirmed);
///
///     // Get receiving address
///     let address = provider.get_address().await?;
///     println!("Address: {}", address);
///
///     // Send transaction
///     let send_params = SendParams {
///         address: "bc1q...".to_string(),
///         amount: 100000, // 0.001 BTC
///         fee_rate: Some(1.0),
///         send_all: false,
///         from_address: None,
///         change_address: None,
///         auto_confirm: false,
///     };
///     let txid = provider.send(send_params).await?;
///     println!("Transaction sent: {}", txid);
///
///     Ok(())
/// }
/// ```
///
/// ## UTXO Management
///
/// ```rust,no_run
/// # use deezel_common::*;
/// # async fn utxo_example<P: WalletProvider>(provider: &P) -> Result<()> {
/// // Get all UTXOs
/// let utxos = provider.get_utxos(false, None).await?;
/// for utxo in &utxos {
///     println!("UTXO: {}:{} - {} sats", utxo.txid, utxo.vout, utxo.amount);
/// }
///
/// // Freeze a specific UTXO
/// if let Some(utxo) = utxos.first() {
///     let utxo_id = format!("{}:{}", utxo.txid, utxo.vout);
///     provider.freeze_utxo(utxo_id, Some("Reserved for special use".to_string())).await?;
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Notes
///
/// - All monetary amounts are in satoshis (1 BTC = 100,000,000 sats)
/// - Address generation follows BIP standards (BIP44, BIP49, BIP84, BIP86)
/// - UTXO management includes freezing/unfreezing for advanced coin control
/// - Transaction creation supports custom fee rates and change addresses
/// - PSBT support enables integration with hardware wallets and multi-sig setups
#[async_trait]
#[cfg(not(feature = "web-compat"))]
pub trait WalletProvider: Send + Sync {
    /// Create a new wallet
    ///
    /// Creates a new HD wallet with optional mnemonic and passphrase. If no mnemonic
    /// is provided, a new one will be generated using cryptographically secure randomness.
    ///
    /// # Arguments
    ///
    /// * `config` - Wallet configuration including network and storage settings
    /// * `mnemonic` - Optional BIP39 mnemonic phrase (12-24 words)
    /// * `passphrase` - Optional encryption passphrase for wallet storage
    ///
    /// # Returns
    ///
    /// Returns [`WalletInfo`] containing the wallet's primary address and network.
    ///
    /// # Security Notes
    ///
    /// - Generated mnemonics use cryptographically secure randomness
    /// - Passphrases are used for wallet file encryption, not BIP39 passphrase
    /// - Wallet files should be stored securely and backed up
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # use bitcoin::Network;
    /// # async fn example<P: WalletProvider>(provider: &P) -> Result<()> {
    /// let config = WalletConfig {
    ///     wallet_path: "my_wallet.json".to_string(),
    ///     network: Network::Bitcoin,
    ///     bitcoin_rpc_url: "http://localhost:8332".to_string(),
    ///     metashrew_rpc_url: "http://localhost:8080".to_string(),
    ///     network_params: None,
    /// };
    ///
    /// let wallet_info = provider.create_wallet(
    ///     config,
    ///     None, // Generate new mnemonic
    ///     Some("secure_passphrase".to_string())
    /// ).await?;
    ///
    /// println!("Created wallet with address: {}", wallet_info.address);
    /// # Ok(())
    /// # }
    /// ```
    async fn create_wallet(&self, config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Load an existing wallet
    ///
    /// Loads a previously created wallet from storage. The wallet must have been
    /// created with the same network configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Wallet configuration matching the original creation
    /// * `passphrase` - Decryption passphrase if the wallet is encrypted
    ///
    /// # Returns
    ///
    /// Returns [`WalletInfo`] for the loaded wallet.
    ///
    /// # Errors
    ///
    /// - [`DeezelError::Wallet`] - If wallet file doesn't exist or is corrupted
    /// - [`DeezelError::Crypto`] - If passphrase is incorrect
    async fn load_wallet(&self, config: WalletConfig, passphrase: Option<String>) -> Result<WalletInfo>;
    
    /// Get wallet balance
    ///
    /// Returns the current wallet balance including confirmed and pending amounts.
    /// Balance calculation includes all wallet addresses and considers UTXO states.
    ///
    /// # Returns
    ///
    /// Returns [`WalletBalance`] with confirmed, trusted pending, and untrusted pending amounts.
    ///
    /// # Balance Categories
    ///
    /// - **Confirmed**: UTXOs with sufficient confirmations (typically 1+)
    /// - **Trusted Pending**: Unconfirmed UTXOs from trusted sources
    /// - **Untrusted Pending**: Unconfirmed UTXOs from untrusted sources
    async fn get_balance(&self) -> Result<WalletBalance>;
    
    /// Get wallet address
    ///
    /// Returns the primary receiving address for the wallet. This is typically
    /// the first unused address in the external derivation chain.
    ///
    /// # Returns
    ///
    /// Returns the primary wallet address as a string.
    ///
    /// # Address Types
    ///
    /// The returned address type depends on the wallet configuration:
    /// - **P2WPKH** (bc1q...): Native SegWit (default for most wallets)
    /// - **P2TR** (bc1p...): Taproot addresses for advanced features
    /// - **P2PKH** (1...): Legacy addresses for compatibility
    async fn get_address(&self) -> Result<String>;
    
    /// Get multiple addresses
    ///
    /// Returns a list of wallet addresses with their derivation information.
    /// Useful for displaying multiple receiving addresses or checking address usage.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of addresses to return
    ///
    /// # Returns
    ///
    /// Returns a vector of [`AddressInfo`] containing addresses and metadata.
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>>;
    
    /// Send Bitcoin transaction
    ///
    /// Creates, signs, and broadcasts a Bitcoin transaction. This is the primary
    /// method for sending Bitcoin from the wallet.
    ///
    /// # Arguments
    ///
    /// * `params` - Transaction parameters including recipient, amount, and options
    ///
    /// # Returns
    ///
    /// Returns the transaction ID (TXID) of the broadcast transaction.
    ///
    /// # Fee Calculation
    ///
    /// - If `fee_rate` is specified, uses that rate in sat/vB
    /// - Otherwise, estimates appropriate fee based on network conditions
    /// - Supports both fixed amounts and "send all" operations
    async fn send(&self, params: SendParams) -> Result<String>;
    
    /// Get UTXOs
    ///
    /// Returns unspent transaction outputs (UTXOs) controlled by the wallet.
    /// This is essential for coin control and understanding wallet composition.
    ///
    /// # Arguments
    ///
    /// * `include_frozen` - Whether to include frozen/locked UTXOs
    /// * `addresses` - Optional filter for specific addresses
    ///
    /// # Returns
    ///
    /// Returns a vector of [`UtxoInfo`] containing UTXO details and metadata.
    ///
    /// # UTXO Metadata
    ///
    /// Each UTXO includes:
    /// - Transaction ID and output index
    /// - Amount in satoshis
    /// - Confirmation count
    /// - Associated address
    /// - Freeze status and reason
    /// - Special properties (inscriptions, runes, alkanes)
    async fn get_utxos(&self, include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>>;
    
    /// Get transaction history
    ///
    /// Returns recent transactions involving the wallet. Useful for displaying
    /// transaction history and tracking wallet activity.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of transactions to return
    /// * `address` - Optional filter for specific address
    ///
    /// # Returns
    ///
    /// Returns a vector of [`TransactionInfo`] with transaction details.
    async fn get_history(&self, count: u32, address: Option<String>) -> Result<Vec<TransactionInfo>>;
    
    /// Freeze a UTXO
    ///
    /// Marks a UTXO as frozen, preventing it from being used in transactions.
    /// This is useful for coin control and reserving specific UTXOs.
    ///
    /// # Arguments
    ///
    /// * `utxo` - UTXO identifier in format "txid:vout"
    /// * `reason` - Optional reason for freezing
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_common::*;
    /// # async fn example<P: WalletProvider>(provider: &P) -> Result<()> {
    /// provider.freeze_utxo(
    ///     "abc123...def:0".to_string(),
    ///     Some("Reserved for special transaction".to_string())
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn freeze_utxo(&self, utxo: String, reason: Option<String>) -> Result<()>;
    
    /// Unfreeze a UTXO
    ///
    /// Removes the freeze status from a UTXO, making it available for transactions again.
    ///
    /// # Arguments
    ///
    /// * `utxo` - UTXO identifier in format "txid:vout"
    async fn unfreeze_utxo(&self, utxo: String) -> Result<()>;
    
    /// Create transaction without broadcasting
    ///
    /// Creates and signs a transaction but does not broadcast it to the network.
    /// Useful for transaction review, offline signing, or batch operations.
    ///
    /// # Arguments
    ///
    /// * `params` - Transaction parameters
    ///
    /// # Returns
    ///
    /// Returns the signed transaction as a hexadecimal string.
    async fn create_transaction(&self, params: SendParams) -> Result<String>;
    
    /// Sign transaction
    ///
    /// Signs a raw transaction hex with the wallet's private keys.
    /// The transaction must spend UTXOs controlled by this wallet.
    ///
    /// # Arguments
    ///
    /// * `tx_hex` - Raw transaction in hexadecimal format
    ///
    /// # Returns
    ///
    /// Returns the signed transaction as a hexadecimal string.
    async fn sign_transaction(&self, tx_hex: String) -> Result<String>;
    
    /// Broadcast transaction
    ///
    /// Broadcasts a signed transaction to the Bitcoin network.
    /// The transaction should be properly signed and valid.
    ///
    /// # Arguments
    ///
    /// * `tx_hex` - Signed transaction in hexadecimal format
    ///
    /// # Returns
    ///
    /// Returns the transaction ID (TXID) if broadcast was successful.
    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String>;
    
    /// Estimate fee
    ///
    /// Estimates the fee rate needed for a transaction to confirm within
    /// the target number of blocks.
    ///
    /// # Arguments
    ///
    /// * `target` - Target confirmation time in blocks
    ///
    /// # Returns
    ///
    /// Returns [`FeeEstimate`] with recommended fee rate in sat/vB.
    async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate>;
    
    /// Get current fee rates
    ///
    /// Returns current network fee rates for different confirmation priorities.
    /// Useful for displaying fee options to users.
    ///
    /// # Returns
    ///
    /// Returns [`FeeRates`] with fast, medium, and slow fee rates.
    async fn get_fee_rates(&self) -> Result<FeeRates>;
    
    /// Synchronize wallet
    ///
    /// Synchronizes the wallet with the blockchain, updating balances,
    /// transaction history, and UTXO set. Should be called periodically
    /// or after network operations.
    async fn sync(&self) -> Result<()>;
    
    /// Backup wallet
    ///
    /// Creates a backup of the wallet data. The format depends on the
    /// implementation but typically includes mnemonic and metadata.
    ///
    /// # Returns
    ///
    /// Returns backup data as a string (JSON, encrypted blob, etc.).
    ///
    /// # Security Note
    ///
    /// Backup data may contain sensitive information and should be stored securely.
    async fn backup(&self) -> Result<String>;
    
    /// Get mnemonic
    ///
    /// Returns the wallet's BIP39 mnemonic phrase if available.
    /// Some wallet types (like browser wallets) may not expose mnemonics.
    ///
    /// # Returns
    ///
    /// Returns the mnemonic phrase if available, or `None` if not accessible.
    ///
    /// # Security Note
    ///
    /// Mnemonic phrases provide full access to wallet funds and should be handled securely.
    async fn get_mnemonic(&self) -> Result<Option<String>>;
    
    /// Get network
    ///
    /// Returns the Bitcoin network this wallet is configured for.
    ///
    /// # Returns
    ///
    /// Returns the [`Network`] (Bitcoin, Testnet, Signet, or Regtest).
    fn get_network(&self) -> Network;
    
    /// Get internal key for wallet
    ///
    /// Returns the wallet's internal public key, typically used for Taproot operations.
    /// This is the key used for keypath spending in Taproot addresses.
    ///
    /// # Returns
    ///
    /// Returns the X-only public key for Taproot operations.
    async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey>;
    
    /// Sign PSBT
    ///
    /// Signs a Partially Signed Bitcoin Transaction (PSBT) with the wallet's keys.
    /// This enables integration with hardware wallets and multi-signature setups.
    ///
    /// # Arguments
    ///
    /// * `psbt` - The PSBT to sign
    ///
    /// # Returns
    ///
    /// Returns the PSBT with added signatures.
    ///
    /// # PSBT Support
    ///
    /// - Supports all standard PSBT fields
    /// - Handles multiple input types (P2PKH, P2WPKH, P2TR, etc.)
    /// - Preserves existing signatures from other signers
    async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt>;
    
    /// Get keypair for wallet
    ///
    /// Returns the wallet's primary keypair for advanced cryptographic operations.
    /// This provides access to both public and private key components.
    ///
    /// # Returns
    ///
    /// Returns the secp256k1 keypair.
    ///
    /// # Security Warning
    ///
    /// This method exposes private key material and should be used with extreme caution.
    /// Many wallet implementations may refuse to provide keypairs for security reasons.
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
#[derive(Debug, Clone)]
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

/// Enhanced alkanes execute parameters with protostones encoding and Rebar support
#[derive(Debug, Clone)]
pub struct EnhancedExecuteParams {
    pub fee_rate: Option<f32>,
    pub to_addresses: Vec<String>,
    pub change_address: Option<String>,
    pub input_requirements: Vec<InputRequirement>,
    pub protostones: Vec<ProtostoneSpec>,
    pub envelope_data: Option<Vec<u8>>,
    pub raw_output: bool,
    pub trace_enabled: bool,
    pub mine_enabled: bool,
    pub auto_confirm: bool,
    pub rebar_enabled: bool,
}

/// Enhanced alkanes execute result with pretty printing capabilities
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnhancedExecuteResult {
    pub commit_txid: Option<String>,
    pub reveal_txid: Option<String>,
    pub commit_fee: Option<u64>,
    pub reveal_fee: Option<u64>,
    pub total_fee: Option<u64>,
    pub commit_tx_hex: Option<String>,
    pub reveal_tx_hex: Option<String>,
    pub inputs_used: Vec<String>,
    pub outputs_created: Vec<String>,
    pub traces: Option<Vec<String>>,
    pub rebar_used: bool,
    pub execution_time_ms: Option<u64>,
    pub protostones_encoded: bool,
}

impl EnhancedExecuteResult {
    /// Pretty print the result for CLI usage
    pub fn pretty_print(&self) -> String {
        let mut output = String::new();
        
        output.push_str("🎉 Enhanced Alkanes Execution Completed\n");
        output.push_str("═══════════════════════════════════════\n");
        
        if self.is_commit_reveal() {
            output.push_str("📋 Transaction Pattern: Commit/Reveal\n");
            if let Some(commit_txid) = &self.commit_txid {
                output.push_str(&format!("🔗 Commit TXID: {}\n", commit_txid));
            }
            if let Some(reveal_txid) = &self.reveal_txid {
                output.push_str(&format!("🔗 Reveal TXID: {}\n", reveal_txid));
            }
        } else {
            output.push_str("📋 Transaction Pattern: Single Transaction\n");
            if let Some(reveal_txid) = &self.reveal_txid {
                output.push_str(&format!("🔗 Transaction ID: {}\n", reveal_txid));
            }
        }
        
        // Fee information
        if let Some(total) = self.total_fee() {
            output.push_str(&format!("💰 Total Fee: {} sats\n", total));
            if let Some(commit_fee) = self.commit_fee {
                output.push_str(&format!("   📤 Commit Fee: {} sats\n", commit_fee));
            }
            if let Some(reveal_fee) = self.reveal_fee {
                output.push_str(&format!("   📥 Reveal Fee: {} sats\n", reveal_fee));
            }
        }
        
        // Protostones encoding status
        if self.protostones_encoded {
            output.push_str("🔮 Protostones: Properly encoded in runestone\n");
        }
        
        // Rebar usage
        if self.rebar_used {
            output.push_str("🛡️  Rebar Labs Shield: Used for private relay\n");
        }
        
        // Execution time
        if let Some(time_ms) = self.execution_time_ms {
            output.push_str(&format!("⏱️  Execution Time: {}ms\n", time_ms));
        }
        
        // Input/output summary
        if !self.inputs_used.is_empty() {
            output.push_str(&format!("📥 Inputs Used: {}\n", self.inputs_used.len()));
        }
        if !self.outputs_created.is_empty() {
            output.push_str(&format!("📤 Outputs Created: {}\n", self.outputs_created.len()));
        }
        
        // Traces if available
        if let Some(traces) = &self.traces {
            if !traces.is_empty() {
                output.push_str(&format!("🔍 Traces Available: {} entries\n", traces.len()));
            }
        }
        
        output
    }
    
    /// Get a summary of the execution
    pub fn summary(&self) -> String {
        if self.is_commit_reveal() {
            format!("Commit/Reveal execution completed with {} total fee",
                   self.total_fee().map_or("unknown".to_string(), |f| format!("{} sats", f)))
        } else {
            format!("Single transaction execution completed with {} fee",
                   self.reveal_fee.map_or("unknown".to_string(), |f| format!("{} sats", f)))
        }
    }
    
    /// Check if this is a commit/reveal pattern
    pub fn is_commit_reveal(&self) -> bool {
        self.commit_txid.is_some()
    }
    
    /// Calculate total fee
    pub fn total_fee(&self) -> Option<u64> {
        match (self.commit_fee, self.reveal_fee) {
            (Some(commit), Some(reveal)) => Some(commit + reveal),
            (None, Some(reveal)) => Some(reveal),
            (Some(commit), None) => Some(commit),
            (None, None) => None,
        }
    }
}

/// Input requirement specification
#[derive(Debug, Clone)]
pub struct InputRequirement {
    pub requirement_type: InputRequirementType,
    pub amount: u64,
    pub alkane_id: Option<AlkaneId>,
}

/// Input requirement type
#[derive(Debug, Clone)]
pub enum InputRequirementType {
    Bitcoin,
    Alkanes,
}

/// Protostone specification
#[derive(Debug, Clone)]
pub struct ProtostoneSpec {
    pub name: String,
    pub data: Vec<u8>,
    pub encoding: ProtostoneEncoding,
}

/// Protostone encoding type
#[derive(Debug, Clone)]
pub enum ProtostoneEncoding {
    Raw,
    Hex,
    Base64,
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