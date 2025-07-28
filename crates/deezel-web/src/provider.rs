//! Web-compatible provider implementation for browser environments
//!
//! This module provides a complete implementation of all deezel-common traits using web-sys APIs,
//! enabling deezel functionality to run in web browsers and WASM environments. The [`WebProvider`]
//! serves as the main entry point for all web-based Bitcoin and Alkanes operations.
//!
//! # Features
//!
//! - **Cross-platform compatibility**: Works in all modern web browsers
//! - **Complete trait implementation**: Implements all deezel-common provider traits
//! - **WASM optimization**: Optimized for WebAssembly execution
//! - **Browser API integration**: Uses fetch API, localStorage, Web Crypto API, etc.
//! - **Rebar Labs Shield support**: Private transaction broadcasting for mainnet
//!
//! # Architecture
//!
//! The [`WebProvider`] aggregates several specialized web implementations:
//! - [`WebStorage`] for localStorage-based persistence
//! - [`WebNetwork`] for HTTP requests using fetch API
//! - [`WebCrypto`] for cryptographic operations using Web Crypto API
//! - [`WebTime`] for timing operations using Performance API
//! - [`WebLogger`] for console-based logging
//!
//! # Example
//!
//! ```rust,no_run
//! use deezel_web::WebProvider;
//! use deezel_common::*;
//!
//! async fn example() -> Result<()> {
//!     // Create a web provider for mainnet
//!     let provider = WebProvider::new("mainnet".to_string()).await?;
//!
//!     // Initialize the provider
//!     provider.initialize().await?;
//!
//!     // Use any deezel functionality
//!     // Note: get_balance requires a wallet connection, this is just an example
//!     // let balance = WalletProvider::get_balance(&provider).await?;
//!     // println!("Balance: {} sats", balance.confirmed);
//!
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use bitcoin::Network;
use deezel_common::*;
use serde_json::Value as JsonValue;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, window};

#[cfg(target_arch = "wasm32")]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::storage::WebStorage;
use crate::network::WebNetwork;
use crate::crypto::WebCrypto;
use crate::time::WebTime;
use crate::logging::WebLogger;

/// Web-compatible provider implementation for browser environments
///
/// The `WebProvider` is the main entry point for using deezel functionality in web browsers
/// and WASM environments. It implements all deezel-common traits using web-standard APIs,
/// providing complete Bitcoin wallet and Alkanes metaprotocol functionality.
///
/// # Features
///
/// - **Bitcoin Operations**: Full wallet functionality, transaction creation, and broadcasting
/// - **Alkanes Integration**: Smart contract execution, token operations, and AMM functionality
/// - **Web Standards**: Uses fetch API, localStorage, Web Crypto API, and console logging
/// - **Network Support**: Configurable for mainnet, testnet, signet, regtest, and custom networks
/// - **Privacy Features**: Rebar Labs Shield integration for private transaction broadcasting
///
/// # Example
///
/// ```rust,no_run
/// use deezel_web::WebProvider;
/// use deezel_common::*;
///
/// async fn create_provider() -> Result<WebProvider> {
///     let provider = WebProvider::new("mainnet".to_string()).await?;
///
///     provider.initialize().await?;
///     Ok(provider)
/// }
/// ```
#[derive(Clone)]
pub struct WebProvider {
    sandshrew_rpc_url: String,
    esplora_rpc_url: Option<String>,
    network: Network,
    storage: WebStorage,
    network_client: WebNetwork,
    crypto: WebCrypto,
    time: WebTime,
    logger: WebLogger,
}

impl WebProvider {
    /// Creates a new WebProvider instance for the specified network
    ///
    /// This is the primary constructor for creating a web-compatible deezel provider.
    /// It configures the provider for the specified Bitcoin network and sets up
    /// connections to the required RPC endpoints.
    ///
    /// # Arguments
    ///
    /// * `network_str` - Network identifier ("mainnet", "testnet", "signet", "regtest")
    ///
    /// # Returns
    ///
    /// Returns a configured `WebProvider` instance ready for initialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the network string is invalid or if provider setup fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use deezel_web::WebProvider;
    /// use deezel_common::Result;
    ///
    /// async fn setup_mainnet() -> Result<WebProvider> {
    ///     let provider = WebProvider::new("mainnet".to_string()).await?;
    ///     Ok(provider)
    /// }
    /// ```
    pub async fn new(
        network_str: String,
    ) -> Result<Self> {
        let network = match network_str.as_str() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            _ => return Err(DeezelError::Configuration(format!("Invalid network: {network_str}"))),
        };

        let sandshrew_rpc_url = match network {
            Network::Bitcoin => "https://mainnet.sandshrew.io/v4/wrlckwrld".to_string(),
            Network::Testnet => "https://signet.sandshrew.io/v4/wrlckwrld".to_string(),
            Network::Signet => "https://signet.sandshrew.io/v4/wrlckwrld".to_string(),
            Network::Regtest => "http://localhost:18888".to_string(),
            _ => return Err(DeezelError::Configuration(format!("Unsupported network: {network_str}"))),
        };

        let esplora_rpc_url = match network {
            Network::Bitcoin => Some("https://mempool.space/api".to_string()),
            Network::Testnet => Some("https://mempool.space/testnet/api".to_string()),
            Network::Signet => Some("https://mempool.space/signet/api".to_string()),
            Network::Regtest => Some("http://localhost:3003".to_string()),
            _ => None,
        };

        Ok(Self {
            sandshrew_rpc_url,
            esplora_rpc_url,
            network,
            storage: WebStorage::new(),
            network_client: WebNetwork::new(),
            crypto: WebCrypto::new(),
            time: WebTime::new(),
            logger: WebLogger::new(),
        })
    }

    /// Returns a wallet configuration suitable for this provider
    ///
    /// Creates a `WalletConfig` with the provider's network settings and RPC URLs.
    /// This configuration can be used with wallet operations that require network
    /// and RPC endpoint information.
    ///
    /// # Returns
    ///
    /// A `WalletConfig` configured for this provider's network and endpoints.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_web::WebProvider;
    /// # use deezel_common::Result;
    /// # async fn example() -> Result<()> {
    /// # let provider = WebProvider::new("mainnet".to_string()).await?;
    /// let config = provider.get_wallet_config();
    /// println!("Network: {:?}", config.network);
    /// println!("Bitcoin RPC: {}", config.bitcoin_rpc_url);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_wallet_config(&self) -> WalletConfig {
        WalletConfig {
            wallet_path: "web-wallet".to_string(),
            network: self.network,
            bitcoin_rpc_url: self.sandshrew_rpc_url.clone(),
            metashrew_rpc_url: self.sandshrew_rpc_url.clone(),
            network_params: None,
        }
    }

    /// Get the network for this provider
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the Sandshrew RPC URL
    pub fn sandshrew_rpc_url(&self) -> &str {
        &self.sandshrew_rpc_url
    }

    /// Get the Esplora RPC URL
    pub fn esplora_rpc_url(&self) -> Option<&str> {
        self.esplora_rpc_url.as_deref()
    }

    /// Make a fetch request using web-sys
    async fn fetch_request(&self, url: &str, method: &str, body: Option<&str>, headers: Option<&js_sys::Object>) -> Result<Response> {
        let window = window().ok_or_else(|| DeezelError::Network("No window object available".to_string()))?;

        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_mode(RequestMode::Cors);

        if let Some(body_str) = body {
            opts.set_body(&JsValue::from_str(body_str));
        }

        if let Some(headers_obj) = headers {
            opts.set_headers(headers_obj);
        }

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| DeezelError::Network(format!("Failed to create request: {e:?}")))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| DeezelError::Network(format!("Fetch failed: {e:?}")))?;

        let resp: Response = resp_value.dyn_into()
            .map_err(|e| DeezelError::Network(format!("Failed to cast response: {e:?}")))?;

        Ok(resp)
    }

    /// Broadcasts a transaction via Rebar Labs Shield for enhanced privacy
    ///
    /// Rebar Labs Shield provides private transaction broadcasting by sending transactions
    /// directly to mining pools without exposing them to public mempools. This is particularly
    /// useful for sensitive transactions or when privacy is a concern.
    ///
    /// # Arguments
    ///
    /// * `tx_hex` - The raw transaction in hexadecimal format
    ///
    /// # Returns
    ///
    /// Returns the transaction ID (TXID) if the broadcast was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The network request fails
    /// - The Rebar Shield service returns an error
    /// - The transaction is invalid or rejected
    ///
    /// # Privacy Features
    ///
    /// - Transactions are sent directly to mining pools
    /// - No public mempool exposure
    /// - Enhanced privacy for sensitive operations
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use deezel_web::WebProvider;
    /// # use deezel_common::Result;
    /// # async fn example() -> Result<()> {
    /// # let provider = WebProvider::new("mainnet".to_string()).await?;
    /// let tx_hex = "0200000001..."; // Your transaction hex
    /// let txid = provider.broadcast_via_rebar_shield(tx_hex).await?;
    /// println!("Transaction broadcast privately: {}", txid);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn broadcast_via_rebar_shield(&self, tx_hex: &str) -> Result<String> {
        self.logger.info("🛡️  Broadcasting transaction via Rebar Labs Shield (web)");
        
        // Rebar Labs Shield endpoint
        let rebar_endpoint = "https://shield.rebarlabs.io/v1/rpc";
        
        // Create JSON-RPC request for sendrawtransaction
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "sendrawtransaction",
            "params": [tx_hex]
        });
        
        self.logger.info(&format!("Sending transaction to Rebar Shield endpoint: {rebar_endpoint}"));
        
        // Create headers
        let headers = js_sys::Object::new();
        js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into())
            .map_err(|e| DeezelError::Network(format!("Failed to set header: {e:?}")))?;
        
        // Make HTTP POST request to Rebar Labs Shield
        let response = self.fetch_request(
            rebar_endpoint,
            "POST",
            Some(&request_body.to_string()),
            Some(&headers),
        ).await?;
        
        let response_text = JsFuture::from(response.text()
            .map_err(|e| DeezelError::Network(format!("Failed to get response text: {e:?}")))?)
            .await
            .map_err(|e| DeezelError::Network(format!("Failed to read Rebar Shield response: {e:?}")))?;
        
        let response_str = response_text.as_string()
            .ok_or_else(|| DeezelError::Network("Response is not a string".to_string()))?;
        
        let response_json: JsonValue = serde_json::from_str(&response_str)
            .map_err(|e| DeezelError::Serialization(format!("Failed to parse Rebar Shield JSON: {e}")))?;
        
        // Check for JSON-RPC error
        if let Some(error) = response_json.get("error") {
            return Err(DeezelError::JsonRpc(format!("Rebar Shield error: {error}")));
        }
        
        // Extract transaction ID from result
        let txid = response_json.get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| DeezelError::JsonRpc("No transaction ID in Rebar Shield response".to_string()))?;
        
        self.logger.info(&format!("✅ Transaction broadcast via Rebar Shield: {txid}"));
        self.logger.info("🛡️  Transaction sent privately to mining pools");
        
        Ok(txid.to_string())
    }
}

#[async_trait(?Send)]
impl JsonRpcProvider for WebProvider {
    async fn call(&self, url: &str, method: &str, params: JsonValue, id: u64) -> Result<JsonValue> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id
        });

        // Create headers
        let headers = js_sys::Object::new();
        js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into())
            .map_err(|e| DeezelError::Network(format!("Failed to set header: {e:?}")))?;

        let response = self.fetch_request(
            url,
            "POST",
            Some(&request_body.to_string()),
            Some(&headers),
        ).await?;

        let response_text = JsFuture::from(response.text()
            .map_err(|e| DeezelError::Network(format!("Failed to get response text: {e:?}")))?)
            .await
            .map_err(|e| DeezelError::Network(format!("Failed to read response: {e:?}")))?;

        let response_str = response_text.as_string()
            .ok_or_else(|| DeezelError::Network("Response is not a string".to_string()))?;

        let response_json: JsonValue = serde_json::from_str(&response_str)
            .map_err(|e| DeezelError::Serialization(format!("Failed to parse JSON: {e}")))?;

        if let Some(error) = response_json.get("error") {
            return Err(DeezelError::JsonRpc(format!("JSON-RPC error: {error}")));
        }

        response_json.get("result")
            .cloned()
            .ok_or_else(|| DeezelError::JsonRpc("No result in JSON-RPC response".to_string()))
    }

    async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String> {
        let params = serde_json::json!([block, tx]);
        let result = self.call(self.sandshrew_rpc_url(), "get_bytecode", params, 1).await?;
        Ok(result.as_str().unwrap_or("").to_string())
    }
}

#[async_trait(?Send)]
impl StorageProvider for WebProvider {
    async fn read(&self, key: &str) -> Result<Vec<u8>> {
        self.storage.read(key).await
    }

    async fn write(&self, key: &str, data: &[u8]) -> Result<()> {
        self.storage.write(key, data).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.storage.exists(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.storage.delete(key).await
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        self.storage.list_keys(prefix).await
    }

    fn storage_type(&self) -> &'static str {
        "localStorage"
    }
}

#[async_trait(?Send)]
impl NetworkProvider for WebProvider {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.network_client.get(url).await
    }

    async fn post(&self, url: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>> {
        self.network_client.post(url, body, content_type).await
    }

    async fn is_reachable(&self, url: &str) -> bool {
        self.network_client.is_reachable(url).await
    }
}

#[async_trait(?Send)]
impl CryptoProvider for WebProvider {
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        self.crypto.random_bytes(len)
    }

    fn sha256(&self, data: &[u8]) -> Result<[u8; 32]> {
        self.crypto.sha256(data)
    }

    fn sha3_256(&self, data: &[u8]) -> Result<[u8; 32]> {
        self.crypto.sha3_256(data)
    }

    async fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        self.crypto.encrypt_aes_gcm(data, key, nonce).await
    }

    async fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        self.crypto.decrypt_aes_gcm(data, key, nonce).await
    }

    async fn pbkdf2_derive(&self, password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Result<Vec<u8>> {
        self.crypto.pbkdf2_derive(password, salt, iterations, key_len).await
    }
}

#[async_trait(?Send)]
impl TimeProvider for WebProvider {
    fn now_secs(&self) -> u64 {
        self.time.now_secs()
    }

    fn now_millis(&self) -> u64 {
        self.time.now_millis()
    }

    async fn sleep_ms(&self, ms: u64) {
        self.time.sleep_ms(ms).await
    }
}

impl LogProvider for WebProvider {
    fn debug(&self, message: &str) {
        self.logger.debug(message);
    }

    fn info(&self, message: &str) {
        self.logger.info(message);
    }

    fn warn(&self, message: &str) {
        self.logger.warn(message);
    }

    fn error(&self, message: &str) {
        self.logger.error(message);
    }
}

#[async_trait(?Send)]
impl EsploraProvider for WebProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BLOCKS_TIP_HASH, esplora::params::empty(), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid tip hash response".to_string()))
    }

    async fn get_blocks_tip_height(&self) -> Result<u64> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BLOCKS_TIP_HEIGHT, esplora::params::empty(), 1).await?;
        result.as_u64().ok_or_else(|| DeezelError::RpcError("Invalid tip height response".to_string()))
    }

    async fn get_blocks(&self, start_height: Option<u64>) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::BLOCKS, esplora::params::optional_single(start_height), 1).await
    }

    async fn get_block_by_height(&self, height: u64) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_HEIGHT, esplora::params::single(height), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block hash response".to_string()))
    }

    async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::BLOCK, esplora::params::single(hash), 1).await
    }

    async fn get_block_status(&self, hash: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_STATUS, esplora::params::single(hash), 1).await
    }

    async fn get_block_txids(&self, hash: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_TXIDS, esplora::params::single(hash), 1).await
    }

    async fn get_block_header(&self, hash: &str) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_HEADER, esplora::params::single(hash), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block header response".to_string()))
    }

    async fn get_block_raw(&self, hash: &str) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_RAW, esplora::params::single(hash), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid raw block response".to_string()))
    }

    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_TXID, esplora::params::dual(hash, index), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid txid response".to_string()))
    }

    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::BLOCK_TXS, esplora::params::optional_dual(hash, start_index), 1).await
    }

    async fn get_address_info(&self, address: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS, esplora::params::single(address), 1).await
    }

    async fn get_address(&self, address: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS, esplora::params::single(address), 1).await
    }

    async fn get_address_txs(&self, address: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS_TXS, esplora::params::single(address), 1).await
    }

    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS_TXS_CHAIN, esplora::params::optional_dual(address, last_seen_txid), 1).await
    }

    async fn get_address_txs_mempool(&self, address: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS_TXS_MEMPOOL, esplora::params::single(address), 1).await
    }

    async fn get_address_utxo(&self, address: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS_UTXO, esplora::params::single(address), 1).await
    }

    async fn get_address_prefix(&self, prefix: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::ADDRESS_PREFIX, esplora::params::single(prefix), 1).await
    }

    async fn get_tx(&self, txid: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::TX, esplora::params::single(txid), 1).await
    }

    async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::TX_HEX, esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid tx hex response".to_string()))
    }

    async fn get_tx_raw(&self, txid: &str) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::TX_RAW, esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid raw tx response".to_string()))
    }

    async fn get_tx_status(&self, txid: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::TX_STATUS, esplora::params::single(txid), 1).await
    }

    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::TX_MERKLE_PROOF, esplora::params::single(txid), 1).await
    }

    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::TX_MERKLEBLOCK_PROOF, esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid merkleblock proof response".to_string()))
    }

    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::TX_OUTSPEND, esplora::params::dual(txid, index), 1).await
    }

    async fn get_tx_outspends(&self, txid: &str) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::TX_OUTSPENDS, esplora::params::single(txid), 1).await
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        let result = self.call(url, esplora::EsploraJsonRpcMethods::BROADCAST, esplora::params::single(tx_hex), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid broadcast response".to_string()))
    }

    async fn get_mempool(&self) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::MEMPOOL, esplora::params::empty(), 1).await
    }

    async fn get_mempool_txids(&self) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::MEMPOOL_TXIDS, esplora::params::empty(), 1).await
    }

    async fn get_mempool_recent(&self) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::MEMPOOL_RECENT, esplora::params::empty(), 1).await
    }

    async fn get_fee_estimates(&self) -> Result<serde_json::Value> {
        let url = self.esplora_rpc_url.as_ref().ok_or_else(|| DeezelError::Configuration("Esplora URL not configured".to_string()))?;
        self.call(url, esplora::EsploraJsonRpcMethods::FEE_ESTIMATES, esplora::params::empty(), 1).await
    }
}

// The trait implementations are included via the lib.rs module system