//! Esplora RPC client implementation
//!
//! This module provides a specialized RPC client for Esplora API.
//! It handles error handling, rate limiting, and provides typed methods
//! for common Esplora API calls.

use anyhow::{Context, Result, anyhow};
use log::{debug, warn, error};
use reqwest::{Client, header, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use url::Url;

use super::RpcConfig;

/// Esplora RPC configuration
#[derive(Clone, Debug)]
pub struct EsploraRpcConfig {
    /// API URL (e.g., https://blockstream.info/api/)
    pub url: String,
    /// Connection timeout in seconds
    pub timeout: u64,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Retry delay in milliseconds
    pub retry_delay: u64,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
}

impl Default for EsploraRpcConfig {
    fn default() -> Self {
        Self {
            url: "https://blockstream.info/api/".to_string(),
            timeout: 30,
            max_retries: 3,
            retry_delay: 1000,
            max_concurrent_requests: 10,
        }
    }
}

/// Esplora transaction input
#[derive(Debug, Deserialize)]
pub struct EsploraTxInput {
    /// Previous transaction ID
    pub txid: String,
    /// Previous output index
    pub vout: u32,
    /// Previous output value in satoshis
    pub prevout: Option<EsploraPrevout>,
    /// Sequence number
    pub sequence: u32,
    /// Witness data (if available)
    pub witness: Option<Vec<String>>,
    /// Script signature
    pub scriptsig: String,
    /// Script signature in ASM format
    pub scriptsig_asm: String,
}

/// Esplora previous output
#[derive(Debug, Deserialize)]
pub struct EsploraPrevout {
    /// Output value in satoshis
    pub value: u64,
    /// Output script pubkey
    pub scriptpubkey: String,
    /// Output script pubkey in ASM format
    pub scriptpubkey_asm: String,
    /// Output script pubkey type
    pub scriptpubkey_type: String,
    /// Output script pubkey address
    pub scriptpubkey_address: Option<String>,
}

/// Esplora transaction output
#[derive(Debug, Deserialize)]
pub struct EsploraTxOutput {
    /// Output value in satoshis
    pub value: u64,
    /// Output script pubkey
    pub scriptpubkey: String,
    /// Output script pubkey in ASM format
    pub scriptpubkey_asm: String,
    /// Output script pubkey type
    pub scriptpubkey_type: String,
    /// Output script pubkey address
    pub scriptpubkey_address: Option<String>,
}

/// Esplora transaction status
#[derive(Debug, Deserialize)]
pub struct EsploraTxStatus {
    /// Transaction confirmation status
    pub confirmed: bool,
    /// Block height (if confirmed)
    pub block_height: Option<u64>,
    /// Block hash (if confirmed)
    pub block_hash: Option<String>,
    /// Block time (if confirmed)
    pub block_time: Option<u64>,
}

/// Esplora transaction
#[derive(Debug, Deserialize)]
pub struct EsploraTx {
    /// Transaction ID
    pub txid: String,
    /// Transaction version
    pub version: u32,
    /// Transaction locktime
    pub locktime: u32,
    /// Transaction size in bytes
    pub size: u32,
    /// Transaction weight
    pub weight: u32,
    /// Transaction fee in satoshis
    pub fee: u64,
    /// Transaction inputs
    pub vin: Vec<EsploraTxInput>,
    /// Transaction outputs
    pub vout: Vec<EsploraTxOutput>,
    /// Transaction status
    pub status: EsploraTxStatus,
}

/// Esplora UTXO
#[derive(Debug, Deserialize)]
pub struct EsploraUtxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Output value in satoshis
    pub value: u64,
    /// Output status
    pub status: EsploraTxStatus,
}

/// Esplora block
#[derive(Debug, Deserialize)]
pub struct EsploraBlock {
    /// Block ID
    pub id: String,
    /// Block height
    pub height: u64,
    /// Block version
    pub version: u32,
    /// Block timestamp
    pub timestamp: u64,
    /// Block bits
    pub bits: u32,
    /// Block nonce
    pub nonce: u32,
    /// Block difficulty
    pub difficulty: f64,
    /// Block merkle root
    pub merkle_root: String,
    /// Block transaction count
    pub tx_count: u32,
    /// Block size in bytes
    pub size: u32,
    /// Block weight
    pub weight: u32,
    /// Previous block hash
    pub previousblockhash: String,
    /// Next block hash (if available)
    pub nextblockhash: Option<String>,
}

/// Esplora RPC client
pub struct EsploraRpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: EsploraRpcConfig,
    /// Rate limiter
    rate_limiter: Arc<Semaphore>,
}

impl EsploraRpcClient {
    /// Create a new Esplora RPC client
    pub fn new(config: EsploraRpcConfig) -> Self {
        // Create HTTP client with appropriate timeouts
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .build()
            .expect("Failed to create HTTP client");
        
        // Create rate limiter
        let rate_limiter = Arc::new(Semaphore::new(config.max_concurrent_requests));
        
        Self {
            client,
            config,
            rate_limiter,
        }
    }
    
    /// Create a new Esplora RPC client from a generic RPC config
    pub fn from_rpc_config(config: &RpcConfig) -> Self {
        // Create Esplora config from generic RPC config
        // In a real implementation, we would use a dedicated Esplora URL
        // For now, use the Bitcoin RPC URL as a fallback
        let esplora_config = EsploraRpcConfig {
            url: config.bitcoin_rpc_url.clone(),
            timeout: 30,
            max_retries: 3,
            retry_delay: 1000,
            max_concurrent_requests: 10,
        };
        
        Self::new(esplora_config)
    }
    
    /// Make a GET request to the Esplora API with retry logic
    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        // Acquire permit from rate limiter
        let _permit = self.rate_limiter.acquire().await?;
        
        let mut retries = 0;
        let mut last_error = None;
        
        while retries <= self.config.max_retries {
            if retries > 0 {
                debug!("Retrying Esplora API request to {} (attempt {}/{})", path, retries, self.config.max_retries);
                sleep(Duration::from_millis(self.config.retry_delay)).await;
            }
            
            match self.execute_get::<T>(path).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_error = Some(err);
                    retries += 1;
                    
                    // Only retry on connection errors, rate limiting, or server errors
                    if !is_retryable_error(&last_error.as_ref().unwrap()) {
                        break;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow!("Unknown error during Esplora API request")))
    }
    
    /// Execute a single GET request to the Esplora API without retry logic
    async fn execute_get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        debug!("Making Esplora API request to {}", path);
        
        let url = format!("{}{}", self.config.url.trim_end_matches('/'), path);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to send Esplora API request")?;
        
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("Esplora API request failed with status: {}", status));
        }
        
        let result = response
            .json::<T>()
            .await
            .context("Failed to parse Esplora API response")?;
        
        Ok(result)
    }
    
    /// Make a POST request to the Esplora API with retry logic
    async fn post<T: for<'de> Deserialize<'de>>(&self, path: &str, body: &[u8]) -> Result<T> {
        // Acquire permit from rate limiter
        let _permit = self.rate_limiter.acquire().await?;
        
        let mut retries = 0;
        let mut last_error = None;
        
        while retries <= self.config.max_retries {
            if retries > 0 {
                debug!("Retrying Esplora API request to {} (attempt {}/{})", path, retries, self.config.max_retries);
                sleep(Duration::from_millis(self.config.retry_delay)).await;
            }
            
            match self.execute_post::<T>(path, body).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_error = Some(err);
                    retries += 1;
                    
                    // Only retry on connection errors, rate limiting, or server errors
                    if !is_retryable_error(&last_error.as_ref().unwrap()) {
                        break;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow!("Unknown error during Esplora API request")))
    }
    
    /// Execute a single POST request to the Esplora API without retry logic
    async fn execute_post<T: for<'de> Deserialize<'de>>(&self, path: &str, body: &[u8]) -> Result<T> {
        debug!("Making Esplora API POST request to {}", path);
        
        let url = format!("{}{}", self.config.url.trim_end_matches('/'), path);
        
        let response = self.client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(body.to_vec())
            .send()
            .await
            .context("Failed to send Esplora API request")?;
        
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("Esplora API request failed with status: {}", status));
        }
        
        let result = response
            .json::<T>()
            .await
            .context("Failed to parse Esplora API response")?;
        
        Ok(result)
    }
    
    /// Get the current block height
    pub async fn get_block_height(&self) -> Result<u64> {
        debug!("Getting block height from Esplora API");
        
        let height = self.get::<u64>("/blocks/tip/height").await?;
        
        debug!("Current block height: {}", height);
        Ok(height)
    }
    
    /// Get block hash at the given height
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        debug!("Getting block hash for height: {}", height);
        
        let hash = self.get::<String>(&format!("/block-height/{}", height)).await?;
        
        debug!("Block hash for height {}: {}", height, hash);
        Ok(hash)
    }
    
    /// Get block details
    pub async fn get_block(&self, hash: &str) -> Result<EsploraBlock> {
        debug!("Getting block details for hash: {}", hash);
        
        let block = self.get::<EsploraBlock>(&format!("/block/{}", hash)).await?;
        
        debug!("Got block details for hash: {}", hash);
        Ok(block)
    }
    
    /// Get transaction details
    pub async fn get_transaction(&self, txid: &str) -> Result<EsploraTx> {
        debug!("Getting transaction details for txid: {}", txid);
        
        let tx = self.get::<EsploraTx>(&format!("/tx/{}", txid)).await?;
        
        debug!("Got transaction details for txid: {}", txid);
        Ok(tx)
    }
    
    /// Get transaction hex
    pub async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        debug!("Getting transaction hex for txid: {}", txid);
        
        let hex = self.get::<String>(&format!("/tx/{}/hex", txid)).await?;
        
        debug!("Got transaction hex for txid: {}", txid);
        Ok(hex)
    }
    
    /// Get transaction status
    pub async fn get_transaction_status(&self, txid: &str) -> Result<EsploraTxStatus> {
        debug!("Getting transaction status for txid: {}", txid);
        
        let status = self.get::<EsploraTxStatus>(&format!("/tx/{}/status", txid)).await?;
        
        debug!("Got transaction status for txid: {}", txid);
        Ok(status)
    }
    
    /// Get address UTXOs
    pub async fn get_address_utxos(&self, address: &str) -> Result<Vec<EsploraUtxo>> {
        debug!("Getting UTXOs for address: {}", address);
        
        let utxos = self.get::<Vec<EsploraUtxo>>(&format!("/address/{}/utxo", address)).await?;
        
        debug!("Got {} UTXOs for address: {}", utxos.len(), address);
        Ok(utxos)
    }
    
    /// Get address transactions
    pub async fn get_address_transactions(&self, address: &str) -> Result<Vec<String>> {
        debug!("Getting transactions for address: {}", address);
        
        let txids = self.get::<Vec<String>>(&format!("/address/{}/txs", address)).await?;
        
        debug!("Got {} transactions for address: {}", txids.len(), address);
        Ok(txids)
    }
    
    /// Get address balance
    pub async fn get_address_balance(&self, address: &str) -> Result<u64> {
        debug!("Getting balance for address: {}", address);
        
        // Esplora doesn't have a direct balance endpoint, so we need to calculate it from UTXOs
        let utxos = self.get_address_utxos(address).await?;
        
        let balance = utxos.iter().map(|utxo| utxo.value).sum();
        
        debug!("Balance for address {}: {} satoshis", address, balance);
        Ok(balance)
    }
    
    /// Broadcast a raw transaction
    pub async fn broadcast_transaction(&self, hex: &str) -> Result<String> {
        debug!("Broadcasting transaction");
        
        let bytes = hex::decode(hex).context("Invalid transaction hex")?;
        
        let txid = self.post::<String>("/tx", &bytes).await?;
        
        debug!("Transaction broadcast with ID: {}", txid);
        Ok(txid)
    }
    
    /// Get fee estimates
    pub async fn get_fee_estimates(&self) -> Result<Value> {
        debug!("Getting fee estimates");
        
        let estimates = self.get::<Value>("/fee-estimates").await?;
        
        debug!("Got fee estimates");
        Ok(estimates)
    }
}

/// Check if an error is retryable
fn is_retryable_error(err: &anyhow::Error) -> bool {
    let err_string = err.to_string();
    
    // Connection errors
    if err_string.contains("connection") || 
       err_string.contains("timeout") || 
       err_string.contains("timed out") {
        return true;
    }
    
    // Rate limiting
    if err_string.contains("rate") || 
       err_string.contains("limit") || 
       err_string.contains("too many requests") {
        return true;
    }
    
    // Server errors (5xx)
    if err_string.contains("status: 5") {
        return true;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::mock;
    
    #[tokio::test]
    async fn test_get_block_height() {
        // Set up mock server
        let _m = mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("123456")
            .create();
        
        // Create client with mock server URL
        let mut config = EsploraRpcConfig::default();
        config.url = mockito::server_address().to_string();
        let client = EsploraRpcClient::new(config);
        
        // Call method
        let result = client.get_block_height().await.unwrap();
        
        // Verify result
        assert_eq!(result, 123456);
    }
    
    #[tokio::test]
    async fn test_get_block_hash() {
        // Set up mock server
        let _m = mock("GET", "/block-height/0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("\"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\"")
            .create();
        
        // Create client with mock server URL
        let mut config = EsploraRpcConfig::default();
        config.url = mockito::server_address().to_string();
        let client = EsploraRpcClient::new(config);
        
        // Call method
        let result = client.get_block_hash(0).await.unwrap();
        
        // Verify result
        assert_eq!(result, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    }
    
    #[tokio::test]
    async fn test_get_address_utxos() {
        // Set up mock server
        let _m = mock("GET", "/address/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4/utxo")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[
                {
                    "txid": "0000000000000000000000000000000000000000000000000000000000000000",
                    "vout": 0,
                    "value": 1000000,
                    "status": {
                        "confirmed": true,
                        "block_height": 123456,
                        "block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "block_time": 1600000000
                    }
                }
            ]"#)
            .create();
        
        // Create client with mock server URL
        let mut config = EsploraRpcConfig::default();
        config.url = mockito::server_address().to_string();
        let client = EsploraRpcClient::new(config);
        
        // Call method
        let result = client.get_address_utxos("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").await.unwrap();
        
        // Verify result
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, 1000000);
    }
    
    #[tokio::test]
    async fn test_error_handling() {
        // Set up mock server
        let _m = mock("GET", "/blocks/tip/height")
            .with_status(500)
            .create();
        
        // Create client with mock server URL
        let mut config = EsploraRpcConfig::default();
        config.url = mockito::server_address().to_string();
        config.max_retries = 0; // No retries for this test
        let client = EsploraRpcClient::new(config);
        
        // Call method
        let result = client.get_block_height().await;
        
        // Verify error
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("status: 500"));
    }
    
    #[tokio::test]
    async fn test_retry_logic() {
        // Set up mock server to fail twice then succeed
        let _m1 = mock("GET", "/blocks/tip/height")
            .with_status(500)
            .create();
        
        let _m2 = mock("GET", "/blocks/tip/height")
            .with_status(500)
            .create();
        
        let _m3 = mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("123456")
            .create();
        
        // Create client with mock server URL and fast retry
        let mut config = EsploraRpcConfig::default();
        config.url = mockito::server_address().to_string();
        config.max_retries = 2;
        config.retry_delay = 10; // Fast retry for testing
        let client = EsploraRpcClient::new(config);
        
        // Call method
        let result = client.get_block_height().await.unwrap();
        
        // Verify result
        assert_eq!(result, 123456);
    }
}
