//! Bitcoin RPC client implementation
//!
//! This module provides a specialized RPC client for Bitcoin Core.
//! It handles authentication, error handling, and provides typed methods
//! for common Bitcoin RPC calls.

use anyhow::{Context, Result, anyhow};
use log::{debug, warn, error};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use url::Url;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use super::RpcConfig;

/// Bitcoin RPC configuration
#[derive(Clone, Debug)]
pub struct BitcoinRpcConfig {
    /// RPC URL (e.g., http://localhost:8332)
    pub url: String,
    /// RPC username
    pub username: Option<String>,
    /// RPC password
    pub password: Option<String>,
    /// Connection timeout in seconds
    pub timeout: u64,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Retry delay in milliseconds
    pub retry_delay: u64,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
}

impl Default for BitcoinRpcConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8332".to_string(),
            username: None,
            password: None,
            timeout: 30,
            max_retries: 3,
            retry_delay: 1000,
            max_concurrent_requests: 10,
        }
    }
}

/// Bitcoin RPC request
#[derive(Serialize, Debug)]
struct BitcoinRpcRequest {
    /// JSON-RPC version
    jsonrpc: String,
    /// Method name
    method: String,
    /// Method parameters
    params: Value,
    /// Request ID
    id: u64,
}

/// Bitcoin RPC response
#[derive(Deserialize, Debug)]
struct BitcoinRpcResponse {
    /// Result value
    result: Option<Value>,
    /// Error value
    error: Option<BitcoinRpcError>,
    /// Response ID
    id: u64,
}

/// Bitcoin RPC error
#[derive(Deserialize, Debug)]
struct BitcoinRpcError {
    /// Error code
    code: i32,
    /// Error message
    message: String,
}

/// Bitcoin RPC client
pub struct BitcoinRpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: BitcoinRpcConfig,
    /// Request ID counter
    request_id: std::sync::atomic::AtomicU64,
    /// Rate limiter
    rate_limiter: Arc<Semaphore>,
}

impl BitcoinRpcClient {
    /// Create a new Bitcoin RPC client
    pub fn new(config: BitcoinRpcConfig) -> Self {
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
            request_id: std::sync::atomic::AtomicU64::new(0),
            rate_limiter,
        }
    }
    
    /// Create a new Bitcoin RPC client from a generic RPC config
    pub fn from_rpc_config(config: &RpcConfig) -> Self {
        // Parse URL to extract username and password
        let url_str = &config.bitcoin_rpc_url;
        let url = Url::parse(url_str).expect("Invalid Bitcoin RPC URL");
        
        let username = url.username();
        let password = url.password();
        
        // Create Bitcoin RPC config
        let bitcoin_config = BitcoinRpcConfig {
            url: format!("{}://{}:{}", url.scheme(), url.host_str().unwrap_or("localhost"), url.port().unwrap_or(8332)),
            username: if username.is_empty() { None } else { Some(username.to_string()) },
            password: password.map(|p| p.to_string()),
            ..Default::default()
        };
        
        Self::new(bitcoin_config)
    }
    
    /// Call a Bitcoin RPC method with retry logic
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        // Acquire permit from rate limiter
        let _permit = self.rate_limiter.acquire().await?;
        
        let mut retries = 0;
        let mut last_error = None;
        
        while retries <= self.config.max_retries {
            if retries > 0 {
                debug!("Retrying RPC call to {} (attempt {}/{})", method, retries, self.config.max_retries);
                sleep(Duration::from_millis(self.config.retry_delay)).await;
            }
            
            match self.execute_call(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_error = Some(err);
                    retries += 1;
                    
                    // Only retry on connection errors or rate limiting
                    if !is_retryable_error(&last_error.as_ref().unwrap()) {
                        break;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow!("Unknown error during RPC call")))
    }
    
    /// Execute a single RPC call without retry logic
    async fn execute_call(&self, method: &str, params: Value) -> Result<Value> {
        debug!("Calling Bitcoin RPC method: {}", method);
        
        let request = BitcoinRpcRequest {
            jsonrpc: "1.0".to_string(),
            method: method.to_string(),
            params,
            id: self.next_request_id(),
        };
        
        // Build request with authentication if provided
        let mut req_builder = self.client.post(&self.config.url)
            .header(header::CONTENT_TYPE, "application/json");
        
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let auth = format!("{}:{}", username, password);
            let auth_header = format!("Basic {}", BASE64.encode(auth));
            req_builder = req_builder.header(header::AUTHORIZATION, auth_header);
        }
        
        let response = req_builder
            .json(&request)
            .send()
            .await
            .context("Failed to send Bitcoin RPC request")?;
        
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("Bitcoin RPC request failed with status: {}", status));
        }
        
        let response_body = response
            .json::<BitcoinRpcResponse>()
            .await
            .context("Failed to parse Bitcoin RPC response")?;
        
        match response_body.result {
            Some(result) => Ok(result),
            None => {
                let error = response_body.error.unwrap_or(BitcoinRpcError {
                    code: -1,
                    message: "Unknown error".to_string(),
                });
                Err(anyhow!("Bitcoin RPC error: {} (code: {})", error.message, error.code))
            }
        }
    }
    
    /// Get the next request ID
    fn next_request_id(&self) -> u64 {
        self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Get the current block count
    pub async fn get_block_count(&self) -> Result<u64> {
        debug!("Getting block count from Bitcoin RPC");
        
        let result = self.call("getblockcount", json!([])).await?;
        
        let height = result.as_u64().context("Invalid block height")?;
        debug!("Current block height: {}", height);
        Ok(height)
    }
    
    /// Get block hash at the given height
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        debug!("Getting block hash for height: {}", height);
        
        let result = self.call("getblockhash", json!([height])).await?;
        
        let hash = result.as_str().context("Invalid block hash")?.to_string();
        debug!("Block hash for height {}: {}", height, hash);
        Ok(hash)
    }
    
    /// Get block details
    pub async fn get_block(&self, hash: &str, verbosity: u8) -> Result<Value> {
        debug!("Getting block details for hash: {}", hash);
        
        let result = self.call("getblock", json!([hash, verbosity])).await?;
        
        debug!("Got block details for hash: {}", hash);
        Ok(result)
    }
    
    /// Get raw transaction
    pub async fn get_raw_transaction(&self, txid: &str, verbose: bool) -> Result<Value> {
        debug!("Getting raw transaction: {}", txid);
        
        let result = self.call("getrawtransaction", json!([txid, verbose])).await?;
        
        debug!("Got raw transaction: {}", txid);
        Ok(result)
    }
    
    /// Send raw transaction
    pub async fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        debug!("Sending raw transaction");
        
        let result = self.call("sendrawtransaction", json!([hex])).await?;
        
        let txid = result.as_str().context("Invalid transaction ID")?.to_string();
        debug!("Transaction sent with ID: {}", txid);
        Ok(txid)
    }
    
    /// Get transaction output (UTXO) information
    pub async fn get_tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Option<Value>> {
        debug!("Getting transaction output: {}:{}", txid, vout);
        
        let result = self.call("gettxout", json!([txid, vout, include_mempool])).await?;
        
        if result.is_null() {
            debug!("Transaction output {}:{} not found", txid, vout);
            return Ok(None);
        }
        
        debug!("Got transaction output: {}:{}", txid, vout);
        Ok(Some(result))
    }
    
    /// Get mempool information
    pub async fn get_mempool_info(&self) -> Result<Value> {
        debug!("Getting mempool information");
        
        let result = self.call("getmempoolinfo", json!([])).await?;
        
        debug!("Got mempool information");
        Ok(result)
    }
    
    /// Get network information
    pub async fn get_network_info(&self) -> Result<Value> {
        debug!("Getting network information");
        
        let result = self.call("getnetworkinfo", json!([])).await?;
        
        debug!("Got network information");
        Ok(result)
    }
    
    /// Get blockchain information
    pub async fn get_blockchain_info(&self) -> Result<Value> {
        debug!("Getting blockchain information");
        
        let result = self.call("getblockchaininfo", json!([])).await?;
        
        debug!("Got blockchain information");
        Ok(result)
    }
    
    /// Estimate smart fee
    pub async fn estimate_smart_fee(&self, conf_target: u16) -> Result<f64> {
        debug!("Estimating smart fee for {} confirmations", conf_target);
        
        let result = self.call("estimatesmartfee", json!([conf_target])).await?;
        
        let fee_rate = result
            .get("feerate")
            .context("Missing feerate in response")?
            .as_f64()
            .context("Invalid fee rate")?;
        
        debug!("Estimated fee rate: {} BTC/kB", fee_rate);
        Ok(fee_rate)
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
    async fn test_get_block_count() {
        // Set up mock server
        let _m = mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": 123456, "error": null, "id": 1}"#)
            .create();
        
        // Create client with mock server URL
        let config = BitcoinRpcConfig {
            url: mockito::server_address().to_string(),
            ..Default::default()
        };
        let client = BitcoinRpcClient::new(config);
        
        // Call method
        let result = client.get_block_count().await.unwrap();
        
        // Verify result
        assert_eq!(result, 123456);
    }
    
    #[tokio::test]
    async fn test_get_block_hash() {
        // Set up mock server
        let _m = mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "error": null, "id": 1}"#)
            .create();
        
        // Create client with mock server URL
        let config = BitcoinRpcConfig {
            url: mockito::server_address().to_string(),
            ..Default::default()
        };
        let client = BitcoinRpcClient::new(config);
        
        // Call method
        let result = client.get_block_hash(0).await.unwrap();
        
        // Verify result
        assert_eq!(result, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    }
    
    #[tokio::test]
    async fn test_error_handling() {
        // Set up mock server
        let _m = mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": null, "error": {"code": -1, "message": "Test error"}, "id": 1}"#)
            .create();
        
        // Create client with mock server URL
        let config = BitcoinRpcConfig {
            url: mockito::server_address().to_string(),
            ..Default::default()
        };
        let client = BitcoinRpcClient::new(config);
        
        // Call method
        let result = client.get_block_count().await;
        
        // Verify error
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Test error"));
    }
    
    #[tokio::test]
    async fn test_retry_logic() {
        // Set up mock server to fail twice then succeed
        let _m1 = mock("POST", "/")
            .with_status(500)
            .create();
        
        let _m2 = mock("POST", "/")
            .with_status(500)
            .create();
        
        let _m3 = mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": 123456, "error": null, "id": 1}"#)
            .create();
        
        // Create client with mock server URL and fast retry
        let config = BitcoinRpcConfig {
            url: mockito::server_address().to_string(),
            max_retries: 2,
            retry_delay: 10, // Fast retry for testing
            ..Default::default()
        };
        let client = BitcoinRpcClient::new(config);
        
        // Call method
        let result = client.get_block_count().await.unwrap();
        
        // Verify result
        assert_eq!(result, 123456);
    }
}
