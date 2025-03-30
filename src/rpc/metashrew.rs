// Metashrew RPC client implementation

//! This module provides a specialized RPC client for Metashrew API.
//! It handles error handling, rate limiting, and provides typed methods
//! for common Metashrew API calls.

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

use super::RpcConfig;

/// Metashrew RPC configuration
#[derive(Clone, Debug)]
pub struct MetashrewRpcConfig {
    /// API URL (e.g. https://mainnet.sandshrew.io/v2/lasereyes)
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

impl Default for MetashrewRpcConfig {
    fn default() -> Self {
        Self {
            url: "https://mainnet.sandshrew.io/v2/lasereyes".to_string(),
            timeout: 30,
            max_retries: 3,
            retry_delay: 1000,
            max_concurrent_requests: 10,
        }
    }
}

/// Metashrew RPC request
#[derive(Serialize, Debug)]
struct MetashrewRpcRequest {
    /// JSON-RPC version
    jsonrpc: String,
    /// Method name
    method: String,
    /// Method parameters
    params: Value,
    /// Request ID
    id: u64,
}

/// Metashrew RPC response
#[derive(Deserialize, Debug)]
struct MetashrewRpcResponse {
    /// Result value
    result: Option<Value>,
    /// Error value
    error: Option<MetashrewRpcError>,
    /// Response ID
    id: u64,
}

/// Metashrew RPC error
#[derive(Deserialize, Debug)]
struct MetashrewRpcError {
    /// Error code
    code: i32,
    /// Error message
    message: String,
}

/// Metashrew UTXO
#[derive(Debug, Deserialize, Serialize)]
pub struct MetashrewUtxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Output value in satoshis
    pub value: u64,
    /// Output script pubkey
    pub scriptpubkey: String,
    /// Output script pubkey type
    pub scriptpubkey_type: String,
    /// Output script pubkey address
    pub scriptpubkey_address: Option<String>,
    /// Confirmation status
    pub confirmed: bool,
    /// Block height (if confirmed)
    pub block_height: Option<u64>,
}

/// Metashrew token balance
#[derive(Debug, Deserialize, Serialize)]
pub struct MetashrewTokenBalance {
    /// Token ID
    pub id: String,
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Token decimals
    pub decimals: u8,
    /// Token balance
    pub balance: String,
}

/// Metashrew RPC client
pub struct MetashrewRpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: MetashrewRpcConfig,
    /// Request ID counter
    request_id: std::sync::atomic::AtomicU64,
    /// Rate limiter
    rate_limiter: Arc<Semaphore>,
}

impl MetashrewRpcClient {
    /// Create a new Metashrew RPC client
    pub fn new(config: MetashrewRpcConfig) -> Self {
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

    /// Create a new Metashrew RPC client from a generic RPC config
    pub fn from_rpc_config(config: &RpcConfig) -> Self {
        // Create Metashrew config from generic RPC config
        let metashrew_config = MetashrewRpcConfig {
            url: config.metashrew_rpc_url.clone(),
            ..Default::default()
        };

        Self::new(metashrew_config)
    }

    /// Call a Metashrew RPC method with retry logic
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        // Acquire permit from rate limiter
        let _permit = self.rate_limiter.acquire().await?;

        let mut retries = 0;
        let mut last_error = None;

        while retries <= self.config.max_retries {
            if retries > 0 {
                debug!("Retrying Metashrew RPC call to {} (attempt {}/{})", method, retries, self.config.max_retries);
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

        Err(last_error.unwrap_or_else(|| anyhow!("Unknown error during Metashrew RPC call")))
    }

    /// Execute a single RPC call without retry logic
    async fn execute_call(&self, method: &str, params: Value) -> Result<Value> {
        debug!("Calling Metashrew RPC method: {}", method);

        let request = MetashrewRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: self.next_request_id(),
        };

        let response = self.client
            .post(&self.config.url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send Metashrew RPC request")?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("Metashrew RPC request failed with status: {}", status));
        }

        let response_body = response
            .json::<MetashrewRpcResponse>()
            .await
            .context("Failed to parse Metashrew RPC response")?;

        match response_body.result {
            Some(result) => Ok(result),
            None => {
                let error = response_body.error.unwrap_or(MetashrewRpcError {
                    code: -1,
                    message: "Unknown error".to_string(),
                });
                Err(anyhow!("Metashrew RPC error: {} (code: {})", error.message, error.code))
            }
        }
    }

    /// Get the next request ID
    fn next_request_id(&self) -> u64 {
        self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the current block height
    pub async fn get_height(&self) -> Result<u64> {
        debug!("Getting block height from Metashrew RPC");

        let result = self.call("metashrew_height", json!([])).await?;

        let height = result.as_u64().context("Invalid block height")?;
        debug!("Current Metashrew height: {}", height);
        Ok(height)
    }

    /// Get blockchain view data
    pub async fn get_view(&self, view_name: &str, params: Value) -> Result<Value> {
        debug!("Getting view data for: {}", view_name);

        let result = self.call("metashrew_view", json!([view_name, params])).await?;

        debug!("Got view data for: {}", view_name);
        Ok(result)
    }

    /// Get spendable UTXOs by address
    pub async fn get_spendables_by_address(&self, address: &str) -> Result<Vec<MetashrewUtxo>> {
        debug!("Getting spendables for address: {}", address);

        let result = self.call("spendablesbyaddress", json!([address])).await?;

        let utxos = serde_json::from_value(result).context("Failed to parse UTXOs")?;

        debug!("Got spendables for address: {}", address);
        Ok(utxos)
    }

    /// Get ordinal address information
    pub async fn get_ord_address(&self, address: &str) -> Result<Value> {
        debug!("Getting ordinal info for address: {}", address);

        let result = self.call("ord_address", json!([address])).await?;

        debug!("Got ordinal info for address: {}", address);
        Ok(result)
    }

    /// Get DIESEL token balance
    pub async fn get_protorunes_by_address(&self, address: &str) -> Result<Vec<MetashrewTokenBalance>> {
        debug!("Getting protorunes for address: {}", address);

        let result = self.call("alkanes_protorunesbyaddress", json!([address])).await?;

        let balances = serde_json::from_value(result).context("Failed to parse token balances")?;

        debug!("Got protorunes for address: {}", address);
        Ok(balances)
    }

    /// Trace a transaction for DIESEL token minting
    pub async fn trace_transaction(&self, txid: &str, vout: usize) -> Result<Value> {
        debug!("Tracing transaction: {} vout: {}", txid, vout);

        // In a real implementation we would reverse the txid bytes
        // For now just use the txid as-is
        let reversed_txid = txid.to_string();

        let result = self.call("alkanes_trace", json!([reversed_txid, vout])).await?;

        debug!("Trace result for transaction: {}", txid);
        Ok(result)
    }

    /// Get mempool transactions
    pub async fn get_mempool(&self) -> Result<Vec<String>> {
        debug!("Getting mempool transactions");

        let result = self.call("metashrew_mempool", json!([])).await?;

        let txids = serde_json::from_value(result).context("Failed to parse mempool transactions")?;

        debug!("Got mempool transactions");
        Ok(txids)
    }

    /// Get transaction details
    pub async fn get_transaction(&self, txid: &str) -> Result<Value> {
        debug!("Getting transaction details for: {}", txid);

        let result = self.call("metashrew_tx", json!([txid])).await?;

        debug!("Got transaction details for: {}", txid);
        Ok(result)
    }

    /// Build a block with mempool transactions
    pub async fn build_block(&self) -> Result<Value> {
        debug!("Building block with mempool transactions");

        let result = self.call("metashrew_build", json!([])).await?;

        debug!("Built block with mempool transactions");
        Ok(result)
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
    async fn test_get_height() {
        // Set up mock server
        let _m = mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": 123456, "error": null, "id": 1}"#)
            .create();

        // Create client with mock server URL
        let config = MetashrewRpcConfig {
            url: mockito::server_address().to_string(),
            ..Default::default()
        };
        let client = MetashrewRpcClient::new(config);

        // Call method
        let result = client.get_height().await.unwrap();

        // Verify result
        assert_eq!(result, 123456);
    }

    #[tokio::test]
    async fn test_get_spendables_by_address() {
        // Set up mock server
        let _m = mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": [
                {
                    "txid": "0000000000000000000000000000000000000000000000000000000000000000",
                    "vout": 0,
                    "value": 1000000,
                    "scriptpubkey": "0014000000000000000000000000000000000000",
                    "scriptpubkey_type": "v0_p2wpkh",
                    "scriptpubkey_address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    "confirmed": true,
                    "block_height": 123456
                }
            ], "error": null, "id": 1}"#)
            .create();

        // Create client with mock server URL
        let config = MetashrewRpcConfig {
            url: mockito::server_address().to_string(),
            ..Default::default()
        };
        let client = MetashrewRpcClient::new(config);

        // Call method
        let result = client.get_spendables_by_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").await.unwrap();

        // Verify result
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, 1000000);
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
        let config = MetashrewRpcConfig {
            url: mockito::server_address().to_string(),
            ..Default::default()
        };
        let client = MetashrewRpcClient::new(config);

        // Call method
        let result = client.get_height().await;

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
        let config = MetashrewRpcConfig {
            url: mockito::server_address().to_string(),
            max_retries: 2,
            retry_delay: 10, // Fast retry for testing
            ..Default::default()
        };
        let client = MetashrewRpcClient::new(config);

        // Call method
        let result = client.get_height().await.unwrap();

        // Verify result
        assert_eq!(result, 123456);
    }
}
