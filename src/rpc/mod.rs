//! RPC client implementation for Bitcoin and Metashrew
//!
//! This module handles:
//! - Communication with Bitcoin RPC
//! - Communication with Metashrew RPC
//! - Request/response serialization
//! - Error handling and retries

use anyhow::{Context, Result, anyhow};
use log::debug;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// RPC client configuration
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// Bitcoin RPC URL
    pub bitcoin_rpc_url: String,
    /// Metashrew RPC URL
    pub metashrew_rpc_url: String,
}

/// RPC request
#[derive(Serialize, Debug)]
struct RpcRequest {
    /// JSON-RPC version
    jsonrpc: String,
    /// Method name
    method: String,
    /// Method parameters
    params: Value,
    /// Request ID
    id: u64,
}

/// RPC response
#[derive(Deserialize, Debug)]
struct RpcResponse {
    /// Result value
    result: Option<Value>,
    /// Error value
    error: Option<RpcError>,
    /// Response ID
    id: u64,
}

/// RPC error
#[derive(Deserialize, Debug)]
struct RpcError {
    /// Error code
    code: i32,
    /// Error message
    message: String,
}

/// RPC client for Bitcoin and Metashrew
pub struct RpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: RpcConfig,
    /// Request ID counter
    request_id: std::sync::atomic::AtomicU64,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(config: RpcConfig) -> Self {
        // Create HTTP client with appropriate timeouts
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            config,
            request_id: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Generic method to call any RPC method
    pub async fn _call(&self, method: &str, params: Value) -> Result<Value> {
        debug!("Calling RPC method: {}", method);
        
        // Determine which RPC endpoint to use based on the method prefix
        let (url, jsonrpc_version) = if method.starts_with("btc_") {
            (&self.config.bitcoin_rpc_url, "1.0")
        } else {
            (&self.config.metashrew_rpc_url, "2.0")
        };
        
        let request = RpcRequest {
            jsonrpc: jsonrpc_version.to_string(),
            method: method.to_string(),
            params,
            id: self.next_request_id(),
        };
        
        let response = self.client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send RPC request")?;
        
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("RPC request failed with status: {}", status));
        }
        
        let response_body = response
            .json::<RpcResponse>()
            .await
            .context("Failed to parse RPC response")?;
        
        match response_body.result {
            Some(result) => Ok(result),
            None => {
                let error = response_body.error.unwrap_or(RpcError {
                    code: -1,
                    message: "Unknown error".to_string(),
                });
                Err(anyhow!("RPC error: {} (code: {})", error.message, error.code))
            }
        }
    }
    
    /// Get the current block count from Bitcoin RPC
    pub async fn get_block_count(&self) -> Result<u64> {
        debug!("Getting block count from Bitcoin RPC");
        
        let result = self._call("btc_getblockcount", json!([])).await?;
        
        let height = result.as_u64().context("Invalid block height")?;
        debug!("Current block height: {}", height);
        Ok(height)
    }
    
    /// Get the current block height from Metashrew RPC
    pub async fn get_metashrew_height(&self) -> Result<u64> {
        debug!("Getting block height from Metashrew RPC");
        
        let result = self._call("metashrew_height", json!([])).await?;
        
        let height = result.as_u64().context("Invalid block height")?;
        debug!("Current Metashrew height: {}", height);
        Ok(height)
    }
    
    /// Get spendable UTXOs by address from Metashrew RPC
    pub async fn get_spendables_by_address(&self, address: &str) -> Result<Value> {
        debug!("Getting spendables for address: {}", address);
        
        let result = self._call("spendablesbyaddress", json!([address])).await?;
        
        debug!("Got spendables for address: {}", address);
        Ok(result)
    }
    
    /// Get ordinal address information from Metashrew RPC
    pub async fn get_ord_address(&self, address: &str) -> Result<Value> {
        debug!("Getting ordinal info for address: {}", address);
        
        let result = self._call("ord_address", json!([address])).await?;
        
        debug!("Got ordinal info for address: {}", address);
        Ok(result)
    }
    
    /// Get DIESEL token balance from Metashrew RPC
    pub async fn get_protorunes_by_address(&self, address: &str) -> Result<Value> {
        debug!("Getting protorunes for address: {}", address);
        
        let result = self._call("alkanes_protorunesbyaddress", json!([address])).await?;
        
        debug!("Got protorunes for address: {}", address);
        Ok(result)
    }
    
    /// Trace a transaction for DIESEL token minting
    pub async fn trace_transaction(&self, txid: &str, vout: usize) -> Result<Value> {
        debug!("Tracing transaction: {} vout: {}", txid, vout);
        
        // In a real implementation, we would reverse the txid bytes
        // For now, just use the txid as-is
        let reversed_txid = txid.to_string();
        
        let result = self._call("alkanes_trace", json!([reversed_txid, vout])).await?;
        
        debug!("Trace result for transaction: {}", txid);
        Ok(result)
    }
    
    
    /// Get the next request ID
    fn next_request_id(&self) -> u64 {
        // Use atomic fetch_add for thread safety
        self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rpc_client_creation() {
        let config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        
        let client = RpcClient::new(config.clone());
        
        assert_eq!(client.config.bitcoin_rpc_url, config.bitcoin_rpc_url);
        assert_eq!(client.config.metashrew_rpc_url, config.metashrew_rpc_url);
    }
}