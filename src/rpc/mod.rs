//! RPC client implementation for Bitcoin and Metashrew
//!
//! This module handles:
//! - Communication with Bitcoin RPC
//! - Communication with Metashrew RPC
//! - Request/response serialization
//! - Error handling and retries
//! - Rate limiting and connection pooling

// Export submodules
pub mod bitcoin;
pub mod esplora;
pub mod metashrew;

// Re-export key types
pub use bitcoin::BitcoinRpcClient;
pub use esplora::EsploraRpcClient;
pub use metashrew::MetashrewRpcClient;

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

/// Generic RPC client for Bitcoin, Esplora, and Metashrew
pub struct RpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: RpcConfig,
    /// Request ID counter
    request_id: std::sync::atomic::AtomicU64,
    /// Bitcoin RPC client
    bitcoin_client: Option<BitcoinRpcClient>,
    /// Esplora RPC client
    esplora_client: Option<EsploraRpcClient>,
    /// Metashrew RPC client
    metashrew_client: Option<MetashrewRpcClient>,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(config: RpcConfig) -> Self {
        // Create HTTP client with appropriate timeouts
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        
        // Create Bitcoin RPC client
        let bitcoin_client = Some(BitcoinRpcClient::from_rpc_config(&config));

        // Create Esplora RPC client
        let esplora_client = Some(EsploraRpcClient::from_rpc_config(&config));

        // Create Metashrew RPC client
        let metashrew_client = Some(MetashrewRpcClient::from_rpc_config(&config));

        Self {
            client,
            config,
            request_id: std::sync::atomic::AtomicU64::new(0),
            bitcoin_client,
            esplora_client,
            metashrew_client,
        }
    }
    
    /// Get the Bitcoin RPC client
    pub fn bitcoin(&self) -> &BitcoinRpcClient {
        self.bitcoin_client.as_ref().expect("Bitcoin RPC client not initialized")
    }
    
    /// Get the Esplora RPC client
    pub fn esplora(&self) -> &EsploraRpcClient {
        self.esplora_client.as_ref().expect("Esplora RPC client not initialized")
    }

    /// Get the Metashrew RPC client
    pub fn metashrew(&self) -> &MetashrewRpcClient {
        self.metashrew_client.as_ref().expect("Metashrew RPC client not initialized")
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
        self.bitcoin().get_block_count().await
    }
    
    /// Get the current block height from Metashrew RPC
    pub async fn get_metashrew_height(&self) -> Result<u64> {
        self.metashrew().get_height().await
    }
    
    /// Get spendable UTXOs by address from Metashrew RPC
    pub async fn get_spendables_by_address(&self, address: &str) -> Result<Value> {
        let utxos = self.metashrew().get_spendables_by_address(address).await?;
        Ok(serde_json::to_value(utxos)?)
    }
    
    /// Get ordinal address information from Metashrew RPC
    pub async fn get_ord_address(&self, address: &str) -> Result<Value> {
        self.metashrew().get_ord_address(address).await
    }
    
    /// Get DIESEL token balance from Metashrew RPC
    pub async fn get_protorunes_by_address(&self, address: &str) -> Result<Value> {
        let balances = self.metashrew().get_protorunes_by_address(address).await?;
        Ok(serde_json::to_value(balances)?)
    }
    
    /// Trace a transaction for DIESEL token minting
    pub async fn trace_transaction(&self, txid: &str, vout: usize) -> Result<Value> {
        self.metashrew().trace_transaction(txid, vout).await
    }

    /// Build a block with mempool transactions
    pub async fn build_block(&self) -> Result<Value> {
        self.metashrew().build_block().await
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
