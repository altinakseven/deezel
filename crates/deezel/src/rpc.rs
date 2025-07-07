//! Concrete RPC client implementation for the refactored CLI
//! 
//! This is a simplified version of the original RPC client that works
//! with the alkanes inspector functionality.

use anyhow::{Context, Result, anyhow};
use log::debug;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

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
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcResponse {
    /// Result value
    pub result: Option<Value>,
    /// Error value
    pub error: Option<RpcError>,
    /// Response ID
    pub id: u64,
}

/// RPC error
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
}

/// RPC client for Bitcoin and Metashrew
pub struct RpcClient {
    /// HTTP client
    client: Client,
    /// RPC configuration
    config: RpcConfig,
    /// Request ID counter
    request_id: AtomicU64,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(config: RpcConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(600))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            config,
            request_id: AtomicU64::new(0),
        }
    }
    
    /// Generic method to call any RPC method
    pub async fn _call(&self, method: &str, params: Value) -> Result<Value> {
        debug!("Calling RPC method: {}", method);
        
        let url = &self.config.metashrew_rpc_url;
        
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
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
        let result = self._call("btc_getblockcount", json!([])).await?;
        
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid block height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid block height format"));
        };
        
        Ok(height)
    }

    /// Generate blocks to an address (regtest only)
    pub async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<Value> {
        let result = self._call("generatetoaddress", json!([nblocks, address])).await?;
        Ok(result)
    }
    
    /// Get the current block height from Metashrew RPC
    pub async fn get_metashrew_height(&self) -> Result<u64> {
        let result = self._call("metashrew_height", json!([])).await?;
        
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid block height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid block height format"));
        };
        
        Ok(height)
    }
    
    /// Get contract bytecode
    pub async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String> {
        debug!("Getting bytecode for contract: {}:{}", block, tx);
        
        // Create and encode the BytecodeRequest protobuf message
        use alkanes_support::proto::alkanes::BytecodeRequest;
        let mut bytecode_request = BytecodeRequest::new();
        let mut alkane_id = alkanes_support::proto::alkanes::AlkaneId::new();
        
        // Parse block and tx as u128 values
        let block_u128 = block.parse::<u128>()
            .context("Invalid block number")?;
        let tx_u128 = tx.parse::<u128>()
            .context("Invalid tx number")?;
        
        // Convert to Uint128 protobuf format
        let mut block_uint128 = alkanes_support::proto::alkanes::Uint128::new();
        block_uint128.lo = (block_u128 & 0xFFFFFFFFFFFFFFFF) as u64;
        block_uint128.hi = (block_u128 >> 64) as u64;
        
        let mut tx_uint128 = alkanes_support::proto::alkanes::Uint128::new();
        tx_uint128.lo = (tx_u128 & 0xFFFFFFFFFFFFFFFF) as u64;
        tx_uint128.hi = (tx_u128 >> 64) as u64;
        
        alkane_id.block = protobuf::MessageField::some(block_uint128);
        alkane_id.tx = protobuf::MessageField::some(tx_uint128);
        
        bytecode_request.id = protobuf::MessageField::some(alkane_id);
        
        // Serialize to bytes and hex encode with 0x prefix
        use protobuf::Message;
        let encoded_bytes = bytecode_request.write_to_bytes()
            .context("Failed to encode BytecodeRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["getbytecode", hex_input, "latest"])
        ).await?;
        
        let bytecode = result.as_str()
            .context("Invalid bytecode response")?
            .to_string();
        
        debug!("Got bytecode for contract: {}:{}", block, tx);
        Ok(bytecode)
    }
    
    /// Get the next request ID
    fn next_request_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }
}