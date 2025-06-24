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
use alkanes_support::proto::alkanes::{
    BlockRequest, BlockResponse, BytecodeRequest, TraceBlockRequest, TraceBlockResponse,
    AlkaneInventoryRequest, AlkaneInventoryResponse, AlkaneIdToOutpointRequest, AlkaneIdToOutpointResponse
};
use protobuf::Message;

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
    
    /// Get protorunes by outpoint
    pub async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<Value> {
        debug!("Getting protorunes for outpoint: {}:{}", txid, vout);
        
        let result = self._call("alkanes_protorunesbyoutpoint", json!([txid, vout])).await?;
        
        debug!("Got protorunes for outpoint: {}:{}", txid, vout);
        Ok(result)
    }
    
    /// Trace a block
    pub async fn trace_block(&self, height: u64) -> Result<Value> {
        debug!("Tracing block at height: {}", height);
        
        // Create and encode the TraceBlockRequest protobuf message
        let mut trace_request = TraceBlockRequest::new();
        trace_request.block = height;
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = trace_request.write_to_bytes()
            .context("Failed to encode TraceBlockRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["traceblock", hex_input, "latest"])
        ).await?;
        
        debug!("Trace result for block at height: {}", height);
        Ok(result)
    }
    
    /// Simulate a contract execution
    pub async fn simulate(&self, block: &str, tx: &str, inputs: &[String]) -> Result<Value> {
        debug!("Simulating contract execution: {}:{} with {} inputs", block, tx, inputs.len());
        
        // Create params array with block, tx, and inputs
        let mut params = Vec::new();
        params.push(json!(block));
        params.push(json!(tx));
        for input in inputs {
            params.push(json!(input));
        }
        
        let result = self._call("alkanes_simulate", json!(params)).await?;
        
        debug!("Simulation result for contract: {}:{}", block, tx);
        Ok(result)
    }
    
    /// Get contract metadata
    pub async fn get_contract_meta(&self, block: &str, tx: &str) -> Result<Value> {
        debug!("Getting metadata for contract: {}:{}", block, tx);
        
        let result = self._call("alkanes_meta", json!([block, tx])).await?;
        
        debug!("Got metadata for contract: {}:{}", block, tx);
        Ok(result)
    }
    
    /// Get contract bytecode
    pub async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String> {
        debug!("Getting bytecode for contract: {}:{}", block, tx);
        
        // Create and encode the BytecodeRequest protobuf message
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
    
    /// Get transaction hex by transaction ID
    pub async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        debug!("Getting transaction hex for txid: {}", txid);
        
        let result = self._call(
            "esplora_gettransaction",
            json!([txid])
        ).await?;
        
        let tx_hex = result.as_str()
            .context("Invalid transaction hex response")?
            .to_string();
        
        debug!("Got transaction hex for txid: {}", txid);
        Ok(tx_hex)
    }
    
    
    /// Get block data by height
    pub async fn get_block(&self, height: u64, block_tag: &str) -> Result<String> {
        debug!("Getting block data for height: {} with block tag: {}", height, block_tag);
        
        // Create and encode the BlockRequest protobuf message
        let mut block_request = BlockRequest::new();
        block_request.height = height as u32;
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = block_request.write_to_bytes()
            .context("Failed to encode BlockRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));

        let result = self._call(
            "metashrew_view",
            json!(["getblock", hex_input, block_tag])
        ).await?;
        
        let result_hex = result.as_str()
            .context("Invalid response format - expected hex string")?;

        // Decode the hex response (remove 0x prefix if present)
        let hex_data = if result_hex.starts_with("0x") {
            &result_hex[2..]
        } else {
            result_hex
        };

        let response_bytes = hex::decode(hex_data)
            .context("Failed to decode hex response")?;
        let block_response = BlockResponse::parse_from_bytes(&response_bytes)
            .context("Failed to parse BlockResponse")?;
        
        debug!("Got block data for height: {}", height);
        // Return the block data as hex string
        Ok(hex::encode(&block_response.block))
    }
    
    /// Get transaction by ID
    pub async fn get_transaction_by_id(&self, txid: &str, block_tag: &str) -> Result<Value> {
        debug!("Getting transaction by ID: {} with block tag: {}", txid, block_tag);
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "transactionbyid",
                "params": [txid]
            }])
        ).await?;
        
        debug!("Got transaction by ID: {}", txid);
        Ok(result)
    }
    
    /// Get protorunes by height
    pub async fn get_protorunes_by_height(&self, height: u64, protocol_tag: u64) -> Result<Value> {
        debug!("Getting protorunes for height: {} with protocol tag: {}", height, protocol_tag);
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "protorunesbyheight",
                "params": [height, protocol_tag]
            }])
        ).await?;
        
        debug!("Got protorunes for height: {}", height);
        Ok(result)
    }
    
    /// Get protorunes by address with protocol tag and block tag
    pub async fn get_protorunes_by_address_with_tags(&self, address: &str, protocol_tag: u64, block_tag: &str) -> Result<Value> {
        debug!("Getting protorunes for address: {} with protocol tag: {} and block tag: {}", address, protocol_tag, block_tag);
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "protorunesbyaddress",
                "params": [address, protocol_tag]
            }])
        ).await?;
        
        debug!("Got protorunes for address: {}", address);
        Ok(result)
    }
    
    /// Get protorunes by outpoint with protocol tag
    pub async fn get_protorunes_by_outpoint_with_protocol(&self, txid: &str, vout: u32, protocol_tag: u64) -> Result<Value> {
        debug!("Getting protorunes for outpoint: {}:{} with protocol tag: {}", txid, vout, protocol_tag);
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "protorunesbyoutpoint",
                "params": [txid, vout, protocol_tag]
            }])
        ).await?;
        
        debug!("Got protorunes for outpoint: {}:{}", txid, vout);
        Ok(result)
    }
    
    /// Get spendables by address with block tag
    pub async fn get_spendables_by_address_with_tag(&self, address: &str, block_tag: &str) -> Result<Value> {
        debug!("Getting spendables for address: {} with block tag: {}", address, block_tag);
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "spendablesbyaddress",
                "params": [address]
            }])
        ).await?;
        
        debug!("Got spendables for address: {}", address);
        Ok(result)
    }
    
    /// Get bytecode with block tag
    pub async fn get_bytecode_with_tag(&self, block: &str, tx: &str, block_tag: &str) -> Result<String> {
        debug!("Getting bytecode for contract: {}:{} with block tag: {}", block, tx, block_tag);
        
        // Create and encode the BytecodeRequest protobuf message
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
        let encoded_bytes = bytecode_request.write_to_bytes()
            .context("Failed to encode BytecodeRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["getbytecode", hex_input, block_tag])
        ).await?;
        
        let bytecode = result.as_str()
            .context("Invalid bytecode response")?
            .to_string();
        
        debug!("Got bytecode for contract: {}:{}", block, tx);
        Ok(bytecode)
    }
    
    /// Trace transaction with outpoint
    pub async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<Value> {
        debug!("Tracing outpoint: {}:{}", txid, vout);
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "trace",
                "params": [txid, vout]
            }])
        ).await?;
        
        debug!("Trace result for outpoint: {}:{}", txid, vout);
        Ok(result)
    }
    
    /// Simulate contract execution with detailed parameters
    pub async fn simulate_detailed(&self,
        alkanes: Option<&str>,
        transaction: &str,
        height: u64,
        block: &str,
        txindex: u32,
        inputs: &str,
        vout: u32,
        pointer: u32,
        refund_pointer: u32,
        block_tag: &str
    ) -> Result<Value> {
        debug!("Simulating contract execution with detailed parameters");
        
        // Parse alkanes if provided
        let alkanes_parsed = if let Some(alkanes_str) = alkanes {
            // Parse alkanes format: block:tx:amount,block:tx:amount,...
            let alkanes_vec: Result<Vec<Value>> = alkanes_str
                .split(',')
                .map(|alkane| {
                    let parts: Vec<&str> = alkane.split(':').collect();
                    if parts.len() != 3 {
                        return Err(anyhow!("Invalid alkane format. Expected 'block:tx:amount'"));
                    }
                    Ok(json!({
                        "block": parts[0].parse::<u64>()?,
                        "tx": parts[1].parse::<u64>()?,
                        "amount": parts[2].parse::<u64>()?
                    }))
                })
                .collect();
            alkanes_vec?
        } else {
            vec![]
        };
        
        // Parse inputs
        let inputs_vec: Result<Vec<u64>> = inputs
            .split(',')
            .map(|input| input.trim().parse::<u64>().context("Invalid input number"))
            .collect();
        let inputs_parsed = inputs_vec?;
        
        let result = self._call(
            "metashrew_view",
            json!([{
                "method": "simulate",
                "params": {
                    "alkanes": alkanes_parsed,
                    "transaction": transaction,
                    "height": height,
                    "block": block,
                    "txindex": txindex,
                    "inputs": inputs_parsed,
                    "vout": vout,
                    "pointer": pointer,
                    "refund_pointer": refund_pointer
                }
            }])
        ).await?;
        
        debug!("Simulation completed");
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