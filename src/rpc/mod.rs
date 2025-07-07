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
    BlockRequest, BlockResponse, BytecodeRequest, TraceBlockRequest
};
use protorune_support::proto::protorune::{
    WalletRequest, OutpointResponse
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
    request_id: std::sync::atomic::AtomicU64,
}

impl RpcClient {
    /// Maximum size for logging JSON responses (in characters)
    pub const MAX_LOG_SIZE: usize = 2000;
    
    /// Create a new RPC client
    pub fn new(config: RpcConfig) -> Self {
        // Create HTTP client with very long timeouts to prevent timeouts during synchronization waits
        // Services like Esplora and Metashrew may take time to catch up, so we need generous timeouts
        let client = Client::builder()
            .timeout(Duration::from_secs(600)) // 10 minutes - much longer for sync operations
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            config,
            request_id: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Helper function to truncate large JSON responses for logging
    pub fn truncate_json_for_logging(&self, json_value: &Value) -> String {
        let full_json = serde_json::to_string_pretty(json_value)
            .unwrap_or_else(|_| "Failed to serialize response".to_string());
        
        if full_json.len() <= Self::MAX_LOG_SIZE {
            full_json
        } else {
            // For large responses, show structure but truncate content
            match json_value {
                Value::Object(obj) => {
                    let mut truncated = serde_json::Map::new();
                    for (key, value) in obj {
                        match value {
                            Value::Array(arr) => {
                                truncated.insert(key.clone(), json!({
                                    "_truncated": format!("Array with {} elements", arr.len()),
                                    "_first_few": arr.iter().take(2).cloned().collect::<Vec<_>>()
                                }));
                            },
                            Value::String(s) if s.len() > 100 => {
                                truncated.insert(key.clone(), json!({
                                    "_truncated": format!("String with {} chars", s.len()),
                                    "_preview": format!("{}...", &s[..std::cmp::min(100, s.len())])
                                }));
                            },
                            _ => {
                                truncated.insert(key.clone(), value.clone());
                            }
                        }
                    }
                    serde_json::to_string_pretty(&Value::Object(truncated))
                        .unwrap_or_else(|_| format!("{{\"_truncated\": \"Large response ({} chars)\"}}", full_json.len()))
                },
                Value::Array(arr) => {
                    json!({
                        "_truncated": format!("Array with {} elements", arr.len()),
                        "_first_few": arr.iter().take(3).cloned().collect::<Vec<_>>(),
                        "_total_size": format!("{} chars", full_json.len())
                    }).to_string()
                },
                _ => {
                    format!("{{\"_truncated\": \"Large response ({} chars)\", \"_type\": \"{}\"}}",
                           full_json.len(),
                           match json_value {
                               Value::String(_) => "string",
                               Value::Number(_) => "number",
                               Value::Bool(_) => "boolean",
                               Value::Null => "null",
                               _ => "unknown"
                           })
                }
            }
        }
    }
    
    /// Helper function to truncate RPC response for logging
    pub fn truncate_rpc_response_for_logging(&self, response: &RpcResponse) -> String {
        if let Some(ref result) = response.result {
            let truncated_result = self.truncate_json_for_logging(result);
            format!("{{\"result\": {}, \"id\": {}}}", truncated_result, response.id)
        } else {
            // For error responses, always show full content since they're typically small
            serde_json::to_string_pretty(response)
                .unwrap_or_else(|_| "Failed to serialize response".to_string())
        }
    }
    
    /// Generic method to call any RPC method
    pub async fn _call(&self, method: &str, params: Value) -> Result<Value> {
        debug!("Calling RPC method: {}", method);
        
        // CRITICAL FIX: Always route ALL RPC requests through the unified Sandshrew endpoint
        // Sandshrew is a superset of Bitcoin Core RPC and handles both Bitcoin and Metashrew calls
        // This ensures consistent endpoint usage regardless of method prefix
        let (url, jsonrpc_version) = (&self.config.metashrew_rpc_url, "2.0");
        
        let request = RpcRequest {
            jsonrpc: jsonrpc_version.to_string(),
            method: method.to_string(),
            params,
            id: self.next_request_id(),
        };
        
        // Log the request for debugging (truncated if large)
        debug!("JSON-RPC Request to {}: {}", url, self.truncate_json_for_logging(&json!(request)));
        
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
        
        // Log the response for debugging (truncated if large)
        debug!("JSON-RPC Response: {}", self.truncate_rpc_response_for_logging(&response_body));
        
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
    
    /// Helper method to call RPC with protobuf encoding
    async fn call_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        debug!("Calling RPC method: {}", method);
        
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: json!(params),
            id: self.next_request_id(),
        };
        
        // Log the request for debugging (truncated if large)
        debug!("JSON-RPC Request to {}: {}", &self.config.metashrew_rpc_url, self.truncate_json_for_logging(&json!(request)));
        
        let response = self.client
            .post(&self.config.metashrew_rpc_url)
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
        
        // Log the response for debugging (truncated if large)
        debug!("JSON-RPC Response: {}", self.truncate_rpc_response_for_logging(&response_body));
        
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
        
        // Handle both string and number responses
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid block height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid block height format"));
        };
        
        debug!("Current block height: {}", height);
        Ok(height)
    }

    /// Generate blocks to an address (regtest only)
    pub async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<Value> {
        debug!("Generating {} blocks to address: {}", nblocks, address);
        
        // Use generatetoaddress method directly on Sandshrew RPC (which is a superset of Bitcoin Core)
        let result = self._call("generatetoaddress", json!([nblocks, address])).await?;
        
        debug!("Generated {} blocks to address: {}", nblocks, address);
        Ok(result)
    }
    
    /// Get the current block height from Metashrew RPC
    pub async fn get_metashrew_height(&self) -> Result<u64> {
        debug!("Getting block height from Metashrew RPC");
        
        let result = self._call("metashrew_height", json!([])).await?;
        
        // Handle both string and number responses
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid block height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid block height format"));
        };
        
        debug!("Current Metashrew height: {}", height);
        Ok(height)
    }
    
    /// Get spendable UTXOs by address from Metashrew RPC
    pub async fn get_spendables_by_address(&self, address: &str) -> Result<Value> {
        debug!("Getting spendables for address: {}", address);
        
        // Create and encode the ProtorunesWalletRequest protobuf message
        let mut wallet_request = protorune_support::proto::protorune::ProtorunesWalletRequest::new();
        wallet_request.wallet = address.as_bytes().to_vec();
        
        // Set protocol tag to 1 (for alkanes/DIESEL tokens)
        let mut protocol_tag = protorune_support::proto::protorune::Uint128::new();
        protocol_tag.hi = 0;
        protocol_tag.lo = 1;
        wallet_request.protocol_tag = protobuf::MessageField::some(protocol_tag);
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = wallet_request.write_to_bytes()
            .context("Failed to encode ProtorunesWalletRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["spendablesbyaddress", hex_input, "latest"])
        ).await?;
        
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
        
        // Create and encode the ProtorunesWalletRequest protobuf message
        let mut wallet_request = protorune_support::proto::protorune::ProtorunesWalletRequest::new();
        wallet_request.wallet = address.as_bytes().to_vec();
        
        // Set protocol tag to 1 (for alkanes/DIESEL tokens)
        let mut protocol_tag = protorune_support::proto::protorune::Uint128::new();
        protocol_tag.hi = 0;
        protocol_tag.lo = 1;
        wallet_request.protocol_tag = protobuf::MessageField::some(protocol_tag);
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = wallet_request.write_to_bytes()
            .context("Failed to encode ProtorunesWalletRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["protorunesbyaddress", hex_input, "latest"])
        ).await?;
        
        debug!("Got protorunes for address: {}", address);
        
        // Parse the hex response
        let hex_response = result.as_str()
            .context("Expected hex string response")?;
        
        // Handle empty response (0x means no tokens)
        if hex_response == "0x" || hex_response.is_empty() {
            debug!("No protorunes found for address: {}", address);
            return Ok(json!([])); // Return empty array for consistency
        }
        
        // Decode hex response (remove 0x prefix if present)
        let hex_data = if hex_response.starts_with("0x") {
            &hex_response[2..]
        } else {
            hex_response
        };
        
        // If hex_data is empty after removing prefix, return empty array
        if hex_data.is_empty() {
            debug!("Empty hex data for address: {}", address);
            return Ok(json!([]));
        }
        
        // Try to decode the hex data
        match hex::decode(hex_data) {
            Ok(response_bytes) => {
                // For now, return the raw bytes as a hex string until we have proper protobuf parsing
                // In a full implementation, we would parse this as a protobuf response
                debug!("Successfully decoded {} bytes of protorunes data", response_bytes.len());
                
                // Return as an array with the hex data for now
                // This maintains compatibility with existing code expecting an array
                Ok(json!([{
                    "raw_data": hex_response,
                    "decoded_bytes": response_bytes.len(),
                    "note": "Raw protobuf data - needs proper parsing"
                }]))
            },
            Err(e) => {
                debug!("Failed to decode hex response: {}", e);
                // Return empty array if we can't decode
                Ok(json!([]))
            }
        }
    }
    /// Trace a transaction for DIESEL token minting
    pub async fn trace_transaction(&self, txid: &str, vout: usize) -> Result<Value> {
        debug!("Tracing transaction: {} vout: {}", txid, vout);
        
        // Create and encode the Outpoint protobuf message
        let mut outpoint = alkanes_support::proto::alkanes::Outpoint::new();
        
        // Decode the txid hex string to bytes (txid should already be reversed by caller)
        let txid_bytes = hex::decode(txid)
            .context("Invalid txid hex")?;
        outpoint.txid = txid_bytes;
        outpoint.vout = vout as u32;
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = outpoint.write_to_bytes()
            .context("Failed to encode Outpoint")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["trace", hex_input, "latest"])
        ).await?;
        
        debug!("Trace result for transaction: {}", txid);
        Ok(result)
    }
    
    /// Trace a transaction and return a pretty-printed trace
    pub async fn trace_transaction_pretty(&self, txid: &str, vout: usize) -> Result<String> {
        debug!("Tracing transaction with pretty printing: {} vout: {}", txid, vout);
        
        let result = self.trace_transaction(txid, vout).await?;
        
        // Parse the hex response
        let hex_response = result.as_str()
            .context("Expected hex string response")?;
        
        // Handle empty response
        if hex_response == "0x" || hex_response.is_empty() {
            return Ok("No trace data found".to_string());
        }
        
        // Decode hex response (remove 0x prefix if present)
        let hex_data = if hex_response.starts_with("0x") {
            &hex_response[2..]
        } else {
            hex_response
        };
        
        // If hex_data is empty after removing prefix, return empty
        if hex_data.is_empty() {
            return Ok("No trace data found".to_string());
        }
        
        // Decode the hex data
        let response_bytes = hex::decode(hex_data)
            .context("Failed to decode hex response")?;
        
        // Parse as TraceResponse protobuf
        let trace_response = alkanes_support::proto::alkanes::Trace::parse_from_bytes(&response_bytes)
            .context("Failed to parse TraceResponse")?;
        
        // Convert to alkanes_support::trace::Trace
        let trace: alkanes_support::trace::Trace = trace_response.trace.into_option()
            .unwrap_or_default()
            .into();
        
        // Pretty print the trace
        Ok(self.format_trace(&trace))
    }
    
    /// Format a trace for pretty printing with colorful emojis and YAML-like tree structure
    fn format_trace(&self, trace: &alkanes_support::trace::Trace) -> String {
        let events = trace.0.lock().unwrap();
        let mut output = String::new();
        
        // Header with colorful styling
        output.push_str("🔍 ═══════════════════════════════════════════════════════════════\n");
        output.push_str("🧪                    ALKANES EXECUTION TRACE                    🧪\n");
        output.push_str("🔍 ═══════════════════════════════════════════════════════════════\n\n");
        
        if events.is_empty() {
            output.push_str("📭 trace:\n");
            output.push_str("    events: []\n");
            output.push_str("    status: ✅ parsed_successfully\n");
            output.push_str("    note: \"No execution events found\"\n");
        } else {
            output.push_str("📊 trace:\n");
            output.push_str(&format!("    total_events: {}\n", events.len()));
            output.push_str("    events:\n");
            
            for (i, event) in events.iter().enumerate() {
                let is_last = i == events.len() - 1;
                let tree_prefix = if is_last { "    └─" } else { "    ├─" };
                let indent_prefix = if is_last { "      " } else { "    │ " };
                
                match event {
                    alkanes_support::trace::TraceEvent::CreateAlkane(id) => {
                        output.push_str(&format!("{} 🏗️  create_alkane:\n", tree_prefix));
                        output.push_str(&format!("{}    alkane_id:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, id.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, id.tx));
                        output.push_str(&format!("{}    status: ✅ created\n", indent_prefix));
                    },
                    alkanes_support::trace::TraceEvent::EnterCall(ctx) => {
                        output.push_str(&format!("{} 📞 call:\n", tree_prefix));
                        output.push_str(&format!("{}    target:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, ctx.target.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, ctx.target.tx));
                        output.push_str(&format!("{}    caller:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, ctx.inner.caller.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, ctx.inner.caller.tx));
                        output.push_str(&format!("{}    ⛽ fuel_allocated: {}\n", indent_prefix, ctx.fuel));
                        
                        if !ctx.inner.inputs.is_empty() {
                            output.push_str(&format!("{}    📥 inputs:\n", indent_prefix));
                            for (j, input) in ctx.inner.inputs.iter().enumerate() {
                                let input_tree = if j == ctx.inner.inputs.len() - 1 { "└─" } else { "├─" };
                                output.push_str(&format!("{}      {} [{}]: {}\n", indent_prefix, input_tree, j, input));
                            }
                        } else {
                            output.push_str(&format!("{}    📥 inputs: []\n", indent_prefix));
                        }
                    },
                    alkanes_support::trace::TraceEvent::EnterDelegatecall(ctx) => {
                        output.push_str(&format!("{} 🔄 delegatecall:\n", tree_prefix));
                        output.push_str(&format!("{}    target:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, ctx.target.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, ctx.target.tx));
                        output.push_str(&format!("{}    caller:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, ctx.inner.caller.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, ctx.inner.caller.tx));
                        output.push_str(&format!("{}    ⛽ fuel_allocated: {}\n", indent_prefix, ctx.fuel));
                    },
                    alkanes_support::trace::TraceEvent::EnterStaticcall(ctx) => {
                        output.push_str(&format!("{} 🔒 staticcall:\n", tree_prefix));
                        output.push_str(&format!("{}    target:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, ctx.target.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, ctx.target.tx));
                        output.push_str(&format!("{}    caller:\n", indent_prefix));
                        output.push_str(&format!("{}      block: {}\n", indent_prefix, ctx.inner.caller.block));
                        output.push_str(&format!("{}      tx: {}\n", indent_prefix, ctx.inner.caller.tx));
                        output.push_str(&format!("{}    ⛽ fuel_allocated: {}\n", indent_prefix, ctx.fuel));
                    },
                    alkanes_support::trace::TraceEvent::ReturnContext(resp) => {
                        output.push_str(&format!("{} ✅ return:\n", tree_prefix));
                        output.push_str(&format!("{}    ⛽ fuel_used: {}\n", indent_prefix, resp.fuel_used));
                        
                        if !resp.inner.data.is_empty() {
                            output.push_str(&format!("{}    📤 return_data:\n", indent_prefix));
                            output.push_str(&format!("{}      hex: \"{}\"\n", indent_prefix, hex::encode(&resp.inner.data)));
                            output.push_str(&format!("{}      length: {} bytes\n", indent_prefix, resp.inner.data.len()));
                        } else {
                            output.push_str(&format!("{}    📤 return_data: null\n", indent_prefix));
                        }
                        
                        if !resp.inner.alkanes.0.is_empty() {
                            output.push_str(&format!("{}    🪙 alkane_transfers:\n", indent_prefix));
                            for (j, transfer) in resp.inner.alkanes.0.iter().enumerate() {
                                let transfer_tree = if j == resp.inner.alkanes.0.len() - 1 { "└─" } else { "├─" };
                                output.push_str(&format!("{}      {} transfer_{}:\n", indent_prefix, transfer_tree, j));
                                output.push_str(&format!("{}      {}   alkane_id:\n", indent_prefix, if j == resp.inner.alkanes.0.len() - 1 { " " } else { "│" }));
                                output.push_str(&format!("{}      {}     block: {}\n", indent_prefix, if j == resp.inner.alkanes.0.len() - 1 { " " } else { "│" }, transfer.id.block));
                                output.push_str(&format!("{}      {}     tx: {}\n", indent_prefix, if j == resp.inner.alkanes.0.len() - 1 { " " } else { "│" }, transfer.id.tx));
                                output.push_str(&format!("{}      {}   amount: {}\n", indent_prefix, if j == resp.inner.alkanes.0.len() - 1 { " " } else { "│" }, transfer.value));
                            }
                        } else {
                            output.push_str(&format!("{}    🪙 alkane_transfers: []\n", indent_prefix));
                        }
                    },
                    alkanes_support::trace::TraceEvent::RevertContext(resp) => {
                        output.push_str(&format!("{} ❌ revert:\n", tree_prefix));
                        output.push_str(&format!("{}    ⛽ fuel_used: {}\n", indent_prefix, resp.fuel_used));
                        
                        if !resp.inner.data.is_empty() {
                            output.push_str(&format!("{}    🚨 error_data:\n", indent_prefix));
                            output.push_str(&format!("{}      hex: \"{}\"\n", indent_prefix, hex::encode(&resp.inner.data)));
                            output.push_str(&format!("{}      length: {} bytes\n", indent_prefix, resp.inner.data.len()));
                        } else {
                            output.push_str(&format!("{}    🚨 error_data: null\n", indent_prefix));
                        }
                    },
                }
                
                // Add spacing between events except for the last one
                if !is_last {
                    output.push_str("    │\n");
                }
            }
        }
        
        output.push_str("\n🎯 ═══════════════════════════════════════════════════════════════\n");
        output.push_str("✨                      TRACE COMPLETE                         ✨\n");
        output.push_str("🎯 ═══════════════════════════════════════════════════════════════\n");
        output
    }
    
    /// Convert a trace to JSON format for raw output
    fn trace_to_json(&self, trace: &alkanes_support::trace::Trace) -> serde_json::Value {
        let events = trace.0.lock().unwrap();
        let mut json_events = Vec::new();
        
        for event in events.iter() {
            let json_event = match event {
                alkanes_support::trace::TraceEvent::CreateAlkane(id) => {
                    json!({
                        "type": "create_alkane",
                        "alkane_id": {
                            "block": id.block,
                            "tx": id.tx
                        }
                    })
                },
                alkanes_support::trace::TraceEvent::EnterCall(ctx) => {
                    json!({
                        "type": "call",
                        "target": {
                            "block": ctx.target.block,
                            "tx": ctx.target.tx
                        },
                        "caller": {
                            "block": ctx.inner.caller.block,
                            "tx": ctx.inner.caller.tx
                        },
                        "fuel_allocated": ctx.fuel,
                        "inputs": ctx.inner.inputs
                    })
                },
                alkanes_support::trace::TraceEvent::EnterDelegatecall(ctx) => {
                    json!({
                        "type": "delegatecall",
                        "target": {
                            "block": ctx.target.block,
                            "tx": ctx.target.tx
                        },
                        "caller": {
                            "block": ctx.inner.caller.block,
                            "tx": ctx.inner.caller.tx
                        },
                        "fuel_allocated": ctx.fuel
                    })
                },
                alkanes_support::trace::TraceEvent::EnterStaticcall(ctx) => {
                    json!({
                        "type": "staticcall",
                        "target": {
                            "block": ctx.target.block,
                            "tx": ctx.target.tx
                        },
                        "caller": {
                            "block": ctx.inner.caller.block,
                            "tx": ctx.inner.caller.tx
                        },
                        "fuel_allocated": ctx.fuel
                    })
                },
                alkanes_support::trace::TraceEvent::ReturnContext(resp) => {
                    let alkane_transfers: Vec<serde_json::Value> = resp.inner.alkanes.0.iter().map(|transfer| {
                        json!({
                            "alkane_id": {
                                "block": transfer.id.block,
                                "tx": transfer.id.tx
                            },
                            "amount": transfer.value
                        })
                    }).collect();
                    
                    json!({
                        "type": "return",
                        "fuel_used": resp.fuel_used,
                        "return_data": if resp.inner.data.is_empty() {
                            serde_json::Value::Null
                        } else {
                            json!({
                                "hex": hex::encode(&resp.inner.data),
                                "length": resp.inner.data.len()
                            })
                        },
                        "alkane_transfers": alkane_transfers
                    })
                },
                alkanes_support::trace::TraceEvent::RevertContext(resp) => {
                    json!({
                        "type": "revert",
                        "fuel_used": resp.fuel_used,
                        "error_data": if resp.inner.data.is_empty() {
                            serde_json::Value::Null
                        } else {
                            json!({
                                "hex": hex::encode(&resp.inner.data),
                                "length": resp.inner.data.len()
                            })
                        }
                    })
                },
            };
            json_events.push(json_event);
        }
        
        json!({
            "trace": {
                "total_events": events.len(),
                "events": json_events
            }
        })
    }
    
    /// Get protorunes by outpoint
    pub async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<Value> {
        debug!("Getting protorunes for outpoint: {}:{}", txid, vout);
        
        // Create and encode the OutpointWithProtocol protobuf message
        let mut outpoint_request = protorune_support::proto::protorune::OutpointWithProtocol::new();
        
        // Reverse txid bytes for protorunes calls
        let reversed_txid = reverse_txid_bytes(txid)?;
        
        // Decode the reversed txid hex string to bytes
        let txid_bytes = hex::decode(&reversed_txid)
            .context("Invalid txid hex")?;
        outpoint_request.txid = txid_bytes;
        outpoint_request.vout = vout;
        
        // Set protocol tag to 1 (for alkanes/DIESEL tokens)
        let mut protocol_tag = protorune_support::proto::protorune::Uint128::new();
        protocol_tag.hi = 0;
        protocol_tag.lo = 1;
        outpoint_request.protocol = protobuf::MessageField::some(protocol_tag);
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = outpoint_request.write_to_bytes()
            .context("Failed to encode OutpointWithProtocol")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["protorunesbyoutpoint", hex_input, "latest"])
        ).await?;
        
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
        
        // Create and encode the MessageContextParcel protobuf message
        let mut parcel = alkanes_support::proto::alkanes::MessageContextParcel::new();
        
        // Parse inputs as u128 values and convert to cellpack format
        let parsed_inputs: Result<Vec<u128>> = inputs
            .iter()
            .map(|input| input.parse::<u128>().context("Invalid input number"))
            .collect();
        let parsed_inputs = parsed_inputs?;
        
        // Create a simple cellpack with the target and inputs
        // Parse block and tx as u128 values for the target AlkaneId
        let block_u128 = block.parse::<u128>()
            .context("Invalid block number")?;
        let tx_u128 = tx.parse::<u128>()
            .context("Invalid tx number")?;
        
        // Encode the cellpack as calldata (simplified version)
        // In a full implementation, this would use the proper Cellpack encoding
        let mut calldata = Vec::new();
        
        // Add target (block:tx)
        calldata.extend_from_slice(&block_u128.to_le_bytes());
        calldata.extend_from_slice(&tx_u128.to_le_bytes());
        
        // Add inputs
        for input in parsed_inputs {
            calldata.extend_from_slice(&input.to_le_bytes());
        }
        
        parcel.calldata = calldata;
        parcel.height = 0; // Default height
        parcel.vout = 0; // Default vout
        parcel.pointer = 0; // Default pointer
        parcel.refund_pointer = 0; // Default refund pointer
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = parcel.write_to_bytes()
            .context("Failed to encode MessageContextParcel")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["simulate", hex_input, "latest"])
        ).await?;
        
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
    
    /// Get transaction hex by transaction ID using esplora
    pub async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        debug!("Getting transaction hex for txid: {}", txid);
        
        let result = self._call(
            "esplora_tx::hex",
            json!([txid])
        ).await?;
        
        let tx_hex = result.as_str()
            .context("Invalid transaction hex response")?
            .to_string();
        
        debug!("Got transaction hex for txid: {}", txid);
        Ok(tx_hex)
    }
    
    /// Get raw transaction bytes by transaction ID using esplora
    pub async fn get_transaction_raw(&self, txid: &str) -> Result<String> {
        debug!("Getting raw transaction bytes for txid: {}", txid);
        
        let result = self._call(
            "esplora_tx::raw",
            json!([txid])
        ).await?;
        
        let tx_raw = result.as_str()
            .context("Invalid transaction raw response")?
            .to_string();
        
        debug!("Got raw transaction bytes for txid: {}", txid);
        Ok(tx_raw)
    }
    
    /// Get transaction using Bitcoin RPC method
    pub async fn get_transaction_btc_rpc(&self, txid: &str, verbose: bool) -> Result<String> {
        debug!("Getting transaction using Bitcoin RPC for txid: {}", txid);
        
        let result = self._call(
            "btc_getrawtransaction",
            json!([txid, verbose])
        ).await?;
        
        let tx_hex = result.as_str()
            .context("Invalid transaction response")?
            .to_string();
        
        debug!("Got transaction via Bitcoin RPC for txid: {}", txid);
        Ok(tx_hex)
    }
    
    /// Broadcast a transaction using esplora interface
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String> {
        debug!("Broadcasting transaction via esplora");
        
        let result = self._call("esplora_broadcast", json!([tx_hex])).await?;
        
        let txid = result.as_str()
            .context("Invalid broadcast response")?
            .to_string();
        
        debug!("Transaction broadcast successful: {}", txid);
        Ok(txid)
    }
    
    /// Send raw transaction using Bitcoin JSON-RPC sendrawtransaction method
    pub async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String> {
        debug!("Sending raw transaction via Bitcoin RPC: {}", &tx_hex[..std::cmp::min(tx_hex.len(), 64)]);
        
        // Use maxfeerate=0 to bypass Bitcoin Core's fee rate validation for envelope transactions
        // This is necessary because Bitcoin Core incorrectly calculates fee rates for transactions with large witness data
        let result = self._call("btc_sendrawtransaction", json!([tx_hex, 0])).await?;
        
        let txid = result.as_str()
            .context("Invalid sendrawtransaction response")?
            .to_string();
        
        debug!("Transaction sent successfully via Bitcoin RPC: {}", txid);
        Ok(txid)
    }
    
    /// Get address UTXOs using esplora interface
    pub async fn get_address_utxos(&self, address: &str) -> Result<Value> {
        debug!("Getting UTXOs for address: {}", address);
        
        // Use a longer timeout and larger body limit for UTXO requests since they can be very large
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "esplora_address::utxo".to_string(),
            params: json!([address]),
            id: self.next_request_id(),
        };
        
        // Log the request for debugging (truncated if large)
        debug!("JSON-RPC Request to {}: {}", &self.config.metashrew_rpc_url, self.truncate_json_for_logging(&json!(request)));
        
        // Create a client with extended timeout for large UTXO responses
        let extended_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(600)) // 10 minutes for large UTXO responses (matches main client)
            .build()
            .context("Failed to create extended HTTP client")?;
        
        let response = extended_client
            .post(&self.config.metashrew_rpc_url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send RPC request")?;
        
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("RPC request failed with status: {}", status));
        }
        
        // Get the response text first to handle large responses better
        let response_text = response
            .text()
            .await
            .context("Failed to get response text")?;
        
        debug!("Raw response size: {} bytes", response_text.len());
        
        // Parse the response text as JSON
        let response_body: RpcResponse = serde_json::from_str(&response_text)
            .context("Failed to parse RPC response JSON")?;
        
        // Log the response for debugging (truncated if large)
        debug!("JSON-RPC Response: {}", self.truncate_rpc_response_for_logging(&response_body));
        
        match response_body.result {
            Some(result) => {
                debug!("Got UTXOs for address: {} (response size: {} bytes)", address, response_text.len());
                Ok(result)
            },
            None => {
                let error = response_body.error.unwrap_or(RpcError {
                    code: -1,
                    message: "Unknown error".to_string(),
                });
                Err(anyhow!("RPC error: {} (code: {})", error.message, error.code))
            }
        }
    }
    
    /// Get address transaction history using esplora interface
    pub async fn get_address_transactions(&self, address: &str) -> Result<Value> {
        debug!("Getting transaction history for address: {}", address);
        
        let result = self._call("esplora_address::txs", json!([address])).await?;
        
        debug!("Got transaction history for address: {}", address);
        Ok(result)
    }
    
    /// Get address mempool transactions using esplora interface
    pub async fn get_address_mempool_transactions(&self, address: &str) -> Result<Value> {
        debug!("Getting mempool transactions for address: {}", address);
        
        let result = self._call("esplora_address::txs:mempool", json!([address])).await?;
        
        debug!("Got mempool transactions for address: {}", address);
        Ok(result)
    }
    
    /// Get fee estimates using esplora interface
    pub async fn get_fee_estimates(&self) -> Result<Value> {
        debug!("Getting fee estimates");
        
        let result = self._call("esplora_fee:estimates", json!([])).await?;
        
        debug!("Got fee estimates");
        Ok(result)
    }
    
    /// Get transaction status using esplora interface
    pub async fn get_transaction_status(&self, txid: &str) -> Result<Value> {
        debug!("Getting transaction status for: {}", txid);
        
        let result = self._call("esplora_tx::status", json!([txid])).await?;
        
        debug!("Got transaction status for: {}", txid);
        Ok(result)
    }
    
    /// Get block hash by height using esplora interface
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        debug!("Getting block hash for height: {}", height);
        
        let result = self._call("esplora_block:height", json!([height])).await?;
        
        let block_hash = result.as_str()
            .context("Invalid block hash response")?
            .to_string();
        
        debug!("Got block hash for height {}: {}", height, block_hash);
        Ok(block_hash)
    }
    
    /// Get best block hash from Bitcoin RPC
    pub async fn get_best_block_hash(&self) -> Result<String> {
        debug!("Getting best block hash from Bitcoin RPC");
        
        let result = self._call("btc_getbestblockhash", json!([])).await?;
        
        let block_hash = result.as_str()
            .context("Invalid best block hash response")?
            .to_string();
        
        debug!("Got best block hash: {}", block_hash);
        Ok(block_hash)
    }
    
    /// Get block hash by height from Bitcoin RPC
    pub async fn get_block_hash_btc(&self, height: u64) -> Result<String> {
        debug!("Getting block hash for height {} from Bitcoin RPC", height);
        
        let result = self._call("btc_getblockhash", json!([height])).await?;
        
        let block_hash = result.as_str()
            .context("Invalid block hash response")?
            .to_string();
        
        debug!("Got block hash for height {} from Bitcoin RPC: {}", height, block_hash);
        Ok(block_hash)
    }
    
    /// Get ord block height
    pub async fn get_ord_block_height(&self) -> Result<u64> {
        debug!("Getting ord block height");
        
        let result = self._call("ord_blockheight", json!([])).await?;
        
        // Handle both string and number responses
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid ord block height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid ord block height format"));
        };
        
        debug!("Current ord block height: {}", height);
        Ok(height)
    }
    
    /// Get ord block hash
    pub async fn get_ord_block_hash(&self) -> Result<String> {
        debug!("Getting ord block hash");
        
        let result = self._call("ord_blockhash", json!([])).await?;
        
        let block_hash = result.as_str()
            .context("Invalid ord block hash response")?
            .to_string();
        
        debug!("Got ord block hash: {}", block_hash);
        Ok(block_hash)
    }
    
    /// Get esplora tip height
    pub async fn get_esplora_tip_height(&self) -> Result<u64> {
        debug!("Getting esplora tip height");
        
        let result = self._call("esplora_block:tip:height", json!([])).await?;
        
        // Handle both string and number responses
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid esplora tip height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid esplora tip height format"));
        };
        
        debug!("Current esplora tip height: {}", height);
        Ok(height)
    }

    /// Get esplora blocks tip height using the correct method name
    pub async fn get_esplora_blocks_tip_height(&self) -> Result<u64> {
        debug!("Getting esplora blocks tip height");
        
        let result = self._call("esplora_blocks:tip:height", json!([])).await?;
        
        // Handle both string and number responses
        let height = if let Some(height_str) = result.as_str() {
            height_str.parse::<u64>().context("Invalid esplora blocks tip height string")?
        } else if let Some(height_num) = result.as_u64() {
            height_num
        } else {
            return Err(anyhow!("Invalid esplora blocks tip height format"));
        };
        
        debug!("Current esplora blocks tip height: {}", height);
        Ok(height)
    }
    
    /// Get esplora tip hash
    pub async fn get_esplora_tip_hash(&self) -> Result<String> {
        debug!("Getting esplora tip hash");
        
        let result = self._call("esplora_block:tip:hash", json!([])).await?;
        
        let block_hash = result.as_str()
            .context("Invalid esplora tip hash response")?
            .to_string();
        
        debug!("Got esplora tip hash: {}", block_hash);
        Ok(block_hash)
    }
    
    /// Get metashrew block hash by height
    pub async fn get_metashrew_block_hash(&self, height: u64) -> Result<String> {
        debug!("Getting metashrew block hash for height: {}", height);
        
        let result = self._call("metashrew_getblockhash", json!([height])).await?;
        
        let block_hash = result.as_str()
            .context("Invalid metashrew block hash response")?
            .to_string();
        
        debug!("Got metashrew block hash for height {}: {}", height, block_hash);
        Ok(block_hash)
    }
    
    /// Get ord inscriptions for an address
    pub async fn get_ord_inscriptions(&self, address: &str) -> Result<Value> {
        debug!("Getting ord inscriptions for address: {}", address);
        
        let result = self._call("ord_address", json!([address])).await?;
        
        debug!("Got ord inscriptions for address: {}", address);
        Ok(result)
    }
    
    /// Get ord inscription content
    pub async fn get_ord_content(&self, inscription_id: &str) -> Result<String> {
        debug!("Getting ord content for inscription: {}", inscription_id);
        
        let result = self._call("ord_content", json!([inscription_id])).await?;
        
        // ord_content returns base64 encoded data
        let content = result.as_str()
            .context("Invalid ord content response")?
            .to_string();
        
        debug!("Got ord content for inscription: {}", inscription_id);
        Ok(content)
    }
    
    /// Get ord output information for a specific outpoint
    pub async fn get_ord_output(&self, txid: &str, vout: u32) -> Result<Value> {
        debug!("Getting ord output for outpoint: {}:{}", txid, vout);
        
        let outpoint = format!("{}:{}", txid, vout);
        let result = self._call("ord_output", json!([outpoint])).await?;
        
        debug!("Got ord output for outpoint: {}:{}", txid, vout);
        Ok(result)
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
        
        // For now, use a simplified approach until we have the correct protobuf types
        let hex_input = format!("0x{}", hex::encode(txid.as_bytes()));
        
        let result = self.call_rpc("metashrew_view", vec![
            json!("transactionbyid"),
            json!(hex_input),
            json!(block_tag)
        ]).await?;
        
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
        
        // Create and encode the ProtorunesWalletRequest protobuf message
        let mut wallet_request = protorune_support::proto::protorune::ProtorunesWalletRequest::new();
        wallet_request.wallet = address.as_bytes().to_vec();
        
        // Set protocol tag
        let mut protocol = protorune_support::proto::protorune::Uint128::new();
        protocol.hi = 0; // For u64 values, hi is always 0
        protocol.lo = protocol_tag;
        wallet_request.protocol_tag = protobuf::MessageField::some(protocol);
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = wallet_request.write_to_bytes()
            .context("Failed to encode ProtorunesWalletRequest")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["protorunesbyaddress", hex_input, block_tag])
        ).await?;
        
        debug!("Got protorunes for address: {}", address);
        Ok(result)
    }
    
    /// Get protorunes by outpoint with protocol tag
    pub async fn get_protorunes_by_outpoint_with_protocol(&self, txid: &str, vout: u32, protocol_tag: u64) -> Result<OutpointResponse> {
        debug!("Getting protorunes for outpoint: {}:{} with protocol tag: {}", txid, vout, protocol_tag);
        
        // Create and encode the OutpointWithProtocol protobuf message
        let mut outpoint_request = protorune_support::proto::protorune::OutpointWithProtocol::new();
        
        // Reverse txid bytes for protorunes calls
        let reversed_txid = reverse_txid_bytes(txid)?;
        
        // Decode the reversed txid hex string to bytes
        let txid_bytes = hex::decode(&reversed_txid)
            .context("Invalid txid hex")?;
        outpoint_request.txid = txid_bytes;
        outpoint_request.vout = vout;
        
        // Set protocol tag
        let mut protocol = protorune_support::proto::protorune::Uint128::new();
        protocol.hi = 0; // For u64 values, hi is always 0
        protocol.lo = protocol_tag;
        outpoint_request.protocol = protobuf::MessageField::some(protocol);
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = outpoint_request.write_to_bytes()
            .context("Failed to encode OutpointWithProtocol")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["protorunesbyoutpoint", hex_input, "latest"])
        ).await?;
        
        debug!("Got protorunes for outpoint: {}:{}", txid, vout);
        if let Some(hex_str) = result.as_str() {
            let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
                .context("Failed to decode hex string from RPC response")?;
            if bytes.is_empty() {
                return Ok(OutpointResponse::new());
            }
            let response = OutpointResponse::parse_from_bytes(&bytes)
                .context("Failed to parse OutpointResponse from bytes")?;
            Ok(response)
        } else {
            Err(anyhow!("Expected a hex string from RPC but got something else"))
        }
    }
    
    /// Get spendables by address with block tag
    pub async fn get_spendables_by_address_with_tag(&self, address: &str, block_tag: &str) -> Result<Value> {
        debug!("Getting spendables for address: {} with block tag: {}", address, block_tag);
        
        // For now, use a simplified approach with basic hex encoding
        let address_bytes = address.as_bytes();
        let hex_input = format!("0x{}", hex::encode(address_bytes));
        
        let result = self.call_rpc("metashrew_view", vec![
            json!("spendablesbyaddress"),
            json!(hex_input),
            json!(block_tag)
        ]).await?;
        
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
        
        // Create and encode the Outpoint protobuf message
        let mut outpoint = alkanes_support::proto::alkanes::Outpoint::new();
        
        // Reverse txid bytes for trace calls
        let reversed_txid = reverse_txid_bytes(txid)?;
        debug!("Original txid: {}", txid);
        debug!("Reversed txid: {}", reversed_txid);
        
        // Decode the reversed txid hex string to bytes
        let txid_bytes = hex::decode(&reversed_txid)
            .context("Invalid txid hex")?;
        outpoint.txid = txid_bytes.clone();
        outpoint.vout = vout;
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = outpoint.write_to_bytes()
            .context("Failed to encode Outpoint")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        debug!("Protobuf encoded outpoint: {}", hex_input);
        debug!("Outpoint txid bytes: {}", hex::encode(&txid_bytes));
        debug!("Outpoint vout: {}", vout);
        
        let result = self._call(
            "metashrew_view",
            json!(["trace", hex_input, "latest"])
        ).await?;
        
        debug!("Raw trace result: {:?}", result);
        Ok(result)
    }
    
    /// Trace an outpoint and return a pretty-printed trace
    pub async fn trace_outpoint_pretty(&self, txid: &str, vout: u32) -> Result<String> {
        debug!("Tracing outpoint with pretty printing: {}:{}", txid, vout);
        
        let result = self.trace_outpoint(txid, vout).await?;
        
        // Parse the hex response
        let hex_response = result.as_str()
            .context("Expected hex string response")?;
        
        // Handle empty response
        if hex_response == "0x" || hex_response.is_empty() {
            return Ok("=== ALKANES TRACE ===\nNo trace events found\n=====================".to_string());
        }
        
        // Decode hex response (remove 0x prefix if present)
        let hex_data = if hex_response.starts_with("0x") {
            &hex_response[2..]
        } else {
            hex_response
        };
        
        // If hex_data is empty after removing prefix, return empty
        if hex_data.is_empty() {
            return Ok("=== ALKANES TRACE ===\nNo trace events found\n=====================".to_string());
        }
        
        // Decode the hex data
        let response_bytes = hex::decode(hex_data)
            .context("Failed to decode hex response")?;
        
        debug!("Decoded {} bytes of trace data", response_bytes.len());
        
        // Try to parse as AlkanesTrace protobuf directly
        match alkanes_support::proto::alkanes::AlkanesTrace::parse_from_bytes(&response_bytes) {
            Ok(alkanes_trace) => {
                debug!("Successfully parsed protobuf AlkanesTrace response");
                
                // Convert to alkanes_support::trace::Trace
                let trace: alkanes_support::trace::Trace = alkanes_trace.into();
                
                // Pretty print the trace
                Ok(self.format_trace(&trace))
            },
            Err(e) => {
                debug!("Failed to parse as protobuf Trace: {}", e);
                
                // If protobuf parsing fails, show the raw data
                let mut output = String::new();
                output.push_str("=== ALKANES TRACE ===\n");
                output.push_str(&format!("Raw trace data ({} bytes):\n", response_bytes.len()));
                output.push_str(&format!("Hex: {}\n", hex::encode(&response_bytes)));
                
                // Try to interpret as raw bytes
                if response_bytes.len() >= 4 {
                    output.push_str("Possible interpretations:\n");
                    
                    // Show first few bytes as different integer types
                    let first_u32 = u32::from_le_bytes([
                        response_bytes.get(0).copied().unwrap_or(0),
                        response_bytes.get(1).copied().unwrap_or(0),
                        response_bytes.get(2).copied().unwrap_or(0),
                        response_bytes.get(3).copied().unwrap_or(0),
                    ]);
                    output.push_str(&format!("  First 4 bytes as u32 (LE): {}\n", first_u32));
                    
                    if response_bytes.len() >= 8 {
                        let first_u64 = u64::from_le_bytes([
                            response_bytes.get(0).copied().unwrap_or(0),
                            response_bytes.get(1).copied().unwrap_or(0),
                            response_bytes.get(2).copied().unwrap_or(0),
                            response_bytes.get(3).copied().unwrap_or(0),
                            response_bytes.get(4).copied().unwrap_or(0),
                            response_bytes.get(5).copied().unwrap_or(0),
                            response_bytes.get(6).copied().unwrap_or(0),
                            response_bytes.get(7).copied().unwrap_or(0),
                        ]);
                        output.push_str(&format!("  First 8 bytes as u64 (LE): {}\n", first_u64));
                    }
                    
                    // Show as ASCII if printable
                    let ascii_str: String = response_bytes.iter()
                        .take(64) // Limit to first 64 bytes
                        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                        .collect();
                    output.push_str(&format!("  As ASCII (first 64 bytes): {}\n", ascii_str));
                }
                
                output.push_str("Note: Failed to parse as protobuf - this may be raw trace data\n");
                output.push_str("=====================\n");
                Ok(output)
            }
        }
    }
    
    /// Trace an outpoint and return JSON-formatted trace data
    pub async fn trace_outpoint_json(&self, txid: &str, vout: u32) -> Result<String> {
        debug!("Tracing outpoint with JSON output: {}:{}", txid, vout);
        
        let result = self.trace_outpoint(txid, vout).await?;
        
        // Parse the hex response
        let hex_response = result.as_str()
            .context("Expected hex string response")?;
        
        // Handle empty response
        if hex_response == "0x" || hex_response.is_empty() {
            return Ok(json!({
                "trace": {
                    "total_events": 0,
                    "events": []
                },
                "status": "no_trace_data"
            }).to_string());
        }
        
        // Decode hex response (remove 0x prefix if present)
        let hex_data = if hex_response.starts_with("0x") {
            &hex_response[2..]
        } else {
            hex_response
        };
        
        // If hex_data is empty after removing prefix, return empty
        if hex_data.is_empty() {
            return Ok(json!({
                "trace": {
                    "total_events": 0,
                    "events": []
                },
                "status": "no_trace_data"
            }).to_string());
        }
        
        // Decode the hex data
        let response_bytes = hex::decode(hex_data)
            .context("Failed to decode hex response")?;
        
        debug!("Decoded {} bytes of trace data for JSON output", response_bytes.len());
        
        // Try to parse as AlkanesTrace protobuf directly
        match alkanes_support::proto::alkanes::AlkanesTrace::parse_from_bytes(&response_bytes) {
            Ok(alkanes_trace) => {
                debug!("Successfully parsed protobuf AlkanesTrace response for JSON");
                
                // Convert to alkanes_support::trace::Trace
                let trace: alkanes_support::trace::Trace = alkanes_trace.into();
                
                // Convert to JSON
                let json_output = self.trace_to_json(&trace);
                Ok(serde_json::to_string_pretty(&json_output)?)
            },
            Err(e) => {
                debug!("Failed to parse as protobuf Trace for JSON: {}", e);
                
                // If protobuf parsing fails, return raw data in JSON format
                Ok(json!({
                    "trace": {
                        "total_events": 0,
                        "events": []
                    },
                    "status": "parse_error",
                    "error": format!("Failed to parse protobuf: {}", e),
                    "raw_data": {
                        "hex": hex::encode(&response_bytes),
                        "length": response_bytes.len()
                    }
                }).to_string())
            }
        }
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
        
        // For now, use the old format until we have the correct protobuf types
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
    
    /// Get raw hex response from metashrew_view for any method
    pub async fn get_metashrew_view_hex(&self, method: &str, hex_input: &str, block_tag: &str) -> Result<String> {
        debug!("Getting raw hex from metashrew_view: {} with input: {} and block_tag: {}", method, hex_input, block_tag);
        
        let result = self._call(
            "metashrew_view",
            json!([method, hex_input, block_tag])
        ).await?;
        
        let hex_response = result.as_str()
            .context("Expected hex string response from metashrew_view")?
            .to_string();
        
        debug!("Got raw hex response from metashrew_view: {}", hex_response);
        Ok(hex_response)
    }
    
    /// Get the next request ID
    fn next_request_id(&self) -> u64 {
        // Use atomic fetch_add for thread safety
        self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Generic esplora API call - handles all esplora endpoints
    pub async fn esplora_call(&self, endpoint: &str, params: Vec<String>) -> Result<Value> {
        debug!("Making esplora call to endpoint: {} with params: {:?}", endpoint, params);
        
        // Convert endpoint format from CLI to RPC method name
        // Examples:
        // "blocks:tip:hash" -> "esplora_blocks:tip:hash"
        // "address::utxo" -> "esplora_address::utxo"
        // "tx::hex" -> "esplora_tx::hex"
        let method_name = if endpoint.starts_with("esplora_") {
            endpoint.to_string()
        } else {
            format!("esplora_{}", endpoint)
        };
        
        let result = self._call(&method_name, serde_json::json!(params)).await?;
        
        debug!("Esplora call completed for endpoint: {}", endpoint);
        Ok(result)
    }
    
    /// Get blocks tip hash
    pub async fn get_esplora_blocks_tip_hash(&self) -> Result<String> {
        debug!("Getting esplora blocks tip hash");
        
        let result = self._call("esplora_blocks:tip:hash", serde_json::json!([])).await?;
        
        let hash = result.as_str()
            .context("Invalid blocks tip hash response")?
            .to_string();
        
        debug!("Got esplora blocks tip hash: {}", hash);
        Ok(hash)
    }
    
    /// Get block by hash
    pub async fn get_esplora_block(&self, hash: &str) -> Result<Value> {
        debug!("Getting esplora block: {}", hash);
        
        let result = self._call("esplora_block", serde_json::json!([hash])).await?;
        
        debug!("Got esplora block: {}", hash);
        Ok(result)
    }
    
    /// Get block status
    pub async fn get_esplora_block_status(&self, hash: &str) -> Result<Value> {
        debug!("Getting esplora block status: {}", hash);
        
        let result = self._call("esplora_block::status", serde_json::json!([hash])).await?;
        
        debug!("Got esplora block status: {}", hash);
        Ok(result)
    }
    
    /// Get block transaction IDs
    pub async fn get_esplora_block_txids(&self, hash: &str) -> Result<Value> {
        debug!("Getting esplora block txids: {}", hash);
        
        let result = self._call("esplora_block::txids", serde_json::json!([hash])).await?;
        
        debug!("Got esplora block txids: {}", hash);
        Ok(result)
    }
    
    /// Get block header
    pub async fn get_esplora_block_header(&self, hash: &str) -> Result<String> {
        debug!("Getting esplora block header: {}", hash);
        
        let result = self._call("esplora_block::header", serde_json::json!([hash])).await?;
        
        let header = result.as_str()
            .context("Invalid block header response")?
            .to_string();
        
        debug!("Got esplora block header: {}", hash);
        Ok(header)
    }
    
    /// Get raw block data
    pub async fn get_esplora_block_raw(&self, hash: &str) -> Result<String> {
        debug!("Getting esplora raw block: {}", hash);
        
        let result = self._call("esplora_block::raw", serde_json::json!([hash])).await?;
        
        let raw_block = result.as_str()
            .context("Invalid raw block response")?
            .to_string();
        
        debug!("Got esplora raw block: {}", hash);
        Ok(raw_block)
    }
    
    /// Get transaction ID by block hash and index
    pub async fn get_esplora_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        debug!("Getting esplora block txid: {} index: {}", hash, index);
        
        let result = self._call("esplora_block::txid", serde_json::json!([hash, index])).await?;
        
        let txid = result.as_str()
            .context("Invalid block txid response")?
            .to_string();
        
        debug!("Got esplora block txid: {} index: {}", hash, index);
        Ok(txid)
    }
    
    /// Get block transactions
    pub async fn get_esplora_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<Value> {
        debug!("Getting esplora block txs: {} start_index: {:?}", hash, start_index);
        
        let params = if let Some(index) = start_index {
            serde_json::json!([hash, index])
        } else {
            serde_json::json!([hash])
        };
        
        let result = self._call("esplora_block::txs", params).await?;
        
        debug!("Got esplora block txs: {}", hash);
        Ok(result)
    }
    
    /// Get address information
    pub async fn get_esplora_address(&self, address: &str) -> Result<Value> {
        debug!("Getting esplora address info: {}", address);
        
        let result = self._call("esplora_address", serde_json::json!([address])).await?;
        
        debug!("Got esplora address info: {}", address);
        Ok(result)
    }
    
    /// Get address transactions
    pub async fn get_esplora_address_txs(&self, address: &str) -> Result<Value> {
        debug!("Getting esplora address txs: {}", address);
        
        let result = self._call("esplora_address::txs", serde_json::json!([address])).await?;
        
        debug!("Got esplora address txs: {}", address);
        Ok(result)
    }
    
    /// Get address chain transactions
    pub async fn get_esplora_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<Value> {
        debug!("Getting esplora address chain txs: {} last_seen: {:?}", address, last_seen_txid);
        
        let params = if let Some(txid) = last_seen_txid {
            serde_json::json!([address, txid])
        } else {
            serde_json::json!([address])
        };
        
        let result = self._call("esplora_address::txs:chain", params).await?;
        
        debug!("Got esplora address chain txs: {}", address);
        Ok(result)
    }
    
    /// Get address mempool transactions
    pub async fn get_esplora_address_txs_mempool(&self, address: &str) -> Result<Value> {
        debug!("Getting esplora address mempool txs: {}", address);
        
        let result = self._call("esplora_address::txs:mempool", serde_json::json!([address])).await?;
        
        debug!("Got esplora address mempool txs: {}", address);
        Ok(result)
    }
    
    /// Get address UTXOs (already exists as get_address_utxos, but adding esplora-specific version)
    pub async fn get_esplora_address_utxo(&self, address: &str) -> Result<Value> {
        debug!("Getting esplora address UTXOs: {}", address);
        
        let result = self._call("esplora_address::utxo", serde_json::json!([address])).await?;
        
        debug!("Got esplora address UTXOs: {}", address);
        Ok(result)
    }
    
    /// Search addresses by prefix
    pub async fn get_esplora_address_prefix(&self, prefix: &str) -> Result<Value> {
        debug!("Getting esplora address prefix search: {}", prefix);
        
        let result = self._call("esplora_address:prefix", serde_json::json!([prefix])).await?;
        
        debug!("Got esplora address prefix search: {}", prefix);
        Ok(result)
    }
    
    /// Get transaction information
    pub async fn get_esplora_tx(&self, txid: &str) -> Result<Value> {
        debug!("Getting esplora transaction: {}", txid);
        
        let result = self._call("esplora_tx", serde_json::json!([txid])).await?;
        
        debug!("Got esplora transaction: {}", txid);
        Ok(result)
    }
    
    /// Get transaction status (already exists as get_transaction_status, but adding esplora-specific version)
    pub async fn get_esplora_tx_status(&self, txid: &str) -> Result<Value> {
        debug!("Getting esplora transaction status: {}", txid);
        
        let result = self._call("esplora_tx::status", serde_json::json!([txid])).await?;
        
        debug!("Got esplora transaction status: {}", txid);
        Ok(result)
    }
    
    /// Get transaction merkle proof
    pub async fn get_esplora_tx_merkle_proof(&self, txid: &str) -> Result<Value> {
        debug!("Getting esplora transaction merkle proof: {}", txid);
        
        let result = self._call("esplora_tx::merkle:proof", serde_json::json!([txid])).await?;
        
        debug!("Got esplora transaction merkle proof: {}", txid);
        Ok(result)
    }
    
    /// Get transaction merkle block proof
    pub async fn get_esplora_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        debug!("Getting esplora transaction merkleblock proof: {}", txid);
        
        let result = self._call("esplora_tx::merkleblock:proof", serde_json::json!([txid])).await?;
        
        let proof = result.as_str()
            .context("Invalid merkleblock proof response")?
            .to_string();
        
        debug!("Got esplora transaction merkleblock proof: {}", txid);
        Ok(proof)
    }
    
    /// Get transaction output spend status
    pub async fn get_esplora_tx_outspend(&self, txid: &str, index: u32) -> Result<Value> {
        debug!("Getting esplora transaction outspend: {} index: {}", txid, index);
        
        let result = self._call("esplora_tx::outspend", serde_json::json!([txid, index])).await?;
        
        debug!("Got esplora transaction outspend: {} index: {}", txid, index);
        Ok(result)
    }
    
    /// Get transaction output spends
    pub async fn get_esplora_tx_outspends(&self, txid: &str) -> Result<Value> {
        debug!("Getting esplora transaction outspends: {}", txid);
        
        let result = self._call("esplora_tx::outspends", serde_json::json!([txid])).await?;
        
        debug!("Got esplora transaction outspends: {}", txid);
        Ok(result)
    }
    
    /// Broadcast transaction (already exists as broadcast_transaction, but adding esplora-specific version)
    pub async fn esplora_broadcast(&self, tx_hex: &str) -> Result<String> {
        debug!("Broadcasting transaction via esplora");
        
        let result = self._call("esplora_broadcast", serde_json::json!([tx_hex])).await?;
        
        let txid = result.as_str()
            .context("Invalid broadcast response")?
            .to_string();
        
        debug!("Transaction broadcast successful via esplora: {}", txid);
        Ok(txid)
    }
    
    /// Get mempool information
    pub async fn get_esplora_mempool(&self) -> Result<Value> {
        debug!("Getting esplora mempool info");
        
        let result = self._call("esplora_mempool", serde_json::json!([])).await?;
        
        debug!("Got esplora mempool info");
        Ok(result)
    }
    
    /// Get mempool transaction IDs
    pub async fn get_esplora_mempool_txids(&self) -> Result<Value> {
        debug!("Getting esplora mempool txids");
        
        let result = self._call("esplora_mempool::txids", serde_json::json!([])).await?;
        
        debug!("Got esplora mempool txids");
        Ok(result)
    }
    
    /// Get recent mempool transactions
    pub async fn get_esplora_mempool_recent(&self) -> Result<Value> {
        debug!("Getting esplora mempool recent");
        
        let result = self._call("esplora_mempool::recent", serde_json::json!([])).await?;
        
        debug!("Got esplora mempool recent");
        Ok(result)
    }
    
    /// Get fee estimates (already exists as get_fee_estimates, but adding esplora-specific version)
    pub async fn get_esplora_fee_estimates(&self) -> Result<Value> {
        debug!("Getting esplora fee estimates");
        
        let result = self._call("esplora_fee:estimates", serde_json::json!([])).await?;
        
        debug!("Got esplora fee estimates");
        Ok(result)
    }
}

/// Reverse the bytes of a txid for trace calls
/// Bitcoin txids are displayed in reverse byte order compared to their internal representation
fn reverse_txid_bytes(txid: &str) -> Result<String> {
    // Decode the hex string to bytes
    let mut txid_bytes = hex::decode(txid)
        .context("Invalid txid hex")?;
    
    // Reverse the bytes
    txid_bytes.reverse();
    
    // Encode back to hex string
    Ok(hex::encode(txid_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rpc_client_creation() {
        let config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:8080".to_string(), // FIXED: Use Sandshrew endpoint
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        
        let client = RpcClient::new(config.clone());
        
        assert_eq!(client.config.bitcoin_rpc_url, config.bitcoin_rpc_url);
        assert_eq!(client.config.metashrew_rpc_url, config.metashrew_rpc_url);
    }
}