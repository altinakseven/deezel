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
struct RpcResponse {
    /// Result value
    result: Option<Value>,
    /// Error value
    error: Option<RpcError>,
    /// Response ID
    id: u64,
}

/// RPC error
#[derive(Serialize, Deserialize, Debug)]
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
        
        // Log the full request for debugging
        debug!("JSON-RPC Request to {}: {}", url, serde_json::to_string_pretty(&request).unwrap_or_else(|_| "Failed to serialize request".to_string()));
        
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
        
        // Log the response for debugging
        debug!("JSON-RPC Response: {}", serde_json::to_string_pretty(&response_body).unwrap_or_else(|_| "Failed to serialize response".to_string()));
        
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
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: json!(params),
            id: self.next_request_id(),
        };
        
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
    
    /// Format a trace for pretty printing
    fn format_trace(&self, trace: &alkanes_support::trace::Trace) -> String {
        let events = trace.0.lock().unwrap();
        let mut output = String::new();
        
        output.push_str("=== ALKANES TRACE ===\n");
        
        if events.is_empty() {
            output.push_str("No trace events found\n");
        } else {
            for (i, event) in events.iter().enumerate() {
                output.push_str(&format!("Event {}: ", i + 1));
                match event {
                    alkanes_support::trace::TraceEvent::EnterCall(ctx) => {
                        output.push_str(&format!("CALL to {}:{}\n", ctx.target.block, ctx.target.tx));
                        output.push_str(&format!("  Caller: {}:{}\n", ctx.inner.caller.block, ctx.inner.caller.tx));
                        output.push_str(&format!("  Fuel: {}\n", ctx.fuel));
                        if !ctx.inner.inputs.is_empty() {
                            output.push_str(&format!("  Inputs: {:?}\n", ctx.inner.inputs));
                        }
                    },
                    alkanes_support::trace::TraceEvent::EnterDelegatecall(ctx) => {
                        output.push_str(&format!("DELEGATECALL to {}:{}\n", ctx.target.block, ctx.target.tx));
                        output.push_str(&format!("  Caller: {}:{}\n", ctx.inner.caller.block, ctx.inner.caller.tx));
                        output.push_str(&format!("  Fuel: {}\n", ctx.fuel));
                    },
                    alkanes_support::trace::TraceEvent::EnterStaticcall(ctx) => {
                        output.push_str(&format!("STATICCALL to {}:{}\n", ctx.target.block, ctx.target.tx));
                        output.push_str(&format!("  Caller: {}:{}\n", ctx.inner.caller.block, ctx.inner.caller.tx));
                        output.push_str(&format!("  Fuel: {}\n", ctx.fuel));
                    },
                    alkanes_support::trace::TraceEvent::ReturnContext(resp) => {
                        output.push_str("RETURN\n");
                        output.push_str(&format!("  Fuel used: {}\n", resp.fuel_used));
                        if !resp.inner.data.is_empty() {
                            output.push_str(&format!("  Data: {}\n", hex::encode(&resp.inner.data)));
                        }
                        if !resp.inner.alkanes.0.is_empty() {
                            output.push_str("  Alkane transfers:\n");
                            for transfer in &resp.inner.alkanes.0 {
                                output.push_str(&format!("    {}:{} -> {}\n",
                                    transfer.id.block, transfer.id.tx, transfer.value));
                            }
                        }
                    },
                    alkanes_support::trace::TraceEvent::RevertContext(resp) => {
                        output.push_str("REVERT\n");
                        output.push_str(&format!("  Fuel used: {}\n", resp.fuel_used));
                        if !resp.inner.data.is_empty() {
                            output.push_str(&format!("  Error data: {}\n", hex::encode(&resp.inner.data)));
                        }
                    },
                    alkanes_support::trace::TraceEvent::CreateAlkane(id) => {
                        output.push_str(&format!("CREATE alkane {}:{}\n", id.block, id.tx));
                    },
                }
            }
        }
        
        output.push_str("=====================\n");
        output
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
    
    /// Get address UTXOs using esplora interface
    pub async fn get_address_utxos(&self, address: &str) -> Result<Value> {
        debug!("Getting UTXOs for address: {}", address);
        
        let result = self._call("esplora_address::utxo", json!([address])).await?;
        
        debug!("Got UTXOs for address: {}", address);
        Ok(result)
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
    pub async fn get_protorunes_by_outpoint_with_protocol(&self, txid: &str, vout: u32, protocol_tag: u64) -> Result<Value> {
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
        Ok(result)
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
        
        // Decode the reversed txid hex string to bytes
        let txid_bytes = hex::decode(&reversed_txid)
            .context("Invalid txid hex")?;
        outpoint.txid = txid_bytes;
        outpoint.vout = vout;
        
        // Serialize to bytes and hex encode with 0x prefix
        let encoded_bytes = outpoint.write_to_bytes()
            .context("Failed to encode Outpoint")?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));
        
        let result = self._call(
            "metashrew_view",
            json!(["trace", hex_input, "latest"])
        ).await?;
        
        debug!("Trace result for outpoint: {}:{}", txid, vout);
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
    
    /// Get the next request ID
    fn next_request_id(&self) -> u64 {
        // Use atomic fetch_add for thread safety
        self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
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
            bitcoin_rpc_url: "http://localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        
        let client = RpcClient::new(config.clone());
        
        assert_eq!(client.config.bitcoin_rpc_url, config.bitcoin_rpc_url);
        assert_eq!(client.config.metashrew_rpc_url, config.metashrew_rpc_url);
    }
}