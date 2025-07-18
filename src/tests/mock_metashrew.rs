//! Mock Metashrew server implementation for e2e testing
//!
//! This module provides a complete mock implementation of the Metashrew RPC interface
//! that can be used for end-to-end testing of the deezel CLI without requiring
//! a full metashrew indexer setup.

use anyhow::{Result, anyhow};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{info, debug, error};

use super::{TestState, get_test_state, MockUtxo};

/// Mock Metashrew RPC server
#[derive(Clone)]
pub struct MockMetashrewServer {
    /// Server listening address
    pub address: String,
    /// Server port
    pub port: u16,
    /// Test state reference
    pub state: Arc<Mutex<TestState>>,
}

impl MockMetashrewServer {
    /// Create a new mock metashrew server
    pub fn new(port: u16) -> Result<Self> {
        let state = get_test_state()?;
        Ok(Self {
            address: "127.0.0.1".to_string(),
            port,
            state,
        })
    }

    /// Start the mock server
    pub async fn start(&self) -> Result<()> {
        let addr = format!("{}:{}", self.address, self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Mock Metashrew server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    debug!("New connection from {}", addr);
                    let state = self.state.clone();
                    
                    tokio::spawn(async move {
                        let mut buffer = vec![0; 4096];
                        
                        match stream.read(&mut buffer).await {
                            Ok(n) => {
                                if n == 0 {
                                    debug!("Connection closed by peer");
                                    return;
                                }

                                let request = String::from_utf8_lossy(&buffer[..n]);
                                debug!("Received request: {}", request);
                                
                                let response = match Self::handle_request(&request, state).await {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        error!("Error handling request: {}", e);
                                        Self::error_response(-1, &format!("Internal error: {}", e))
                                    }
                                };
                                
                                let response_str = response.to_string();
                                let http_response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                                    response_str.len(),
                                    response_str
                                );
                                
                                if let Err(e) = stream.write_all(http_response.as_bytes()).await {
                                    error!("Failed to write response: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to read from stream: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle incoming RPC request
    async fn handle_request(request: &str, state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Parse HTTP request to extract JSON-RPC body
        let body = if let Some(body_start) = request.find("\r\n\r\n") {
            &request[body_start + 4..]
        } else {
            request
        };

        let rpc_request: Value = serde_json::from_str(body)
            .map_err(|e| anyhow!("Failed to parse JSON-RPC request: {}", e))?;

        let method = rpc_request["method"].as_str()
            .ok_or_else(|| anyhow!("Missing method in RPC request"))?;
        let params = &rpc_request["params"];
        let id = rpc_request["id"].as_u64().unwrap_or(1);

        debug!("Handling RPC method: {}", method);

        let result = match method {
            "metashrew_height" => Self::handle_metashrew_height(state).await,
            "metashrew_view" => Self::handle_metashrew_view(params, state).await,
            "spendablesbyaddress" => Self::handle_spendables_by_address(params, state).await,
            "alkanes_protorunesbyaddress" => Self::handle_protorunes_by_address(params, state).await,
            "alkanes_protorunesbyoutpoint" => Self::handle_protorunes_by_outpoint(params, state).await,
            "alkanes_trace" => Self::handle_trace(params, state).await,
            "alkanes_simulate" => Self::handle_simulate(params, state).await,
            "alkanes_meta" => Self::handle_meta(params, state).await,
            "esplora_gettransaction" => Self::handle_get_transaction(params, state).await,
            _ => Err(anyhow!("Unknown method: {}", method)),
        };

        match result {
            Ok(value) => Ok(json!({
                "jsonrpc": "2.0",
                "result": value,
                "id": id
            })),
            Err(e) => Ok(Self::error_response(id as i32, &e.to_string())),
        }
    }

    /// Handle metashrew_height method
    async fn handle_metashrew_height(state: Arc<Mutex<TestState>>) -> Result<Value> {
        let state_guard = state.lock().unwrap();
        Ok(json!(state_guard.height))
    }

    /// Handle metashrew_view method
    async fn handle_metashrew_view(params: &Value, state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("metashrew_view params must be an array"))?;

        if params_array.len() < 2 {
            return Err(anyhow!("metashrew_view requires at least 2 parameters"));
        }

        let view_method = params_array[0].as_str()
            .ok_or_else(|| anyhow!("First parameter must be view method name"))?;
        let hex_input = params_array[1].as_str()
            .ok_or_else(|| anyhow!("Second parameter must be hex input"))?;
        let _block_tag = params_array.get(2)
            .and_then(|v| v.as_str())
            .unwrap_or("latest");

        debug!("metashrew_view method: {}, input: {}", view_method, hex_input);

        match view_method {
            "getblock" => Self::handle_get_block(hex_input, state).await,
            "getbytecode" => Self::handle_get_bytecode(hex_input, state).await,
            "traceblock" => Self::handle_trace_block(hex_input, state).await,
            "spendablesbyaddress" => Self::handle_spendables_view(hex_input, state).await,
            "protorunesbyaddress" => Self::handle_protorunes_view(hex_input, state).await,
            "protorunesbyoutpoint" => Self::handle_protorunes_outpoint_view(hex_input, state).await,
            "trace" => Self::handle_trace_view(hex_input, state).await,
            _ => Err(anyhow!("Unknown view method: {}", view_method)),
        }
    }

    /// Handle spendablesbyaddress method
    async fn handle_spendables_by_address(params: &Value, state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("spendablesbyaddress params must be an array"))?;

        if params_array.is_empty() {
            return Err(anyhow!("spendablesbyaddress requires address parameter"));
        }

        let address = params_array[0].as_str()
            .ok_or_else(|| anyhow!("Address must be a string"))?;

        let state_guard = state.lock().unwrap();
        let utxos = state_guard.utxos.get(address).cloned().unwrap_or_default();

        // Convert UTXOs to the expected format
        let spendables: Vec<Value> = utxos.iter().map(|utxo| {
            json!({
                "txid": utxo.txid,
                "vout": utxo.vout,
                "amount": utxo.amount,
                "script_pubkey": utxo.script_pubkey,
                "confirmations": utxo.confirmations
            })
        }).collect();

        Ok(json!(spendables))
    }

    /// Handle protorunes by address
    async fn handle_protorunes_by_address(params: &Value, state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("alkanes_protorunesbyaddress params must be an array"))?;

        if params_array.is_empty() {
            return Err(anyhow!("alkanes_protorunesbyaddress requires address parameter"));
        }

        let address = params_array[0].as_str()
            .ok_or_else(|| anyhow!("Address must be a string"))?;

        let state_guard = state.lock().unwrap();
        let balances = state_guard.alkanes_balances.get(address).cloned().unwrap_or_default();

        // Convert to expected protorune format
        let protorunes: Vec<Value> = balances.iter().map(|(rune_id, amount)| {
            json!({
                "rune_id": rune_id,
                "amount": amount,
                "protocol_tag": 1 // DIESEL protocol tag
            })
        }).collect();

        Ok(json!(protorunes))
    }

    /// Handle protorunes by outpoint
    async fn handle_protorunes_by_outpoint(params: &Value, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("alkanes_protorunesbyoutpoint params must be an array"))?;

        if params_array.len() < 2 {
            return Err(anyhow!("alkanes_protorunesbyoutpoint requires txid and vout parameters"));
        }

        let _txid = params_array[0].as_str()
            .ok_or_else(|| anyhow!("Txid must be a string"))?;
        let _vout = params_array[1].as_u64()
            .ok_or_else(|| anyhow!("Vout must be a number"))?;

        // For now, return empty protorunes for any outpoint
        // In a real implementation, this would look up the specific outpoint
        Ok(json!([]))
    }

    /// Handle trace method
    async fn handle_trace(params: &Value, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("alkanes_trace params must be an array"))?;

        if params_array.len() < 2 {
            return Err(anyhow!("alkanes_trace requires txid and vout parameters"));
        }

        let _txid = params_array[0].as_str()
            .ok_or_else(|| anyhow!("Txid must be a string"))?;
        let _vout = params_array[1].as_u64()
            .ok_or_else(|| anyhow!("Vout must be a number"))?;

        // Return mock trace result for DIESEL minting
        Ok(json!({
            "success": true,
            "result": {
                "protocol_tag": 1,
                "message": [2, 0, 77], // DIESEL mint cellpack
                "amount": 50000000, // 0.5 DIESEL
                "pointer": 0
            }
        }))
    }

    /// Handle simulate method
    async fn handle_simulate(params: &Value, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        let _params_array = params.as_array()
            .ok_or_else(|| anyhow!("alkanes_simulate params must be an array"))?;

        // Return mock simulation result
        Ok(json!({
            "success": true,
            "gas_used": 21000,
            "result": "0x1"
        }))
    }

    /// Handle meta method
    async fn handle_meta(params: &Value, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("alkanes_meta params must be an array"))?;

        if params_array.len() < 2 {
            return Err(anyhow!("alkanes_meta requires block and tx parameters"));
        }

        let _block = params_array[0].as_str()
            .ok_or_else(|| anyhow!("Block must be a string"))?;
        let _tx = params_array[1].as_str()
            .ok_or_else(|| anyhow!("Tx must be a string"))?;

        // Return mock contract metadata
        Ok(json!({
            "name": "DIESEL Token",
            "symbol": "DIESEL",
            "decimals": 8,
            "total_supply": "21000000000000000"
        }))
    }

    /// Handle get transaction
    async fn handle_get_transaction(params: &Value, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        let params_array = params.as_array()
            .ok_or_else(|| anyhow!("esplora_gettransaction params must be an array"))?;

        if params_array.is_empty() {
            return Err(anyhow!("esplora_gettransaction requires txid parameter"));
        }

        let _txid = params_array[0].as_str()
            .ok_or_else(|| anyhow!("Txid must be a string"))?;

        // Return mock transaction hex
        Ok(json!("0100000001000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100e1f50500000000160014000000000000000000000000000000000000000000000000"))
    }

    /// Handle get block view
    async fn handle_get_block(hex_input: &str, state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Decode the hex input to get block request
        let hex_data = if hex_input.starts_with("0x") {
            &hex_input[2..]
        } else {
            hex_input
        };

        let _request_bytes = hex::decode(hex_data)
            .map_err(|e| anyhow!("Failed to decode hex input: {}", e))?;

        // For now, return a mock block response
        let state_guard = state.lock().unwrap();
        let _current_height = state_guard.height;

        // Create a mock block response
        let mock_block_data = vec![0u8; 80]; // Mock 80-byte block header
        let response_hex = format!("0x{}", hex::encode(mock_block_data));

        Ok(json!(response_hex))
    }

    /// Handle get bytecode view
    async fn handle_get_bytecode(_hex_input: &str, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Return mock DIESEL contract bytecode
        Ok(json!("0x608060405234801561001057600080fd5b50"))
    }

    /// Handle trace block view
    async fn handle_trace_block(_hex_input: &str, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Return mock trace block result
        Ok(json!({
            "traces": [],
            "block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "transactions": []
        }))
    }

    /// Handle spendables view
    async fn handle_spendables_view(hex_input: &str, state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Decode address from hex input
        let hex_data = if hex_input.starts_with("0x") {
            &hex_input[2..]
        } else {
            hex_input
        };

        let address_bytes = hex::decode(hex_data)
            .map_err(|e| anyhow!("Failed to decode address hex: {}", e))?;
        let address = String::from_utf8_lossy(&address_bytes);

        Self::handle_spendables_by_address(&json!([address]), state).await
    }

    /// Handle protorunes view
    async fn handle_protorunes_view(hex_input: &str, state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Decode address from hex input
        let hex_data = if hex_input.starts_with("0x") {
            &hex_input[2..]
        } else {
            hex_input
        };

        let address_bytes = hex::decode(hex_data)
            .map_err(|e| anyhow!("Failed to decode address hex: {}", e))?;
        let address = String::from_utf8_lossy(&address_bytes);

        Self::handle_protorunes_by_address(&json!([address]), state).await
    }

    /// Handle protorunes outpoint view
    async fn handle_protorunes_outpoint_view(_hex_input: &str, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Return empty protorunes for any outpoint in view mode
        Ok(json!([]))
    }

    /// Handle trace view
    async fn handle_trace_view(_hex_input: &str, _state: Arc<Mutex<TestState>>) -> Result<Value> {
        // Return mock trace result
        Ok(json!({
            "success": true,
            "result": {
                "protocol_tag": 1,
                "message": [2, 0, 77],
                "amount": 50000000,
                "pointer": 0
            }
        }))
    }

    /// Create an error response
    fn error_response(id: i32, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -1,
                "message": message
            },
            "id": id
        })
    }
}

/// Helper functions for setting up test data

/// Add mock UTXOs for an address
pub fn add_mock_utxos(address: &str, utxos: Vec<MockUtxo>) -> Result<()> {
    let state = get_test_state()?;
    let mut state_guard = state.lock().unwrap();
    state_guard.utxos.insert(address.to_string(), utxos);
    Ok(())
}

/// Add mock protorune balance for an address
pub fn add_mock_protorune_balance(address: &str, rune_id: &str, amount: u64) -> Result<()> {
    let state = get_test_state()?;
    let mut state_guard = state.lock().unwrap();
    
    let balances = state_guard.alkanes_balances
        .entry(address.to_string())
        .or_insert_with(HashMap::new);
    balances.insert(rune_id.to_string(), amount);
    
    Ok(())
}

/// Set mock block height
pub fn set_mock_height(height: u32) -> Result<()> {
    let state = get_test_state()?;
    let mut state_guard = state.lock().unwrap();
    state_guard.height = height;
    Ok(())
}

/// Create a vector of mock UTXOs for testing
pub fn create_test_utxos(address: &str, count: u32) -> Vec<MockUtxo> {
    (0..count).map(|i| MockUtxo {
        txid: format!("f00d_txid_{}", i),
        vout: i,
        amount: 100000 + (i as u64 * 10000),
        script_pubkey: address.to_string(), // Simplified for testing
        confirmations: 1,
    }).collect()
}