//! Demonstration of RPC logging truncation functionality
//! 
//! This demo shows how large JSON RPC responses are truncated in debug logging
//! to prevent log spam while preserving important structural information.

use crate::rpc::{RpcClient, RpcConfig};
use serde_json::{json, Value};

/// Demo function to show truncation in action
pub fn demo_rpc_truncation() {
    println!("=== RPC Logging Truncation Demo ===\n");
    
    let config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(), // FIXED: Use Sandshrew endpoint
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let client = RpcClient::new(config);

    // Demo 1: Small response (not truncated)
    println!("1. Small JSON response (not truncated):");
    let small_response = json!({
        "method": "getblockcount",
        "result": 840000,
        "id": 1
    });
    let truncated = client.truncate_json_for_logging(&small_response);
    println!("{}\n", truncated);

    // Demo 2: Large array response (truncated)
    println!("2. Large UTXO array response (truncated):");
    let large_utxos: Vec<Value> = (0..500).map(|i| json!({
        "txid": format!("abcd{:04x}ef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", i),
        "vout": i % 4,
        "amount": 50000 + (i * 1000),
        "script_pubkey": format!("76a914{:040x}88ac", i),
        "confirmations": 6
    })).collect();
    
    let large_response = json!({
        "result": large_utxos,
        "id": 1
    });
    let truncated = client.truncate_json_for_logging(&large_response);
    println!("{}\n", truncated);

    // Demo 3: Large string response (truncated)
    println!("3. Large string response (truncated):");
    let large_string = "a".repeat(3000);
    let string_response = json!({
        "result": large_string,
        "id": 1
    });
    let truncated = client.truncate_json_for_logging(&string_response);
    println!("{}\n", truncated);

    // Demo 4: Error response (never truncated)
    println!("4. Error response (never truncated):");
    let error_response = crate::rpc::RpcResponse {
        result: None,
        error: Some(crate::rpc::RpcError {
            code: -32601,
            message: "Method not found: this is a detailed error message that explains what went wrong and provides debugging information".to_string(),
        }),
        id: 1,
    };
    let truncated = client.truncate_rpc_response_for_logging(&error_response);
    println!("{}\n", truncated);

    println!("=== Demo Complete ===");
    println!("Max log size limit: {} characters", RpcClient::MAX_LOG_SIZE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demo_runs_without_panic() {
        // Just ensure the demo runs without panicking
        demo_rpc_truncation();
    }
}