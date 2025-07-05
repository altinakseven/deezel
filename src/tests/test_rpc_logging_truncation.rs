//! Test for RPC logging truncation functionality
//! 
//! This test verifies that large JSON RPC responses are properly truncated
//! in debug logging to prevent log spam while preserving important information.

use crate::rpc::{RpcClient, RpcConfig};
use serde_json::{json, Value};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the truncation helper functions work correctly
    #[test]
    fn test_json_truncation_for_logging() {
        let config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:8080".to_string(), // FIXED: Use Sandshrew endpoint
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        let client = RpcClient::new(config);

        // Test small JSON (should not be truncated)
        let small_json = json!({
            "method": "test",
            "params": [1, 2, 3],
            "id": 1
        });
        let result = client.truncate_json_for_logging(&small_json);
        assert!(result.contains("\"method\": \"test\""));
        assert!(result.len() < 2000); // Should be well under the limit

        // Test large array (should be truncated)
        let large_array: Vec<Value> = (0..1000).map(|i| json!({"utxo": i, "amount": 50000})).collect();
        let large_json = json!({
            "result": large_array,
            "id": 1
        });
        let result = client.truncate_json_for_logging(&large_json);
        assert!(result.contains("_truncated"));
        assert!(result.contains("Array with 1000 elements"));
        
        // Test large string (should be truncated)
        let large_string = "x".repeat(5000);
        let large_string_json = json!({
            "result": large_string,
            "id": 1
        });
        let result = client.truncate_json_for_logging(&large_string_json);
        assert!(result.contains("_truncated"));
        assert!(result.contains("String with 5000 chars"));
    }

    /// Test that RPC response truncation preserves error information
    #[test]
    fn test_rpc_response_truncation_preserves_errors() {
        let config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:8080".to_string(), // FIXED: Use Sandshrew endpoint
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        let client = RpcClient::new(config);

        // Create a mock RPC response with error (should not be truncated)
        let error_response = crate::rpc::RpcResponse {
            result: None,
            error: Some(crate::rpc::RpcError {
                code: -1,
                message: "Test error message".to_string(),
            }),
            id: 1,
        };
        
        let result = client.truncate_rpc_response_for_logging(&error_response);
        assert!(result.contains("Test error message"));
        assert!(!result.contains("_truncated")); // Errors should not be truncated
    }

    /// Test that the MAX_LOG_SIZE constant is reasonable
    #[test]
    fn test_max_log_size_constant() {
        // Verify that the MAX_LOG_SIZE is set to a reasonable value
        assert_eq!(RpcClient::MAX_LOG_SIZE, 2000);
        
        // This should be large enough for normal responses but small enough
        // to prevent log spam from large UTXO responses
        assert!(RpcClient::MAX_LOG_SIZE > 500);  // Large enough for normal responses
        assert!(RpcClient::MAX_LOG_SIZE < 10000); // Small enough to prevent spam
    }
}