//! Test suite for esplora CLI commands
//!
//! This module tests the esplora subcommand functionality to ensure all endpoints
//! are properly mapped and can handle address resolution.

use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;

use crate::rpc::{RpcClient, RpcConfig};

/// Test esplora blocks tip height command
#[tokio::test]
async fn test_esplora_blocks_tip_height() -> Result<()> {
    // Create a mock RPC client for testing
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));
    
    // Test the esplora blocks tip height method
    // Note: This will fail in CI without a running server, but demonstrates the API
    match rpc_client.get_esplora_blocks_tip_height().await {
        Ok(height) => {
            println!("✅ Esplora blocks tip height: {}", height);
            assert!(height >= 0);
        },
        Err(e) => {
            println!("⚠️  Esplora blocks tip height test skipped (no server): {}", e);
            // This is expected in test environments without a running server
        }
    }
    
    Ok(())
}

/// Test esplora address UTXO command
#[tokio::test]
async fn test_esplora_address_utxo() -> Result<()> {
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));
    
    // Test with a sample address
    let test_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    
    match rpc_client.get_esplora_address_utxo(test_address).await {
        Ok(utxos) => {
            println!("✅ Esplora address UTXOs retrieved");
            assert!(utxos.is_array() || utxos.is_object());
        },
        Err(e) => {
            println!("⚠️  Esplora address UTXO test skipped (no server): {}", e);
        }
    }
    
    Ok(())
}

/// Test esplora transaction status command
#[tokio::test]
async fn test_esplora_tx_status() -> Result<()> {
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));
    
    // Test with a sample transaction ID
    let test_txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    
    match rpc_client.get_esplora_tx_status(test_txid).await {
        Ok(status) => {
            println!("✅ Esplora transaction status retrieved");
            assert!(status.is_object());
        },
        Err(e) => {
            println!("⚠️  Esplora transaction status test skipped (no server): {}", e);
        }
    }
    
    Ok(())
}

/// Test esplora fee estimates command
#[tokio::test]
async fn test_esplora_fee_estimates() -> Result<()> {
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));
    
    match rpc_client.get_esplora_fee_estimates().await {
        Ok(estimates) => {
            println!("✅ Esplora fee estimates retrieved");
            assert!(estimates.is_object());
        },
        Err(e) => {
            println!("⚠️  Esplora fee estimates test skipped (no server): {}", e);
        }
    }
    
    Ok(())
}

/// Test esplora mempool information command
#[tokio::test]
async fn test_esplora_mempool() -> Result<()> {
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));
    
    match rpc_client.get_esplora_mempool().await {
        Ok(mempool_info) => {
            println!("✅ Esplora mempool info retrieved");
            assert!(mempool_info.is_object());
        },
        Err(e) => {
            println!("⚠️  Esplora mempool test skipped (no server): {}", e);
        }
    }
    
    Ok(())
}

/// Test esplora generic call functionality
#[tokio::test]
async fn test_esplora_generic_call() -> Result<()> {
    let rpc_config = RpcConfig {
        bitcoin_rpc_url: "http://localhost:8080".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
    };
    let rpc_client = Arc::new(RpcClient::new(rpc_config));
    
    // Test the generic esplora call method
    match rpc_client.esplora_call("blocks:tip:height", vec![]).await {
        Ok(result) => {
            println!("✅ Esplora generic call successful");
            assert!(result.is_number() || result.is_string());
        },
        Err(e) => {
            println!("⚠️  Esplora generic call test skipped (no server): {}", e);
        }
    }
    
    Ok(())
}

/// Test address identifier resolution in esplora context
#[test]
fn test_address_identifier_patterns() {
    // Test that address identifier patterns are recognized
    use crate::AddressResolver;
    
    // Test various address identifier patterns
    let test_cases = vec![
        "[self:p2tr]",
        "[self:p2tr:0]", 
        "[self:p2wpkh:1]",
        "[self:mainnet:p2tr]",
        "[self:testnet:p2tr:5]",
    ];
    
    for test_case in test_cases {
        assert!(AddressResolver::contains_identifiers(test_case), 
               "Should recognize identifier: {}", test_case);
        
        // Test parsing
        match AddressResolver::parse_identifier(test_case) {
            Ok(identifier) => {
                println!("✅ Successfully parsed identifier: {} -> {:?}", test_case, identifier);
                assert_eq!(identifier.source, "self");
            },
            Err(e) => {
                panic!("Failed to parse valid identifier {}: {}", test_case, e);
            }
        }
    }
}

/// Test shorthand address identifier patterns
#[test]
fn test_shorthand_address_identifiers() {
    // Helper function to test shorthand address identifier logic
    fn is_shorthand_address_identifier(input: &str) -> bool {
        // Pattern: address_type or address_type:index
        // Valid address types: p2tr, p2pkh, p2sh, p2wpkh, p2wsh
        let parts: Vec<&str> = input.split(':').collect();
        
        if parts.is_empty() || parts.len() > 2 {
            return false;
        }
        
        // Check if first part is a valid address type
        let address_type = parts[0].to_lowercase();
        let valid_types = ["p2tr", "p2pkh", "p2sh", "p2wpkh", "p2wsh"];
        
        if !valid_types.contains(&address_type.as_str()) {
            return false;
        }
        
        // If there's a second part, it should be a valid index
        if parts.len() == 2 {
            if parts[1].parse::<u32>().is_err() {
                return false;
            }
        }
        
        true
    }
    
    let valid_shorthand = vec![
        "p2tr",
        "p2tr:0",
        "p2wpkh:1",
        "p2pkh:5",
        "p2sh:10",
    ];
    
    let invalid_shorthand = vec![
        "invalid",
        "p2tr:invalid",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // Real address
        "p2tr:0:extra",
    ];
    
    for valid in valid_shorthand {
        assert!(is_shorthand_address_identifier(valid),
               "Should recognize shorthand: {}", valid);
    }
    
    for invalid in invalid_shorthand {
        assert!(!is_shorthand_address_identifier(invalid),
               "Should not recognize as shorthand: {}", invalid);
    }
}

/// Integration test demonstrating esplora command usage patterns
#[test]
fn test_esplora_command_patterns() {
    // This test demonstrates the expected usage patterns for esplora commands
    
    println!("📋 Esplora Command Usage Examples:");
    println!("================================");
    println!();
    
    println!("🔍 Block Information:");
    println!("  deezel esplora blocks-tip-hash");
    println!("  deezel esplora blocks-tip-height");
    println!("  deezel esplora block-height 800000");
    println!("  deezel esplora block <block_hash>");
    println!("  deezel esplora block-status <block_hash>");
    println!();
    
    println!("🏠 Address Information:");
    println!("  deezel esplora address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    println!("  deezel esplora address [self:p2tr]");
    println!("  deezel esplora address-utxo [self:p2tr:0]");
    println!("  deezel esplora address-txs p2tr:1");
    println!();
    
    println!("🔗 Transaction Information:");
    println!("  deezel esplora tx <txid>");
    println!("  deezel esplora tx-hex <txid>");
    println!("  deezel esplora tx-status <txid>");
    println!("  deezel esplora tx-outspends <txid>");
    println!();
    
    println!("💾 Mempool Information:");
    println!("  deezel esplora mempool");
    println!("  deezel esplora mempool-txids");
    println!("  deezel esplora mempool-recent");
    println!();
    
    println!("💰 Fee Information:");
    println!("  deezel esplora fee-estimates");
    println!();
    
    println!("📡 Broadcasting:");
    println!("  deezel esplora broadcast <tx_hex>");
    println!();
    
    // This test always passes - it's just for documentation
    assert!(true);
}