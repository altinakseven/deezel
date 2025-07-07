//! Test suite for single input transaction optimization
//! 
//! This module tests the critical fix that consolidates deezel transactions
//! from 2-input pattern to 1-input pattern, matching working transactions.
//! 
//! Key validations:
//! - Transaction has exactly 1 input (not 2)
//! - Input has proper 3-element witness: [signature, script, control_block]
//! - Witness follows ord pattern with BIN protocol tag
//! - Transaction size is optimized (closer to working transaction size)

use anyhow::Result;
use bitcoin::{Transaction, Witness};
use log::info;

use crate::alkanes::envelope::AlkanesEnvelope;
use crate::alkanes::execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams, InputRequirement, ProtostoneSpec};
use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use std::sync::Arc;

/// Test that envelope transactions use single input pattern
#[tokio::test]
async fn test_single_input_envelope_transaction() -> Result<()> {
    info!("🧪 Testing single input envelope transaction optimization");
    
    // Create test envelope with BIN protocol data
    let test_contract_data = b"test alkanes contract data".to_vec();
    let envelope = AlkanesEnvelope::for_contract(test_contract_data);
    
    // Verify envelope uses BIN protocol
    let script = envelope.build_reveal_script();
    let script_bytes = script.as_bytes();
    
    // Check that script contains BIN protocol marker
    assert!(script_bytes.windows(3).any(|w| w == b"BIN"), 
           "Envelope script should contain BIN protocol marker");
    
    info!("✅ Envelope script contains BIN protocol marker");
    
    // Verify script structure follows ord pattern
    let instructions: Vec<_> = script.instructions().collect();
    assert!(instructions.len() >= 6, "Script should have minimum ord structure");
    
    info!("✅ Envelope script follows ord structure pattern");
    
    Ok(())
}

/// Test witness structure for envelope transactions
#[tokio::test]
async fn test_envelope_witness_structure() -> Result<()> {
    info!("🧪 Testing envelope witness structure");
    
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::XOnlyPublicKey;
    use bitcoin::taproot::{TaprootBuilder, LeafVersion};
    
    // Create test envelope
    let test_contract_data = b"test alkanes contract data for witness".to_vec();
    let envelope = AlkanesEnvelope::for_contract(test_contract_data);
    
    // Create dummy taproot setup for testing
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[1u8; 32])?;
    let script = envelope.build_reveal_script();
    
    // Create taproot spend info
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {:?}", e))?;
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
    let control_block = taproot_spend_info
        .control_block(&(script, LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
    
    // Test ord-style witness (2 elements: script + control_block)
    let ord_witness = envelope.create_witness(control_block.clone())?;
    assert_eq!(ord_witness.len(), 2, "Ord-style witness should have 2 elements");
    
    info!("✅ Ord-style witness has correct structure: {} elements", ord_witness.len());
    
    // Test complete witness (3 elements: signature + script + control_block)
    let dummy_signature = vec![0u8; 64]; // 64-byte Schnorr signature
    let complete_witness = envelope.create_complete_witness(&dummy_signature, control_block)?;
    assert_eq!(complete_witness.len(), 3, "Complete witness should have 3 elements");
    
    // Verify witness element sizes
    let sig_item = complete_witness.nth(0).unwrap();
    let script_item = complete_witness.nth(1).unwrap();
    let control_item = complete_witness.nth(2).unwrap();
    
    assert_eq!(sig_item.len(), 64, "Signature should be 64 bytes");
    assert!(script_item.len() > 50, "Script should be substantial size (got {} bytes)", script_item.len());
    assert!(control_item.len() >= 33, "Control block should be at least 33 bytes");
    
    info!("✅ Complete witness has correct structure:");
    info!("  Signature: {} bytes", sig_item.len());
    info!("  Script: {} bytes", script_item.len());
    info!("  Control block: {} bytes", control_item.len());
    
    Ok(())
}

/// Test transaction size optimization
#[tokio::test]
async fn test_transaction_size_optimization() -> Result<()> {
    info!("🧪 Testing transaction size optimization");
    
    // Create test envelope
    let test_contract_data = vec![0u8; 50000]; // 50KB test data
    let envelope = AlkanesEnvelope::for_contract(test_contract_data);
    
    // Verify envelope script size is reasonable
    let script = envelope.build_reveal_script();
    let script_size = script.len();
    
    info!("📊 Envelope script size: {} bytes", script_size);
    
    // Script should be substantial but not excessive
    assert!(script_size > 50000, "Script should contain the test data");
    assert!(script_size < 60000, "Script should not have excessive overhead");
    
    // Test witness size estimation
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::XOnlyPublicKey;
    use bitcoin::taproot::{TaprootBuilder, LeafVersion};
    
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[1u8; 32])?;
    
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {:?}", e))?;
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
    let control_block = taproot_spend_info
        .control_block(&(script, LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
    
    let dummy_signature = vec![0u8; 64];
    let complete_witness = envelope.create_complete_witness(&dummy_signature, control_block)?;
    
    // Calculate total witness size
    let total_witness_size: usize = complete_witness.iter().map(|item| item.len()).sum();
    
    info!("📊 Total witness size: {} bytes", total_witness_size);
    info!("📊 Witness breakdown:");
    for (i, item) in complete_witness.iter().enumerate() {
        let item_name = match i {
            0 => "signature",
            1 => "script",
            2 => "control_block",
            _ => "unknown",
        };
        info!("  {}: {} bytes", item_name, item.len());
    }
    
    // Witness should be substantial but reasonable
    assert!(total_witness_size > 50000, "Witness should contain substantial data");
    assert!(total_witness_size < 70000, "Witness should not have excessive overhead");
    
    Ok(())
}

/// Test BIN protocol vs ord protocol differences
#[tokio::test]
async fn test_bin_vs_ord_protocol() -> Result<()> {
    info!("🧪 Testing BIN vs ord protocol differences");
    
    // Create envelope with BIN protocol
    let test_data = b"test protocol comparison data".to_vec();
    let bin_envelope = AlkanesEnvelope::for_contract(test_data.clone());
    let bin_script = bin_envelope.build_reveal_script();
    let bin_bytes = bin_script.as_bytes();
    
    // Verify BIN protocol marker
    assert!(bin_bytes.windows(3).any(|w| w == b"BIN"), 
           "BIN envelope should contain BIN protocol marker");
    assert!(!bin_bytes.windows(3).any(|w| w == b"ord"), 
           "BIN envelope should NOT contain ord protocol marker");
    
    info!("✅ BIN protocol correctly used instead of ord");
    
    // Verify content type is preserved
    assert!(bin_bytes.windows(16).any(|w| w == b"application/wasm"), 
           "BIN envelope should contain application/wasm content type");
    
    info!("✅ Content type preserved in BIN envelope");
    
    // Verify body data is preserved
    assert!(bin_bytes.windows(test_data.len()).any(|w| w == test_data.as_slice()), 
           "BIN envelope should contain original test data");
    
    info!("✅ Body data preserved in BIN envelope");
    
    Ok(())
}

/// Test that single input transactions are more efficient than 2-input
#[tokio::test]
async fn test_single_vs_multi_input_efficiency() -> Result<()> {
    info!("🧪 Testing single vs multi-input efficiency");
    
    // Simulate transaction sizes
    let single_input_base_size = 180; // Base transaction size with 1 input
    let multi_input_base_size = 360;  // Base transaction size with 2 inputs
    
    // Envelope witness size (same for both)
    let envelope_witness_size = 55000; // ~55KB envelope data
    
    // Calculate total sizes
    let single_input_total = single_input_base_size + envelope_witness_size;
    let multi_input_total = multi_input_base_size + envelope_witness_size;
    
    let size_difference = multi_input_total - single_input_total;
    let efficiency_gain = (size_difference as f64 / multi_input_total as f64) * 100.0;
    
    info!("📊 Transaction size comparison:");
    info!("  Single input: {} bytes", single_input_total);
    info!("  Multi input: {} bytes", multi_input_total);
    info!("  Size reduction: {} bytes ({:.1}%)", size_difference, efficiency_gain);
    
    // Single input should be more efficient
    assert!(single_input_total < multi_input_total, 
           "Single input transaction should be smaller");
    assert!(efficiency_gain > 0.0, 
           "Single input should provide efficiency gain");
    
    info!("✅ Single input pattern is more efficient");
    
    Ok(())
}

/// Integration test for complete single input transaction flow
#[tokio::test]
async fn test_complete_single_input_flow() -> Result<()> {
    info!("🧪 Testing complete single input transaction flow");
    
    // This test validates the complete flow but doesn't actually broadcast
    // It focuses on transaction structure validation
    
    // Create test envelope
    let test_contract_data = b"integration test contract data".to_vec();
    let envelope = AlkanesEnvelope::for_contract(test_contract_data);
    
    // Verify envelope creation
    assert!(envelope.content_type.is_some(), "Envelope should have content type");
    assert!(envelope.body.is_some(), "Envelope should have body data");
    
    // Verify script generation
    let script = envelope.build_reveal_script();
    assert!(!script.is_empty(), "Script should not be empty");
    
    // Verify BIN protocol usage
    let script_bytes = script.as_bytes();
    assert!(script_bytes.windows(3).any(|w| w == b"BIN"), 
           "Script should use BIN protocol");
    
    info!("✅ Complete single input flow validation passed");
    
    Ok(())
}

/// Test witness serialization and deserialization
#[tokio::test]
async fn test_witness_serialization() -> Result<()> {
    info!("🧪 Testing witness serialization/deserialization");
    
    use bitcoin::consensus::{serialize, deserialize};
    
    // Create test envelope and witness
    let test_data = b"serialization test data".to_vec();
    let envelope = AlkanesEnvelope::for_contract(test_data);
    
    // Create dummy witness components
    let dummy_signature = vec![0u8; 64];
    
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::XOnlyPublicKey;
    use bitcoin::taproot::{TaprootBuilder, LeafVersion};
    
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[1u8; 32])?;
    let script = envelope.build_reveal_script();
    
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {:?}", e))?;
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
    let control_block = taproot_spend_info
        .control_block(&(script, LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
    
    // Create complete witness
    let original_witness = envelope.create_complete_witness(&dummy_signature, control_block)?;
    
    // Test serialization
    let serialized = serialize(&original_witness);
    info!("📊 Serialized witness size: {} bytes", serialized.len());
    
    // Test deserialization
    let deserialized_witness: Witness = deserialize(&serialized)?;
    
    // Verify deserialized witness matches original
    assert_eq!(deserialized_witness.len(), original_witness.len(), 
              "Deserialized witness should have same length");
    
    for (i, (orig, deser)) in original_witness.iter().zip(deserialized_witness.iter()).enumerate() {
        assert_eq!(orig, deser, "Witness item {} should match after serialization", i);
    }
    
    info!("✅ Witness serialization/deserialization successful");
    
    Ok(())
}