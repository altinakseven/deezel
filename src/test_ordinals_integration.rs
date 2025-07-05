//! Test ordinals crate integration for runestone construction
//!
//! This test verifies that we're properly using the ordinals crate
//! to construct runestones with protocol field support for protostones.

use anyhow::Result;
use bitcoin::{Transaction, TxOut, Amount};
use ordinals::Runestone;
use alkanes_support::cellpack::Cellpack;
use alkanes_support::id::AlkaneId;

#[tokio::test]
async fn test_ordinals_runestone_construction() -> Result<()> {
    // Create a test cellpack
    let cellpack = Cellpack {
        target: AlkaneId { block: 3, tx: 797 },
        inputs: vec![101],
    };
    
    // Encode the cellpack using LEB128
    let cellpack_bytes = cellpack.encipher();
    println!("Cellpack encoded to {} bytes: {}", cellpack_bytes.len(), hex::encode(&cellpack_bytes));
    
    // Convert cellpack bytes to u128 values for protocol field
    let mut protocol_data = Vec::<u128>::new();
    let mut i = 0;
    while i < cellpack_bytes.len() {
        let (value, length) = ordinals::varint::decode(&cellpack_bytes[i..])
            .expect("Failed to decode LEB128 varint from cellpack");
        protocol_data.push(value);
        i += length;
    }
    
    println!("Protocol field contains {} u128 values: {:?}", protocol_data.len(), protocol_data);
    
    // Create runestone with protocol field
    let runestone = Runestone {
        edicts: Vec::new(),
        etching: None,
        mint: None,
        pointer: None,
        protocol: Some(protocol_data.clone()),
    };
    
    // Encode the runestone using ordinals crate
    let script = runestone.encipher();
    println!("Runestone script: {} bytes", script.len());
    println!("Script hex: {}", hex::encode(script.as_bytes()));
    
    // Verify the script starts with OP_RETURN and OP_13 (magic number)
    let script_bytes = script.as_bytes();
    assert!(script_bytes.len() >= 2, "Script should have at least OP_RETURN and magic number");
    assert_eq!(script_bytes[0], 0x6a, "First byte should be OP_RETURN (0x6a)");
    assert_eq!(script_bytes[1], 0x5d, "Second byte should be OP_13 (0x5d) - runestone magic");
    
    // Create a test transaction with the runestone
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }],
    };
    
    // Try to decode the runestone back from the transaction
    if let Some(artifact) = Runestone::decipher(&tx) {
        match artifact {
            ordinals::Artifact::Runestone(decoded_runestone) => {
                println!("Successfully decoded runestone!");
                println!("Protocol field: {:?}", decoded_runestone.protocol);
                
                // Verify the protocol field matches what we encoded
                assert_eq!(decoded_runestone.protocol, Some(protocol_data.clone()));
                println!("✅ Protocol field matches original data");
            },
            ordinals::Artifact::Cenotaph(cenotaph) => {
                panic!("Runestone was decoded as cenotaph: {:?}", cenotaph);
            }
        }
    } else {
        panic!("Failed to decode runestone from transaction");
    }
    
    println!("✅ Ordinals crate integration test passed!");
    Ok(())
}

#[tokio::test]
async fn test_cellpack_encoding() -> Result<()> {
    // Test the cellpack encoding directly
    let cellpack = Cellpack {
        target: AlkaneId { block: 2, tx: 0 },
        inputs: vec![1000],
    };
    
    // Test the to_vec method
    let vec_data = cellpack.to_vec();
    println!("Cellpack as Vec<u128>: {:?}", vec_data);
    assert_eq!(vec_data, vec![2, 0, 1000]);
    
    // Test the encipher method (LEB128 encoding)
    let encoded = cellpack.encipher();
    println!("Cellpack LEB128 encoded: {} bytes: {}", encoded.len(), hex::encode(&encoded));
    
    // Verify we can decode it back
    let mut decoded_values = Vec::new();
    let mut i = 0;
    while i < encoded.len() {
        let (value, length) = ordinals::varint::decode(&encoded[i..])
            .expect("Failed to decode LEB128 varint");
        decoded_values.push(value);
        i += length;
    }
    
    println!("Decoded values: {:?}", decoded_values);
    assert_eq!(decoded_values, vec_data);
    
    println!("✅ Cellpack encoding test passed!");
    Ok(())
}

#[tokio::test]
async fn test_empty_runestone() -> Result<()> {
    // Test creating an empty runestone (no protocol field)
    let runestone = Runestone {
        edicts: Vec::new(),
        etching: None,
        mint: None,
        pointer: None,
        protocol: None,
    };
    
    let script = runestone.encipher();
    println!("Empty runestone script: {} bytes: {}", script.len(), hex::encode(script.as_bytes()));
    
    // Should be minimal: OP_RETURN + OP_13
    assert_eq!(script.len(), 2);
    
    // Create transaction and decode
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }],
    };
    
    if let Some(artifact) = Runestone::decipher(&tx) {
        match artifact {
            ordinals::Artifact::Runestone(decoded_runestone) => {
                assert_eq!(decoded_runestone.protocol, None);
                println!("✅ Empty runestone decoded correctly");
            },
            ordinals::Artifact::Cenotaph(cenotaph) => {
                panic!("Empty runestone was decoded as cenotaph: {:?}", cenotaph);
            }
        }
    } else {
        panic!("Failed to decode empty runestone");
    }
    
    println!("✅ Empty runestone test passed!");
    Ok(())
}