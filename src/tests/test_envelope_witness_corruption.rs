//! Test suite for envelope witness data corruption issue
//! 
//! This test reproduces the issue where envelope witness data (118KB+) is created correctly
//! but gets corrupted to only 2 bytes during transaction serialization/deserialization.
//! 
//! The issue manifests as:
//! - Witness is created correctly with proper data (118535 + 33 bytes)
//! - All verification checks pass
//! - Serialization/deserialization test passes
//! - But final transaction shows "Input 0 witness: 2 bytes (2 items)" instead of ~118KB
//! - Bitcoin Core rejects with "Witness program was passed an empty witness"

use anyhow::Result;
use bitcoin::{
    consensus::{deserialize, serialize},
    script::Builder as ScriptBuilder,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    secp256k1::{rand, Secp256k1},
    OutPoint, ScriptBuf, Amount,
};
use crate::alkanes::envelope::AlkanesEnvelope;

/// Test data for envelope witness corruption
struct TestEnvelopeData {
    envelope: AlkanesEnvelope,
    internal_key: XOnlyPublicKey,
    control_block: ControlBlock,
    reveal_script: ScriptBuf,
}

impl TestEnvelopeData {
    /// Create test envelope data with realistic contract size
    fn new() -> Result<Self> {
        // Create a realistic contract size (similar to free_mint.wasm.gz)
        let contract_data = vec![0u8; 100_000]; // 100KB contract
        let envelope = AlkanesEnvelope::for_contract(contract_data);
        
        // Generate test internal key
        let secp = Secp256k1::new();
        let (_, internal_key) = secp.generate_keypair(&mut rand::thread_rng());
        let internal_key = XOnlyPublicKey::from(internal_key);
        
        // Build reveal script
        let reveal_script = envelope.build_reveal_script();
        
        // Create taproot spend info and control block
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())?;
        
        let taproot_spend_info = taproot_builder
            .finalize(&secp, internal_key)
            .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
        
        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
        
        Ok(Self {
            envelope,
            internal_key,
            control_block,
            reveal_script,
        })
    }
}

fn test_envelope_witness_creation() -> Result<()> {
    let test_data = TestEnvelopeData::new()?;
    
    // Create envelope witness
    let witness = test_data.envelope.create_witness(test_data.control_block.clone())?;
    
    // Verify witness structure
    assert_eq!(witness.len(), 2, "Envelope witness should have exactly 2 items");
    
    // Verify script item (first item)
    let script_item = witness.nth(0).expect("Script item should exist");
    assert!(!script_item.is_empty(), "Script item should not be empty");
    assert!(script_item.len() > 100_000, "Script item should be large (>100KB)");
    
    // Verify control block item (second item)
    let control_block_item = witness.nth(1).expect("Control block item should exist");
    assert!(!control_block_item.is_empty(), "Control block item should not be empty");
    assert_eq!(control_block_item.len(), 33, "Control block should be 33 bytes");
    
    println!("✅ Envelope witness created successfully:");
    println!("  Script item: {} bytes", script_item.len());
    println!("  Control block item: {} bytes", control_block_item.len());
    
    Ok(())
}

fn test_witness_serialization_preservation() -> Result<()> {
    let test_data = TestEnvelopeData::new()?;
    
    // Create envelope witness
    let original_witness = test_data.envelope.create_witness(test_data.control_block.clone())?;
    
    // Test direct witness serialization
    let witness_bytes = original_witness.to_vec();
    let reconstructed_witness = Witness::from_slice(&witness_bytes);
    
    // Verify reconstruction preserves data
    assert_eq!(reconstructed_witness.len(), original_witness.len());
    
    for (i, (original_item, reconstructed_item)) in original_witness.iter().zip(reconstructed_witness.iter()).enumerate() {
        assert_eq!(original_item.len(), reconstructed_item.len(), "Item {} size mismatch", i);
        assert_eq!(original_item, reconstructed_item, "Item {} content mismatch", i);
    }
    
    println!("✅ Direct witness serialization preserves data correctly");
    
    Ok(())
}

fn test_transaction_witness_corruption_issue() -> Result<()> {
    let test_data = TestEnvelopeData::new()?;
    
    // Create a test transaction with envelope witness
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    // Create envelope witness
    let envelope_witness = test_data.envelope.create_witness(test_data.control_block.clone())?;
    
    println!("🔍 Original envelope witness:");
    println!("  Items: {}", envelope_witness.len());
    for (i, item) in envelope_witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // Method 1: Direct assignment (this might be where corruption occurs)
    println!("\n🧪 Testing Method 1: Direct witness assignment");
    tx.input[0].witness = envelope_witness.clone();
    
    println!("After direct assignment:");
    println!("  Items: {}", tx.input[0].witness.len());
    for (i, item) in tx.input[0].witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // Test serialization of transaction with direct assignment
    let serialized_tx = serialize(&tx);
    let deserialized_tx: Transaction = deserialize(&serialized_tx)?;
    
    println!("After transaction serialization/deserialization:");
    println!("  Items: {}", deserialized_tx.input[0].witness.len());
    for (i, item) in deserialized_tx.input[0].witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // Check if data was corrupted
    let is_corrupted = deserialized_tx.input[0].witness.iter()
        .zip(envelope_witness.iter())
        .any(|(deserialized_item, original_item)| {
            deserialized_item.len() != original_item.len() || deserialized_item != original_item
        });
    
    if is_corrupted {
        println!("❌ CORRUPTION DETECTED: Transaction serialization corrupted witness data");
        
        // Analyze the corruption
        for (i, (deserialized_item, original_item)) in deserialized_tx.input[0].witness.iter()
            .zip(envelope_witness.iter()).enumerate() {
            if deserialized_item.len() != original_item.len() {
                println!("  Item {} size changed: {} -> {} bytes", i, original_item.len(), deserialized_item.len());
            }
            if deserialized_item != original_item {
                println!("  Item {} content changed", i);
            }
        }
        
        return Err(anyhow::anyhow!("Witness data corruption detected during transaction serialization"));
    }
    
    println!("✅ Method 1: No corruption detected");
    
    // Method 2: Manual witness construction (alternative approach)
    println!("\n🧪 Testing Method 2: Manual witness construction");
    let mut manual_witness = Witness::new();
    for item in envelope_witness.iter() {
        manual_witness.push(item);
    }
    
    tx.input[0].witness = manual_witness;
    
    println!("After manual construction:");
    println!("  Items: {}", tx.input[0].witness.len());
    for (i, item) in tx.input[0].witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // Test serialization with manual construction
    let serialized_tx2 = serialize(&tx);
    let deserialized_tx2: Transaction = deserialize(&serialized_tx2)?;
    
    println!("After transaction serialization/deserialization (manual):");
    println!("  Items: {}", deserialized_tx2.input[0].witness.len());
    for (i, item) in deserialized_tx2.input[0].witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // Check manual construction for corruption
    let is_corrupted2 = deserialized_tx2.input[0].witness.iter()
        .zip(envelope_witness.iter())
        .any(|(deserialized_item, original_item)| {
            deserialized_item.len() != original_item.len() || deserialized_item != original_item
        });
    
    if is_corrupted2 {
        println!("❌ CORRUPTION DETECTED: Manual construction also corrupted witness data");
        return Err(anyhow::anyhow!("Witness data corruption detected with manual construction"));
    }
    
    println!("✅ Method 2: No corruption detected");
    
    Ok(())
}

fn test_witness_size_limits() -> Result<()> {
    // Test different witness sizes to find corruption threshold
    let sizes = vec![1000, 10_000, 50_000, 100_000, 150_000, 200_000];
    
    for size in sizes {
        println!("\n🧪 Testing witness size: {} bytes", size);
        
        let test_data = vec![0u8; size];
        let envelope = AlkanesEnvelope::for_contract(test_data);
        
        // Generate test keys
        let secp = Secp256k1::new();
        let (_, internal_key) = secp.generate_keypair(&mut rand::thread_rng());
        let internal_key = XOnlyPublicKey::from(internal_key);
        
        // Create control block
        let reveal_script = envelope.build_reveal_script();
        let taproot_builder = TaprootBuilder::new().add_leaf(0, reveal_script.clone())?;
        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key)
            .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
        let control_block = taproot_spend_info
            .control_block(&(reveal_script, LeafVersion::TapScript))
            .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
        
        // Create witness
        let witness = envelope.create_witness(control_block)?;
        
        // Test in transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(546),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        
        // Test serialization
        let serialized = serialize(&tx);
        let deserialized: Transaction = deserialize(&serialized)?;
        
        let original_size = tx.input[0].witness.iter().map(|item| item.len()).sum::<usize>();
        let deserialized_size = deserialized.input[0].witness.iter().map(|item| item.len()).sum::<usize>();
        
        println!("  Original witness total size: {} bytes", original_size);
        println!("  Deserialized witness total size: {} bytes", deserialized_size);
        
        if original_size != deserialized_size {
            println!("  ❌ SIZE CORRUPTION at {} bytes", size);
        } else {
            println!("  ✅ Size preserved");
        }
    }
    
    Ok(())
}

fn test_reproduce_exact_issue() -> Result<()> {
    println!("🎯 Reproducing exact issue from alkanes execute");
    
    // Create the exact same envelope as in the failing case
    let contract_data = include_bytes!("../../examples/free_mint.wasm.gz").to_vec();
    let envelope = AlkanesEnvelope::for_contract(contract_data);
    
    // Generate test keys (simulating wallet internal key)
    let secp = Secp256k1::new();
    let (_, internal_key) = secp.generate_keypair(&mut rand::thread_rng());
    let internal_key = XOnlyPublicKey::from(internal_key);
    
    // Create taproot spend info exactly as in execute.rs
    let reveal_script = envelope.build_reveal_script();
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {:?}", e))?;
    
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
    
    let control_block = taproot_spend_info
        .control_block(&(reveal_script, LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
    
    // Create envelope witness exactly as in envelope.rs
    let envelope_witness = envelope.create_witness(control_block)?;
    
    println!("📊 Envelope witness created:");
    println!("  Items: {}", envelope_witness.len());
    for (i, item) in envelope_witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
        if item.len() <= 64 {
            println!("    Content (hex): {}", hex::encode(item));
        } else {
            println!("    Content (first 32 bytes): {}", hex::encode(&item[..32]));
            println!("    Content (last 32 bytes): {}", hex::encode(&item[item.len()-32..]));
        }
    }
    
    // Create transaction exactly as in execute.rs
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::null(), // Simulating commit outpoint
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint::null(), // Simulating funding UTXO
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(546),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(546),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuilder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                    .push_slice(b"RUNE_TEST")
                    .into_script(),
            },
        ],
    };
    
    // Apply envelope witness to first input (exactly as in execute.rs)
    println!("\n🔧 Applying envelope witness to input 0");
    
    // Method from execute.rs: Create new witness and push items
    let mut new_witness = Witness::new();
    for (i, item) in envelope_witness.iter().enumerate() {
        println!("  Pushing witness item {}: {} bytes", i, item.len());
        new_witness.push(item);
    }
    
    tx.input[0].witness = new_witness;
    
    println!("\n📊 After witness assignment:");
    println!("  Items: {}", tx.input[0].witness.len());
    for (i, item) in tx.input[0].witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // Test serialization (this is where the issue occurs)
    println!("\n🧪 Testing serialization...");
    let serialized_tx = serialize(&tx);
    println!("  Serialized transaction: {} bytes", serialized_tx.len());
    
    // Deserialize and check
    let deserialized_tx: Transaction = deserialize(&serialized_tx)?;
    
    println!("\n📊 After deserialization:");
    println!("  Input 0 witness items: {}", deserialized_tx.input[0].witness.len());
    
    let total_witness_size: usize = deserialized_tx.input[0].witness.iter()
        .map(|item| item.len()).sum();
    
    println!("  Total witness size: {} bytes", total_witness_size);
    
    for (i, item) in deserialized_tx.input[0].witness.iter().enumerate() {
        println!("  Item {}: {} bytes", i, item.len());
    }
    
    // This should reproduce the exact issue: witness shows 2 items but only 2 bytes total
    if total_witness_size < 1000 {
        println!("\n❌ ISSUE REPRODUCED: Witness data corrupted during serialization");
        println!("   Expected: ~118KB witness data");
        println!("   Actual: {} bytes", total_witness_size);
        
        // Analyze the hex to see what's happening
        println!("\n🔍 Analyzing serialized transaction hex:");
        let hex_str = hex::encode(&serialized_tx);
        println!("  Transaction hex length: {} chars", hex_str.len());
        println!("  First 128 chars: {}", &hex_str[..std::cmp::min(hex_str.len(), 128)]);
        println!("  Last 128 chars: {}", &hex_str[hex_str.len().saturating_sub(128)..]);
        
        return Err(anyhow::anyhow!("Successfully reproduced witness corruption issue"));
    }
    
    println!("✅ No corruption detected - issue not reproduced");
    
    Ok(())
}

/// Run all envelope witness corruption tests
pub fn run_envelope_witness_tests() -> Result<()> {
    println!("🧪 Running envelope witness corruption test suite...\n");
    
    // Test 1: Basic witness creation
    match test_envelope_witness_creation() {
        Ok(_) => println!("✅ Test 1: Envelope witness creation - PASSED"),
        Err(e) => {
            println!("❌ Test 1: Envelope witness creation - FAILED: {}", e);
            return Err(e);
        }
    }
    
    // Test 2: Direct witness serialization
    match test_witness_serialization_preservation() {
        Ok(_) => println!("✅ Test 2: Witness serialization preservation - PASSED"),
        Err(e) => {
            println!("❌ Test 2: Witness serialization preservation - FAILED: {}", e);
            return Err(e);
        }
    }
    
    // Test 3: Transaction witness corruption
    match test_transaction_witness_corruption_issue() {
        Ok(_) => println!("✅ Test 3: Transaction witness corruption - PASSED"),
        Err(e) => {
            println!("❌ Test 3: Transaction witness corruption - FAILED: {}", e);
            // Don't return error here as this test is expected to fail
        }
    }
    
    // Test 4: Size limits
    match test_witness_size_limits() {
        Ok(_) => println!("✅ Test 4: Witness size limits - PASSED"),
        Err(e) => {
            println!("❌ Test 4: Witness size limits - FAILED: {}", e);
            return Err(e);
        }
    }
    
    // Test 5: Reproduce exact issue
    match test_reproduce_exact_issue() {
        Ok(_) => println!("✅ Test 5: Exact issue reproduction - PASSED (no corruption)"),
        Err(e) => {
            println!("❌ Test 5: Exact issue reproduction - FAILED: {}", e);
            // This is expected to fail if we successfully reproduce the issue
        }
    }
    
    println!("\n🎯 Envelope witness corruption test suite completed");
    Ok(())
}