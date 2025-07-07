//! Comprehensive test for commit-reveal pattern with script-path spending
//! 
//! This test validates the complete commit-reveal transaction flow:
//! 1. Commit transaction creates UTXO with envelope script in taproot tree
//! 2. Reveal transaction spends commit UTXO using script-path spending
//! 3. Reveal transaction has proper 3-element witness: [signature, BIN_envelope_script, control_block]
//! 4. BIN envelope data is properly embedded in the witness script
//! 5. Transaction structure matches expected patterns

use anyhow::Result;
use bitcoin::{
    secp256k1::{Secp256k1, SecretKey, rand::thread_rng},
    key::{Keypair, UntweakedKeypair},
    XOnlyPublicKey, Network, Address,
    Transaction, TxIn, TxOut, OutPoint, Txid,
    ScriptBuf, Witness,
    taproot::{TaprootBuilder, LeafVersion, ControlBlock},
    Amount, WPubkeyHash,
    hashes::{Hash, hash160},
};
use std::str::FromStr;

use crate::alkanes::{
    envelope::AlkanesEnvelope,
    execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams, InputRequirement, ProtostoneSpec},
    types::AlkaneId,
};
use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use std::sync::Arc;

/// Comprehensive test for commit-reveal pattern with script-path spending
#[tokio::test]
async fn test_commit_reveal_script_path_spending() -> Result<()> {
    println!("🧪 Testing commit-reveal pattern with script-path spending");
    
    // Step 1: Create test envelope with BIN data
    let test_envelope_data = create_test_bin_envelope_data();
    let envelope = AlkanesEnvelope::for_contract(test_envelope_data.clone());
    
    println!("✅ Created test envelope with {} bytes of BIN data", test_envelope_data.len());
    
    // Step 2: Test commit address creation
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut thread_rng());
    let internal_key = XOnlyPublicKey::from_keypair(&keypair).0;
    
    let commit_address = create_test_commit_address(&envelope, Network::Regtest, internal_key)?;
    println!("✅ Created commit address: {}", commit_address);
    
    // Verify commit address is P2TR
    assert!(commit_address.script_pubkey().is_p2tr(), "Commit address must be P2TR");
    
    // Step 3: Test taproot spend info creation
    let (taproot_spend_info, control_block) = create_test_taproot_spend_info(&envelope, internal_key)?;
    println!("✅ Created taproot spend info and control block");
    
    // Verify control block structure
    let control_block_bytes = control_block.serialize();
    assert!(control_block_bytes.len() >= 33, "Control block must be at least 33 bytes");
    println!("✅ Control block: {} bytes", control_block_bytes.len());
    
    // Step 4: Test reveal script creation
    let reveal_script = envelope.build_reveal_script();
    println!("✅ Created reveal script: {} bytes", reveal_script.len());
    
    // Verify reveal script contains BIN protocol markers
    let script_bytes = reveal_script.as_bytes();
    assert!(script_bytes.windows(3).any(|w| w == b"BIN"), "Reveal script must contain BIN protocol marker");
    println!("✅ Reveal script contains BIN protocol marker");
    
    // Step 5: Test 3-element witness creation
    let test_signature = create_test_schnorr_signature();
    let complete_witness = envelope.create_complete_witness(&test_signature, control_block)?;
    
    // Verify witness structure
    assert_eq!(complete_witness.len(), 3, "Witness must have exactly 3 elements");
    println!("✅ Created 3-element witness structure");
    
    // Verify witness elements
    let sig_element = &complete_witness[0];
    let script_element = &complete_witness[1]; 
    let control_element = &complete_witness[2];
    
    // Signature should be 64-65 bytes (Schnorr signature)
    assert!(sig_element.len() >= 64 && sig_element.len() <= 65, 
           "Signature element should be 64-65 bytes, got {}", sig_element.len());
    println!("✅ Witness element 0 (signature): {} bytes", sig_element.len());
    
    // Script should contain the BIN envelope data
    assert!(script_element.len() > 1000, "Script element should be large (contains BIN data)");
    assert!(script_element.windows(3).any(|w| w == b"BIN"), "Script element must contain BIN marker");
    println!("✅ Witness element 1 (BIN script): {} bytes", script_element.len());
    
    // Control block should match what we created
    assert_eq!(control_element.len(), control_block_bytes.len(), "Control block sizes must match");
    assert_eq!(control_element, &control_block_bytes, "Control block content must match");
    println!("✅ Witness element 2 (control block): {} bytes", control_element.len());
    
    // Step 6: Test commit transaction structure
    let commit_tx = create_test_commit_transaction(&commit_address)?;
    println!("✅ Created test commit transaction");
    
    // Verify commit transaction structure
    assert_eq!(commit_tx.input.len(), 1, "Commit transaction should have 1 input");
    assert!(commit_tx.output.len() >= 1, "Commit transaction should have at least 1 output");
    
    // First output should be the commit output (dust amount to commit address)
    let commit_output = &commit_tx.output[0];
    assert_eq!(commit_output.value, Amount::from_sat(546), "Commit output should be dust amount");
    assert_eq!(commit_output.script_pubkey, commit_address.script_pubkey(), "Commit output should pay to commit address");
    println!("✅ Commit transaction structure verified");
    
    // Step 7: Test reveal transaction structure
    let commit_outpoint = OutPoint {
        txid: commit_tx.compute_txid(),
        vout: 0,
    };
    
    let reveal_tx = create_test_reveal_transaction(commit_outpoint, &complete_witness)?;
    println!("✅ Created test reveal transaction");
    
    // Verify reveal transaction structure
    assert_eq!(reveal_tx.input.len(), 1, "Reveal transaction should have 1 input");
    assert!(reveal_tx.output.len() >= 2, "Reveal transaction should have at least 2 outputs (recipient + OP_RETURN)");
    
    // Verify reveal input spends commit output
    let reveal_input = &reveal_tx.input[0];
    assert_eq!(reveal_input.previous_output, commit_outpoint, "Reveal input should spend commit output");
    
    // Verify reveal input has 3-element witness
    assert_eq!(reveal_input.witness.len(), 3, "Reveal input should have 3-element witness");
    println!("✅ Reveal transaction structure verified");
    
    // Step 8: Verify witness data preservation
    assert_eq!(reveal_input.witness[0].len(), sig_element.len(), "Signature preserved in transaction");
    assert_eq!(reveal_input.witness[1].len(), script_element.len(), "Script preserved in transaction");
    assert_eq!(reveal_input.witness[2].len(), control_element.len(), "Control block preserved in transaction");
    println!("✅ Witness data preservation verified");
    
    // Step 9: Test transaction serialization/deserialization
    let serialized = bitcoin::consensus::serialize(&reveal_tx);
    let deserialized: Transaction = bitcoin::consensus::deserialize(&serialized)?;
    
    // Verify witness survives serialization
    assert_eq!(deserialized.input[0].witness.len(), 3, "Witness survives serialization");
    assert_eq!(deserialized.input[0].witness[1].len(), script_element.len(), "Script element survives serialization");
    println!("✅ Transaction serialization/deserialization verified");
    
    // Step 10: Verify BIN envelope data accessibility
    let witness_script = &deserialized.input[0].witness[1];
    assert!(witness_script.windows(3).any(|w| w == b"BIN"), "BIN marker accessible in serialized transaction");
    assert!(witness_script.windows(16).any(|w| w == b"application/wasm"), "WASM content type accessible");
    println!("✅ BIN envelope data accessibility verified");
    
    // Step 11: Test transaction size and efficiency
    let reveal_tx_size = reveal_tx.total_size();
    let reveal_tx_vsize = reveal_tx.vsize();
    let reveal_tx_weight = reveal_tx.weight();
    
    println!("📊 Reveal transaction metrics:");
    println!("   Total size: {} bytes", reveal_tx_size);
    println!("   Virtual size: {} vbytes", reveal_tx_vsize);
    println!("   Weight: {} WU", reveal_tx_weight.to_wu());
    
    // Verify transaction is reasonably sized (not absurdly large)
    assert!(reveal_tx_size < 200_000, "Transaction size should be reasonable (< 200KB)");
    assert!(reveal_tx_vsize < 150_000, "Transaction vsize should be reasonable (< 150KB)");
    println!("✅ Transaction size efficiency verified");
    
    // Step 12: Verify script-path spending configuration
    // The reveal script should be derivable from the commit address
    let script_map = taproot_spend_info.script_map();
    assert!(!script_map.is_empty(), "Taproot spend info should have scripts");
    
    let (script_in_map, _) = script_map.iter().next().unwrap().0;
    assert_eq!(script_in_map.as_bytes(), reveal_script.as_bytes(), "Script in spend info should match reveal script");
    println!("✅ Script-path spending configuration verified");
    
    println!("\n🎉 ALL TESTS PASSED!");
    println!("✅ Commit-reveal pattern with script-path spending works correctly");
    println!("✅ 3-element witness structure: [signature, BIN_envelope_script, control_block]");
    println!("✅ BIN envelope data properly embedded in witness script");
    println!("✅ Transaction structure matches expected patterns");
    println!("✅ Single input optimization achieved");
    
    Ok(())
}

/// Create test BIN envelope data that mimics a real contract deployment
fn create_test_bin_envelope_data() -> Vec<u8> {
    let mut data = Vec::new();
    
    // Add BIN protocol header
    data.extend_from_slice(b"BIN");
    data.push(0x00); // Separator
    
    // Add content type
    data.extend_from_slice(b"application/wasm");
    data.push(0x00); // Separator
    
    // Add mock WASM bytecode (simplified)
    data.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]); // WASM magic number
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // WASM version
    
    // Add some mock contract data to make it realistic size
    let mock_contract_data = vec![0x42; 50000]; // 50KB of mock data
    data.extend_from_slice(&mock_contract_data);
    
    data
}

/// Create test commit address using the envelope's taproot script
fn create_test_commit_address(
    envelope: &AlkanesEnvelope,
    network: Network,
    internal_key: XOnlyPublicKey,
) -> Result<Address> {
    let reveal_script = envelope.build_reveal_script();
    
    // Create taproot builder with the reveal script
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, reveal_script)
        .map_err(|e| anyhow::anyhow!("Failed to add reveal script: {:?}", e))?;
    
    // Finalize the taproot spend info
    let taproot_spend_info = taproot_builder
        .finalize(&Secp256k1::verification_only(), internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
    
    // Create the commit address
    let commit_address = Address::p2tr_tweaked(
        taproot_spend_info.output_key(),
        network,
    );
    
    Ok(commit_address)
}

/// Create test taproot spend info for the envelope
fn create_test_taproot_spend_info(
    envelope: &AlkanesEnvelope,
    internal_key: XOnlyPublicKey,
) -> Result<(bitcoin::taproot::TaprootSpendInfo, ControlBlock)> {
    let reveal_script = envelope.build_reveal_script();
    
    // Create taproot builder with the reveal script
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add reveal script: {:?}", e))?;
    
    // Finalize the taproot spend info
    let taproot_spend_info = taproot_builder
        .finalize(&Secp256k1::verification_only(), internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize taproot: {:?}", e))?;
    
    // Create control block for script-path spending
    let control_block = taproot_spend_info
        .control_block(&(reveal_script, LeafVersion::TapScript))
        .ok_or_else(|| anyhow::anyhow!("Failed to create control block"))?;
    
    Ok((taproot_spend_info, control_block))
}

/// Create test Schnorr signature (mock for testing)
fn create_test_schnorr_signature() -> Vec<u8> {
    // Create a mock 64-byte Schnorr signature for testing
    // In real implementation, this would be a proper signature
    let mut sig = vec![0x30; 64]; // Mock signature bytes
    sig[0] = 0x01; // Make it slightly different from all zeros
    sig[63] = 0x01; // SIGHASH_ALL
    sig
}

/// Create test commit transaction
fn create_test_commit_transaction(commit_address: &Address) -> Result<Transaction> {
    // Create a mock funding input (would be a real UTXO in practice)
    let funding_input = TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    
    // Create commit output (dust amount to commit address)
    let commit_output = TxOut {
        value: Amount::from_sat(546), // Dust limit
        script_pubkey: commit_address.script_pubkey(),
    };
    
    // Create change output (mock)
    let change_output = TxOut {
        value: Amount::from_sat(50000), // Mock change
        script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_raw_hash(hash160::Hash::from_slice(&[0; 20])?)),
    };
    
    let commit_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![funding_input],
        output: vec![commit_output, change_output],
    };
    
    Ok(commit_tx)
}

/// Create test reveal transaction with proper witness
fn create_test_reveal_transaction(
    commit_outpoint: OutPoint,
    witness: &Witness,
) -> Result<Transaction> {
    // Create reveal input spending the commit output
    let mut reveal_input = TxIn {
        previous_output: commit_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    
    // Apply the 3-element witness
    reveal_input.witness = witness.clone();
    
    // Create recipient output
    let recipient_output = TxOut {
        value: Amount::from_sat(546), // Dust limit
        script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_raw_hash(hash160::Hash::from_slice(&[0; 20])?)),
    };
    
    // Create OP_RETURN output with mock runestone
    let op_return_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(&[0x5d, 0x01]), // Mock runestone
    };
    
    let reveal_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![reveal_input],
        output: vec![recipient_output, op_return_output],
    };
    
    Ok(reveal_tx)
}

/// Test helper to verify envelope script structure
#[test]
fn test_envelope_script_structure() -> Result<()> {
    println!("🧪 Testing envelope script structure");
    
    let test_data = create_test_bin_envelope_data();
    let envelope = AlkanesEnvelope::for_contract(test_data);
    
    let reveal_script = envelope.build_reveal_script();
    let script_bytes = reveal_script.as_bytes();
    
    // Verify script contains expected elements
    assert!(script_bytes.len() > 1000, "Script should be substantial size");
    assert!(script_bytes.windows(3).any(|w| w == b"BIN"), "Script should contain BIN marker");
    assert!(script_bytes.windows(16).any(|w| w == b"application/wasm"), "Script should contain content type");
    
    // Verify script structure (should start with OP_PUSHBYTES_0 OP_IF)
    assert_eq!(script_bytes[0], 0x00, "Script should start with OP_PUSHBYTES_0");
    assert_eq!(script_bytes[1], 0x63, "Script should have OP_IF after OP_PUSHBYTES_0");
    
    // Verify script ends with OP_ENDIF
    assert_eq!(script_bytes[script_bytes.len() - 1], 0x68, "Script should end with OP_ENDIF");
    
    println!("✅ Envelope script structure verified");
    Ok(())
}

/// Test helper to verify witness creation consistency
#[test]
fn test_witness_creation_consistency() -> Result<()> {
    println!("🧪 Testing witness creation consistency");
    
    let test_data = create_test_bin_envelope_data();
    let envelope = AlkanesEnvelope::for_contract(test_data);
    
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut thread_rng());
    let internal_key = XOnlyPublicKey::from_keypair(&keypair).0;
    
    let (_, control_block) = create_test_taproot_spend_info(&envelope, internal_key)?;
    let test_signature = create_test_schnorr_signature();
    
    // Create witness multiple times and verify consistency
    let witness1 = envelope.create_complete_witness(&test_signature, control_block.clone())?;
    let witness2 = envelope.create_complete_witness(&test_signature, control_block)?;
    
    assert_eq!(witness1.len(), witness2.len(), "Witness length should be consistent");
    assert_eq!(witness1[0], witness2[0], "Signature element should be consistent");
    assert_eq!(witness1[1], witness2[1], "Script element should be consistent");
    assert_eq!(witness1[2], witness2[2], "Control block element should be consistent");
    
    println!("✅ Witness creation consistency verified");
    Ok(())
}