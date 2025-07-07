//! Test for fixing the prevouts sighash issue in taproot script signature generation
//!
//! This test reproduces the error:
//! "Failed to compute taproot script spend sighash: prevouts kind: single prevout provided but all prevouts are needed without `ANYONECANPAY`"
//!
//! The issue is that when creating taproot script-path signatures, we need to provide
//! ALL prevouts (UTXOs) for the transaction inputs, not just the single input being signed.

use anyhow::Result;
use bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
use bitcoin::{Transaction, TxIn, TxOut, OutPoint, ScriptBuf, Amount, Witness};
use bitcoin::secp256k1::Secp256k1;

#[tokio::test]
async fn test_prevouts_sighash_error_reproduction() -> Result<()> {
    println!("🔍 Testing prevouts sighash error reproduction");
    
    // Create a mock transaction with 2 inputs (like the failing deezel transaction)
    let tx = create_mock_transaction_with_multiple_inputs();
    
    // Try to create sighash with single prevout (this should fail)
    let result = try_sighash_with_single_prevout(&tx, 0);
    
    match result {
        Err(e) => {
            println!("✅ Successfully reproduced the error: {}", e);
            assert!(e.to_string().contains("prevouts kind"));
        },
        Ok(_) => {
            panic!("❌ Expected error but sighash calculation succeeded");
        }
    }
    
    // Now try with all prevouts (this should work)
    let result = try_sighash_with_all_prevouts(&tx, 0);
    
    match result {
        Ok(_) => {
            println!("✅ Sighash calculation succeeded with all prevouts");
        },
        Err(e) => {
            panic!("❌ Sighash calculation failed even with all prevouts: {}", e);
        }
    }
    
    Ok(())
}

fn create_mock_transaction_with_multiple_inputs() -> Transaction {
    // Create a transaction similar to the failing deezel transaction
    // Input 0: Commit output (envelope with script-path spending)
    // Input 1: Regular wallet UTXO (key-path spending)
    
    let input0 = TxIn {
        previous_output: OutPoint {
            txid: "1111111111111111111111111111111111111111111111111111111111111111".parse().unwrap(),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    
    let input1 = TxIn {
        previous_output: OutPoint {
            txid: "2222222222222222222222222222222222222222222222222222222222222222".parse().unwrap(),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    
    let output = TxOut {
        value: Amount::from_sat(546),
        script_pubkey: ScriptBuf::new(),
    };
    
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![input0, input1],
        output: vec![output],
    }
}

fn try_sighash_with_single_prevout(tx: &Transaction, input_index: usize) -> Result<bitcoin::sighash::TapSighash> {
    // This reproduces the failing approach in deezel
    let prevout = TxOut {
        value: Amount::from_sat(546), // Dust limit for commit output
        script_pubkey: ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            bitcoin::XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap()
        )),
    };
    
    // This is the problematic line - using Prevouts::One when we have multiple inputs
    let prevouts = Prevouts::One(input_index, &prevout);
    
    let mut sighash_cache = SighashCache::new(tx);
    
    // Create a dummy script for the test
    let script = ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript);
    
    sighash_cache.taproot_script_spend_signature_hash(
        input_index,
        &prevouts,
        leaf_hash,
        TapSighashType::Default,
    ).map_err(|e| anyhow::anyhow!("Sighash error: {}", e))
}

fn try_sighash_with_all_prevouts(tx: &Transaction, input_index: usize) -> Result<bitcoin::sighash::TapSighash> {
    // This is the correct approach - provide all prevouts
    let prevout0 = TxOut {
        value: Amount::from_sat(546), // Commit output
        script_pubkey: ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            bitcoin::XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap()
        )),
    };
    
    let prevout1 = TxOut {
        value: Amount::from_sat(10000), // Regular wallet UTXO
        script_pubkey: ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
            bitcoin::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap()
        )),
    };
    
    // This is the correct approach - using Prevouts::All with all UTXOs
    let all_prevouts = vec![prevout0, prevout1];
    let prevouts = Prevouts::All(&all_prevouts);
    
    let mut sighash_cache = SighashCache::new(tx);
    
    // Create a dummy script for the test
    let script = ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript);
    
    sighash_cache.taproot_script_spend_signature_hash(
        input_index,
        &prevouts,
        leaf_hash,
        TapSighashType::Default,
    ).map_err(|e| anyhow::anyhow!("Sighash error: {}", e))
}

#[test]
fn test_prevouts_understanding() {
    println!("🔍 Understanding Prevouts requirements:");
    println!("  - Prevouts::One(index, utxo): Only valid when using ANYONECANPAY sighash type");
    println!("  - Prevouts::All(&[utxo1, utxo2, ...]): Required for DEFAULT sighash type");
    println!("  - For taproot script-path spending with multiple inputs, we MUST use Prevouts::All");
    println!("  - The order of prevouts must match the order of transaction inputs");
}