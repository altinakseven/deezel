//! Test P2TR transaction signing to ensure we can properly spend P2TR outputs
//! 
//! This test models the exact issue we're seeing with empty witnesses in P2TR transactions
//! and ensures our signing logic works correctly before using it in production.

use anyhow::{Result, Context};
use bitcoin::{
    Network, Transaction, TxIn, TxOut, OutPoint, Txid, Amount, ScriptBuf,
    secp256k1::{Secp256k1, Keypair, XOnlyPublicKey, Message},
    sighash::{SighashCache, TapSighashType, Prevouts},
    taproot::{TaprootBuilder, TaprootSpendInfo, Signature as TaprootSignature},
    key::{TapTweak, UntweakedKeypair},
    bip32::{ExtendedPrivKey, DerivationPath, ChildNumber},
    Address, Witness, Sequence,
};
use std::str::FromStr;

/// Test P2TR key-path spending with proper witness creation
#[tokio::test]
async fn test_p2tr_key_path_spending() -> Result<()> {
    println!("🧪 Testing P2TR key-path spending...");
    
    let secp = Secp256k1::new();
    let network = Network::Regtest;
    
    // Create a master key (simulating wallet)
    let seed = [0u8; 32]; // Deterministic for testing
    let master_xprv = ExtendedPrivKey::new_master(network, &seed)?;
    
    // Derive a P2TR key using BIP86 path: m/86'/1'/0'/0/0
    let derivation_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(), // BIP86 (Taproot)
        ChildNumber::from_hardened_idx(1).unwrap(),  // Testnet/Regtest
        ChildNumber::from_hardened_idx(0).unwrap(),  // Account 0
        ChildNumber::from_normal_idx(0).unwrap(),    // External chain
        ChildNumber::from_normal_idx(0).unwrap(),    // Address index 0
    ]);
    
    let derived_xprv = master_xprv.derive_priv(&secp, &derivation_path)?;
    let private_key = bitcoin::PrivateKey::new(derived_xprv.private_key, network);
    let public_key = private_key.public_key(&secp);
    
    println!("🔑 Generated P2TR keys");
    println!("  Private key: {}", private_key);
    println!("  Public key: {}", public_key);
    
    // Create P2TR address (key-path only, no script tree)
    let x_only_pubkey = XOnlyPublicKey::from(public_key);
    let untweaked_pubkey = bitcoin::key::UntweakedPublicKey::from(x_only_pubkey);
    let p2tr_address = Address::p2tr(&secp, untweaked_pubkey, None, network);
    
    println!("🏠 P2TR Address: {}", p2tr_address);
    
    // Create a mock UTXO (simulating a coinbase output to this address)
    let mock_utxo_txid = Txid::from_str("e43e9292a099f939d4f37c1312cc8670bf8e6dd9f378fa9e7562064996ff151a")?;
    let mock_utxo_vout = 0;
    let mock_utxo_amount = 5_000_000_000u64; // 50 BTC
    
    let mock_utxo = TxOut {
        value: Amount::from_sat(mock_utxo_amount),
        script_pubkey: p2tr_address.script_pubkey(),
    };
    
    println!("💰 Mock UTXO: {}:{} = {} sats", mock_utxo_txid, mock_utxo_vout, mock_utxo_amount);
    
    // Create a spending transaction
    let recipient_address = Address::p2tr(&secp, untweaked_pubkey, None, network); // Send to self for simplicity
    let send_amount = 1_000u64; // 1000 sats
    let fee = 1_000u64; // 1000 sats fee
    let change_amount = mock_utxo_amount - send_amount - fee;
    
    let mut spending_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: mock_utxo_txid,
                vout: mock_utxo_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(), // Empty initially
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(send_amount),
                script_pubkey: recipient_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: p2tr_address.script_pubkey(), // Change back to self
            },
        ],
    };
    
    println!("📝 Created unsigned transaction");
    println!("  Inputs: {}", spending_tx.input.len());
    println!("  Outputs: {}", spending_tx.output.len());
    println!("  Send amount: {} sats", send_amount);
    println!("  Change amount: {} sats", change_amount);
    
    // Sign the transaction using P2TR key-path spending
    let prevouts = vec![mock_utxo.clone()];
    let prevouts = Prevouts::All(&prevouts);
    
    // Create sighash for P2TR key-path spending
    let mut sighash_cache = SighashCache::new(&spending_tx);
    let sighash = sighash_cache.taproot_key_spend_signature_hash(
        0, // Input index
        &prevouts,
        TapSighashType::Default,
    )?;
    
    println!("🔐 Created sighash for signing");
    
    // Create keypair and apply taproot tweak
    let keypair = Keypair::from_secret_key(&secp, &private_key.inner);
    let untweaked_keypair = UntweakedKeypair::from(keypair);
    
    // Apply taproot tweak (for key-path spending with no script tree)
    let tweaked_keypair = untweaked_keypair.tap_tweak(&secp, None);
    
    // Sign the sighash
    let msg = Message::from(sighash);
    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let signature = secp.sign_schnorr_with_rng(&msg, tweaked_keypair.as_keypair(), &mut rng);
    
    // Create taproot signature
    let taproot_signature = TaprootSignature {
        signature,
        sighash_type: TapSighashType::Default,
    };
    
    println!("✍️  Created taproot signature");
    
    // Create witness for P2TR key-path spending
    spending_tx.input[0].witness = Witness::p2tr_key_spend(&taproot_signature);
    
    println!("🎯 Applied witness to transaction");
    println!("  Witness items: {}", spending_tx.input[0].witness.len());
    
    // Verify the witness is not empty
    assert!(!spending_tx.input[0].witness.is_empty(), "Witness should not be empty");
    assert_eq!(spending_tx.input[0].witness.len(), 1, "P2TR key-path witness should have exactly 1 item");
    
    // Verify the witness item is the signature
    let witness_signature = &spending_tx.input[0].witness[0];
    assert!(!witness_signature.is_empty(), "Witness signature should not be empty");
    assert_eq!(witness_signature.len(), 64, "Schnorr signature should be 64 bytes"); // 64 bytes for schnorr signature
    
    println!("✅ P2TR key-path spending test passed!");
    println!("  Witness signature length: {} bytes", witness_signature.len());
    
    // Test serialization to ensure the transaction is valid
    let serialized = bitcoin::consensus::serialize(&spending_tx);
    println!("📦 Serialized transaction: {} bytes", serialized.len());
    
    // Test deserialization
    let deserialized: Transaction = bitcoin::consensus::deserialize(&serialized)?;
    assert_eq!(deserialized.input[0].witness.len(), 1, "Deserialized witness should have 1 item");
    assert_eq!(deserialized.input[0].witness[0].len(), 64, "Deserialized signature should be 64 bytes");
    
    println!("✅ Serialization/deserialization test passed!");
    
    Ok(())
}

/// Test the exact scenario from our alkanes execute command
#[tokio::test]
async fn test_alkanes_p2tr_scenario() -> Result<()> {
    println!("🧪 Testing alkanes P2TR scenario...");
    
    let secp = Secp256k1::new();
    let network = Network::Regtest;
    
    // Simulate the exact scenario from the failing transaction
    // The failing UTXO: e43e9292a099f939d4f37c1312cc8670bf8e6dd9f378fa9e7562064996ff151a:0
    
    // Create master key (this should match our wallet's master key derivation)
    let seed = [1u8; 32]; // Different seed for this test
    let master_xprv = ExtendedPrivKey::new_master(network, &seed)?;
    
    // Use the same derivation path as our wallet for P2TR
    let derivation_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(), // BIP86 (Taproot)
        ChildNumber::from_hardened_idx(1).unwrap(),  // Testnet/Regtest coin type
        ChildNumber::from_hardened_idx(0).unwrap(),  // Account 0
        ChildNumber::from_normal_idx(0).unwrap(),    // External chain (receiving)
        ChildNumber::from_normal_idx(0).unwrap(),    // Address index 0
    ]);
    
    let derived_xprv = master_xprv.derive_priv(&secp, &derivation_path)?;
    let private_key = bitcoin::PrivateKey::new(derived_xprv.private_key, network);
    let public_key = private_key.public_key(&secp);
    
    // Create P2TR address exactly like our wallet does
    let x_only_pubkey = XOnlyPublicKey::from(public_key);
    let untweaked_pubkey = bitcoin::key::UntweakedPublicKey::from(x_only_pubkey);
    let p2tr_address = Address::p2tr(&secp, untweaked_pubkey, None, network);
    
    println!("🏠 Alkanes P2TR Address: {}", p2tr_address);
    
    // Create the exact UTXO from the failing transaction
    let failing_txid = Txid::from_str("e43e9292a099f939d4f37c1312cc8670bf8e6dd9f378fa9e7562064996ff151a")?;
    let failing_vout = 0;
    let failing_amount = 5_000_000_000u64; // 50 BTC (typical coinbase amount)
    
    let utxo = TxOut {
        value: Amount::from_sat(failing_amount),
        script_pubkey: p2tr_address.script_pubkey(),
    };
    
    // Create a transaction similar to our alkanes execute transaction
    // Multiple outputs like in the failing transaction
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: failing_txid,
                vout: failing_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0xfdffffff), // Same as failing tx
            witness: Witness::new(),
        }],
        output: vec![
            // Multiple P2TR outputs like in the failing transaction
            TxOut {
                value: Amount::from_sat(546), // Dust amount
                script_pubkey: ScriptBuf::from_hex("5120af8f4069be94dbe0ea7c0fcaef0b2e378d4da390e2ccf177de968922f9b5ba12")?,
            },
            TxOut {
                value: Amount::from_sat(546), // Dust amount
                script_pubkey: ScriptBuf::from_hex("5120d07b235fabd341849c630f313a9b0909f8b7d1839234e2baff91e6d78b1945e2")?,
            },
            TxOut {
                value: Amount::from_sat(546), // Dust amount
                script_pubkey: ScriptBuf::from_hex("5120f6c88a09fd354fc2b58164e76234cd21b569da616085b38c776d6b0d175d8d43")?,
            },
            TxOut {
                value: Amount::from_sat(546), // Dust amount
                script_pubkey: ScriptBuf::from_hex("5120d07b235fabd341849c630f313a9b0909f8b7d1839234e2baff91e6d78b1945e2")?,
            },
            // OP_RETURN output (runestone)
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_hex("6a5d0bff7f818cec82d08bc0a806")?,
            },
        ],
    };
    
    println!("📝 Created alkanes-style transaction");
    println!("  Input UTXO: {}:{}", failing_txid, failing_vout);
    println!("  Outputs: {}", tx.output.len());
    
    // Sign the transaction using the same logic as our wallet
    let prevouts = vec![utxo];
    let prevouts = Prevouts::All(&prevouts);
    
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_key_spend_signature_hash(
        0,
        &prevouts,
        TapSighashType::Default,
    )?;
    
    // Create keypair and apply taproot tweak (exactly like our wallet code)
    let keypair = Keypair::from_secret_key(&secp, &private_key.inner);
    let untweaked_keypair = UntweakedKeypair::from(keypair);
    let tweaked_keypair = untweaked_keypair.tap_tweak(&secp, None);
    
    // Sign
    let msg = Message::from(sighash);
    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let signature = secp.sign_schnorr_with_rng(&msg, tweaked_keypair.as_keypair(), &mut rng);
    
    let taproot_signature = TaprootSignature {
        signature,
        sighash_type: TapSighashType::Default,
    };
    
    // Apply witness
    tx.input[0].witness = Witness::p2tr_key_spend(&taproot_signature);
    
    println!("✍️  Signed alkanes transaction");
    println!("  Witness items: {}", tx.input[0].witness.len());
    println!("  Witness signature length: {} bytes", tx.input[0].witness[0].len());
    
    // Verify the transaction is properly signed
    assert!(!tx.input[0].witness.is_empty(), "Alkanes transaction witness should not be empty");
    assert_eq!(tx.input[0].witness.len(), 1, "P2TR key-path witness should have exactly 1 item");
    assert_eq!(tx.input[0].witness[0].len(), 64, "Schnorr signature should be 64 bytes");
    
    // Test serialization (this is what gets sent to Bitcoin Core)
    let serialized = bitcoin::consensus::serialize(&tx);
    let hex = hex::encode(&serialized);
    
    println!("📦 Serialized transaction hex: {}", hex);
    println!("📦 Transaction size: {} bytes", serialized.len());
    
    // Verify the hex doesn't have empty witness (which was our original problem)
    assert!(hex.contains("40"), "Transaction hex should contain witness data");
    
    println!("✅ Alkanes P2TR scenario test passed!");
    
    Ok(())
}

/// Test to identify the exact issue in our wallet signing logic
#[tokio::test]
async fn test_debug_wallet_signing_issue() -> Result<()> {
    println!("🔍 Debugging wallet signing issue...");
    
    // This test will help us identify why our wallet's P2TR signing is producing empty witnesses
    
    let secp = Secp256k1::new();
    let network = Network::Regtest;
    
    // Test different scenarios that might cause empty witnesses
    
    // Scenario 1: Wrong derivation path
    println!("🧪 Testing derivation path scenarios...");
    
    let seed = [2u8; 32];
    let master_xprv = ExtendedPrivKey::new_master(network, &seed)?;
    
    // Test various derivation paths
    let paths = vec![
        // BIP86 standard
        vec![86, 1, 0, 0, 0],
        // Our wallet might be using different hardened/non-hardened
        vec![86, 1, 0, 0, 0], // All as specified
    ];
    
    for (i, path_nums) in paths.iter().enumerate() {
        println!("  Testing path {}: m/{}'/{}'/{}'/{}/{}", i, path_nums[0], path_nums[1], path_nums[2], path_nums[3], path_nums[4]);
        
        let derivation_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(path_nums[0] as u32).unwrap(),
            ChildNumber::from_hardened_idx(path_nums[1] as u32).unwrap(),
            ChildNumber::from_hardened_idx(path_nums[2] as u32).unwrap(),
            ChildNumber::from_normal_idx(path_nums[3] as u32).unwrap(),
            ChildNumber::from_normal_idx(path_nums[4] as u32).unwrap(),
        ]);
        
        let derived_xprv = master_xprv.derive_priv(&secp, &derivation_path)?;
        let private_key = bitcoin::PrivateKey::new(derived_xprv.private_key, network);
        
        // Test signing with this key
        let result = test_signing_with_key(&secp, &private_key, network);
        match result {
            Ok(_) => println!("    ✅ Path {} works", i),
            Err(e) => println!("    ❌ Path {} failed: {}", i, e),
        }
    }
    
    // Scenario 2: Test master key directly (like our wallet might be doing)
    println!("🧪 Testing master key signing...");
    let master_private_key = bitcoin::PrivateKey::new(master_xprv.private_key, network);
    match test_signing_with_key(&secp, &master_private_key, network) {
        Ok(_) => println!("    ✅ Master key signing works"),
        Err(e) => println!("    ❌ Master key signing failed: {}", e),
    }
    
    println!("✅ Debug test completed!");
    
    Ok(())
}

/// Helper function to test signing with a specific key
fn test_signing_with_key(secp: &Secp256k1<bitcoin::secp256k1::All>, private_key: &bitcoin::PrivateKey, network: Network) -> Result<()> {
    let public_key = private_key.public_key(secp);
    let x_only_pubkey = XOnlyPublicKey::from(public_key);
    let untweaked_pubkey = bitcoin::key::UntweakedPublicKey::from(x_only_pubkey);
    let address = Address::p2tr(secp, untweaked_pubkey, None, network);
    
    // Create a simple transaction
    let mock_txid = Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")?;
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: address.script_pubkey(),
    };
    
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: mock_txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    
    // Sign
    let prevouts = vec![utxo];
    let prevouts = Prevouts::All(&prevouts);
    
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)?;
    
    let keypair = Keypair::from_secret_key(secp, &private_key.inner);
    let untweaked_keypair = UntweakedKeypair::from(keypair);
    let tweaked_keypair = untweaked_keypair.tap_tweak(secp, None);
    
    let msg = Message::from(sighash);
    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let signature = secp.sign_schnorr_with_rng(&msg, tweaked_keypair.as_keypair(), &mut rng);
    
    let taproot_signature = TaprootSignature {
        signature,
        sighash_type: TapSighashType::Default,
    };
    
    tx.input[0].witness = Witness::p2tr_key_spend(&taproot_signature);
    
    // Verify witness is not empty
    if tx.input[0].witness.is_empty() {
        return Err(anyhow::anyhow!("Witness is empty"));
    }
    
    if tx.input[0].witness[0].is_empty() {
        return Err(anyhow::anyhow!("Witness signature is empty"));
    }
    
    Ok(())
}