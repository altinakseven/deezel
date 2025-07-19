// This file is part of the deezel project.
// Copyright (c) 2024, The Deezel Developers, all rights reserved.
// Deezel is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

//! Tests for the EnhancedAlkanesExecutor.
//!
//! This file contains tests for the commit-reveal and single-transaction
//! execution flows of the `EnhancedAlkanesExecutor`. It uses a mock
//! `DeezelProvider` to simulate wallet and blockchain interactions, allowing
//! for isolated testing of the core logic.

mod mock_provider;

use bitcoin::{Address, Amount, Network, OutPoint, TxOut};
use deezel_common::{
    alkanes::{
        execute::EnhancedAlkanesExecutor, AlkaneId, EnhancedExecuteParams, InputRequirement,
        OutputTarget, ProtostoneEdict, ProtostoneSpec,
    },
    DeezelError,
    traits::WalletProvider,
};

use mock_provider::MockProvider;
use std::str::FromStr;
use alkanes_support::cellpack::Cellpack;

// --- Test Cases ---

#[tokio::test]
async fn test_execute_single_transaction_success() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Setup
    let mut provider = MockProvider::new(Network::Regtest);
    let address = { WalletProvider::get_address(&provider).await.unwrap() };
    let to_addresses = vec![address.clone()];
    let funding_outpoint = OutPoint::from_str("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:0").unwrap();
    let funding_tx_out = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: Address::from_str(&address).unwrap().require_network(Network::Regtest).unwrap().script_pubkey(),
    };
    provider.utxos.lock().unwrap().push((funding_outpoint, funding_tx_out));

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses,
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 10_000 }],
        protostones: vec![
            ProtostoneSpec {
                edicts: vec![],
                cellpack: Some(Cellpack::try_from(vec![0,0,1,2,3]).unwrap()),
                bitcoin_transfer: None,
            }
        ],
        envelope_data: None,
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    // Execute
    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;

    // Assert
    assert!(result.is_ok(), "Execution failed: {:?}", result.err());
    let result = result.unwrap();
    assert!(result.commit_txid.is_none());
    assert!(!result.reveal_txid.is_empty());
    assert_eq!(provider.broadcasted_txs.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_execute_commit_reveal_success() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Setup
    let mut provider = MockProvider::new(Network::Regtest);
    let address = { WalletProvider::get_address(&provider).await.unwrap() };
    let to_addresses = vec![address.clone()];
    let funding_outpoint = OutPoint::from_str("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1:0").unwrap();
    let funding_tx_out = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: Address::from_str(&address).unwrap().require_network(Network::Regtest).unwrap().script_pubkey(),
    };
    provider.utxos.lock().unwrap().push((funding_outpoint, funding_tx_out));

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses,
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 5_000 }],
        protostones: vec![
            ProtostoneSpec {
                edicts: vec![],
                cellpack: Some(Cellpack::try_from(vec![0,0,1,2,3]).unwrap()),
                bitcoin_transfer: None,
            }
        ],
        envelope_data: Some(vec![1, 2, 3, 4]),
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    // Execute
    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;

    // Assert
    assert!(result.is_ok(), "Execution failed: {:?}", result.err());
    let result = result.unwrap();
    assert!(result.commit_txid.is_some());
    assert!(!result.reveal_txid.is_empty());
    assert_eq!(provider.broadcasted_txs.lock().unwrap().len(), 2); // Commit and Reveal
}

#[tokio::test]
async fn test_execute_insufficient_funds() {
    // Setup
    let mut provider = MockProvider::new(Network::Regtest);
    // No UTXOs added to the provider
    let to_addresses = vec![{ WalletProvider::get_address(&provider).await.unwrap() }];

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses,
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 10_000 }],
        protostones: vec![],
        envelope_data: None,
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    // Execute
    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;

    // Assert
    assert!(result.is_err());
    match result.err().unwrap() {
        DeezelError::Wallet(msg) => assert!(msg.contains("Insufficient funds")),
        e => panic!("Expected InsufficientFunds error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_protostone_validation_error() {
    // Setup
    let mut provider = MockProvider::new(Network::Regtest);
    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec![],
        change_address: None,
        input_requirements: vec![],
        protostones: vec![
            ProtostoneSpec {
                edicts: vec![
                    ProtostoneEdict {
                        alkane_id: AlkaneId { block: 1, tx: 1 },
                        amount: 100,
                        target: OutputTarget::Protostone(0), // Invalid: targets itself
                    }
                ],
                cellpack: Some(Cellpack::try_from(vec![0,0,1,2,3]).unwrap()),
                bitcoin_transfer: None,
            }
        ],
        envelope_data: None,
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    // Execute
    let result = executor.execute(params).await;

    // Assert
    assert!(result.is_err());
    match result.err().unwrap() {
        DeezelError::Validation(msg) => assert!(msg.contains("Protostone 0 refers to protostone 0 which is not allowed (must be > 0)")),
        e => panic!("Expected Validation error, got {:?}", e),
    }
}

// TODO: Add more tests for complex protostones, etc.


use bitcoin::secp256k1::{Secp256k1, All};
use bitcoin::PublicKey;

#[tokio::test]
async fn test_alkanes_execute_with_mock_provider_and_protostone() {
    let _ = env_logger::builder().is_test(true).try_init();
    
    // 1. Setup the provider
    let mut provider = MockProvider::new(Network::Regtest);
    // 2. Fund the wallet
    let address = { WalletProvider::get_address(&provider).await.unwrap() };
    let funding_outpoint = OutPoint::from_str("c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1:0").unwrap();
    let funding_tx_out = TxOut {
        value: Amount::from_sat(500_000),
        script_pubkey: Address::from_str(&address).unwrap().require_network(Network::Regtest).unwrap().script_pubkey(),
    };
    provider.utxos.lock().unwrap().push((funding_outpoint, funding_tx_out));

    // 3. Generate dynamic addresses
    let secp = Secp256k1::<All>::new();
    let to_address_1 = {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        Address::p2tr(&secp, pk.inner.x_only_public_key().0, None, Network::Regtest)
    };
    let to_address_2 = {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        Address::p2tr(&secp, pk.inner.x_only_public_key().0, None, Network::Regtest)
    };
    let to_address_3 = {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[3; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        Address::p2tr(&secp, pk.inner.x_only_public_key().0, None, Network::Regtest)
    };
    let change_address = {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[4; 32]).unwrap();
        let pk = PublicKey::new(sk.public_key(&secp));
        Address::p2tr(&secp, pk.inner.x_only_public_key().0, None, Network::Regtest)
    };

    // 4. Setup and run the executor
    let envelope_path = "/data/metashrew/deezel/examples/free_mint.wasm.gz";
    let envelope_data = std::fs::read(envelope_path).expect("Failed to read envelope");

    let protostone_str = "[3,797,101]:v0:v0";
    let protostones = deezel_common::alkanes::parsing::parse_protostones(protostone_str).unwrap();

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec![
            to_address_1.to_string(),
            to_address_2.to_string(),
            to_address_3.to_string(),
        ],
        change_address: Some(change_address.to_string()),
        input_requirements: vec![InputRequirement::Bitcoin { amount: 1000 }],
        protostones,
        envelope_data: Some(envelope_data),
        raw_output: false,
        trace_enabled: true,
        mine_enabled: true,
        auto_confirm: true,
    };

    log::info!("Executing alkanes command...");
    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;
    log::info!("Execution result: {:?}", result);

    // Assert
    assert!(result.is_ok(), "Execution failed: {:?}", result.err());
    let result = result.unwrap();
    assert!(result.commit_txid.is_some());
    assert!(!result.reveal_txid.is_empty());
}

#[tokio::test]
async fn test_execute_with_trace() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Setup
    let mut provider = MockProvider::new(Network::Regtest);
    let address = { WalletProvider::get_address(&provider).await.unwrap() };
    let to_addresses = vec![address.clone()];
    let funding_outpoint = OutPoint::from_str("d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1:0").unwrap();
    let funding_tx_out = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: Address::from_str(&address).unwrap().require_network(Network::Regtest).unwrap().script_pubkey(),
    };
    provider.utxos.lock().unwrap().push((funding_outpoint, funding_tx_out));

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses,
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 10_000 }],
        protostones: vec![
            ProtostoneSpec {
                edicts: vec![],
                cellpack: Some(Cellpack::try_from(vec![0,0,1,2,3]).unwrap()),
                bitcoin_transfer: None,
            }
        ],
        envelope_data: None,
        raw_output: false,
        trace_enabled: true,
        mine_enabled: true,
        auto_confirm: true,
    };

    // Execute
    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;

    // Assert
    assert!(result.is_ok(), "Execution failed: {:?}", result.err());
    let result = result.unwrap();
    assert!(result.traces.is_some());
    let traces = result.traces.unwrap();
    assert!(!traces.is_empty());
}
