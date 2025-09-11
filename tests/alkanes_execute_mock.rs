//! Mocked End-to-End Tests for Alkanes Execute Command
//
// This module contains tests that execute the alkanes logic against a
// mocked provider, ensuring that the transaction construction and execution
// flow work correctly without needing a live blockchain backend.

use anyhow::Result;
use deezel_common::alkanes::execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams};
use deezel_common::alkanes::types::{InputRequirement, OutputTarget, ProtostoneSpec};
use alkanes_support::id::AlkaneId;
use alkanes_support::cellpack::Cellpack;
use deezel_common::mock_provider::MockProvider;
use deezel_common::traits::WalletProvider;
use bitcoin::{Amount, Network, OutPoint, TxOut, Address, Txid, PublicKey};
use std::str::FromStr;
use bitcoin::secp256k1::{Secp256k1, rand};

async fn setup_mock_provider() -> Result<(MockProvider, Address)> {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    let address = Address::p2pkh(&PublicKey::new(public_key), Network::Regtest);

    let mut provider = MockProvider::new(Network::Regtest);
    provider.set_keypair(secret_key, bitcoin::PublicKey::new(public_key));

    // Fund the mock provider with a UTXO
    let txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")?;
    let vout = 0;
    let amount = Amount::from_sat(100_000_000); // 1 BTC
    let script_pubkey = address.script_pubkey();
    let utxo = (OutPoint::new(txid, vout), TxOut { value: amount, script_pubkey });
    provider.utxos.lock().unwrap().push(utxo);

    Ok((provider, address))
}

#[tokio::test]
async fn test_alkanes_execute_mock_preview() -> Result<()> {
    let (mut provider, change_address) = setup_mock_provider().await?;
    let to_address = WalletProvider::get_address(&provider).await?;

    let params = EnhancedExecuteParams {
        input_requirements: vec![InputRequirement::Bitcoin { amount: 10000 }],
        to_addresses: vec![to_address],
        from_addresses: None,
        change_address: Some(change_address.to_string()),
        fee_rate: Some(1.0),
        envelope_data: None,
        protostones: vec![],
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;
    assert!(result.is_ok(), "test_alkanes_execute_mock_preview failed: {:?}", result.err());

    Ok(())
}

#[tokio::test]
async fn test_alkanes_execute_with_protostone() -> Result<()> {
    let (mut provider, change_address) = setup_mock_provider().await?;
    let to_address = WalletProvider::get_address(&provider).await?;

    let protostone = ProtostoneSpec {
        bitcoin_transfer: Some(deezel_common::alkanes::types::BitcoinTransfer {
            target: OutputTarget::Output(0),
            amount: 5000,
        }),
        edicts: vec![],
        cellpack: Some(Cellpack {
            target: AlkaneId { block: 0, tx: 0 },
            inputs: vec![1, 2, 3],
        }),
    };

    let params = EnhancedExecuteParams {
        input_requirements: vec![],
        to_addresses: vec![to_address],
        from_addresses: None,
        change_address: Some(change_address.to_string()),
        fee_rate: Some(1.0),
        envelope_data: None,
        protostones: vec![protostone],
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;
    assert!(result.is_ok(), "test_alkanes_execute_with_protostone failed: {:?}", result.err());

    Ok(())
}

#[tokio::test]
async fn test_alkanes_execute_with_envelope() -> Result<()> {
    let (mut provider, change_address) = setup_mock_provider().await?;
    let to_address = WalletProvider::get_address(&provider).await?;

    let envelope_data = b"hello world".to_vec();

    let params = EnhancedExecuteParams {
        input_requirements: vec![],
        to_addresses: vec![to_address],
        from_addresses: None,
        change_address: Some(change_address.to_string()),
        fee_rate: Some(1.0),
        envelope_data: Some(envelope_data),
        protostones: vec![ProtostoneSpec {
            bitcoin_transfer: None,
            edicts: vec![],
            cellpack: Some(Cellpack {
                target: AlkaneId { block: 0, tx: 0 },
                inputs: vec![1, 2, 3],
            }),
        }],
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    let mut executor = EnhancedAlkanesExecutor::new(&mut provider);
    let result = executor.execute(params).await;
    assert!(result.is_ok(), "test_alkanes_execute_with_envelope failed: {:?}", result.err());

    Ok(())
}
