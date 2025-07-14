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

use deezel_common::alkanes::execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams, ProtostoneSpec, InputRequirement, OutputTarget};
use deezel_common::alkanes::types::{AlkaneId, ProtostoneEdict, EnhancedExecuteResult};
use deezel_common::{DeezelProvider, DeezelError, Result, JsonValue, AddressResolver, OrdProvider};
use deezel_common::traits::*;
use bitcoin::{Address, Network, OutPoint, Transaction, TxOut, XOnlyPublicKey, psbt::Psbt, Amount};
use bitcoin::secp256k1::{Secp256k1, All, Message, schnorr, SecretKey};
use bitcoin::key::Keypair;
use std::str::FromStr;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::pin::Pin;
use std::future::Future;


// --- Mock DeezelProvider Implementation ---

#[derive(Clone)]
struct MockDeezelProvider {
    secp: Secp256k1<All>,
    secret_key: SecretKey,
    internal_key: XOnlyPublicKey,
    utxos: Arc<Mutex<Vec<TxOut>>>,
    broadcasted_txs: Arc<Mutex<Vec<String>>>,
}

impl MockDeezelProvider {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let (internal_key, _) = public_key.x_only_public_key();
        
        Self {
            secp,
            secret_key,
            internal_key,
            utxos: Arc::new(Mutex::new(vec![])),
            broadcasted_txs: Arc::new(Mutex::new(vec![])),
        }
    }

    fn add_utxo(&self, utxo: TxOut) {
        self.utxos.lock().unwrap().push(utxo);
    }
}

#[async_trait(?Send)]
impl DeezelProvider for MockDeezelProvider {
    fn provider_name(&self) -> &str { "MockDeezelProvider" }

    fn clone_box(&self) -> Box<dyn DeezelProvider> {
        Box::new(self.clone())
    }

    async fn initialize(&self) -> Result<()> { Ok(()) }
    async fn shutdown(&self) -> Result<()> { Ok(()) }

    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        let utxos = self.utxos.lock().unwrap();
        // This is a mock, so we can't look up the txid. We'll just return the first one.
        // A real implementation would need to find the correct one.
        Ok(utxos.iter().find(|_u| true).cloned())
    }

    async fn sign_taproot_script_spend(&self, sighash: Message) -> Result<schnorr::Signature> {
        let keypair = Keypair::from_secret_key(&self.secp, &self.secret_key);
        Ok(self.secp.sign_schnorr(&sighash, &keypair))
    }
}

#[async_trait(?Send)]
impl WalletProvider for MockDeezelProvider {
    fn get_network(&self) -> Network {
        Network::Regtest
    }

    async fn get_address(&self) -> Result<String> {
        let address = Address::p2tr(&self.secp, self.internal_key, None, Network::Regtest);
        Ok(address.to_string())
    }
    
    async fn get_internal_key(&self) -> Result<XOnlyPublicKey> {
        Ok(self.internal_key)
    }

    async fn get_utxos(&self, _include_frozen: bool, _addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>> {
        // This is a simplified mock. A real implementation would need to construct UtxoInfo properly.
        Ok(vec![])
    }

    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String> {
        let txid = bitcoin::consensus::deserialize::<Transaction>(&hex::decode(&tx_hex).unwrap()).unwrap().compute_txid().to_string();
        self.broadcasted_txs.lock().unwrap().push(tx_hex);
        Ok(txid)
    }

    async fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        Ok(psbt.clone())
    }
    
    async fn get_keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_secret_key(&self.secp, &self.secret_key))
    }

    // --- Unimplemented Methods ---
    async fn create_wallet(&self, _config: WalletConfig, _mnemonic: Option<String>, _passphrase: Option<String>) -> Result<WalletInfo> { todo!() }
    async fn load_wallet(&self, _config: WalletConfig, _passphrase: Option<String>) -> Result<WalletInfo> { todo!() }
    async fn get_balance(&self, _addresses: Option<Vec<String>>) -> Result<WalletBalance> { todo!() }
    async fn get_addresses(&self, _count: u32) -> Result<Vec<AddressInfo>> { todo!() }
    async fn send(&self, _params: SendParams) -> Result<String> { todo!() }
    async fn get_history(&self, _count: u32, _address: Option<String>) -> Result<Vec<TransactionInfo>> { todo!() }
    async fn freeze_utxo(&self, _utxo: String, _reason: Option<String>) -> Result<()> { todo!() }
    async fn unfreeze_utxo(&self, _utxo: String) -> Result<()> { todo!() }
    async fn create_transaction(&self, _params: SendParams) -> Result<String> { todo!() }
    async fn sign_transaction(&self, _tx_hex: String) -> Result<String> { todo!() }
    async fn estimate_fee(&self, _target: u32) -> Result<FeeEstimate> { todo!() }
    async fn get_fee_rates(&self) -> Result<FeeRates> { todo!() }
    async fn sync(&self) -> Result<()> { todo!() }
    async fn backup(&self) -> Result<String> { todo!() }
    async fn get_mnemonic(&self) -> Result<Option<String>> { todo!() }
    fn set_passphrase(&mut self, _passphrase: Option<String>) { todo!() }
}

#[async_trait(?Send)]
impl BitcoinRpcProvider for MockDeezelProvider {
    async fn get_block_count(&self) -> Result<u64> { Ok(100) }
    async fn generate_to_address(&self, _nblocks: u32, _address: &str) -> Result<JsonValue> { Ok(serde_json::json!([])) }
    async fn get_new_address(&self) -> Result<JsonValue> { todo!() }
    async fn get_transaction_hex(&self, _txid: &str) -> Result<String> { Ok("".to_string()) }
    async fn get_block(&self, _hash: &str) -> Result<JsonValue> { todo!() }
    async fn get_block_hash(&self, _height: u64) -> Result<String> { todo!() }
    async fn send_raw_transaction(&self, _tx_hex: &str) -> Result<String> { todo!() }
    async fn get_mempool_info(&self) -> Result<JsonValue> { todo!() }
    async fn estimate_smart_fee(&self, _target: u32) -> Result<JsonValue> { todo!() }
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64> { todo!() }
    async fn trace_transaction(&self, _txid: &str, _vout: u32, _block: Option<&str>, _tx: Option<&str>) -> Result<serde_json::Value> { todo!() }
}

#[async_trait(?Send)]
impl MetashrewRpcProvider for MockDeezelProvider {
    async fn get_metashrew_height(&self) -> Result<u64> { Ok(100) }
    async fn get_contract_meta(&self, _block: &str, _tx: &str) -> Result<JsonValue> { todo!() }
    async fn trace_outpoint(&self, _txid: &str, _vout: u32) -> Result<JsonValue> { Ok(serde_json::json!({ "trace": "success" })) }
    async fn get_spendables_by_address(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_protorunes_by_address(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_protorunes_by_outpoint(&self, _txid: &str, _vout: u32) -> Result<JsonValue> { todo!() }
}

#[async_trait(?Send)]
impl TimeProvider for MockDeezelProvider {
    fn now_secs(&self) -> u64 { todo!() }
    fn now_millis(&self) -> u64 { todo!() }
    async fn sleep_ms(&self, _ms: u64) { todo!() }
}
#[async_trait(?Send)]
impl LogProvider for MockDeezelProvider {
    fn debug(&self, _message: &str) { todo!() }
    fn info(&self, _message: &str) { todo!() }
    fn warn(&self, _message: &str) { todo!() }
    fn error(&self, _message: &str) { todo!() }
}
#[async_trait(?Send)]
impl PgpProvider for MockDeezelProvider {
    async fn generate_keypair(&self, _user_id: &str, _passphrase: Option<&str>) -> Result<PgpKeyPair> { todo!() }
    async fn import_key(&self, _armored_key: &str) -> Result<PgpKey> { todo!() }
    async fn export_key(&self, _key: &PgpKey, _include_private: bool) -> Result<String> { todo!() }
    async fn encrypt(&self, _data: &[u8], _recipient_keys: &[PgpKey], _armor: bool) -> Result<Vec<u8>> { todo!() }
    async fn decrypt(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>) -> Result<Vec<u8>> { todo!() }
    async fn sign(&self, _data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> { todo!() }
    async fn verify(&self, _data: &[u8], _signature: &[u8], _public_key: &PgpKey) -> Result<bool> { todo!() }
    async fn encrypt_and_sign(&self, _data: &[u8], _recipient_keys: &[PgpKey], _signing_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> { todo!() }
    async fn decrypt_and_verify(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _sender_public_key: &PgpKey, _passphrase: Option<&str>) -> Result<PgpDecryptResult> { todo!() }
    async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>> { todo!() }
    async fn get_key(&self, _identifier: &str) -> Result<Option<PgpKey>> { todo!() }
    async fn delete_key(&self, _identifier: &str) -> Result<()> { todo!() }
    async fn change_passphrase(&self, _key: &PgpKey, _old_passphrase: Option<&str>, _new_passphrase: Option<&str>) -> Result<PgpKey> { todo!() }
}
#[async_trait(?Send)]
impl CryptoProvider for MockDeezelProvider {
    fn random_bytes(&self, _len: usize) -> Result<Vec<u8>> { todo!() }
    fn sha256(&self, _data: &[u8]) -> Result<[u8; 32]> { todo!() }
    fn sha3_256(&self, _data: &[u8]) -> Result<[u8; 32]> { todo!() }
    async fn encrypt_aes_gcm(&self, _data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> { todo!() }
    async fn decrypt_aes_gcm(&self, _data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> { todo!() }
    async fn pbkdf2_derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, _key_len: usize) -> Result<Vec<u8>> { todo!() }
}
#[async_trait(?Send)]
impl NetworkProvider for MockDeezelProvider {
    async fn get(&self, _url: &str) -> Result<Vec<u8>> { todo!() }
    async fn post(&self, _url: &str, _body: &[u8], _content_type: &str) -> Result<Vec<u8>> { todo!() }
    async fn is_reachable(&self, _url: &str) -> bool { todo!() }
}
#[async_trait(?Send)]
impl StorageProvider for MockDeezelProvider {
    async fn read(&self, _key: &str) -> Result<Vec<u8>> { todo!() }
    async fn write(&self, _key: &str, _data: &[u8]) -> Result<()> { todo!() }
    async fn exists(&self, _key: &str) -> Result<bool> { todo!() }
    async fn delete(&self, _key: &str) -> Result<()> { todo!() }
    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>> { todo!() }
    fn storage_type(&self) -> &'static str { todo!() }
}
#[async_trait(?Send)]
impl JsonRpcProvider for MockDeezelProvider {
    async fn call(&self, _url: &str, _method: &str, _params: JsonValue, _id: u64) -> Result<JsonValue> { todo!() }
    async fn get_bytecode(&self, _block: &str, _tx: &str) -> Result<String> { todo!() }
}
#[async_trait(?Send)]
impl EsploraProvider for MockDeezelProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> { todo!() }
    async fn get_blocks_tip_height(&self) -> Result<u64> { todo!() }
    async fn get_blocks(&self, _start_height: Option<u64>) -> Result<JsonValue> { todo!() }
    async fn get_block_by_height(&self, _height: u64) -> Result<String> { todo!() }
    async fn get_block(&self, _hash: &str) -> Result<JsonValue> { todo!() }
    async fn get_block_status(&self, _hash: &str) -> Result<JsonValue> { todo!() }
    async fn get_block_txids(&self, _hash: &str) -> Result<JsonValue> { todo!() }
    async fn get_block_header(&self, _hash: &str) -> Result<String> { todo!() }
    async fn get_block_raw(&self, _hash: &str) -> Result<String> { todo!() }
    async fn get_block_txid(&self, _hash: &str, _index: u32) -> Result<String> { todo!() }
    async fn get_block_txs(&self, _hash: &str, _start_index: Option<u32>) -> Result<JsonValue> { todo!() }
    async fn get_address_info(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_address(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_address_txs(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_address_txs_chain(&self, _address: &str, _last_seen_txid: Option<&str>) -> Result<JsonValue> { todo!() }
    async fn get_address_txs_mempool(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_address_utxo(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn get_address_prefix(&self, _prefix: &str) -> Result<JsonValue> { todo!() }
    async fn get_tx(&self, _txid: &str) -> Result<JsonValue> { todo!() }
    async fn get_tx_hex(&self, _txid: &str) -> Result<String> { todo!() }
    async fn get_tx_raw(&self, _txid: &str) -> Result<String> { todo!() }
    async fn get_tx_status(&self, _txid: &str) -> Result<JsonValue> { todo!() }
    async fn get_tx_merkle_proof(&self, _txid: &str) -> Result<JsonValue> { todo!() }
    async fn get_tx_merkleblock_proof(&self, _txid: &str) -> Result<String> { todo!() }
    async fn get_tx_outspend(&self, _txid: &str, _index: u32) -> Result<JsonValue> { todo!() }
    async fn get_tx_outspends(&self, _txid: &str) -> Result<JsonValue> { todo!() }
    async fn broadcast(&self, _tx_hex: &str) -> Result<String> { todo!() }
    async fn get_mempool(&self) -> Result<JsonValue> { todo!() }
    async fn get_mempool_txids(&self) -> Result<JsonValue> { todo!() }
    async fn get_mempool_recent(&self) -> Result<JsonValue> { todo!() }
    async fn get_fee_estimates(&self) -> Result<JsonValue> { todo!() }
}
#[async_trait(?Send)]
impl RunestoneProvider for MockDeezelProvider {
    async fn decode_runestone(&self, _tx: &Transaction) -> Result<JsonValue> { todo!() }
    async fn format_runestone_with_decoded_messages(&self, _tx: &Transaction) -> Result<JsonValue> { todo!() }
    async fn analyze_runestone(&self, _txid: &str) -> Result<JsonValue> { todo!() }
}
#[async_trait(?Send)]
impl AlkanesProvider for MockDeezelProvider {
    async fn execute(&self, _params: EnhancedExecuteParams) -> Result<deezel_common::alkanes::types::EnhancedExecuteResult> { todo!() }
    async fn protorunes_by_address(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn protorunes_by_outpoint(&self, _txid: &str, _vout: u32) -> Result<protorune_support::proto::protorune::OutpointResponse> { todo!() }
    async fn simulate(&self, _contract_id: &str, _params: Option<&str>) -> Result<JsonValue> { todo!() }
    async fn trace(&self, _outpoint: &str) -> Result<alkanes_support::proto::alkanes::Trace> { todo!() }
    async fn get_block(&self, _height: u64) -> Result<alkanes_support::proto::alkanes::BlockResponse> { todo!() }
    async fn sequence(&self, _txid: &str, _vout: u32) -> Result<JsonValue> { todo!() }
    async fn spendables_by_address(&self, _address: &str) -> Result<JsonValue> { todo!() }
    async fn trace_block(&self, _height: u64) -> Result<alkanes_support::proto::alkanes::Trace> { todo!() }
    async fn get_bytecode(&self, _alkane_id: &str) -> Result<String> { todo!() }
    async fn inspect(&self, _target: &str, _config: deezel_common::alkanes::AlkanesInspectConfig) -> Result<deezel_common::alkanes::AlkanesInspectResult> { todo!() }
    async fn get_balance(&self, _address: Option<&str>) -> Result<Vec<deezel_common::alkanes::AlkaneBalance>> { todo!() }
}
#[async_trait(?Send)]
impl MonitorProvider for MockDeezelProvider {
    async fn monitor_blocks(&self, _start: Option<u64>) -> Result<()> { todo!() }
    async fn get_block_events(&self, _height: u64) -> Result<Vec<BlockEvent>> { todo!() }
}
#[async_trait(?Send)]
impl KeystoreProvider for MockDeezelProvider {
    async fn derive_addresses(&self, _master_public_key: &str, _network: Network, _script_types: &[&str], _start_index: u32, _count: u32) -> Result<Vec<KeystoreAddress>> { todo!() }
    async fn get_default_addresses(&self, _master_public_key: &str, _network: Network) -> Result<Vec<KeystoreAddress>> { todo!() }
    fn parse_address_range(&self, _range_spec: &str) -> Result<(String, u32, u32)> { todo!() }
    async fn get_keystore_info(&self, _master_public_key: &str, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> { todo!() }
}
#[async_trait(?Send)]
impl AddressResolver for MockDeezelProvider {
    async fn resolve_all_identifiers(&self, _input: &str) -> Result<String> { todo!() }
    fn contains_identifiers(&self, _input: &str) -> bool { todo!() }
    async fn get_address(&self, _address_type: &str, _index: u32) -> Result<String> { todo!() }
    async fn list_identifiers(&self) -> Result<Vec<String>> { todo!() }
}
#[async_trait(?Send)]
impl OrdProvider for MockDeezelProvider {
    async fn get_inscription(&self, _inscription_id: &str) -> Result<deezel_common::ord::Inscription> { todo!() }
    async fn get_inscriptions_in_block(&self, _block_hash: &str) -> Result<deezel_common::ord::Inscriptions> { todo!() }
    async fn get_ord_address_info(&self, _address: &str) -> Result<deezel_common::ord::AddressInfo> { todo!() }
    async fn get_block_info(&self, _query: &str) -> Result<deezel_common::ord::Block> { todo!() }
    async fn get_ord_block_count(&self) -> Result<u64> { todo!() }
    async fn get_ord_blocks(&self) -> Result<deezel_common::ord::Blocks> { todo!() }
    async fn get_children(&self, _inscription_id: &str, _page: Option<u32>) -> Result<deezel_common::ord::Children> { todo!() }
    async fn get_content(&self, _inscription_id: &str) -> Result<Vec<u8>> { todo!() }
    async fn get_inscriptions(&self, _page: Option<u32>) -> Result<deezel_common::ord::Inscriptions> { todo!() }
    async fn get_output(&self, _output: &str) -> Result<deezel_common::ord::Output> { todo!() }
    async fn get_parents(&self, _inscription_id: &str, _page: Option<u32>) -> Result<deezel_common::ord::ParentInscriptions> { todo!() }
    async fn get_rune(&self, _rune: &str) -> Result<deezel_common::ord::RuneInfo> { todo!() }
    async fn get_runes(&self, _page: Option<u32>) -> Result<deezel_common::ord::Runes> { todo!() }
    async fn get_sat(&self, _sat: u64) -> Result<deezel_common::ord::SatResponse> { todo!() }
    async fn get_tx_info(&self, _txid: &str) -> Result<deezel_common::ord::TxInfo> { todo!() }
}

// --- Test Cases ---

#[tokio::test]
async fn test_execute_single_transaction_success() {
    // Setup
    let provider = MockDeezelProvider::new();
    let executor = EnhancedAlkanesExecutor::new(&provider);
    
    let funding_utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: Address::from_str("bcrt1p3zaeam33npp4u22a82xmgpy22qs53mtg4g63q648gqg5wzayxvaq6z2wgd").unwrap().require_network(Network::Regtest).unwrap().script_pubkey(),
    };
    provider.add_utxo(funding_utxo);

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bcrt1qkz4ed2zscf3je3n2g2sxwornz2nsv043z2g2h2".to_string()],
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 10_000 }],
        protostones: vec![
            ProtostoneSpec {
                edicts: vec![],
                cellpack: None,
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
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.commit_txid.is_none());
    assert!(!result.reveal_txid.is_empty());
    assert_eq!(provider.broadcasted_txs.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_execute_commit_reveal_success() {
    // Setup
    let provider = MockDeezelProvider::new();
    let executor = EnhancedAlkanesExecutor::new(&provider);

    let funding_utxo = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: Address::from_str("bcrt1p3zaeam33npp4u22a82xmgpy22qs53mtg4g63q648gqg5wzayxvaq6z2wgd").unwrap().require_network(Network::Regtest).unwrap().script_pubkey(),
    };
    provider.add_utxo(funding_utxo);

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bcrt1qkz4ed2zscf3je3n2g2sxwornz2nsv043z2g2h2".to_string()],
        change_address: None,
        input_requirements: vec![InputRequirement::Bitcoin { amount: 5_000 }],
        protostones: vec![],
        envelope_data: Some(vec![1, 2, 3, 4]),
        raw_output: false,
        trace_enabled: false,
        mine_enabled: false,
        auto_confirm: true,
    };

    // Execute
    let result = executor.execute(params).await;

    // Assert
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.commit_txid.is_some());
    assert!(!result.reveal_txid.is_empty());
    assert_eq!(provider.broadcasted_txs.lock().unwrap().len(), 2); // Commit and Reveal
}

#[tokio::test]
async fn test_execute_insufficient_funds() {
    // Setup
    let provider = MockDeezelProvider::new();
    let executor = EnhancedAlkanesExecutor::new(&provider);

    // No UTXOs added to the provider

    let params = EnhancedExecuteParams {
        fee_rate: Some(1.0),
        to_addresses: vec!["bcrt1qkz4ed2zscf3je3n2g2sxwornz2nsv043z2g2h2".to_string()],
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
    let provider = MockDeezelProvider::new();
    let executor = EnhancedAlkanesExecutor::new(&provider);

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
                cellpack: None,
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
        DeezelError::Validation(msg) => assert!(msg.contains("refers to protostone 0 which is not allowed")),
        e => panic!("Expected Validation error, got {:?}", e),
    }
}

// TODO: Add more tests for complex protostones, etc.
