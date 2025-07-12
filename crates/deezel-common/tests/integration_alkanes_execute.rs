//! Integration tests for alkanes execute functionality

use deezel_common::*;
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::anyhow;
use tokio::sync::Mutex;
use bitcoin::{Address, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use std::str::FromStr;

/// Mock provider for testing alkanes execute functionality
#[derive(Clone)]
struct MockAlkanesProvider {
    storage: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    rpc_responses: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    broadcasted_txs: Arc<Mutex<Vec<String>>>,
}

impl MockAlkanesProvider {
    fn new() -> Self {
        let mut rpc_responses = HashMap::new();
        rpc_responses.insert("getblockcount".to_string(), serde_json::json!(800000));
        rpc_responses.insert("getblockhash".to_string(), serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000"));
        rpc_responses.insert("sendrawtransaction".to_string(), serde_json::json!("abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234"));
        rpc_responses.insert("metashrew_height".to_string(), serde_json::json!(800000));
        rpc_responses.insert("metashrew_view".to_string(), serde_json::json!({ "bytecode": "0x" }));
        
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
            rpc_responses: Arc::new(Mutex::new(rpc_responses)),
            broadcasted_txs: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl traits::JsonRpcProvider for MockAlkanesProvider {
    async fn call(&self, _url: &str, method: &str, _params: serde_json::Value, _id: u64) -> deezel_common::Result<serde_json::Value> {
        let responses = self.rpc_responses.lock().await;
        Ok(responses.get(method).cloned().unwrap_or(serde_json::json!(null)))
    }
    async fn get_bytecode(&self, _block: &str, _tx: &str) -> deezel_common::Result<String> { Ok("0x".to_string()) }
}

#[async_trait::async_trait(?Send)]
impl traits::StorageProvider for MockAlkanesProvider {
    async fn read(&self, key: &str) -> deezel_common::Result<Vec<u8>> { self.storage.lock().await.get(key).cloned().ok_or_else(|| DeezelError::Storage(format!("Key not found: {}", key))) }
    async fn write(&self, key: &str, data: &[u8]) -> deezel_common::Result<()> { self.storage.lock().await.insert(key.to_string(), data.to_vec()); Ok(()) }
    async fn exists(&self, key: &str) -> deezel_common::Result<bool> { Ok(self.storage.lock().await.contains_key(key)) }
    async fn delete(&self, key: &str) -> deezel_common::Result<()> { self.storage.lock().await.remove(key); Ok(()) }
    async fn list_keys(&self, prefix: &str) -> deezel_common::Result<Vec<String>> { Ok(self.storage.lock().await.keys().filter(|k| k.starts_with(prefix)).cloned().collect()) }
    fn storage_type(&self) -> &'static str { "mock" }
}

#[async_trait::async_trait(?Send)]
impl traits::NetworkProvider for MockAlkanesProvider {
    async fn get(&self, _url: &str) -> deezel_common::Result<Vec<u8>> { Ok(b"mock response".to_vec()) }
    async fn post(&self, _url: &str, _body: &[u8], _content_type: &str) -> deezel_common::Result<Vec<u8>> { Ok(b"mock response".to_vec()) }
    async fn is_reachable(&self, _url: &str) -> bool { true }
}

#[async_trait::async_trait(?Send)]
impl traits::CryptoProvider for MockAlkanesProvider {
    fn random_bytes(&self, len: usize) -> deezel_common::Result<Vec<u8>> { Ok(vec![0u8; len]) }
    fn sha256(&self, data: &[u8]) -> deezel_common::Result<[u8; 32]> { use sha2::{Sha256, Digest}; let mut hasher = Sha256::new(); hasher.update(data); Ok(hasher.finalize().into()) }
    fn sha3_256(&self, data: &[u8]) -> deezel_common::Result<[u8; 32]> { use sha3::{Sha3_256, Digest}; let mut hasher = Sha3_256::new(); hasher.update(data); Ok(hasher.finalize().into()) }
    async fn encrypt_aes_gcm(&self, data: &[u8], _key: &[u8], _nonce: &[u8]) -> deezel_common::Result<Vec<u8>> { Ok(data.to_vec()) }
    async fn decrypt_aes_gcm(&self, data: &[u8], _key: &[u8], _nonce: &[u8]) -> deezel_common::Result<Vec<u8>> { Ok(data.to_vec()) }
    async fn pbkdf2_derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, key_len: usize) -> deezel_common::Result<Vec<u8>> { Ok(vec![0u8; key_len]) }
}

impl traits::TimeProvider for MockAlkanesProvider {
    fn now_secs(&self) -> u64 { 1640995200 }
    fn now_millis(&self) -> u64 { 1640995200000 }
    #[cfg(not(target_arch = "wasm32"))]
    fn sleep_ms(&self, ms: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
    }

    #[cfg(target_arch = "wasm32")]
    fn sleep_ms(&self, ms: u64) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()>>> {
        Box::pin(gloo_timers::future::sleep(std::time::Duration::from_millis(ms)))
    }
}

impl traits::LogProvider for MockAlkanesProvider {
    fn debug(&self, _message: &str) {}
    fn info(&self, _message: &str) {}
    fn warn(&self, _message: &str) {}
    fn error(&self, _message: &str) {}
}

#[async_trait::async_trait(?Send)]
impl traits::WalletProvider for MockAlkanesProvider {
    async fn create_wallet(&self, _config: traits::WalletConfig, _mnemonic: Option<String>, _passphrase: Option<String>) -> deezel_common::Result<traits::WalletInfo> { Ok(traits::WalletInfo { address: "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297".to_string(), network: bitcoin::Network::Regtest, mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()) }) }
    async fn load_wallet(&self, config: traits::WalletConfig, passphrase: Option<String>) -> deezel_common::Result<traits::WalletInfo> { self.create_wallet(config, None, passphrase).await }
    async fn get_balance(&self) -> deezel_common::Result<traits::WalletBalance> { Ok(traits::WalletBalance { confirmed: 100_000_000, trusted_pending: 0, untrusted_pending: 0 }) }
    async fn get_address(&self) -> deezel_common::Result<String> { Ok("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297".to_string()) }
    async fn get_addresses(&self, count: u32) -> deezel_common::Result<Vec<traits::AddressInfo>> { Ok((0..count).map(|i| traits::AddressInfo { address: format!("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg329{}", i), script_type: "p2tr".to_string(), derivation_path: format!("m/86'/0'/0'/0/{}", i), index: i, used: false }).collect()) }
    async fn send(&self, _params: traits::SendParams) -> deezel_common::Result<String> { Ok("abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234".to_string()) }
    async fn get_utxos(&self, _include_frozen: bool, _addresses: Option<Vec<String>>) -> deezel_common::Result<Vec<traits::UtxoInfo>> { Ok(vec![traits::UtxoInfo { txid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(), vout: 0, amount: 50_000_000, address: "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297".to_string(), script_pubkey: Some(bitcoin::script::Builder::new().push_int(1).into_script()), confirmations: 6, frozen: false, freeze_reason: None, block_height: Some(799994), has_inscriptions: false, has_runes: false, has_alkanes: false, is_coinbase: false }]) }
    async fn get_history(&self, _count: u32, _address: Option<String>) -> deezel_common::Result<Vec<traits::TransactionInfo>> { Ok(vec![]) }
    async fn freeze_utxo(&self, _utxo: String, _reason: Option<String>) -> deezel_common::Result<()> { Ok(()) }
    async fn unfreeze_utxo(&self, _utxo: String) -> deezel_common::Result<()> { Ok(()) }
    async fn create_transaction(&self, _params: traits::SendParams) -> deezel_common::Result<String> { Ok("020000000001011234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef0000000000ffffffff0100e1f50500000000160014deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0000000000".to_string()) }
    async fn sign_transaction(&self, tx_hex: String) -> deezel_common::Result<String> { Ok(tx_hex) }
    async fn broadcast_transaction(&self, tx_hex: String) -> deezel_common::Result<String> { self.broadcasted_txs.lock().await.push(tx_hex); Ok("abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234".to_string()) }
    async fn estimate_fee(&self, _target: u32) -> deezel_common::Result<traits::FeeEstimate> { Ok(traits::FeeEstimate { fee_rate: 5.0, target_blocks: 6 }) }
    async fn get_fee_rates(&self) -> deezel_common::Result<traits::FeeRates> { Ok(traits::FeeRates { fast: 10.0, medium: 5.0, slow: 1.0 }) }
    async fn sync(&self) -> deezel_common::Result<()> { Ok(()) }
    async fn backup(&self) -> deezel_common::Result<String> { Ok("mock backup data".to_string()) }
    async fn get_mnemonic(&self) -> deezel_common::Result<Option<String>> { Ok(Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())) }
    fn get_network(&self) -> bitcoin::Network { bitcoin::Network::Regtest }
    async fn get_internal_key(&self) -> deezel_common::Result<bitcoin::XOnlyPublicKey> { let bytes = [1u8; 32]; bitcoin::XOnlyPublicKey::from_slice(&bytes).map_err(|e| DeezelError::Crypto(e.to_string())) }
    async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> deezel_common::Result<bitcoin::psbt::Psbt> { Ok(psbt.clone()) }
    async fn get_keypair(&self) -> deezel_common::Result<bitcoin::secp256k1::Keypair> { use bitcoin::secp256k1::{Secp256k1, SecretKey}; let secp = Secp256k1::new(); let secret_key = SecretKey::from_slice(&[1u8; 32]).map_err(|e| DeezelError::Crypto(e.to_string()))?; Ok(bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key)) }
    fn set_passphrase(&mut self, _passphrase: Option<String>) {}
}

#[async_trait::async_trait(?Send)]
impl traits::AddressResolver for MockAlkanesProvider {
    async fn resolve_all_identifiers(&self, input: &str) -> deezel_common::Result<String> { Ok(input.to_string()) }
    fn contains_identifiers(&self, _input: &str) -> bool { false }
    async fn get_address(&self, _address_type: &str, _index: u32) -> deezel_common::Result<String> { Ok("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297".to_string()) }
    async fn list_identifiers(&self) -> deezel_common::Result<Vec<String>> { Ok(vec!["p2tr:0".to_string(), "p2wpkh:0".to_string()]) }
}

#[async_trait::async_trait(?Send)]
impl traits::BitcoinRpcProvider for MockAlkanesProvider {
    async fn get_block_count(&self) -> deezel_common::Result<u64> { Ok(800000) }
    async fn generate_to_address(&self, _nblocks: u32, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!(["0000000000000000000000000000000000000000000000000000000000000000"])) }
    async fn get_new_address(&self) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297")) }
    async fn get_transaction_hex(&self, _txid: &str) -> deezel_common::Result<String> { Ok("0200000001".to_string()) }
    async fn get_block(&self, _hash: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_block_hash(&self, _height: u64) -> deezel_common::Result<String> { Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string()) }
    async fn send_raw_transaction(&self, tx_hex: &str) -> deezel_common::Result<String> { self.broadcasted_txs.lock().await.push(tx_hex.to_string()); Ok("abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234".to_string()) }
    async fn get_mempool_info(&self) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn estimate_smart_fee(&self, _target: u32) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({"feerate": 0.00005})) }
    async fn get_esplora_blocks_tip_height(&self) -> deezel_common::Result<u64> { Ok(800000) }
    async fn trace_transaction(&self, _txid: &str, _vout: u32, _block: Option<&str>, _tx: Option<&str>) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
}

#[async_trait::async_trait(?Send)]
impl traits::MetashrewRpcProvider for MockAlkanesProvider {
    async fn get_metashrew_height(&self) -> deezel_common::Result<u64> { Ok(800000) }
    async fn get_contract_meta(&self, _block: &str, _tx: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn trace_outpoint(&self, _txid: &str, _vout: u32) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_spendables_by_address(&self, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_protorunes_by_address(&self, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_protorunes_by_outpoint(&self, _txid: &str, _vout: u32) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
}

#[async_trait::async_trait(?Send)]
impl traits::EsploraProvider for MockAlkanesProvider {
    async fn get_blocks_tip_hash(&self) -> deezel_common::Result<String> { Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string()) }
    async fn get_blocks_tip_height(&self) -> deezel_common::Result<u64> { Ok(800000) }
    async fn get_blocks(&self, _start_height: Option<u64>) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_block_by_height(&self, _height: u64) -> deezel_common::Result<String> { Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string()) }
    async fn get_block(&self, _hash: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_block_status(&self, _hash: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_block_txids(&self, _hash: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_block_header(&self, _hash: &str) -> deezel_common::Result<String> { Ok("".to_string()) }
    async fn get_block_raw(&self, _hash: &str) -> deezel_common::Result<String> { Ok("".to_string()) }
    async fn get_block_txid(&self, _hash: &str, _index: u32) -> deezel_common::Result<String> { Ok("0000000000000000000000000000000000000000000000000000000000000000".to_string()) }
    async fn get_block_txs(&self, _hash: &str, _start_index: Option<u32>) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_address(&self, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_address_txs(&self, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_address_txs_chain(&self, _address: &str, _last_seen_txid: Option<&str>) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_address_txs_mempool(&self, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_address_utxo(&self, _address: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_address_prefix(&self, _prefix: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_tx(&self, _txid: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_tx_hex(&self, _txid: &str) -> deezel_common::Result<String> { Ok("0200000001".to_string()) }
    async fn get_tx_raw(&self, _txid: &str) -> deezel_common::Result<String> { Ok("0200000001".to_string()) }
    async fn get_tx_status(&self, _txid: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_tx_merkle_proof(&self, _txid: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_tx_merkleblock_proof(&self, _txid: &str) -> deezel_common::Result<String> { Ok("".to_string()) }
    async fn get_tx_outspend(&self, _txid: &str, _index: u32) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_tx_outspends(&self, _txid: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn broadcast(&self, _tx_hex: &str) -> deezel_common::Result<String> { Ok("abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234".to_string()) }
    async fn get_mempool(&self) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn get_mempool_txids(&self) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_mempool_recent(&self) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!([])) }
    async fn get_fee_estimates(&self) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
}

#[async_trait::async_trait(?Send)]
impl traits::RunestoneProvider for MockAlkanesProvider {
    async fn decode_runestone(&self, _tx: &bitcoin::Transaction) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn format_runestone_with_decoded_messages(&self, _tx: &bitcoin::Transaction) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn analyze_runestone(&self, _txid: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
}

#[async_trait::async_trait(?Send)]
impl traits::AlkanesProvider for MockAlkanesProvider {
    async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        let protostones = alkanes::execute::parse_protostones(&params.protostones)?;
        
        let mut all_edicts = Vec::new();
        for spec in &protostones {
            for edict_spec in &spec.edicts {
                all_edicts.push(ordinals::Edict {
                    id: ordinals::RuneId { block: edict_spec.alkane_id.block, tx: edict_spec.alkane_id.tx as u32 },
                    amount: edict_spec.amount as u128,
                    output: match edict_spec.target {
                        alkanes::execute::OutputTarget::Output(v) => v,
                        _ => 0,
                    },
                });
            }
        }

        let runestone = ordinals::Runestone {
            edicts: all_edicts,
            ..Default::default()
        };

        let script_pubkey = runestone.encipher();

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Default::default(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(0), script_pubkey },
                TxOut { value: Amount::from_sat(546), script_pubkey: Address::from_str(&params.to).map_err(|e| DeezelError::JsonRpc(e.to_string()))?.require_network(bitcoin::Network::Regtest).map_err(|e| DeezelError::JsonRpc(e.to_string()))?.script_pubkey() }
            ],
        };
        
        let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
        self.broadcasted_txs.lock().await.push(tx_hex);

        Ok(AlkanesExecuteResult {
            commit_txid: Some("0000000000000000000000000000000000000000000000000000000000000000".to_string()),
            reveal_txid: tx.compute_txid().to_string(),
            commit_fee: Some(1000),
            reveal_fee: 1000,
            inputs_used: vec![],
            outputs_created: vec![],
            traces: None,
        })
    }
    async fn get_balance(&self, _address: Option<&str>) -> deezel_common::Result<Vec<traits::AlkanesBalance>> { Ok(vec![]) }
    async fn get_alkanes_balance(&self, _address: Option<&str>) -> deezel_common::Result<Vec<traits::AlkanesBalance>> { Ok(vec![]) }
    async fn get_token_info(&self, _alkane_id: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn trace(&self, _outpoint: &str) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
    async fn inspect(&self, _target: &str, _config: traits::AlkanesInspectConfig) -> deezel_common::Result<traits::AlkanesInspectResult> { Ok(traits::AlkanesInspectResult { alkane_id: traits::AlkaneId { block: 1, tx: 100 }, bytecode_length: 0, disassembly: None, metadata: None, codehash: None, fuzzing_results: None }) }
    async fn get_bytecode(&self, _alkane_id: &str) -> deezel_common::Result<String> { Ok("".to_string()) }
    async fn simulate(&self, _contract_id: &str, _params: Option<&str>) -> deezel_common::Result<serde_json::Value> { Ok(serde_json::json!({})) }
}

#[async_trait::async_trait(?Send)]
impl traits::MonitorProvider for MockAlkanesProvider {
    async fn monitor_blocks(&self, _start: Option<u64>) -> deezel_common::Result<()> { Ok(()) }
    async fn get_block_events(&self, _height: u64) -> deezel_common::Result<Vec<traits::BlockEvent>> { Ok(vec![]) }
}

#[async_trait::async_trait(?Send)]
impl traits::PgpProvider for MockAlkanesProvider {
    async fn generate_keypair(&self, _user_id: &str, _passphrase: Option<&str>) -> Result<PgpKeyPair> { unimplemented!() }
    async fn import_key(&self, _armored_key: &str) -> Result<PgpKey> { unimplemented!() }
    async fn export_key(&self, _key: &PgpKey, _include_private: bool) -> Result<String> { unimplemented!() }
    async fn encrypt(&self, data: &[u8], _recipient_keys: &[PgpKey], _armor: bool) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    async fn decrypt(&self, encrypted_data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>) -> Result<Vec<u8>> { Ok(encrypted_data.to_vec()) }
    async fn sign(&self, data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    async fn verify(&self, _data: &[u8], _signature: &[u8], _public_key: &PgpKey) -> Result<bool> { Ok(true) }
    async fn encrypt_and_sign(&self, data: &[u8], _recipient_keys: &[PgpKey], _signing_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> { Ok(data.to_vec()) }
    async fn decrypt_and_verify(&self, encrypted_data: &[u8], _private_key: &PgpKey, _sender_public_key: &PgpKey, _passphrase: Option<&str>) -> Result<PgpDecryptResult> { Ok(PgpDecryptResult { data: encrypted_data.to_vec(), signature_valid: true, signer_key_id: None, signature_time: None }) }
    async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>> { Ok(vec![]) }
    async fn get_key(&self, _identifier: &str) -> Result<Option<PgpKey>> { Ok(None) }
    async fn delete_key(&self, _identifier: &str) -> Result<()> { Ok(()) }
    async fn change_passphrase(&self, key: &PgpKey, _old_passphrase: Option<&str>, _new_passphrase: Option<&str>) -> Result<PgpKey> { Ok(key.clone()) }
}

#[async_trait::async_trait(?Send)]
impl traits::KeystoreProvider for MockAlkanesProvider {
    async fn derive_addresses(&self, _master_public_key: &str, _network: Network, _script_types: &[&str], _start_index: u32, _count: u32) -> Result<Vec<KeystoreAddress>> { Ok(vec![]) }
    async fn get_default_addresses(&self, _master_public_key: &str, _network: Network) -> Result<Vec<KeystoreAddress>> { Ok(vec![]) }
    fn parse_address_range(&self, _range_spec: &str) -> Result<(String, u32, u32)> { Ok(("p2tr".to_string(), 0, 1000)) }
    async fn get_keystore_info(&self, _master_public_key: &str, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> { Ok(KeystoreInfo { master_public_key: "".to_string(), master_fingerprint: "".to_string(), created_at: 0, version: "".to_string() }) }
}

#[async_trait::async_trait(?Send)]
impl traits::DeezelProvider for MockAlkanesProvider {
    fn provider_name(&self) -> &str { "MockAlkanesProvider" }
    fn clone_box(&self) -> Box<dyn DeezelProvider> { Box::new(self.clone()) }
    async fn initialize(&self) -> deezel_common::Result<()> { Ok(()) }
    async fn shutdown(&self) -> deezel_common::Result<()> { Ok(()) }
}

#[tokio::test]
async fn test_alkanes_execute_with_edict() -> anyhow::Result<()> {
    let provider = MockAlkanesProvider::new();
    let alkanes_manager = alkanes::AlkanesManager::new(provider.clone());

    let params = traits::AlkanesExecuteParams {
        inputs: Some("B:1000000".to_string()),
        to: "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297".to_string(),
        change: None,
        fee_rate: Some(5.0),
        envelope: None,
        protostones: "[2:0:100:v0]".to_string(),
        trace: false,
        mine: false,
        auto_confirm: true,
        rebar: false,
    };

    let result = alkanes_manager.execute(params).await?;
    assert!(!result.reveal_txid.is_empty());

    let broadcasted_txs = provider.broadcasted_txs.lock().await;
    let reveal_tx_hex = broadcasted_txs.last().ok_or_else(|| anyhow!("No transaction was broadcasted"))?;

    use bitcoin::consensus::Decodable;
    let tx_bytes = hex::decode(reveal_tx_hex)?;
    let tx = bitcoin::Transaction::consensus_decode(&mut &tx_bytes[..])?;

    let artifact = ordinals::Runestone::decipher(&tx)
        .ok_or_else(|| anyhow!("Transaction did not contain a runestone"))?;

    if let ordinals::Artifact::Runestone(runestone) = artifact {
        assert_eq!(runestone.edicts.len(), 1);
        let edict = &runestone.edicts[0];
        assert_eq!(edict.id.block, 2);
        assert_eq!(edict.id.tx, 0);
        assert_eq!(edict.amount, 100);
        assert_eq!(edict.output, 0);
    } else {
        panic!("Expected a Runestone artifact, but got a Cenotaph.");
    }

    println!("✅ Execute with edict test passed");
    Ok(())
}