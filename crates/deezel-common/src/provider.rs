//! The ConcreteProvider implementation for deezel.

use crate::traits::*;
use crate::Result;
use async_trait::async_trait;
use std::path::PathBuf;

#[derive(Clone)]
pub struct ConcreteProvider {
    bitcoin_rpc_url: String,
    metashrew_rpc_url: String,
    provider: String,
    wallet_path: Option<PathBuf>,
}

impl ConcreteProvider {
    pub async fn new(
        bitcoin_rpc_url: String,
        metashrew_rpc_url: String,
        provider: String,
        wallet_path: Option<PathBuf>,
    ) -> Result<Self> {
        Ok(Self {
            bitcoin_rpc_url,
            metashrew_rpc_url,
            provider,
            wallet_path,
        })
    }
}

#[async_trait(?Send)]
impl JsonRpcProvider for ConcreteProvider {
    async fn call(
        &self,
        _url: &str,
        _method: &str,
        _params: serde_json::Value,
        _id: u64,
    ) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_bytecode(&self, _block: &str, _tx: &str) -> Result<String> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl StorageProvider for ConcreteProvider {
    async fn read(&self, _key: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn write(&self, _key: &str, _data: &[u8]) -> Result<()> {
        unimplemented!()
    }
    
    async fn exists(&self, _key: &str) -> Result<bool> {
        unimplemented!()
    }
    
    async fn delete(&self, _key: &str) -> Result<()> {
        unimplemented!()
    }
    
    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        unimplemented!()
    }
    
    fn storage_type(&self) -> &'static str {
        "placeholder"
    }
}

#[async_trait(?Send)]
impl NetworkProvider for ConcreteProvider {
    async fn get(&self, _url: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn post(&self, _url: &str, _body: &[u8], _content_type: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn is_reachable(&self, _url: &str) -> bool {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl CryptoProvider for ConcreteProvider {
    fn random_bytes(&self, _len: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    fn sha256(&self, _data: &[u8]) -> Result<[u8; 32]> {
        unimplemented!()
    }
    
    fn sha3_256(&self, _data: &[u8]) -> Result<[u8; 32]> {
        unimplemented!()
    }
    
    async fn encrypt_aes_gcm(&self, _data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn decrypt_aes_gcm(&self, _data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn pbkdf2_derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, _key_len: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
}

impl TimeProvider for ConcreteProvider {
    fn now_secs(&self) -> u64 {
        unimplemented!()
    }
    
    fn now_millis(&self) -> u64 {
        unimplemented!()
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    fn sleep_ms(&self, _ms: u64) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(_ms)))
    }

    #[cfg(target_arch = "wasm32")]
    fn sleep_ms(&self, _ms: u64) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()>>> {
        Box::pin(gloo_timers::future::sleep(std::time::Duration::from_millis(_ms)))
    }
}

impl LogProvider for ConcreteProvider {
    fn debug(&self, _message: &str) {
        unimplemented!()
    }
    
    fn info(&self, _message: &str) {
        unimplemented!()
    }
    
    fn warn(&self, _message: &str) {
        unimplemented!()
    }
    
    fn error(&self, _message: &str) {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl WalletProvider for ConcreteProvider {
    async fn create_wallet(&self, _config: WalletConfig, _mnemonic: Option<String>, _passphrase: Option<String>) -> Result<WalletInfo> {
        unimplemented!()
    }
    
    async fn load_wallet(&self, _config: WalletConfig, _passphrase: Option<String>) -> Result<WalletInfo> {
        unimplemented!()
    }
    
    async fn get_balance(&self) -> Result<WalletBalance> {
        unimplemented!()
    }
    
    async fn get_address(&self) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_addresses(&self, _count: u32) -> Result<Vec<AddressInfo>> {
        unimplemented!()
    }
    
    async fn send(&self, _params: SendParams) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_utxos(&self, _include_frozen: bool, _addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>> {
        unimplemented!()
    }
    
    async fn get_history(&self, _count: u32, _address: Option<String>) -> Result<Vec<TransactionInfo>> {
        unimplemented!()
    }
    
    async fn freeze_utxo(&self, _utxo: String, _reason: Option<String>) -> Result<()> {
        unimplemented!()
    }
    
    async fn unfreeze_utxo(&self, _utxo: String) -> Result<()> {
        unimplemented!()
    }
    
    async fn create_transaction(&self, _params: SendParams) -> Result<String> {
        unimplemented!()
    }
    
    async fn sign_transaction(&self, _tx_hex: String) -> Result<String> {
        unimplemented!()
    }
    
    async fn broadcast_transaction(&self, _tx_hex: String) -> Result<String> {
        unimplemented!()
    }
    
    async fn estimate_fee(&self, _target: u32) -> Result<FeeEstimate> {
        unimplemented!()
    }
    
    async fn get_fee_rates(&self) -> Result<FeeRates> {
        unimplemented!()
    }
    
    async fn sync(&self) -> Result<()> {
        unimplemented!()
    }
    
    async fn backup(&self) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_mnemonic(&self) -> Result<Option<String>> {
        unimplemented!()
    }
    
    fn get_network(&self) -> bitcoin::Network {
        unimplemented!()
    }
    
    async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey> {
        unimplemented!()
    }
    
    async fn sign_psbt(&self, _psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt> {
        unimplemented!()
    }
    
    async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl AddressResolver for ConcreteProvider {
    async fn resolve_all_identifiers(&self, _input: &str) -> Result<String> {
        unimplemented!()
    }
    
    fn contains_identifiers(&self, _input: &str) -> bool {
        unimplemented!()
    }
    
    async fn get_address(&self, _address_type: &str, _index: u32) -> Result<String> {
        unimplemented!()
    }
    
    async fn list_identifiers(&self) -> Result<Vec<String>> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl BitcoinRpcProvider for ConcreteProvider {
    async fn get_block_count(&self) -> Result<u64> {
        unimplemented!()
    }
    
    async fn generate_to_address(&self, _nblocks: u32, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_transaction_hex(&self, _txid: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_block(&self, _hash: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_block_hash(&self, _height: u64) -> Result<String> {
        unimplemented!()
    }
    
    async fn send_raw_transaction(&self, _tx_hex: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_mempool_info(&self) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn estimate_smart_fee(&self, _target: u32) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64> {
        unimplemented!()
    }
    
    async fn trace_transaction(&self, _txid: &str, _vout: u32, _block: Option<&str>, _tx: Option<&str>) -> Result<serde_json::Value> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl MetashrewRpcProvider for ConcreteProvider {
    async fn get_metashrew_height(&self) -> Result<u64> {
        unimplemented!()
    }
    
    async fn get_contract_meta(&self, _block: &str, _tx: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn trace_outpoint(&self, _txid: &str, _vout: u32) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_spendables_by_address(&self, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_protorunes_by_address(&self, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_protorunes_by_outpoint(&self, _txid: &str, _vout: u32) -> Result<serde_json::Value> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl EsploraProvider for ConcreteProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_blocks_tip_height(&self) -> Result<u64> {
        unimplemented!()
    }
    
    async fn get_blocks(&self, _start_height: Option<u64>) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_block_by_height(&self, _height: u64) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_block(&self, _hash: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_block_status(&self, _hash: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_block_txids(&self, _hash: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_block_header(&self, _hash: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_block_raw(&self, _hash: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_block_txid(&self, _hash: &str, _index: u32) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_block_txs(&self, _hash: &str, _start_index: Option<u32>) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_address(&self, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_address_txs(&self, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_address_txs_chain(&self, _address: &str, _last_seen_txid: Option<&str>) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_address_txs_mempool(&self, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_address_utxo(&self, _address: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_address_prefix(&self, _prefix: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_tx(&self, _txid: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_tx_hex(&self, _txid: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_tx_raw(&self, _txid: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_tx_status(&self, _txid: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_tx_merkle_proof(&self, _txid: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_tx_merkleblock_proof(&self, _txid: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_tx_outspend(&self, _txid: &str, _index: u32) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_tx_outspends(&self, _txid: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn broadcast(&self, _tx_hex: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_mempool(&self) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_mempool_txids(&self) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_mempool_recent(&self) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn get_fee_estimates(&self) -> Result<serde_json::Value> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl RunestoneProvider for ConcreteProvider {
    async fn decode_runestone(&self, _tx: &bitcoin::Transaction) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn format_runestone_with_decoded_messages(&self, _tx: &bitcoin::Transaction) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn analyze_runestone(&self, _txid: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl AlkanesProvider for ConcreteProvider {
    async fn execute(&self, _params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        unimplemented!()
    }
    
    async fn get_balance(&self, _address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        unimplemented!()
    }

    async fn get_alkanes_balance(&self, _address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        unimplemented!()
    }
    
    async fn get_token_info(&self, _alkane_id: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn trace(&self, _outpoint: &str) -> Result<serde_json::Value> {
        unimplemented!()
    }
    
    async fn inspect(&self, _target: &str, _config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        unimplemented!()
    }
    
    async fn get_bytecode(&self, _alkane_id: &str) -> Result<String> {
        unimplemented!()
    }
    
    async fn simulate(&self, _contract_id: &str, _params: Option<&str>) -> Result<serde_json::Value> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl MonitorProvider for ConcreteProvider {
    async fn monitor_blocks(&self, _start: Option<u64>) -> Result<()> {
        unimplemented!()
    }
    
    async fn get_block_events(&self, _height: u64) -> Result<Vec<BlockEvent>> {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl DeezelProvider for ConcreteProvider {
    fn provider_name(&self) -> &str {
        "ConcreteProvider"
    }

    fn clone_box(&self) -> Box<dyn DeezelProvider> {
        Box::new(self.clone())
    }
    
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
    
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}