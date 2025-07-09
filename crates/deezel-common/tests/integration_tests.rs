//! Integration tests for deezel-common
//!
//! This test suite provides comprehensive coverage of the deezel-common library
//! functionality using mock providers to test the trait-based architecture.

use deezel_common::*;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use bitcoin::{Network, Transaction};

/// Mock provider for testing
#[derive(Clone)]
pub struct MockProvider {
    pub responses: HashMap<String, JsonValue>,
    pub network: Network,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProvider {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            network: Network::Regtest,
        }
    }
    
    pub fn with_response(mut self, key: &str, value: JsonValue) -> Self {
        self.responses.insert(key.to_string(), value);
        self
    }
}

#[async_trait(?Send)]
impl JsonRpcProvider for MockProvider {
    async fn call(&self, _url: &str, method: &str, _params: JsonValue, _id: u64) -> Result<JsonValue> {
        self.responses.get(method)
            .cloned()
            .ok_or_else(|| DeezelError::JsonRpc(format!("No mock response for method: {}", method)))
    }
    
    async fn get_bytecode(&self, _block: &str, _tx: &str) -> Result<String> {
        Ok("mock_bytecode".to_string())
    }
}

#[async_trait(?Send)]
impl StorageProvider for MockProvider {
    async fn read(&self, _key: &str) -> Result<Vec<u8>> {
        Ok(b"mock_data".to_vec())
    }
    
    async fn write(&self, _key: &str, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    
    async fn exists(&self, _key: &str) -> Result<bool> {
        Ok(true)
    }
    
    async fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }
    
    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        Ok(vec!["mock_key".to_string()])
    }
    
    fn storage_type(&self) -> &'static str {
        "mock"
    }
}

#[async_trait(?Send)]
impl NetworkProvider for MockProvider {
    async fn get(&self, _url: &str) -> Result<Vec<u8>> {
        Ok(b"mock_response".to_vec())
    }
    
    async fn post(&self, _url: &str, _body: &[u8], _content_type: &str) -> Result<Vec<u8>> {
        Ok(b"mock_response".to_vec())
    }
    
    async fn is_reachable(&self, _url: &str) -> bool {
        true
    }
}

#[async_trait(?Send)]
impl CryptoProvider for MockProvider {
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        Ok(vec![0u8; len])
    }
    
    fn sha256(&self, _data: &[u8]) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    
    fn sha3_256(&self, _data: &[u8]) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    
    async fn encrypt_aes_gcm(&self, data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    async fn decrypt_aes_gcm(&self, data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
    
    async fn pbkdf2_derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, key_len: usize) -> Result<Vec<u8>> {
        Ok(vec![0u8; key_len])
    }
}

impl TimeProvider for MockProvider {
    fn now_secs(&self) -> u64 {
        1640995200 // 2022-01-01 00:00:00 UTC
    }
    
    fn now_millis(&self) -> u64 {
        1640995200000
    }
    
    async fn sleep_ms(&self, _ms: u64) {
        // No-op for tests
    }
}

impl LogProvider for MockProvider {
    fn debug(&self, _message: &str) {}
    fn info(&self, _message: &str) {}
    fn warn(&self, _message: &str) {}
    fn error(&self, _message: &str) {}
}

#[async_trait(?Send)]
impl WalletProvider for MockProvider {
    async fn create_wallet(&self, _config: WalletConfig, _mnemonic: Option<String>, _passphrase: Option<String>) -> Result<WalletInfo> {
        Ok(WalletInfo {
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            network: self.network,
            mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        })
    }
    
    async fn load_wallet(&self, _config: WalletConfig, _passphrase: Option<String>) -> Result<WalletInfo> {
        self.create_wallet(WalletConfig {
            wallet_path: "test".to_string(),
            network: self.network,
            bitcoin_rpc_url: "http://localhost:8332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            network_params: None,
        }, None, None).await
    }
    
    async fn get_balance(&self) -> Result<WalletBalance> {
        Ok(WalletBalance {
            confirmed: 100000000,
            trusted_pending: 0,
            untrusted_pending: 0,
        })
    }
    
    async fn get_address(&self) -> Result<String> {
        Ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string())
    }
    
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>> {
        let mut addresses = Vec::new();
        for i in 0..count {
            addresses.push(AddressInfo {
                address: format!("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t{}", i),
                script_type: "p2wpkh".to_string(),
                derivation_path: format!("m/84'/0'/0'/0/{}", i),
                index: i,
                used: false,
            });
        }
        Ok(addresses)
    }
    
    async fn send(&self, _params: SendParams) -> Result<String> {
        Ok("mock_txid".to_string())
    }
    
    async fn get_utxos(&self, _include_frozen: bool, _addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>> {
        Ok(vec![UtxoInfo {
            txid: "mock_txid".to_string(),
            vout: 0,
            amount: 100000000,
            address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            script_pubkey: Some(bitcoin::ScriptBuf::new()),
            confirmations: 6,
            frozen: false,
            freeze_reason: None,
            block_height: Some(800000),
            has_inscriptions: false,
            has_runes: false,
            has_alkanes: false,
            is_coinbase: false,
        }])
    }
    
    async fn get_history(&self, _count: u32, _address: Option<String>) -> Result<Vec<TransactionInfo>> {
        Ok(vec![TransactionInfo {
            txid: "mock_txid".to_string(),
            block_height: Some(800000),
            block_time: Some(1640995200),
            confirmed: true,
            fee: Some(1000),
            inputs: vec![],
            outputs: vec![],
        }])
    }
    
    async fn freeze_utxo(&self, _utxo: String, _reason: Option<String>) -> Result<()> {
        Ok(())
    }
    
    async fn unfreeze_utxo(&self, _utxo: String) -> Result<()> {
        Ok(())
    }
    
    async fn create_transaction(&self, _params: SendParams) -> Result<String> {
        Ok("mock_tx_hex".to_string())
    }
    
    async fn sign_transaction(&self, _tx_hex: String) -> Result<String> {
        Ok("mock_signed_tx_hex".to_string())
    }
    
    async fn broadcast_transaction(&self, _tx_hex: String) -> Result<String> {
        Ok("mock_txid".to_string())
    }
    
    async fn estimate_fee(&self, _target: u32) -> Result<FeeEstimate> {
        Ok(FeeEstimate {
            fee_rate: 10.0,
            target_blocks: 6,
        })
    }
    
    async fn get_fee_rates(&self) -> Result<FeeRates> {
        Ok(FeeRates {
            fast: 20.0,
            medium: 10.0,
            slow: 5.0,
        })
    }
    
    async fn sync(&self) -> Result<()> {
        Ok(())
    }
    
    async fn backup(&self) -> Result<String> {
        Ok("mock_backup_data".to_string())
    }
    
    async fn get_mnemonic(&self) -> Result<Option<String>> {
        Ok(Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()))
    }
    
    fn get_network(&self) -> Network {
        self.network
    }
    
    async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey> {
        Ok(bitcoin::XOnlyPublicKey::from_slice(&[0; 32]).unwrap())
    }
    
    async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt> {
        Ok(psbt.clone())
    }
    
    async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        Ok(bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key))
    }
}

#[async_trait(?Send)]
impl AddressResolver for MockProvider {
    async fn resolve_all_identifiers(&self, input: &str) -> Result<String> {
        // Replace identifiers with actual addresses
        let result = input.replace("p2tr:0", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        Ok(result)
    }
    
    fn contains_identifiers(&self, input: &str) -> bool {
        input.contains("p2tr:") || input.contains("p2wpkh:")
    }
    
    async fn get_address(&self, _address_type: &str, _index: u32) -> Result<String> {
        Ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string())
    }
    
    async fn list_identifiers(&self) -> Result<Vec<String>> {
        Ok(vec!["p2tr:0".to_string(), "p2wpkh:0".to_string()])
    }
}

#[async_trait(?Send)]
impl BitcoinRpcProvider for MockProvider {
    async fn get_block_count(&self) -> Result<u64> {
        Ok(800000)
    }
    
    async fn generate_to_address(&self, _nblocks: u32, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!(["mock_block_hash"]))
    }
    
    async fn get_transaction_hex(&self, _txid: &str) -> Result<String> {
        Ok("mock_tx_hex".to_string())
    }
    
    async fn get_block(&self, _hash: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"height": 800000}))
    }
    
    async fn get_block_hash(&self, _height: u64) -> Result<String> {
        Ok("mock_block_hash".to_string())
    }
    
    async fn send_raw_transaction(&self, _tx_hex: &str) -> Result<String> {
        Ok("mock_txid".to_string())
    }
    
    async fn get_mempool_info(&self) -> Result<JsonValue> {
        Ok(serde_json::json!({"size": 1000}))
    }
    
    async fn estimate_smart_fee(&self, _target: u32) -> Result<JsonValue> {
        Ok(serde_json::json!({"feerate": 0.00010000}))
    }
    
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64> {
        Ok(800000)
    }
    
    async fn trace_transaction(&self, _txid: &str, _vout: u32, _block: Option<&str>, _tx: Option<&str>) -> Result<JsonValue> {
        Ok(serde_json::json!({"trace": "mock_trace"}))
    }
}

#[async_trait(?Send)]
impl MetashrewRpcProvider for MockProvider {
    async fn get_metashrew_height(&self) -> Result<u64> {
        Ok(800001)
    }
    
    async fn get_contract_meta(&self, _block: &str, _tx: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"name": "test_contract"}))
    }
    
    async fn trace_outpoint(&self, _txid: &str, _vout: u32) -> Result<JsonValue> {
        Ok(serde_json::json!({"trace": "mock_trace"}))
    }
    
    async fn get_spendables_by_address(&self, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_protorunes_by_address(&self, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_protorunes_by_outpoint(&self, _txid: &str, _vout: u32) -> Result<JsonValue> {
        Ok(serde_json::json!({}))
    }
}

#[async_trait(?Send)]
impl EsploraProvider for MockProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        Ok("mock_tip_hash".to_string())
    }
    
    async fn get_blocks_tip_height(&self) -> Result<u64> {
        Ok(800000)
    }
    
    async fn get_blocks(&self, _start_height: Option<u64>) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_block_by_height(&self, _height: u64) -> Result<String> {
        Ok("mock_block_hash".to_string())
    }
    
    async fn get_block(&self, _hash: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"height": 800000}))
    }
    
    async fn get_block_status(&self, _hash: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"confirmed": true}))
    }
    
    async fn get_block_txids(&self, _hash: &str) -> Result<JsonValue> {
        Ok(serde_json::json!(["mock_txid"]))
    }
    
    async fn get_block_header(&self, _hash: &str) -> Result<String> {
        Ok("mock_header".to_string())
    }
    
    async fn get_block_raw(&self, _hash: &str) -> Result<String> {
        Ok("mock_raw_block".to_string())
    }
    
    async fn get_block_txid(&self, _hash: &str, _index: u32) -> Result<String> {
        Ok("mock_txid".to_string())
    }
    
    async fn get_block_txs(&self, _hash: &str, _start_index: Option<u32>) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_address(&self, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"balance": 100000000}))
    }
    
    async fn get_address_txs(&self, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_address_txs_chain(&self, _address: &str, _last_seen_txid: Option<&str>) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_address_txs_mempool(&self, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_address_utxo(&self, _address: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_address_prefix(&self, _prefix: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_tx(&self, _txid: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"txid": "mock_txid"}))
    }
    
    async fn get_tx_hex(&self, _txid: &str) -> Result<String> {
        Ok("mock_tx_hex".to_string())
    }
    
    async fn get_tx_raw(&self, _txid: &str) -> Result<String> {
        Ok("mock_raw_tx".to_string())
    }
    
    async fn get_tx_status(&self, _txid: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"confirmed": true}))
    }
    
    async fn get_tx_merkle_proof(&self, _txid: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"proof": "mock_proof"}))
    }
    
    async fn get_tx_merkleblock_proof(&self, _txid: &str) -> Result<String> {
        Ok("mock_merkleblock_proof".to_string())
    }
    
    async fn get_tx_outspend(&self, _txid: &str, _index: u32) -> Result<JsonValue> {
        Ok(serde_json::json!({"spent": false}))
    }
    
    async fn get_tx_outspends(&self, _txid: &str) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn broadcast(&self, _tx_hex: &str) -> Result<String> {
        Ok("mock_txid".to_string())
    }
    
    async fn get_mempool(&self) -> Result<JsonValue> {
        Ok(serde_json::json!({"count": 1000}))
    }
    
    async fn get_mempool_txids(&self) -> Result<JsonValue> {
        Ok(serde_json::json!(["mock_txid"]))
    }
    
    async fn get_mempool_recent(&self) -> Result<JsonValue> {
        Ok(serde_json::json!([]))
    }
    
    async fn get_fee_estimates(&self) -> Result<JsonValue> {
        Ok(serde_json::json!({"1": 20.0, "6": 10.0, "144": 5.0}))
    }
}

#[async_trait(?Send)]
impl RunestoneProvider for MockProvider {
    async fn decode_runestone(&self, _tx: &Transaction) -> Result<JsonValue> {
        Ok(serde_json::json!({"etching": {"rune": "BITCOIN"}}))
    }
    
    async fn format_runestone_with_decoded_messages(&self, _tx: &Transaction) -> Result<JsonValue> {
        Ok(serde_json::json!({"formatted": "mock_formatted_runestone"}))
    }
    
    async fn analyze_runestone(&self, _txid: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"analysis": "mock_analysis"}))
    }
}

#[async_trait(?Send)]
impl AlkanesProvider for MockProvider {
    async fn execute(&self, _params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        Ok(AlkanesExecuteResult {
            commit_txid: Some("mock_commit_txid".to_string()),
            reveal_txid: "mock_reveal_txid".to_string(),
            commit_fee: Some(1000),
            reveal_fee: 2000,
            inputs_used: vec!["mock_input".to_string()],
            outputs_created: vec!["mock_output".to_string()],
            traces: Some(vec!["mock_trace".to_string()]),
        })
    }
    
    async fn get_balance(&self, _address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        Ok(vec![AlkanesBalance {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            balance: 1000000,
            alkane_id: AlkaneId { block: 800000, tx: 1 },
        }])
    }
    
    async fn get_token_info(&self, _alkane_id: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"name": "Test Token", "symbol": "TEST"}))
    }
    
    async fn trace(&self, _outpoint: &str) -> Result<JsonValue> {
        Ok(serde_json::json!({"trace": "mock_trace"}))
    }
    
    async fn inspect(&self, _target: &str, _config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        Ok(AlkanesInspectResult {
            alkane_id: AlkaneId { block: 800000, tx: 1 },
            bytecode_length: 1024,
            disassembly: Some("mock_disassembly".to_string()),
            metadata: None,
            codehash: Some("mock_codehash".to_string()),
            fuzzing_results: None,
        })
    }
    
    async fn get_bytecode(&self, _alkane_id: &str) -> Result<String> {
        Ok("mock_bytecode".to_string())
    }
    
    async fn simulate(&self, _contract_id: &str, _params: Option<&str>) -> Result<JsonValue> {
        Ok(serde_json::json!({"result": "mock_simulation"}))
    }
}

#[async_trait(?Send)]
impl MonitorProvider for MockProvider {
    async fn monitor_blocks(&self, _start: Option<u64>) -> Result<()> {
        Ok(())
    }
    
    async fn get_block_events(&self, _height: u64) -> Result<Vec<BlockEvent>> {
        Ok(vec![BlockEvent {
            event_type: "transaction".to_string(),
            block_height: 800000,
            txid: "mock_txid".to_string(),
            data: serde_json::json!({"amount": 100000}),
        }])
    }
}

#[async_trait(?Send)]
impl DeezelProvider for MockProvider {
    fn provider_name(&self) -> &str {
        "mock"
    }
    
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
    
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

// Test modules
mod network_tests {
    use deezel_common::{NetworkParams, Network};
    
    #[test]
    fn test_network_params_creation() {
        let mainnet = NetworkParams::mainnet();
        assert_eq!(mainnet.network, Network::Bitcoin);
        assert_eq!(mainnet.magic, 0xd9b4bef9);
        assert_eq!(mainnet.bech32_prefix, "bc");
        
        let testnet = NetworkParams::testnet();
        assert_eq!(testnet.network, Network::Testnet);
        assert_eq!(testnet.magic, 0x0709110b);
        assert_eq!(testnet.bech32_prefix, "tb");
    }
    
    #[test]
    fn test_network_from_string() {
        assert!(NetworkParams::from_network_str("mainnet").is_ok());
        assert!(NetworkParams::from_network_str("testnet").is_ok());
        assert!(NetworkParams::from_network_str("signet").is_ok());
        assert!(NetworkParams::from_network_str("regtest").is_ok());
        assert!(NetworkParams::from_network_str("invalid").is_err());
    }
}

mod utils_tests {
    use deezel_common::alkanes::utils::parse_alkane_id;
    
    #[test]
    fn test_parse_alkane_id() {
        let alkane_id = parse_alkane_id("800000:1").unwrap();
        assert_eq!(alkane_id.block, 800000);
        assert_eq!(alkane_id.tx, 1);
        
        assert!(parse_alkane_id("invalid").is_err());
    }
}

mod protostone_tests {
    use deezel_common::utils::protostone::Protostones;
    
    #[test]
    fn test_protostone_creation() {
        let protostone = deezel_common::utils::protostone::Protostone::new(1, b"hello".to_vec());
        assert_eq!(protostone.protocol_tag, 1);
        assert_eq!(protostone.message, b"hello");
        assert_eq!(protostone.message_as_string(), Some("hello".to_string()));
    }
    
    #[test]
    fn test_protostones_from_string() {
        let protostones = Protostones::from_string("1:hello,2:world").unwrap();
        assert_eq!(protostones.len(), 2);
        
        assert_eq!(protostones.protostones[0].protocol_tag, 1);
        assert_eq!(protostones.protostones[0].message_as_string(), Some("hello".to_string()));
        
        assert_eq!(protostones.protostones[1].protocol_tag, 2);
        assert_eq!(protostones.protostones[1].message_as_string(), Some("world".to_string()));
    }
}

mod runestone_enhanced_tests {
    use deezel_common::runestone_enhanced::*;
    use serde_json::json;
    
    #[test]
    fn test_format_runestone_enhanced() {
        let runestone_data = json!({
            "etching": {
                "rune": "BITCOIN",
                "divisibility": 8,
                "premine": 1000000,
                "symbol": "₿"
            },
            "edicts": [
                {
                    "id": "123:456",
                    "amount": 1000,
                    "output": 1
                }
            ],
            "mint": "789:012",
            "pointer": 2
        });
        
        let formatted = format_runestone_with_decoded_messages(&runestone_data).unwrap();
        assert!(formatted.contains("🪨 Enhanced Runestone Analysis"));
        assert!(formatted.contains("📛 Rune Name: BITCOIN"));
        assert!(formatted.contains("🔢 Divisibility: 8"));
        assert!(formatted.contains("📜 Transfer Edicts:"));
        assert!(formatted.contains("🏭 Mint Operation: 789:012"));
        assert!(formatted.contains("👉 Change Pointer: Output 2"));
    }
}

// Integration tests using mock provider
#[tokio::test]
async fn test_wallet_operations() {
    let provider = MockProvider::new();
    let config = WalletConfig {
        wallet_path: "test".to_string(),
        network: Network::Regtest,
        bitcoin_rpc_url: "http://localhost:8332".to_string(),
        metashrew_rpc_url: "http://localhost:8080".to_string(),
        network_params: None,
    };
    
    // Test wallet creation
    let wallet = deezel_common::wallet::WalletManager::new(provider.clone(), deezel_common::wallet::WalletConfig {
        wallet_path: config.wallet_path,
        network: config.network,
        bitcoin_rpc_url: config.bitcoin_rpc_url,
        metashrew_rpc_url: config.metashrew_rpc_url,
        network_params: None,
    });
    
    // Test balance retrieval
    let balance = wallet.get_balance().await.unwrap();
    assert_eq!(balance.confirmed, 100000000);
    
    // Test address generation
    let address = wallet.get_address().await.unwrap();
    assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    
    // Test UTXO retrieval
    let utxos = wallet.get_utxos().await.unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].amount, 100000000);
}

#[tokio::test]
async fn test_rpc_operations() {
    let provider = MockProvider::new()
        .with_response("getblockcount", serde_json::json!(800000))
        .with_response("getblockhash", serde_json::json!("mock_hash"));
    
    let rpc_client = deezel_common::rpc::RpcClient::new(provider);
    
    // Test block count
    let block_count = rpc_client.get_block_count().await.unwrap();
    assert_eq!(block_count, 800000);
}

#[tokio::test]
async fn test_address_resolver() {
    let provider = MockProvider::new();
    
    // Test identifier resolution using the trait method directly
    let resolved = provider.resolve_all_identifiers("Send to p2tr:0").await.unwrap();
    assert!(resolved.contains("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
    
    // Test identifier detection using the trait method directly
    assert!(provider.contains_identifiers("p2tr:0"));
    assert!(!provider.contains_identifiers("regular text"));
    
    // Test the AddressResolver struct methods with bracketed identifiers (which it supports)
    let mut resolver = deezel_common::address_resolver::AddressResolver::new(provider.clone());
    let resolved2 = resolver.resolve_all_identifiers("Send to [self:p2tr:0]").await.unwrap();
    assert!(resolved2.contains("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
    
    // Test shorthand identifier detection
    assert!(resolver.is_shorthand_identifier("p2tr:0"));
    assert!(!resolver.is_shorthand_identifier("regular text"));
    
    // Test individual identifier resolution
    let address = resolver.resolve_identifier("p2tr:0").await.unwrap();
    assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
}

#[tokio::test]
async fn test_alkanes_operations() {
    let provider = MockProvider::new();
    let alkanes = deezel_common::alkanes::AlkanesManager::new(provider);
    
    // Test balance retrieval
    let balances = alkanes.get_balance(None).await.unwrap();
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].symbol, "TEST");
    assert_eq!(balances[0].balance, 1000000);
    
    // Test token info
    let token_info = alkanes.get_token_info("800000:1").await.unwrap();
    assert_eq!(token_info["name"], "Test Token");
    assert_eq!(token_info["symbol"], "TEST");
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn test_monitor_operations() {
    let provider = MockProvider::new();
    let monitor = deezel_common::monitor::BlockMonitor::new(provider);
    
    // Test monitor statistics
    let stats = monitor.get_stats();
    assert!(!stats.is_running);
    assert_eq!(stats.current_height, 0);
}

#[tokio::test]
async fn test_runestone_operations() {
    let provider = MockProvider::new();
    let runestone_manager = deezel_common::runestone::RunestoneManager::new(provider);
    
    // Test runestone formatting using the enhanced formatter directly
    let runestone_data = serde_json::json!({
        "etching": {
            "rune": "BITCOIN",
            "divisibility": 8
        }
    });
    
    // Test the enhanced formatting function directly
    let formatted = deezel_common::runestone_enhanced::format_runestone_with_decoded_messages(&runestone_data).unwrap();
    assert!(formatted.contains("🪨 Enhanced Runestone Analysis"));
    
    // Also test the RunestoneManager format_runestone method
    let runestone_info = deezel_common::runestone::RunestoneInfo {
        etching: Some(deezel_common::runestone::Etching {
            rune: Some("BITCOIN".to_string()),
            divisibility: Some(8),
            premine: None,
            spacers: None,
            symbol: None,
            terms: None,
        }),
        edicts: vec![],
        mint: None,
        pointer: None,
        cenotaph: vec![],
    };
    let basic_formatted = runestone_manager.format_runestone(&runestone_info, true);
    assert!(basic_formatted.contains("🪨 Runestone Analysis"));
}

#[test]
fn test_error_types() {
    let error = DeezelError::JsonRpc("test error".to_string());
    assert!(error.to_string().contains("JSON-RPC error"));
    
    let error = DeezelError::Wallet("wallet error".to_string());
    assert!(error.to_string().contains("Wallet error"));
    
    let error = DeezelError::Network("network error".to_string());
    assert!(error.to_string().contains("Network error"));
}

#[test]
fn test_trait_abstractions() {
    // Test that our mock provider implements all required traits
    let provider = MockProvider::new();
    
    // Test provider name
    assert_eq!(provider.provider_name(), "mock");
    
    // Test network
    assert_eq!(provider.get_network(), Network::Regtest);
    
    // Test storage type
    assert_eq!(provider.storage_type(), "mock");
    
    // Test time provider
    assert_eq!(provider.now_secs(), 1640995200);
    assert_eq!(provider.now_millis(), 1640995200000);
}

#[tokio::test]
async fn test_comprehensive_provider_functionality() {
    let provider = MockProvider::new();
    
    // Test initialization and shutdown
    provider.initialize().await.unwrap();
    provider.shutdown().await.unwrap();
    
    // Test crypto operations
    let random_bytes = provider.random_bytes(32).unwrap();
    assert_eq!(random_bytes.len(), 32);
    
    let hash = provider.sha256(b"test").unwrap();
    assert_eq!(hash.len(), 32);
    
    // Test network operations
    let response = provider.get("http://example.com").await.unwrap();
    assert_eq!(response, b"mock_response");
    
    assert!(provider.is_reachable("http://example.com").await);
    
    // Test storage operations
    provider.write("test_key", b"test_data").await.unwrap();
    let data = provider.read("test_key").await.unwrap();
    assert_eq!(data, b"mock_data");
    
    assert!(provider.exists("test_key").await.unwrap());
    
    let keys = provider.list_keys("test_").await.unwrap();
    assert_eq!(keys, vec!["mock_key"]);
    
    provider.delete("test_key").await.unwrap();
}