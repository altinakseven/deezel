//! Integration tests for deezel-common
//!
//! This test suite provides comprehensive coverage of the deezel-common library
//! functionality using mock providers to test the trait-based architecture.

mod mock_provider;

// Test modules
mod alkanes_execute_unit_tests;
/*
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
    let balance = wallet.get_balance(None).await.unwrap();
    assert_eq!(balance.confirmed, 100000000);
    
    // Test address generation
    let address = wallet.get_address().await.unwrap();
    assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    
    // Test UTXO retrieval
    let utxos = wallet.get_utxos(false, None).await.unwrap();
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
    let balances = <MockProvider as AlkanesProvider>::get_balance(&alkanes.provider, None).await.unwrap();
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].symbol, "TEST");
    assert_eq!(balances[0].balance, 1000000);
    
    // Test token info
    let token_info = serde_json::json!({"name": "Test Token", "symbol": "TEST"});
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

*/