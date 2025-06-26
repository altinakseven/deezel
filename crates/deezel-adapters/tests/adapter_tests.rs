//! Unit tests for deezel-adapters
//!
//! These tests verify that each adapter implementation works correctly
//! and follows the expected patterns for mock data.

use anyhow::Result;
use bitcoin::{Address, Network};
use deezel_adapters::in_memory::*;
use deezel_core::traits::*;
use serde_json::json;
use std::str::FromStr;

#[tokio::test]
async fn test_in_memory_wallet_storage() -> Result<()> {
    let mut storage = InMemoryWalletStorage::new();
    
    // Test wallet creation using the actual API
    let config = WalletConfig {
        name: "test_wallet".to_string(),
        network: Network::Regtest,
        descriptor: Some("wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0/*)".to_string()),
        mnemonic_path: None,
    };
    
    // Serialize config and save as wallet data
    let config_data = serde_json::to_vec(&config)?;
    storage.save_wallet("test_wallet", &config_data).await?;
    
    // Test wallet loading
    let loaded_data = storage.load_wallet("test_wallet").await?;
    assert!(loaded_data.is_some());
    let loaded_config: WalletConfig = serde_json::from_slice(&loaded_data.unwrap())?;
    assert_eq!(loaded_config.name, config.name);
    assert_eq!(loaded_config.network, config.network);
    
    // Test wallet listing
    let wallets = storage.list_wallets().await?;
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0], "test_wallet");
    
    // Test loading non-existent wallet
    let result = storage.load_wallet("non_existent").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    Ok(())
}

#[tokio::test]
async fn test_in_memory_config_storage() -> Result<()> {
    let mut storage = InMemoryConfigStorage::new();
    
    // Test config saving and loading
    let test_config = json!({
        "network": "regtest",
        "fee_rate": 1.0,
        "settings": {
            "auto_sync": true,
            "max_fee": 10000
        }
    });
    
    storage.save_config("test_config", &test_config).await?;
    
    let loaded_config: Option<serde_json::Value> = storage.load_config("test_config").await?;
    assert!(loaded_config.is_some());
    assert_eq!(loaded_config.unwrap(), test_config);
    
    // Test loading non-existent config
    let missing_config: Option<serde_json::Value> = storage.load_config("missing").await?;
    assert!(missing_config.is_none());
    
    // Test overwriting config
    let updated_config = json!({
        "network": "mainnet",
        "fee_rate": 2.0
    });
    
    storage.save_config("test_config", &updated_config).await?;
    let reloaded_config: Option<serde_json::Value> = storage.load_config("test_config").await?;
    assert_eq!(reloaded_config.unwrap(), updated_config);
    
    Ok(())
}

#[tokio::test]
async fn test_in_memory_rpc_client() -> Result<()> {
    let mut rpc_client = InMemoryRpcClient::new();
    
    // Set up mock data
    let address = Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    rpc_client.set_balance(&address.to_string(), 50000);
    
    // Test address balance
    let balance = rpc_client.get_address_balance(&address).await?;
    assert_eq!(balance, 50000);
    
    // Test address UTXOs
    let utxos = rpc_client.get_address_utxos(&address).await?;
    assert!(utxos.is_empty()); // In-memory implementation returns empty by default
    
    // Test block height
    let height = rpc_client.get_block_height().await?;
    assert_eq!(height, 800000); // Default test height
    
    // Test transaction broadcast
    use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Witness, ScriptBuf};
    let mock_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    
    let txid = rpc_client.broadcast_transaction(&mock_tx).await?;
    assert_eq!(txid, mock_tx.compute_txid());
    
    Ok(())
}

#[tokio::test]
async fn test_in_memory_blockchain_client() -> Result<()> {
    let blockchain_client = InMemoryBlockchainClient::new();
    
    // Test tip height (default is 0)
    let height = blockchain_client.get_tip_height().await?;
    assert_eq!(height, 0);
    
    // Test fee estimates
    let estimates = blockchain_client.get_fee_estimates().await?;
    assert!(estimates.contains_key("1"));
    assert!(estimates.contains_key("6"));
    assert!(estimates.contains_key("144"));
    
    // Test block retrieval (should return None for non-existent blocks)
    let block = blockchain_client.get_block_by_height(100).await?;
    assert!(block.is_none());
    
    let block_by_hash = blockchain_client.get_block_by_hash("test_hash").await?;
    assert!(block_by_hash.is_none());
    
    Ok(())
}

#[tokio::test]
async fn test_in_memory_filesystem() -> Result<()> {
    let filesystem = InMemoryFilesystem::new();
    
    // Test file writing and reading
    let test_data = b"Hello, deezel filesystem!";
    filesystem.write_file("test.txt", test_data).await?;
    
    let read_data = filesystem.read_file("test.txt").await?;
    assert_eq!(read_data, test_data);
    
    // Test binary data
    let binary_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    filesystem.write_file("binary.dat", &binary_data).await?;
    
    let read_binary = filesystem.read_file("binary.dat").await?;
    assert_eq!(read_binary, binary_data);
    
    // Test overwriting files
    let new_data = b"Updated content";
    filesystem.write_file("test.txt", new_data).await?;
    
    let updated_data = filesystem.read_file("test.txt").await?;
    assert_eq!(updated_data, new_data);
    
    // Test reading non-existent file
    let result = filesystem.read_file("missing.txt").await;
    assert!(result.is_err());
    
    // Test nested paths
    filesystem.write_file("dir/subdir/nested.txt", b"nested content").await?;
    let nested_data = filesystem.read_file("dir/subdir/nested.txt").await?;
    assert_eq!(nested_data, b"nested content");
    
    Ok(())
}

#[tokio::test]
async fn test_in_memory_wasm_runtime() -> Result<()> {
    let mut wasm_runtime = InMemoryWasmRuntime::new();
    
    // Test module loading
    let mock_wasm = b"\x00asm\x01\x00\x00\x00"; // Minimal WASM header
    wasm_runtime.load_module(mock_wasm).await?;
    
    // Test function execution
    let result = wasm_runtime.execute_function("test_function", b"test_args").await?;
    assert_eq!(result, b"mock_response");
    
    // Test different function names
    let result2 = wasm_runtime.execute_function("another_function", b"other_args").await?;
    assert_eq!(result2, b"mock_response"); // Mock returns same result
    
    // Test exports
    let exports = wasm_runtime.get_exports().await?;
    assert!(!exports.is_empty());
    assert!(exports.contains(&"execute".to_string()));
    assert!(exports.contains(&"simulate".to_string()));
    assert!(exports.contains(&"meta".to_string()));
    
    // Test memory and timeout limits
    wasm_runtime.set_memory_limit(1024 * 1024); // 1MB
    wasm_runtime.set_timeout(5000); // 5 seconds
    
    // Should still work after setting limits
    let result3 = wasm_runtime.execute_function("limited_function", b"args").await?;
    assert_eq!(result3, b"mock_response");
    
    Ok(())
}

#[tokio::test]
async fn test_adapter_error_handling() -> Result<()> {
    // Test wallet storage - non-existent wallet returns None, not error
    let wallet_storage = InMemoryWalletStorage::new();
    let result = wallet_storage.load_wallet("non_existent").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    
    // Test filesystem errors
    let filesystem = InMemoryFilesystem::new();
    let result = filesystem.read_file("missing.txt").await;
    assert!(result.is_err());
    
    // Test WASM runtime errors (loading invalid module)
    let mut wasm_runtime = InMemoryWasmRuntime::new();
    let invalid_wasm = b"invalid wasm data";
    let result = wasm_runtime.load_module(invalid_wasm).await;
    // Mock implementation doesn't validate, so this passes
    // In a real implementation, this would fail
    assert!(result.is_ok());
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_adapter_access() -> Result<()> {
    use std::sync::Arc;
    use tokio::sync::Mutex;
    
    let filesystem = Arc::new(InMemoryFilesystem::new());
    let config_storage = Arc::new(Mutex::new(InMemoryConfigStorage::new()));
    
    // Test concurrent filesystem operations
    let mut handles = vec![];
    for i in 0..10 {
        let fs = Arc::clone(&filesystem);
        let handle = tokio::spawn(async move {
            let data = format!("data_{}", i).into_bytes();
            let filename = format!("file_{}.txt", i);
            fs.write_file(&filename, &data).await?;
            fs.read_file(&filename).await
        });
        handles.push(handle);
    }
    
    // Wait for all operations
    for handle in handles {
        let result = handle.await?;
        assert!(result.is_ok());
    }
    
    // Test concurrent config operations
    let mut config_handles = vec![];
    for i in 0..5 {
        let storage = Arc::clone(&config_storage);
        let handle = tokio::spawn(async move {
            let mut storage = storage.lock().await;
            let config = json!({ "id": i, "value": format!("config_{}", i) });
            let key = format!("config_{}", i);
            storage.save_config(&key, &config).await?;
            storage.load_config::<serde_json::Value>(&key).await
        });
        config_handles.push(handle);
    }
    
    for handle in config_handles {
        let result = handle.await?;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }
    
    Ok(())
}

#[tokio::test]
async fn test_mock_data_consistency() -> Result<()> {
    let mut rpc_client = InMemoryRpcClient::new();
    let blockchain_client = InMemoryBlockchainClient::new();
    
    // Test that mock data is consistent across calls
    let height1 = blockchain_client.get_tip_height().await?;
    let height2 = blockchain_client.get_tip_height().await?;
    assert_eq!(height1, height2);
    
    let address = Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    
    // Set balance for testing
    rpc_client.set_balance(&address.to_string(), 50000);
    
    let balance1 = rpc_client.get_address_balance(&address).await?;
    let balance2 = rpc_client.get_address_balance(&address).await?;
    assert_eq!(balance1, balance2);
    
    // Test that different addresses have different balances (default 0)
    let different_address = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?
        .require_network(Network::Bitcoin)?;
    let different_balance = rpc_client.get_address_balance(&different_address).await?;
    assert_eq!(different_balance, 0); // Default balance for unset addresses
    
    Ok(())
}

#[tokio::test]
async fn test_serialization_compatibility() -> Result<()> {
    let mut config_storage = InMemoryConfigStorage::new();
    
    // Test various data types
    let string_config = "test_string".to_string();
    config_storage.save_config("string", &string_config).await?;
    let loaded_string: Option<String> = config_storage.load_config("string").await?;
    assert_eq!(loaded_string.unwrap(), string_config);
    
    let number_config = 42u64;
    config_storage.save_config("number", &number_config).await?;
    let loaded_number: Option<u64> = config_storage.load_config("number").await?;
    assert_eq!(loaded_number.unwrap(), number_config);
    
    let complex_config = json!({
        "nested": {
            "array": [1, 2, 3],
            "boolean": true,
            "null_value": null
        }
    });
    config_storage.save_config("complex", &complex_config).await?;
    let loaded_complex: Option<serde_json::Value> = config_storage.load_config("complex").await?;
    assert_eq!(loaded_complex.unwrap(), complex_config);
    
    Ok(())
}