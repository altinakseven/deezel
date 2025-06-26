//! Simple integration test for deezel adapters
//! 
//! This test demonstrates the in-memory adapters working correctly
//! and provides a foundation for more comprehensive testing.

use anyhow::Result;
use bitcoin::{Address, Network};
use deezel_adapters::in_memory::*;
use deezel_core::traits::*;
use serde_json::json;
use std::str::FromStr;

#[tokio::test]
async fn test_in_memory_wallet_storage() -> Result<()> {
    let mut storage = InMemoryWalletStorage::new();
    
    // Test wallet saving
    let wallet_data = b"mock_wallet_data";
    storage.save_wallet("test_wallet", wallet_data).await?;
    
    // Test wallet loading
    let loaded_data = storage.load_wallet("test_wallet").await?;
    assert!(loaded_data.is_some());
    assert_eq!(loaded_data.unwrap(), wallet_data);
    
    // Test wallet listing
    let wallets = storage.list_wallets().await?;
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0], "test_wallet");
    
    println!("✅ In-memory wallet storage test passed");
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
    
    println!("✅ In-memory config storage test passed");
    Ok(())
}

#[tokio::test]
async fn test_in_memory_rpc_client() -> Result<()> {
    let rpc_client = InMemoryRpcClient::new();
    
    // Test address balance
    let address = Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    let balance = rpc_client.get_address_balance(&address).await?;
    assert_eq!(balance, 0); // Mock returns 0
    
    // Test address UTXOs
    let utxos = rpc_client.get_address_utxos(&address).await?;
    // Mock implementation returns empty vector
    assert!(utxos.is_empty());
    
    println!("✅ In-memory RPC client test passed");
    Ok(())
}

#[tokio::test]
async fn test_in_memory_blockchain_client() -> Result<()> {
    let blockchain_client = InMemoryBlockchainClient::new();
    
    // Test tip height
    let height = blockchain_client.get_tip_height().await?;
    assert_eq!(height, 0); // Mock returns 0
    
    println!("✅ In-memory blockchain client test passed");
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
    
    println!("✅ In-memory filesystem test passed");
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
    
    // Test exports
    let exports = wasm_runtime.get_exports().await?;
    assert!(!exports.is_empty());
    assert!(exports.contains(&"execute".to_string()));
    
    println!("✅ In-memory WASM runtime test passed");
    Ok(())
}

#[tokio::test]
async fn test_adapter_integration() -> Result<()> {
    // Test that all adapters work together
    let mut wallet_storage = InMemoryWalletStorage::new();
    let mut config_storage = InMemoryConfigStorage::new();
    let rpc_client = InMemoryRpcClient::new();
    let blockchain_client = InMemoryBlockchainClient::new();
    let filesystem = InMemoryFilesystem::new();
    let mut wasm_runtime = InMemoryWasmRuntime::new();
    
    // 1. Save wallet data
    let wallet_data = b"integration_test_wallet_data";
    wallet_storage.save_wallet("integration_test_wallet", wallet_data).await?;
    
    // 2. Save configuration
    let app_config = json!({
        "wallet": "integration_test_wallet",
        "network": "regtest",
        "initialized": true
    });
    config_storage.save_config("app_config", &app_config).await?;
    
    // 3. Check blockchain height
    let height = blockchain_client.get_tip_height().await?;
    assert_eq!(height, 0);
    
    // 4. Check address balance
    let address = Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    let balance = rpc_client.get_address_balance(&address).await?;
    assert_eq!(balance, 0);
    
    // 5. Save file
    let backup_data = "integration_test_wallet_backup";
    filesystem.write_file("wallet_backup.json", backup_data.as_bytes()).await?;
    
    // 6. Execute WASM
    let mock_wasm = b"\x00asm\x01\x00\x00\x00";
    wasm_runtime.load_module(mock_wasm).await?;
    let wasm_result = wasm_runtime.execute_function("execute", b"test_data").await?;
    assert_eq!(wasm_result, b"mock_response");
    
    // 7. Verify all operations worked
    let wallets = wallet_storage.list_wallets().await?;
    assert!(wallets.contains(&"integration_test_wallet".to_string()));
    
    let loaded_config: Option<serde_json::Value> = config_storage.load_config("app_config").await?;
    assert!(loaded_config.is_some());
    
    let backup_file = filesystem.read_file("wallet_backup.json").await?;
    assert!(!backup_file.is_empty());
    
    println!("✅ Full adapter integration test passed");
    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    // Test that adapters handle errors correctly
    let wallet_storage = InMemoryWalletStorage::new();
    let filesystem = InMemoryFilesystem::new();
    
    // Test loading non-existent wallet (returns None, not error)
    let result = wallet_storage.load_wallet("non_existent").await?;
    assert!(result.is_none());
    
    // Test reading non-existent file
    let result = filesystem.read_file("missing.txt").await;
    assert!(result.is_err());
    
    println!("✅ Error handling test passed");
    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
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
    
    println!("✅ Concurrent operations test passed");
    Ok(())
}