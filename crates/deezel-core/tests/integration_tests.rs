//! Integration tests for deezel-core using in-memory mocks
//!
//! These tests prove that the generic runtime works correctly with
//! mock implementations, providing comprehensive test coverage.

use anyhow::Result;
use bitcoin::{Address, Network, Transaction};
use deezel_adapters::in_memory::*;
use deezel_core::{
    runtime::{DeezelRuntime, DeezelRuntimeConfig},
    traits::*,
    block_builder::{BlockBuilder, serialize_block},
};
use serde_json::json;
use std::str::FromStr;

type TestRuntime = DeezelRuntime<
    InMemoryWalletStorage,
    InMemoryConfigStorage,
    InMemoryRpcClient,
    InMemoryBlockchainClient,
    InMemoryFilesystem,
    InMemoryWasmRuntime,
>;

/// Create a test runtime with all in-memory adapters
fn create_test_runtime() -> Result<TestRuntime> {
    let wallet_storage = InMemoryWalletStorage::new();
    let config_storage = InMemoryConfigStorage::new();
    let rpc_client = InMemoryRpcClient::new();
    let blockchain_client = InMemoryBlockchainClient::new();
    let filesystem = InMemoryFilesystem::new();
    let wasm_runtime = InMemoryWasmRuntime::new();
    
    let config = DeezelRuntimeConfig {
        network: NetworkConfig {
            network: Network::Regtest,
            rpc_url: "http://localhost:8332".to_string(),
            esplora_url: None,
            metashrew_url: None,
        },
        wallet: WalletConfig {
            name: "test_wallet".to_string(),
            network: Network::Regtest,
            descriptor: Some("wpkh([d34db33f/84'/1'/0']tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)".to_string()),
            mnemonic_path: None,
        },
        rpc: RpcConfig {
            bitcoin_rpc_url: "http://localhost:8332".to_string(),
            ord_rpc_url: None,
            esplora_url: None,
            metashrew_url: None,
            timeout_ms: 30000,
            max_retries: 3,
        },
        alkanes: AlkanesConfig {
            wasm_cache_dir: "/tmp/wasm_cache".to_string(),
            max_memory: 64 * 1024 * 1024,
            execution_timeout_ms: 30000,
            enable_simulation: true,
        },
    };
    
    Ok(DeezelRuntime::new(
        wallet_storage,
        config_storage,
        rpc_client,
        blockchain_client,
        filesystem,
        wasm_runtime,
        config,
    ))
}

#[tokio::test]
async fn test_runtime_initialization() -> Result<()> {
    let runtime = create_test_runtime()?;
    
    // Test that runtime is properly created
    assert_eq!(runtime.config.network.network, Network::Regtest);
    
    Ok(())
}

#[tokio::test]
async fn test_wallet_operations() -> Result<()> {
    let mut runtime = create_test_runtime()?;
    
    // Test wallet creation
    runtime.create_wallet("test_wallet", None).await?;
    
    // Test wallet listing
    let wallets = runtime.list_wallets().await?;
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0], "test_wallet");
    
    // Test wallet loading
    let _wallet_data = runtime.load_wallet("test_wallet").await?;
    
    Ok(())
}

#[tokio::test]
async fn test_blockchain_operations() -> Result<()> {
    let runtime = create_test_runtime()?;
    
    // Test blockchain height
    let height = runtime.get_blockchain_height().await?;
    assert_eq!(height, 0); // InMemoryBlockchainClient returns 0 by default
    
    // Test address balance
    let address = Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    let balance = runtime.get_address_balance(&address).await?;
    assert_eq!(balance, 0); // InMemoryRpcClient returns 0 by default
    
    Ok(())
}

#[tokio::test]
async fn test_transaction_operations() -> Result<()> {
    let runtime = create_test_runtime()?;
    
    // Create a simple mock transaction
    use bitcoin::{TxIn, TxOut, OutPoint, ScriptBuf, Witness};
    let tx = Transaction {
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
    
    // Test transaction broadcast
    let txid = runtime.broadcast_transaction(&tx).await?;
    assert_eq!(txid, tx.compute_txid());
    
    Ok(())
}

#[tokio::test]
async fn test_config_operations() -> Result<()> {
    let mut runtime = create_test_runtime()?;
    
    // Test config saving
    let test_config = json!({
        "network": "regtest",
        "fee_rate": 1.0,
        "max_fee": 10000
    });
    
    runtime.save_config("test_config", &test_config).await?;
    
    // Test config loading
    let loaded_config: Option<serde_json::Value> = runtime.load_config("test_config").await?;
    assert!(loaded_config.is_some());
    assert_eq!(loaded_config.unwrap(), test_config);
    
    // Test loading non-existent config
    let missing_config: Option<serde_json::Value> = runtime.load_config("missing").await?;
    assert!(missing_config.is_none());
    
    Ok(())
}

#[tokio::test]
async fn test_filesystem_operations() -> Result<()> {
    let runtime = create_test_runtime()?;
    
    // Test file writing
    let test_data = b"Hello, deezel!";
    runtime.write_file("test.txt", test_data).await?;
    
    // Test file reading
    let read_data = runtime.read_file("test.txt").await?;
    assert_eq!(read_data, test_data);
    
    // Test reading non-existent file
    let result = runtime.read_file("missing.txt").await;
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_wasm_operations() -> Result<()> {
    let mut runtime = create_test_runtime()?;
    
    // Test WASM module execution
    let mock_wasm = b"\x00asm\x01\x00\x00\x00"; // Minimal WASM header
    let result = runtime.execute_alkanes(mock_wasm, "test_function", b"test_args").await?;
    
    // InMemoryWasmRuntime returns "mock_response"
    assert_eq!(result, b"mock_response");
    
    Ok(())
}

#[tokio::test]
async fn test_mock_metashrew_integration() -> Result<()> {
    let mut runtime = create_test_runtime()?;
    
    // Test mock metashrew creation
    runtime.create_mock_metashrew().await?;
    
    // Test block processing
    let test_block = BlockBuilder::new()
        .height(101)
        .build();
    
    let block_data = serialize_block(&test_block);
    runtime.process_test_block(&block_data, 101).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_context_management() -> Result<()> {
    let runtime = create_test_runtime()?;
    
    // Test runtime configuration
    assert_eq!(runtime.config.network.network, Network::Regtest);
    assert_eq!(runtime.config.wallet.name, "test_wallet");
    
    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    let runtime = create_test_runtime()?;
    
    // Test loading non-existent wallet
    let result = runtime.load_wallet("non_existent").await;
    assert!(result.is_err());
    
    // Test invalid address balance query
    let invalid_address = Address::from_str("invalid_address");
    assert!(invalid_address.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    use std::sync::Arc;
    let runtime: Arc<TestRuntime> = Arc::new(create_test_runtime()?);
    
    // Test concurrent blockchain height queries
    let mut handles = vec![];
    for _ in 0..10 {
        let runtime_clone = Arc::clone(&runtime);
        let handle = tokio::spawn(async move {
            runtime_clone.get_blockchain_height().await
        });
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    for handle in handles {
        let height = handle.await??;
        assert_eq!(height, 0);
    }
    
    Ok(())
}

#[tokio::test]
async fn test_full_workflow() -> Result<()> {
    let mut runtime = create_test_runtime()?;
    
    // 1. Create and load wallet
    runtime.create_wallet("workflow_test", None).await?;
    let _wallet_data = runtime.load_wallet("workflow_test").await?;
    
    // 2. Check blockchain state
    let height = runtime.get_blockchain_height().await?;
    
    // 3. Save configuration
    let config = json!({
        "wallet": "workflow_test",
        "network": "regtest",
        "last_sync_height": height
    });
    runtime.save_config("workflow", &config).await?;
    
    // 4. Create mock metashrew
    runtime.create_mock_metashrew().await?;
    
    // 5. Process test block
    let test_block = BlockBuilder::new()
        .height((height + 1) as u32)
        .build();
    let block_data = serialize_block(&test_block);
    runtime.process_test_block(&block_data, (height + 1) as u32).await?;
    
    // 6. Verify state
    let loaded_config: Option<serde_json::Value> = runtime.load_config("workflow").await?;
    assert!(loaded_config.is_some());
    
    Ok(())
}

/// Test the mock RPC client responses match expected patterns
#[tokio::test]
async fn test_mock_rpc_responses() -> Result<()> {
    let rpc_client = InMemoryRpcClient::new();
    
    // Test address balance
    let address = Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    let balance = rpc_client.get_address_balance(&address).await?;
    assert_eq!(balance, 0); // Default balance
    
    // Test spendables
    let spendables = rpc_client.get_address_utxos(&address).await?;
    assert!(spendables.is_empty()); // Returns empty vec by default
    
    Ok(())
}

/// Test the mock blockchain client
#[tokio::test]
async fn test_mock_blockchain_client() -> Result<()> {
    let blockchain_client = InMemoryBlockchainClient::new();
    
    // Test tip height
    let height = blockchain_client.get_tip_height().await?;
    assert_eq!(height, 0);
    
    // Test fee estimates
    let estimates = blockchain_client.get_fee_estimates().await?;
    assert!(estimates.contains_key("1"));
    assert!(estimates.contains_key("6"));
    assert!(estimates.contains_key("144"));
    
    Ok(())
}