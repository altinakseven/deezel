//! CLI Integration Tests using In-Memory Adapters
//!
//! These tests demonstrate how to use the generic deezel runtime
//! with in-memory adapters to test CLI functionality without
//! requiring external dependencies or network access.

use anyhow::Result;
use bitcoin::Network;
use deezel_adapters::in_memory::*;
use deezel_core::{
    runtime::{DeezelRuntime, DeezelRuntimeConfig},
    traits::*,
    block_builder::{BlockBuilder, serialize_block},
};
use serde_json::json;
use std::str::FromStr;

type MockDeezelRuntime = DeezelRuntime<
    InMemoryWalletStorage,
    InMemoryConfigStorage,
    InMemoryRpcClient,
    InMemoryBlockchainClient,
    InMemoryFilesystem,
    InMemoryWasmRuntime,
>;

/// Create a mock deezel runtime for CLI testing
fn create_mock_cli_runtime() -> Result<MockDeezelRuntime> {
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
async fn test_cli_wallet_creation_workflow() -> Result<()> {
    let mut runtime = create_mock_cli_runtime()?;
    
    // Simulate CLI wallet creation command
    println!("🔧 Testing CLI wallet creation workflow...");
    
    // 1. Create wallet using the new API
    runtime.create_wallet("cli_test_wallet", None).await?;
    println!("  ✅ Wallet created: cli_test_wallet");
    
    // 2. Load wallet
    let _wallet_data = runtime.load_wallet("cli_test_wallet").await?;
    println!("  ✅ Wallet loaded successfully");
    
    // 3. Save wallet configuration
    let cli_config = json!({
        "default_wallet": "cli_test_wallet",
        "network": "regtest",
        "created_at": "2024-01-01T00:00:00Z",
        "version": "0.1.0"
    });
    runtime.save_config("cli_config", &cli_config).await?;
    println!("  ✅ CLI configuration saved");
    
    // 4. Verify wallet is in list
    let wallets = runtime.list_wallets().await?;
    assert!(wallets.contains(&"cli_test_wallet".to_string()));
    println!("  ✅ Wallet appears in wallet list");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_balance_check_workflow() -> Result<()> {
    let runtime = create_mock_cli_runtime()?;
    
    println!("💰 Testing CLI balance check workflow...");
    
    // Simulate CLI balance check command
    let test_address = bitcoin::Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    
    // 1. Check blockchain height (simulating sync status)
    let height = runtime.get_blockchain_height().await?;
    println!("  📊 Current blockchain height: {}", height);
    
    // 2. Get address balance
    let balance = runtime.get_address_balance(&test_address).await?;
    println!("  💰 Address balance: {} sats", balance);
    
    // 3. Verify mock data consistency
    assert_eq!(height, 0); // InMemoryBlockchainClient returns 0
    assert_eq!(balance, 0); // InMemoryRpcClient returns 0
    
    println!("  ✅ Balance check completed successfully");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_transaction_workflow() -> Result<()> {
    let mut runtime = create_mock_cli_runtime()?;
    
    println!("📤 Testing CLI transaction workflow...");
    
    // Create a simple mock transaction
    use bitcoin::{TxIn, TxOut, OutPoint, ScriptBuf, Witness};
    let tx = bitcoin::Transaction {
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
    
    // 1. Broadcast transaction
    let txid = runtime.broadcast_transaction(&tx).await?;
    println!("  📤 Transaction broadcast: {}", txid);
    
    // 2. Verify transaction ID matches
    assert_eq!(txid, tx.compute_txid());
    println!("  ✅ Transaction ID verified");
    
    // 3. Save transaction record
    let tx_record = json!({
        "txid": txid.to_string(),
        "broadcast_time": "2024-01-01T00:00:00Z",
        "status": "broadcast",
        "fee_rate": 1.0
    });
    runtime.save_config(&format!("tx_{}", txid), &tx_record).await?;
    println!("  ✅ Transaction record saved");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_alkanes_workflow() -> Result<()> {
    let mut runtime = create_mock_cli_runtime()?;
    
    println!("🧪 Testing CLI alkanes workflow...");
    
    // 1. Create mock metashrew environment
    runtime.create_mock_metashrew().await?;
    println!("  ✅ Mock metashrew environment created");
    
    // 2. Execute alkanes WASM module
    let mock_wasm = b"\x00asm\x01\x00\x00\x00"; // Minimal WASM header
    let result = runtime.execute_alkanes(mock_wasm, "execute", b"test_input").await?;
    println!("  🧪 Alkanes execution result: {} bytes", result.len());
    
    // 3. Verify result
    assert_eq!(result, b"mock_response");
    println!("  ✅ Alkanes execution completed");
    
    // 4. Process test block
    let test_block = BlockBuilder::new()
        .height(101)
        .build();
    
    let block_data = serialize_block(&test_block);
    runtime.process_test_block(&block_data, 101).await?;
    println!("  ✅ Test block processed");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_configuration_management() -> Result<()> {
    let mut runtime = create_mock_cli_runtime()?;
    
    println!("⚙️ Testing CLI configuration management...");
    
    // 1. Set up initial configuration
    let initial_config = json!({
        "network": "regtest",
        "rpc_url": "http://localhost:8332",
        "metashrew_url": "http://localhost:8080",
        "fee_rate": 1.0,
        "max_fee": 10000,
        "auto_sync": true,
        "log_level": "info"
    });
    
    runtime.save_config("deezel_config", &initial_config).await?;
    println!("  ✅ Initial configuration saved");
    
    // 2. Load and verify configuration
    let loaded_config: Option<serde_json::Value> = runtime.load_config("deezel_config").await?;
    assert!(loaded_config.is_some());
    assert_eq!(loaded_config.unwrap(), initial_config);
    println!("  ✅ Configuration loaded and verified");
    
    // 3. Update configuration (simulating CLI config update)
    let updated_config = json!({
        "network": "regtest",
        "rpc_url": "http://localhost:8332",
        "metashrew_url": "http://localhost:8080",
        "fee_rate": 2.0, // Updated
        "max_fee": 20000, // Updated
        "auto_sync": false, // Updated
        "log_level": "debug" // Updated
    });
    
    runtime.save_config("deezel_config", &updated_config).await?;
    println!("  ✅ Configuration updated");
    
    // 4. Verify updates
    let final_config: Option<serde_json::Value> = runtime.load_config("deezel_config").await?;
    assert_eq!(final_config.unwrap(), updated_config);
    println!("  ✅ Configuration updates verified");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_file_operations() -> Result<()> {
    let runtime = create_mock_cli_runtime()?;
    
    println!("📁 Testing CLI file operations...");
    
    // 1. Save wallet backup (simulating CLI backup command)
    let wallet_backup = json!({
        "name": "backup_wallet",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "network": "regtest",
        "created_at": "2024-01-01T00:00:00Z",
        "version": "0.1.0"
    });
    
    let backup_data = serde_json::to_string_pretty(&wallet_backup)?;
    runtime.write_file("backups/wallet_backup.json", backup_data.as_bytes()).await?;
    println!("  ✅ Wallet backup saved");
    
    // 2. Read backup file
    let read_backup = runtime.read_file("backups/wallet_backup.json").await?;
    let parsed_backup: serde_json::Value = serde_json::from_slice(&read_backup)?;
    assert_eq!(parsed_backup, wallet_backup);
    println!("  ✅ Wallet backup verified");
    
    // 3. Save transaction log
    let tx_log = "2024-01-01T00:00:00Z: Transaction abc123 broadcast\n2024-01-01T00:01:00Z: Transaction def456 confirmed\n";
    runtime.write_file("logs/transactions.log", tx_log.as_bytes()).await?;
    println!("  ✅ Transaction log saved");
    
    // 4. Read transaction log
    let read_log = runtime.read_file("logs/transactions.log").await?;
    assert_eq!(String::from_utf8(read_log)?, tx_log);
    println!("  ✅ Transaction log verified");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_error_scenarios() -> Result<()> {
    let runtime = create_mock_cli_runtime()?;
    
    println!("❌ Testing CLI error scenarios...");
    
    // 1. Test loading non-existent wallet
    let result = runtime.load_wallet("non_existent_wallet").await;
    assert!(result.is_err());
    println!("  ✅ Non-existent wallet error handled correctly");
    
    // 2. Test reading non-existent file
    let result = runtime.read_file("non_existent_file.txt").await;
    assert!(result.is_err());
    println!("  ✅ Non-existent file error handled correctly");
    
    // 3. Test loading non-existent config
    let result: Result<Option<serde_json::Value>> = runtime.load_config("non_existent_config").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    println!("  ✅ Non-existent config handled correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_cli_full_workflow_simulation() -> Result<()> {
    let mut runtime = create_mock_cli_runtime()?;
    
    println!("🔄 Testing full CLI workflow simulation...");
    
    // Simulate a complete CLI session
    
    // 1. Initialize CLI
    println!("  1️⃣ Initializing CLI...");
    let cli_config = json!({
        "version": "0.1.0",
        "initialized_at": "2024-01-01T00:00:00Z"
    });
    runtime.save_config("cli_init", &cli_config).await?;
    
    // 2. Create wallet
    println!("  2️⃣ Creating wallet...");
    runtime.create_wallet("full_test_wallet", None).await?;
    let _wallet_data = runtime.load_wallet("full_test_wallet").await?;
    
    // 3. Check blockchain status
    println!("  3️⃣ Checking blockchain status...");
    let height = runtime.get_blockchain_height().await?;
    assert_eq!(height, 0);
    
    // 4. Check balance
    println!("  4️⃣ Checking balance...");
    let address = bitcoin::Address::from_str("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")?
        .require_network(Network::Bitcoin)?;
    let balance = runtime.get_address_balance(&address).await?;
    assert_eq!(balance, 0);
    
    // 5. Set up alkanes environment
    println!("  5️⃣ Setting up alkanes environment...");
    runtime.create_mock_metashrew().await?;
    
    // 6. Execute alkanes operation
    println!("  6️⃣ Executing alkanes operation...");
    let mock_wasm = b"\x00asm\x01\x00\x00\x00"; // Minimal WASM header
    let result = runtime.execute_alkanes(mock_wasm, "execute", b"test_data").await?;
    assert_eq!(result, b"mock_response");
    
    // 7. Save session log
    println!("  7️⃣ Saving session log...");
    let session_log = json!({
        "session_id": "test-session-123",
        "wallet": "full_test_wallet",
        "operations": [
            "wallet_create",
            "blockchain_check",
            "balance_check",
            "alkanes_execute"
        ],
        "completed_at": "2024-01-01T00:00:00Z"
    });
    runtime.save_config("last_session", &session_log).await?;
    
    println!("  ✅ Full workflow simulation completed successfully!");
    
    Ok(())
}

/// Helper function to create mock WASM file for testing
fn create_mock_wasm_file() -> Result<()> {
    use std::fs;
    use std::path::Path;
    
    let examples_dir = Path::new("examples");
    if !examples_dir.exists() {
        fs::create_dir_all(examples_dir)?;
    }
    
    // Create a minimal WASM file for testing
    let mock_wasm = b"\x00asm\x01\x00\x00\x00"; // WASM magic number and version
    fs::write("examples/mock_alkanes.wasm", mock_wasm)?;
    
    Ok(())
}

#[tokio::test]
async fn test_setup_mock_files() -> Result<()> {
    // Ensure mock files exist for other tests
    create_mock_wasm_file()?;
    Ok(())
}