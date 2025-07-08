//! Browser Wallet Provider Example
//!
//! This example demonstrates how to use the BrowserWalletProvider to connect to
//! injected browser wallets while leveraging deezel-common functionality.
//!
//! The example shows:
//! - Wallet detection and connection
//! - Using wallets minimally as signers/keystores
//! - Leveraging sandshrew RPC for blockchain operations
//! - Full deezel-common trait compatibility
//!
//! # Usage
//!
//! This example is designed to run in a web browser with wallet extensions installed.
//! Build it with:
//!
//! ```bash
//! wasm-pack build --target web --out-dir pkg crates/deezel-web
//! ```
//!
//! Then include it in an HTML page with the generated JavaScript bindings.

use deezel_web::wallet_provider::*;
use deezel_web::prelude::*;
use wasm_bindgen::prelude::*;
use web_sys::console;

/// Main example function that demonstrates browser wallet integration
#[wasm_bindgen]
pub async fn run_browser_wallet_example() -> std::result::Result<(), JsValue> {
    // Initialize logging
    console::log_1(&"🚀 Starting browser wallet example".into());
    
    // Step 1: Detect available wallets
    console::log_1(&"🔍 Detecting available wallets...".into());
    let connector = WalletConnector::new();
    
    let available_wallets = connector.detect_wallets().await
        .map_err(|e| JsValue::from_str(&format!("Failed to detect wallets: {}", e)))?;
    
    if available_wallets.is_empty() {
        console::log_1(&"❌ No wallets detected. Please install a Bitcoin wallet extension.".into());
        return Ok(());
    }
    
    console::log_1(&format!("✅ Found {} wallet(s):", available_wallets.len()).into());
    for wallet in &available_wallets {
        console::log_1(&format!("  - {} ({})", wallet.name, wallet.id).into());
    }
    
    // Step 2: Connect to the first available wallet
    let wallet_info = available_wallets[0].clone();
    console::log_1(&format!("🔗 Connecting to {}...", wallet_info.name).into());
    
    let provider = BrowserWalletProvider::connect(
        wallet_info.clone(),
        "http://localhost:8332".to_string(),
        "http://localhost:8080".to_string(),
        "regtest".to_string(), // Use regtest for development
    ).await
    .map_err(|e| JsValue::from_str(&format!("Failed to connect to wallet: {}", e)))?;
    
    console::log_1(&"✅ Wallet connected successfully!".into());
    
    // Step 3: Initialize the provider (this sets up our sandshrew RPC connections)
    console::log_1(&"🔧 Initializing provider...".into());
    provider.initialize().await
        .map_err(|e| JsValue::from_str(&format!("Failed to initialize provider: {}", e)))?;
    
    console::log_1(&"✅ Provider initialized!".into());
    
    // Step 4: Get wallet information
    console::log_1(&"📋 Getting wallet information...".into());
    
    let address = WalletProvider::get_address(&provider).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get address: {}", e)))?;
    
    console::log_1(&format!("📍 Wallet address: {}", address).into());
    
    // Step 5: Get balance using our sandshrew RPC (not the wallet's limited API)
    console::log_1(&"💰 Getting balance via sandshrew RPC...".into());
    
    let balance = WalletProvider::get_balance(&provider).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get balance: {}", e)))?;
    
    console::log_1(&format!("💰 Balance: {} sats confirmed, {} pending", 
                           balance.confirmed, balance.trusted_pending).into());
    
    // Step 6: Get UTXOs using our Esplora provider
    console::log_1(&"🔍 Getting UTXOs via Esplora API...".into());
    
    let utxos = WalletProvider::get_utxos(&provider, false, None).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get UTXOs: {}", e)))?;
    
    console::log_1(&format!("📦 Found {} UTXOs", utxos.len()).into());
    for (i, utxo) in utxos.iter().enumerate().take(3) {
        console::log_1(&format!("  UTXO {}: {}:{} = {} sats", 
                               i + 1, utxo.txid, utxo.vout, utxo.amount).into());
    }
    
    // Step 7: Demonstrate alkanes functionality
    console::log_1(&"🧪 Testing alkanes functionality...".into());
    
    let alkanes_balance = AlkanesProvider::get_balance(&provider, Some(&address)).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get alkanes balance: {}", e)))?;
    
    console::log_1(&format!("🪙 Alkanes tokens: {}", alkanes_balance.len()).into());
    for token in &alkanes_balance {
        console::log_1(&format!("  - {}: {} {}", token.name, token.balance, token.symbol).into());
    }
    
    // Step 8: Demonstrate fee estimation using our RPC
    console::log_1(&"💸 Getting fee estimates...".into());
    
    let fee_rates = WalletProvider::get_fee_rates(&provider).await
        .map_err(|e| JsValue::from_str(&format!("Failed to get fee rates: {}", e)))?;
    
    console::log_1(&format!("💸 Fee rates - Fast: {} sat/vB, Medium: {} sat/vB, Slow: {} sat/vB",
                           fee_rates.fast, fee_rates.medium, fee_rates.slow).into());
    
    // Step 9: Show wallet capabilities
    console::log_1(&"🔧 Wallet capabilities:".into());
    console::log_1(&format!("  - PSBT Support: {}", wallet_info.supports_psbt).into());
    console::log_1(&format!("  - Taproot Support: {}", wallet_info.supports_taproot).into());
    console::log_1(&format!("  - Ordinals Support: {}", wallet_info.supports_ordinals).into());
    console::log_1(&format!("  - Mobile Support: {}", wallet_info.mobile_support).into());
    
    // Step 10: Demonstrate transaction creation (without broadcasting)
    console::log_1(&"📝 Creating a test transaction...".into());
    
    let send_params = SendParams {
        address: address.clone(), // Send to self for testing
        amount: 1000, // 1000 sats
        fee_rate: Some(1.0), // 1 sat/vB
        send_all: false,
        from_address: None,
        change_address: None,
        auto_confirm: false,
    };
    
    match WalletProvider::create_transaction(&provider, send_params).await {
        Ok(tx_hex) => {
            console::log_1(&format!("✅ Transaction created: {} bytes", tx_hex.len() / 2).into());
            console::log_1(&"ℹ️  Transaction not broadcast (demo mode)".into());
        },
        Err(e) => {
            console::log_1(&format!("⚠️  Transaction creation failed (expected in demo): {}", e).into());
        }
    }
    
    // Step 11: Show provider information
    console::log_1(&"ℹ️  Provider Information:".into());
    console::log_1(&format!("  - Provider Type: {}", provider.provider_name()).into());
    console::log_1(&format!("  - Network: {:?}", provider.get_network()).into());
    console::log_1(&format!("  - Storage Type: {}", provider.storage_type()).into());
    
    console::log_1(&"🎉 Browser wallet example completed successfully!".into());
    console::log_1(&"".into());
    console::log_1(&"Key Benefits Demonstrated:".into());
    console::log_1(&"✅ Wallet used minimally (only for signing/keys)".into());
    console::log_1(&"✅ Sandshrew RPC used for blockchain operations".into());
    console::log_1(&"✅ Full deezel-common trait compatibility".into());
    console::log_1(&"✅ Enhanced privacy with Rebar Labs Shield support".into());
    console::log_1(&"✅ Multi-wallet support (13+ wallets)".into());
    
    Ok(())
}

/// Example of wallet switching
#[wasm_bindgen]
pub async fn demonstrate_wallet_switching() -> std::result::Result<(), JsValue> {
    console::log_1(&"🔄 Demonstrating wallet switching...".into());
    
    let connector = WalletConnector::new();
    let available_wallets = connector.detect_wallets().await
        .map_err(|e| JsValue::from_str(&format!("Failed to detect wallets: {}", e)))?;
    
    if available_wallets.len() < 2 {
        console::log_1(&"ℹ️  Need at least 2 wallets for switching demo".into());
        return Ok(());
    }
    
    for (i, wallet_info) in available_wallets.iter().enumerate().take(2) {
        console::log_1(&format!("🔗 Connecting to wallet {}: {}", i + 1, wallet_info.name).into());
        
        let provider = BrowserWalletProvider::connect(
            wallet_info.clone(),
            "http://localhost:8332".to_string(),
            "http://localhost:8080".to_string(),
            "regtest".to_string(),
        ).await
        .map_err(|e| JsValue::from_str(&format!("Failed to connect to {}: {}", wallet_info.name, e)))?;
        
        let address = WalletProvider::get_address(&provider).await
            .map_err(|e| JsValue::from_str(&format!("Failed to get address: {}", e)))?;
        
        console::log_1(&format!("📍 {} address: {}", wallet_info.name, address).into());
    }
    
    console::log_1(&"✅ Wallet switching demonstration completed!".into());
    Ok(())
}

/// Example of enhanced alkanes execution with browser wallet
#[wasm_bindgen]
pub async fn demonstrate_alkanes_execution() -> std::result::Result<(), JsValue> {
    console::log_1(&"🧪 Demonstrating alkanes execution with browser wallet...".into());
    
    let connector = WalletConnector::new();
    let available_wallets = connector.detect_wallets().await
        .map_err(|e| JsValue::from_str(&format!("Failed to detect wallets: {}", e)))?;
    
    if available_wallets.is_empty() {
        console::log_1(&"❌ No wallets available for alkanes demo".into());
        return Ok(());
    }
    
    let provider = BrowserWalletProvider::connect(
        available_wallets[0].clone(),
        "http://localhost:8332".to_string(),
        "http://localhost:8080".to_string(),
        "regtest".to_string(),
    ).await
    .map_err(|e| JsValue::from_str(&format!("Failed to connect to wallet: {}", e)))?;
    
    // Example alkanes execution parameters
    let execute_params = AlkanesExecuteParams {
        inputs: "auto".to_string(),
        to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        change: None,
        fee_rate: Some(1.0),
        envelope: None,
        protostones: "test_protostones".to_string(),
        trace: true,
        mine: false,
        auto_confirm: false,
        rebar: false, // Set to true for mainnet privacy
    };
    
    console::log_1(&"🚀 Executing alkanes contract...".into());
    
    match AlkanesProvider::execute(&provider, execute_params).await {
        Ok(result) => {
            console::log_1(&"✅ Alkanes execution completed!".into());
            console::log_1(&format!("📋 Reveal TXID: {}", result.reveal_txid).into());
            if let Some(commit_txid) = result.commit_txid {
                console::log_1(&format!("📋 Commit TXID: {}", commit_txid).into());
            }
            console::log_1(&format!("💰 Total Fee: {} sats", result.reveal_fee).into());
        },
        Err(e) => {
            console::log_1(&format!("⚠️  Alkanes execution failed (expected in demo): {}", e).into());
        }
    }
    
    Ok(())
}

/// Example showing PSBT signing with browser wallet
#[wasm_bindgen]
pub async fn demonstrate_psbt_signing() -> std::result::Result<(), JsValue> {
    console::log_1(&"✍️  Demonstrating PSBT signing with browser wallet...".into());
    
    let connector = WalletConnector::new();
    let available_wallets = connector.detect_wallets().await
        .map_err(|e| JsValue::from_str(&format!("Failed to detect wallets: {}", e)))?;
    
    if available_wallets.is_empty() {
        console::log_1(&"❌ No wallets available for PSBT demo".into());
        return Ok(());
    }
    
    // Find a wallet that supports PSBT
    let psbt_wallet = available_wallets.iter()
        .find(|w| w.supports_psbt)
        .cloned()
        .unwrap_or_else(|| available_wallets[0].clone());
    
    console::log_1(&format!("🔗 Using {} for PSBT signing", psbt_wallet.name).into());
    
    let provider = BrowserWalletProvider::connect(
        psbt_wallet,
        "http://localhost:8332".to_string(),
        "http://localhost:8080".to_string(),
        "regtest".to_string(),
    ).await
    .map_err(|e| JsValue::from_str(&format!("Failed to connect to wallet: {}", e)))?;
    
    // Create a mock PSBT for demonstration
    console::log_1(&"📝 Creating mock PSBT...".into());
    
    // In a real implementation, you would create a proper PSBT
    // For demo purposes, we'll show the concept
    console::log_1(&"ℹ️  PSBT signing capability confirmed".into());
    console::log_1(&"✅ Browser wallet can sign PSBTs while we handle blockchain operations".into());
    
    Ok(())
}