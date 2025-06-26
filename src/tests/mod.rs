//! Test utilities and mock implementations for deezel e2e testing
//!
//! This module provides:
//! - Mock metashrew server implementation
//! - Test block generation utilities
//! - E2E testing framework for deezel CLI

pub mod mock_metashrew;
pub mod test_blocks;
pub mod e2e_helpers;
pub mod e2e_cli_tests;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Test configuration for mock metashrew setup
#[derive(Clone, Debug)]
pub struct TestConfig {
    /// Starting block height for tests
    pub start_height: u32,
    /// Network type (regtest, testnet, mainnet)
    pub network: String,
    /// Mock RPC server port
    pub rpc_port: u16,
    /// Enable debug logging
    pub debug: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            start_height: 840000,
            network: "regtest".to_string(),
            rpc_port: 18080,
            debug: true,
        }
    }
}

/// Global test state for coordinating between mock services
#[derive(Debug)]
pub struct TestState {
    /// Current block height
    pub height: u32,
    /// Mock blockchain data
    pub blocks: HashMap<u32, Vec<u8>>,
    /// Mock UTXO set
    pub utxos: HashMap<String, Vec<MockUtxo>>,
    /// Mock protorune balances
    pub protorune_balances: HashMap<String, HashMap<String, u64>>,
    /// Mock transaction pool
    pub mempool: Vec<MockTransaction>,
}

#[derive(Debug, Clone)]
pub struct MockUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: String,
    pub confirmations: u32,
}

#[derive(Debug, Clone)]
pub struct MockTransaction {
    pub txid: String,
    pub hex: String,
    pub fee: u64,
    pub size: u32,
}

impl Default for TestState {
    fn default() -> Self {
        Self {
            height: 840000,
            blocks: HashMap::new(),
            utxos: HashMap::new(),
            protorune_balances: HashMap::new(),
            mempool: Vec::new(),
        }
    }
}

/// Global test state instance
pub static TEST_STATE: Mutex<Option<Arc<Mutex<TestState>>>> = Mutex::new(None);

/// Initialize the global test state
pub fn init_test_state(config: TestConfig) -> Result<Arc<Mutex<TestState>>> {
    let state = Arc::new(Mutex::new(TestState {
        height: config.start_height,
        ..Default::default()
    }));
    
    let mut global_state = TEST_STATE.lock().unwrap();
    *global_state = Some(state.clone());
    
    Ok(state)
}

/// Get the global test state
pub fn get_test_state() -> Result<Arc<Mutex<TestState>>> {
    let global_state = TEST_STATE.lock().unwrap();
    global_state.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Test state not initialized"))
        .map(|s| s.clone())
}

/// Clear the global test state
pub fn clear_test_state() {
    let mut global_state = TEST_STATE.lock().unwrap();
    *global_state = None;
}