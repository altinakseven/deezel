//! Test utilities and mock implementations for deezel e2e testing
//!
//! This module provides:
//! - Mock metashrew server implementation
//! - Test block generation utilities
//! - E2E testing framework for deezel CLI

pub mod mock_metashrew;
pub mod test_blocks;
pub mod e2e_helpers;
pub mod test_alkanes_fee_debug;
pub mod test_fee_debug_simple;
pub mod test_envelope_fee_issue;
pub mod test_envelope_witness_corruption;
pub mod test_envelope_bin_data;
pub mod test_rpc_logging_truncation;
pub mod demo_rpc_truncation;
pub mod test_p2tr_signing;
pub mod test_esplora_commands;
pub mod test_alkanes_indexer_parsing;
pub mod test_tx_comparison;
pub mod test_taproot_signature_fix;
pub mod test_signature_generation_fix;
pub mod test_prevouts_sighash_fix;
pub mod test_deezel_v2_comparison;
pub mod test_envelope_witness_structure;
pub mod test_deezel_v3_comparison;
pub mod test_deezel_v4_comparison;
pub mod test_deezel_v5_comparison;
pub mod test_timeout_fixes;
pub mod test_single_input_optimization;
pub mod test_commit_reveal_script_path;

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