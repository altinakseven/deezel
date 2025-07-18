//! Test utilities and comprehensive e2e testing for deezel alkanes functionality
//!
//! This module provides:
//! - Mock metashrew server implementation
//! - Test block generation utilities
//! - E2E testing framework for deezel CLI
//! - Comprehensive alkanes envelope and cellpack testing

pub mod mock_metashrew;
pub mod e2e_helpers;
pub mod integration_tests;
pub mod test_alkanes_e2e;
pub mod e2e_deploy;

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
    /// Mock alkanes balances
    pub alkanes_balances: HashMap<String, HashMap<String, u64>>,
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
            alkanes_balances: HashMap::new(),
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
    
    let mut global_state = TEST_STATE.lock().expect("Failed to lock TEST_STATE");
    *global_state = Some(state.clone());
    
    Ok(state)
}

/// Get the global test state
pub fn get_test_state() -> Result<Arc<Mutex<TestState>>> {
    let global_state = TEST_STATE.lock().expect("Failed to lock TEST_STATE");
    global_state.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Test state not initialized"))
        .map(|s| s.clone())
}

/// Clear the global test state
pub fn clear_test_state() {
    let mut global_state = TEST_STATE.lock().expect("Failed to lock TEST_STATE");
    *global_state = None;
}

/// Helper function to create test envelope data
pub fn create_test_envelope_data() -> Vec<u8> {
    // Create a minimal WASM module for testing
    // This is a simple "hello world" WASM module
    vec![
        0x00, 0x61, 0x73, 0x6d, // WASM magic number
        0x01, 0x00, 0x00, 0x00, // WASM version
        // Minimal sections for a valid WASM module
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section
        0x03, 0x02, 0x01, 0x00, // Function section
        0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section
    ]
}

/// Helper function to create test cellpack data
pub fn create_test_cellpack_values(target_block: u64, target_tx: u64, inputs: Vec<u128>) -> Vec<u128> {
    let mut values = vec![target_block as u128, target_tx as u128];
    values.extend(inputs);
    values
}

/// Helper function to create test UTXOs for testing
pub fn create_test_utxos(_address: &str, count: usize) -> Vec<MockUtxo> {
    (0..count)
        .map(|i| MockUtxo {
            txid: format!("test_txid_{}", i),
            vout: i as u32,
            amount: 100000 + (i as u64 * 10000), // Varying amounts
            script_pubkey: format!("test_script_{}", i),
            confirmations: 6,
        })
        .collect()
}

/// Helper function to setup test blockchain state
pub fn setup_test_blockchain(start_height: u32) -> Result<()> {
    // Initialize test state with the given height
    let config = TestConfig {
        start_height,
        ..Default::default()
    };
    let _state = init_test_state(config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TestConfig::default();
        assert_eq!(config.network, "regtest");
        assert_eq!(config.start_height, 840000);
        assert!(config.debug);
    }

    #[test]
    fn test_state_initialization() {
        let config = TestConfig::default();
        let state = init_test_state(config).unwrap();
        
        let state_lock = state.lock().expect("Failed to lock state");
        assert_eq!(state_lock.height, 840000);
        assert!(state_lock.blocks.is_empty());
        assert!(state_lock.utxos.is_empty());
        
        clear_test_state();
    }

    #[test]
    fn test_envelope_data_creation() {
        let envelope_data = create_test_envelope_data();
        assert!(!envelope_data.is_empty());
        assert_eq!(&envelope_data[0..4], &[0x00, 0x61, 0x73, 0x6d]); // WASM magic
    }

    #[test]
    fn test_cellpack_values_creation() {
        let values = create_test_cellpack_values(3, 1000, vec![101]);
        assert_eq!(values, vec![3, 1000, 101]);
        
        let values_multi = create_test_cellpack_values(4, 500, vec![101, 202, 303]);
        assert_eq!(values_multi, vec![4, 500, 101, 202, 303]);
    }
}