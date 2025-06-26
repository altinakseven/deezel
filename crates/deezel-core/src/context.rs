//! Execution context for deezel operations

use bitcoin::{Block, Network};
use serde::{Serialize, Deserialize};

/// Execution context containing current state and configuration
#[derive(Debug, Clone)]
pub struct DeezelContext {
    /// Current block being processed
    pub current_block: Option<Block>,
    
    /// Current block height
    pub current_height: u32,
    
    /// Network configuration
    pub network: Network,
    
    /// Current wallet name
    pub wallet_name: Option<String>,
    
    /// Execution state
    pub state: ExecutionState,
    
    /// Additional metadata
    pub metadata: ContextMetadata,
}

/// Execution state tracking
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionState {
    /// Initial state
    Initialized,
    
    /// Processing a block
    ProcessingBlock,
    
    /// Executing a transaction
    ExecutingTransaction,
    
    /// Running alkanes WASM
    ExecutingWasm,
    
    /// Completed successfully
    Completed,
    
    /// Error state
    Error(String),
}

/// Additional context metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextMetadata {
    /// Timestamp when context was created
    pub created_at: u64,
    
    /// Last updated timestamp
    pub updated_at: u64,
    
    /// Custom metadata fields
    pub custom: std::collections::HashMap<String, serde_json::Value>,
}

impl DeezelContext {
    /// Create a new context
    pub fn new(network: Network) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            current_block: None,
            current_height: 0,
            network,
            wallet_name: None,
            state: ExecutionState::Initialized,
            metadata: ContextMetadata {
                created_at: now,
                updated_at: now,
                custom: std::collections::HashMap::new(),
            },
        }
    }
    
    /// Set current block
    pub fn set_block(&mut self, block: Block, height: u32) {
        self.current_block = Some(block);
        self.current_height = height;
        self.update_timestamp();
    }
    
    /// Set wallet name
    pub fn set_wallet(&mut self, name: String) {
        self.wallet_name = Some(name);
        self.update_timestamp();
    }
    
    /// Update execution state
    pub fn set_state(&mut self, state: ExecutionState) {
        self.state = state;
        self.update_timestamp();
    }
    
    /// Add custom metadata
    pub fn add_metadata(&mut self, key: String, value: serde_json::Value) {
        self.metadata.custom.insert(key, value);
        self.update_timestamp();
    }
    
    /// Update timestamp
    fn update_timestamp(&mut self) {
        self.metadata.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

impl Default for DeezelContext {
    fn default() -> Self {
        Self::new(Network::Bitcoin)
    }
}