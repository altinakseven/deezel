//! Generic alkanes management

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::traits::WasmRuntimeLike;

/// Alkanes configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesConfig {
    pub wasm_cache_dir: String,
    pub max_memory: usize,
    pub execution_timeout_ms: u64,
    pub enable_simulation: bool,
}

/// Alkanes management errors
#[derive(Debug, thiserror::Error)]
pub enum AlkanesError {
    #[error("WASM execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Module load failed: {0}")]
    ModuleLoadFailed(String),
    
    #[error("Invalid WASM: {0}")]
    InvalidWasm(String),
    
    #[error("Timeout")]
    Timeout,
}

/// Generic alkanes manager
pub struct AlkanesManager<WR>
where
    WR: WasmRuntimeLike,
{
    wasm_runtime: WR,
    config: AlkanesConfig,
}

impl<WR> AlkanesManager<WR>
where
    WR: WasmRuntimeLike,
{
    pub fn new(mut wasm_runtime: WR, config: AlkanesConfig) -> Self {
        // Configure runtime limits
        wasm_runtime.set_memory_limit(config.max_memory);
        wasm_runtime.set_timeout(config.execution_timeout_ms);
        
        Self { wasm_runtime, config }
    }
    
    pub async fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<(), AlkanesError> {
        self.wasm_runtime.load_module(wasm_bytes).await
            .map_err(|e| AlkanesError::ModuleLoadFailed(format!("{:?}", e)))
    }
    
    pub async fn execute_function(&mut self, name: &str, args: &[u8]) -> Result<Vec<u8>, AlkanesError> {
        self.wasm_runtime.execute_function(name, args).await
            .map_err(|e| AlkanesError::ExecutionFailed(format!("{:?}", e)))
    }
    
    pub async fn get_exports(&self) -> Result<Vec<String>, AlkanesError> {
        self.wasm_runtime.get_exports().await
            .map_err(|e| AlkanesError::ExecutionFailed(format!("{:?}", e)))
    }
    
    pub async fn simulate_transaction(&mut self, wasm_bytes: &[u8], tx_data: &[u8]) -> Result<Vec<u8>, AlkanesError> {
        if !self.config.enable_simulation {
            return Err(AlkanesError::ExecutionFailed("Simulation disabled".to_string()));
        }
        
        // Load module
        self.load_module(wasm_bytes).await?;
        
        // Execute simulation function
        self.execute_function("simulate", tx_data).await
    }
}