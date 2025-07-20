//! Core alkanes inspector functionality for WASM-compatible environments
//!
//! This module provides the core business logic for alkanes inspection,
//! including fuzzing, metadata extraction, disassembly, and codehash computation.
//! It uses trait abstractions to be platform-agnostic and WASM-compatible.
//!
//! Enhanced with full WASM runtime integration and rich execution details
//! including host call interception, detailed error information, and comprehensive
//! execution context management.

pub mod types;
pub mod runtime;
pub mod analysis;

use anyhow::{Context, Result};
use crate::traits::JsonRpcProvider;
use crate::alkanes::types::AlkaneId;
pub use types::{
    AlkaneMetadata, AlkaneMethod, AlkanesRuntimeContext, AlkanesState, ExecutionResult,
    FuzzingResults, HostCall, InspectionConfig, InspectionResult, MessageContextParcel,
};

#[cfg(not(feature = "std"))]
use alloc::string::ToString;
#[cfg(feature = "std")]
use std::string::ToString;

/// Core alkanes inspector that works with trait abstractions
#[cfg(feature = "wasm-inspection")]
pub struct AlkaneInspector<P: JsonRpcProvider> {
    rpc_provider: P,
}

#[cfg(feature = "wasm-inspection")]
impl<P: JsonRpcProvider> AlkaneInspector<P> {
    /// Create a new alkane inspector
    pub fn new(rpc_provider: P) -> Self {
        Self { rpc_provider }
    }

    /// Inspect an alkane with the specified configuration
    pub async fn inspect_alkane(
        &self,
        alkane_id: &AlkaneId,
        config: &InspectionConfig,
    ) -> Result<InspectionResult> {
        // Get the WASM bytecode for the alkane
        let bytecode = self.get_alkane_bytecode(alkane_id).await?;
        
        // Remove 0x prefix if present
        let hex_string = bytecode.strip_prefix("0x").unwrap_or(&bytecode);
        
        let wasm_bytes = hex::decode(hex_string)
            .with_context(|| "Failed to decode WASM bytecode from hex".to_string())?;
        
        let mut result = InspectionResult {
            alkane_id: alkane_id.clone(),
            bytecode_length: wasm_bytes.len(),
            codehash: None,
            disassembly: None,
            metadata: None,
            metadata_error: None,
            fuzzing_results: None,
        };
        
        // Perform requested analysis
        if config.codehash {
            result.codehash = Some(analysis::compute_codehash(&wasm_bytes)?);
        }
        
        if config.meta {
            match analysis::extract_metadata(&wasm_bytes).await {
                Ok(meta) => result.metadata = Some(meta),
                Err(e) => result.metadata_error = Some(e.to_string()),
            }
        }
        
        if config.disasm {
            result.disassembly = analysis::disassemble_wasm(&wasm_bytes)?;
        }
        
        if config.fuzz {
            result.fuzzing_results = Some(analysis::perform_fuzzing_analysis(
                alkane_id, 
                &wasm_bytes, 
                config.fuzz_ranges.as_deref()
            ).await?);
        }
        
        Ok(result)
    }

    /// Get WASM bytecode for an alkane
    async fn get_alkane_bytecode(&self, alkane_id: &AlkaneId) -> Result<String> {
        crate::traits::JsonRpcProvider::get_bytecode(
            &self.rpc_provider,
            &alkane_id.block.to_string(),
            &alkane_id.tx.to_string()
        ).await
        .map_err(|e| anyhow::anyhow!("Failed to get bytecode: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::JsonRpcProvider;
    use async_trait::async_trait;
    use crate::alkanes::types::AlkaneId;
    use super::types::InspectionConfig;

    struct MockRpcProvider;

    #[async_trait(?Send)]
    impl JsonRpcProvider for MockRpcProvider {
        async fn call(
            &self,
            _url: &str,
            _method: &str,
            _params: serde_json::Value,
            _id: u64,
        ) -> Result<serde_json::Value, crate::DeezelError> {
            Ok(serde_json::json!("0x"))
        }

        async fn get_bytecode(&self, _block: &str, _tx: &str) -> Result<String, crate::DeezelError> {
            Ok("0x".to_string())
        }
    }

    #[tokio::test]
    async fn test_alkane_inspector_creation() {
        let provider = MockRpcProvider;
        let inspector = AlkaneInspector::new(provider);
        
        let alkane_id = AlkaneId { block: 1, tx: 100 };
        let config = InspectionConfig {
            disasm: false,
            fuzz: false,
            fuzz_ranges: None,
            meta: false,
            codehash: true,
            raw: false,
        };
        
        let result = inspector.inspect_alkane(&alkane_id, &config).await;
        assert!(result.is_ok());
    }
}