//! Concrete alkanes inspector implementation for the refactored CLI
//! 
//! This is adapted from the original alkanes inspector to work with
//! the concrete RPC client implementation.

use anyhow::{Context, Result};
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::fs;
use std::time::{Duration, Instant};
use sha3::{Digest, Keccak256};
use serde_json;

use crate::rpc::RpcClient;
use deezel_common::alkanes::types::AlkaneId;
use wasmtime::*;
use alkanes_support::{
    id::AlkaneId as AlkanesAlkaneId,
    parcel::AlkaneTransferParcel,
    trace::Trace,
};

// Simple message context parcel for alkane execution
#[derive(Default, Clone, Debug)]
pub struct MessageContextParcel {
    pub vout: u32,
    pub height: u64,
    pub calldata: Vec<u8>,
}

/// Alkanes runtime context for VM execution - matches alkanes-rs exactly
#[derive(Default, Clone)]
pub struct AlkanesRuntimeContext {
    pub myself: AlkanesAlkaneId,
    pub caller: AlkanesAlkaneId,
    pub incoming_alkanes: AlkaneTransferParcel,
    pub returndata: Vec<u8>,
    pub inputs: Vec<u128>,
    pub message: Box<MessageContextParcel>,
    pub trace: Trace,
}

impl AlkanesRuntimeContext {
    pub fn from_cellpack_inputs(inputs: Vec<u128>) -> Self {
        let message = MessageContextParcel::default();
        Self {
            message: Box::new(message),
            returndata: vec![],
            incoming_alkanes: AlkaneTransferParcel::default(),
            myself: AlkanesAlkaneId::default(),
            caller: AlkanesAlkaneId::default(),
            trace: Trace::default(),
            inputs,
        }
    }
    
    pub fn serialize(&self) -> Vec<u8> {
        let flattened = self.flatten();
        let mut result = Vec::new();
        for value in flattened {
            result.extend_from_slice(&value.to_le_bytes());
        }
        result
    }
    
    pub fn flatten(&self) -> Vec<u128> {
        let mut result = Vec::<u128>::new();
        result.push(self.myself.block);
        result.push(self.myself.tx);
        result.push(self.caller.block);
        result.push(self.caller.tx);
        result.push(self.message.vout as u128);
        result.push(self.incoming_alkanes.0.len() as u128);
        for incoming in &self.incoming_alkanes.0 {
            result.push(incoming.id.block);
            result.push(incoming.id.tx);
            result.push(incoming.value);
        }
        for input in self.inputs.clone() {
            result.push(input);
        }
        result
    }
}

/// VM state for alkanes execution
pub struct AlkanesState {
    pub had_failure: bool,
    pub context: Arc<std::sync::Mutex<AlkanesRuntimeContext>>,
    pub host_calls: Arc<std::sync::Mutex<Vec<HostCall>>>,
}

/// Record of a host function call made during execution
#[derive(Debug, Clone)]
pub struct HostCall {
    pub function_name: String,
    pub parameters: Vec<String>,
    pub result: String,
    pub timestamp: std::time::Instant,
}

/// Method information from alkane metadata
#[derive(Debug, Clone)]
pub struct AlkaneMethod {
    pub name: String,
    pub opcode: u128,
    pub params: Vec<String>,
    pub returns: String,
}

/// Alkane metadata extracted from __meta export
#[derive(Debug, Clone)]
pub struct AlkaneMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub methods: Vec<AlkaneMethod>,
}

/// Result of opcode execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_value: Option<i32>,
    pub return_data: Vec<u8>,
    pub error: Option<String>,
    pub execution_time: Duration,
    pub opcode: u128,
    pub host_calls: Vec<HostCall>,
}

/// Alkane inspector for advanced analysis capabilities
pub struct AlkaneInspector {
    rpc_client: Arc<RpcClient>,
    deezel_dir: PathBuf,
    _vendor_dir: PathBuf,
}

impl AlkaneInspector {
    /// Create a new alkane inspector
    pub fn new(rpc_client: Arc<RpcClient>) -> Result<Self> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        
        let deezel_dir = home_dir.join(".deezel");
        let vendor_dir = deezel_dir.join("vendor");
        
        // Ensure directories exist
        fs::create_dir_all(&vendor_dir)
            .context("Failed to create vendor directory")?;
        
        Ok(Self {
            rpc_client,
            deezel_dir,
            _vendor_dir: vendor_dir,
        })
    }

    /// Inspect an alkane with the specified analysis modes
    pub async fn inspect_alkane(
        &self,
        alkane_id: &AlkaneId,
        disasm: bool,
        fuzz: bool,
        fuzz_ranges: Option<&str>,
        meta: bool,
        codehash: bool,
        raw: bool,
    ) -> Result<()> {
        info!("Inspecting alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        // Get the WASM bytecode for the alkane
        let bytecode = self.get_alkane_bytecode(alkane_id).await?;
        
        // Remove 0x prefix if present
        let hex_string = if bytecode.starts_with("0x") {
            &bytecode[2..]
        } else {
            &bytecode
        };
        
        let wasm_bytes = hex::decode(hex_string)
            .with_context(|| format!("Failed to decode WASM bytecode from hex. Hex string: '{}'",
                                    if hex_string.len() > 200 {
                                        format!("{}...", &hex_string[..200])
                                    } else {
                                        hex_string.to_string()
                                    }))?;
        
        info!("Decoded bytecode length: {} bytes", wasm_bytes.len());
        
        // Save WASM to temporary file for analysis
        let wasm_path = self.deezel_dir.join(format!("alkane_{}_{}.wasm", alkane_id.block, alkane_id.tx));
        fs::write(&wasm_path, &wasm_bytes)
            .context("Failed to write WASM file")?;
        
        info!("WASM bytecode saved to: {}", wasm_path.display());
        
        // Perform requested analysis
        if codehash {
            self.compute_codehash(&wasm_bytes).await?;
        }
        
        if meta {
            self.extract_metadata(&wasm_bytes).await?;
        }
        
        if disasm {
            self.disassemble_wasm(&wasm_path).await?;
        }
        
        if fuzz {
            self.perform_fuzzing_analysis(alkane_id, &wasm_bytes, fuzz_ranges, raw).await?;
        }
        
        Ok(())
    }

    /// Get WASM bytecode for an alkane
    async fn get_alkane_bytecode(&self, alkane_id: &AlkaneId) -> Result<String> {
        info!("Fetching bytecode for alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        let bytecode = self.rpc_client.get_bytecode(
            &alkane_id.block.to_string(),
            &alkane_id.tx.to_string()
        ).await?;
        
        info!("Received bytecode hex (first 100 chars): {}",
              if bytecode.len() > 100 { &bytecode[..100] } else { &bytecode });
        info!("Total bytecode length: {} characters", bytecode.len());
        
        Ok(bytecode)
    }

    /// Compute SHA3 (Keccak256) hash of the WASM bytecode
    async fn compute_codehash(&self, wasm_bytes: &[u8]) -> Result<()> {
        info!("Computing SHA3 hash of WASM bytecode");
        
        // Compute Keccak256 hash (which is what Ethereum calls SHA3)
        let mut hasher = Keccak256::new();
        hasher.update(wasm_bytes);
        let hash = hasher.finalize();
        
        println!("=== WASM CODEHASH ===");
        println!("📦 WASM size: {} bytes", wasm_bytes.len());
        println!("🔐 SHA3 (Keccak256): 0x{}", hex::encode(&hash));
        println!("🔐 SHA3 (no prefix): {}", hex::encode(&hash));
        println!("=====================");
        
        Ok(())
    }

    /// Extract metadata using wasmi runtime
    async fn extract_metadata(&self, _wasm_bytes: &[u8]) -> Result<()> {
        info!("Metadata extraction not yet implemented in refactored version");
        
        println!("=== ALKANE METADATA ===");
        println!("Note: Metadata extraction not yet implemented in refactored version");
        println!("========================");
        
        Ok(())
    }

    /// Disassemble WASM to WAT format using native wasmprinter
    async fn disassemble_wasm(&self, wasm_path: &Path) -> Result<()> {
        info!("Disassembling WASM to WAT format using native wasmprinter");
        
        // Read the WASM file
        let wasm_bytes = fs::read(wasm_path)
            .context("Failed to read WASM file")?;
        
        // Use wasmprinter to convert to WAT
        let wat_content = wasmprinter::print_bytes(&wasm_bytes)
            .context("Failed to disassemble WASM to WAT format")?;
        
        println!("=== WASM DISASSEMBLY (WAT) ===");
        println!("{}", wat_content);
        println!("==============================");
        
        // Save WAT file
        let wat_path = wasm_path.with_extension("wat");
        fs::write(&wat_path, &wat_content)
            .context("Failed to write WAT file")?;
        info!("WAT disassembly saved to: {}", wat_path.display());
        
        Ok(())
    }

    /// Perform fuzzing analysis using wasmi runtime
    async fn perform_fuzzing_analysis(&self, alkane_id: &AlkaneId, _wasm_bytes: &[u8], _fuzz_ranges: Option<&str>, raw: bool) -> Result<()> {
        info!("Performing fuzzing analysis for alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        if raw {
            // JSON output for scripting
            let json_result = serde_json::json!({
                "alkane_id": format!("{}:{}", alkane_id.block, alkane_id.tx),
                "note": "Fuzzing analysis not yet implemented in refactored version"
            });
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        } else {
            println!("=== FUZZING ANALYSIS ===");
            println!("Alkane: {}:{}", alkane_id.block, alkane_id.tx);
            println!("Note: Fuzzing analysis not yet implemented in refactored version");
            println!("========================");
        }
        
        Ok(())
    }
}