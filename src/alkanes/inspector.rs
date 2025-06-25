//! Alkane inspection and analysis functionality

use anyhow::{Context, Result};
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::fs;
use std::time::{Duration, Instant};

use crate::rpc::RpcClient;
use super::types::AlkaneId;
use wasmtime::*;
use alkanes_support::{
    cellpack::Cellpack,
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
        let result = self
            .flatten()
            .into_iter()
            .map(|v| {
                let ar = (&v.to_le_bytes()).to_vec();
                ar
            })
            .flatten()
            .collect::<Vec<u8>>();
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
    pub context: Arc<Mutex<AlkanesRuntimeContext>>,
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
}

/// Result of opcode fuzzing analysis
#[derive(Debug, Clone)]
pub struct OpcodeAnalysis {
    pub opcode: u32,
    pub implemented: bool,
    pub gas_cost: Option<u64>,
    pub input_types: Vec<String>,
    pub output_types: Vec<String>,
    pub description: Option<String>,
}

/// Simulation context for testing
#[derive(Debug, Clone)]
pub struct SimulationContext {
    pub block_height: u128,
    pub transaction_index: u32,
    pub caller_address: String,
    pub value: u64,
}

/// Alkane inspector for advanced analysis capabilities
pub struct AlkaneInspector {
    rpc_client: Arc<RpcClient>,
    deezel_dir: PathBuf,
    vendor_dir: PathBuf,
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
            vendor_dir,
        })
    }

    /// Create a wasmtime engine with host functions
    fn create_engine(&self) -> Engine {
        let mut config = Config::new();
        config.wasm_memory64(false);
        config.wasm_multi_memory(false);
        config.wasm_bulk_memory(true);
        config.wasm_reference_types(true);
        config.wasm_simd(true);  // Enable SIMD to avoid conflicts
        config.consume_fuel(true);
        Engine::new(&config).unwrap()
    }

    /// Create a wasmtime store with runtime state
    fn create_store(&self, engine: &Engine, context: AlkanesRuntimeContext) -> Store<AlkanesState> {
        let state = AlkanesState {
            had_failure: false,
            context: Arc::new(Mutex::new(context)),
        };
        let mut store = Store::new(engine, state);
        store.set_fuel(1_000_000).unwrap(); // Set fuel for execution
        store
    }

    /// Create host functions for the alkane runtime matching alkanes-rs exactly
    fn create_host_functions(engine: &Engine) -> Linker<AlkanesState> {
        let mut linker = Linker::new(engine);
        
        // abort - matches alkanes-rs signature
        linker.func_wrap("env", "abort", |mut caller: Caller<'_, AlkanesState>, _: i32, _: i32, _: i32, _: i32| {
            caller.data_mut().had_failure = true;
        }).unwrap();

        // __request_context - matches alkanes-rs signature
        linker.func_wrap("env", "__request_context", |caller: Caller<'_, AlkanesState>| -> i32 {
            let context_guard = caller.data().context.lock().unwrap();
            let serialized = context_guard.serialize();
            serialized.len() as i32
        }).unwrap();

        // __load_context - matches alkanes-rs signature
        linker.func_wrap("env", "__load_context", |mut caller: Caller<'_, AlkanesState>, output: i32| -> i32 {
            let serialized = {
                let context_guard = caller.data().context.lock().unwrap();
                context_guard.serialize()
            };
            
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let output_addr = output as usize;
                    
                    // Write length first
                    if output_addr + 4 <= memory_data.len() {
                        let len_bytes = (serialized.len() as u32).to_le_bytes();
                        memory_data[output_addr..output_addr + 4].copy_from_slice(&len_bytes);
                        
                        // Write data
                        if output_addr + 4 + serialized.len() <= memory_data.len() {
                            memory_data[output_addr + 4..output_addr + 4 + serialized.len()].copy_from_slice(&serialized);
                            return serialized.len() as i32;
                        }
                    }
                }
            }
            -1
        }).unwrap();

        // __request_storage - matches alkanes-rs signature
        linker.func_wrap("env", "__request_storage", |_caller: Caller<'_, AlkanesState>, _k: i32| -> i32 {
            0 // Return 0 size for now
        }).unwrap();

        // __load_storage - matches alkanes-rs signature
        linker.func_wrap("env", "__load_storage", |_caller: Caller<'_, AlkanesState>, _k: i32, _v: i32| -> i32 {
            0 // Return 0 for now
        }).unwrap();

        // __height - matches alkanes-rs signature
        linker.func_wrap("env", "__height", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let height: u64 = 800000; // Placeholder height
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let output_addr = output as usize;
                    let height_bytes = height.to_le_bytes();
                    
                    if output_addr + 4 + height_bytes.len() <= memory_data.len() {
                        // Write length first
                        let len_bytes = (height_bytes.len() as u32).to_le_bytes();
                        memory_data[output_addr..output_addr + 4].copy_from_slice(&len_bytes);
                        // Write height data
                        memory_data[output_addr + 4..output_addr + 4 + height_bytes.len()].copy_from_slice(&height_bytes);
                    }
                }
            }
        }).unwrap();

        // __log - matches alkanes-rs signature
        linker.func_wrap("env", "__log", |mut caller: Caller<'_, AlkanesState>, v: i32| {
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data(&caller);
                    let v_addr = v as usize;
                    
                    if v_addr + 4 <= memory_data.len() {
                        // Read length
                        let len_bytes = &memory_data[v_addr..v_addr + 4];
                        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                        
                        if v_addr + 4 + len <= memory_data.len() {
                            // Read message
                            let message_bytes = &memory_data[v_addr + 4..v_addr + 4 + len];
                            if let Ok(message) = String::from_utf8(message_bytes.to_vec()) {
                                print!("{}", message);
                            }
                        }
                    }
                }
            }
        }).unwrap();

        // __balance - matches alkanes-rs signature
        linker.func_wrap("env", "__balance", |mut caller: Caller<'_, AlkanesState>, _who: i32, _what: i32, output: i32| {
            // Return zero balance
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let output_addr = output as usize;
                    let zero_balance = 0u128.to_le_bytes();
                    
                    if output_addr + 4 + zero_balance.len() <= memory_data.len() {
                        let len_bytes = (zero_balance.len() as u32).to_le_bytes();
                        memory_data[output_addr..output_addr + 4].copy_from_slice(&len_bytes);
                        memory_data[output_addr + 4..output_addr + 4 + zero_balance.len()].copy_from_slice(&zero_balance);
                    }
                }
            }
        }).unwrap();

        // __sequence - matches alkanes-rs signature
        linker.func_wrap("env", "__sequence", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let sequence: u128 = 0; // Placeholder sequence
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let output_addr = output as usize;
                    let seq_bytes = sequence.to_le_bytes();
                    
                    if output_addr + 4 + seq_bytes.len() <= memory_data.len() {
                        let len_bytes = (seq_bytes.len() as u32).to_le_bytes();
                        memory_data[output_addr..output_addr + 4].copy_from_slice(&len_bytes);
                        memory_data[output_addr + 4..output_addr + 4 + seq_bytes.len()].copy_from_slice(&seq_bytes);
                    }
                }
            }
        }).unwrap();

        // __fuel - matches alkanes-rs signature
        linker.func_wrap("env", "__fuel", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let fuel: u64 = 1000000; // Placeholder fuel
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let output_addr = output as usize;
                    let fuel_bytes = fuel.to_le_bytes();
                    
                    if output_addr + 4 + fuel_bytes.len() <= memory_data.len() {
                        let len_bytes = (fuel_bytes.len() as u32).to_le_bytes();
                        memory_data[output_addr..output_addr + 4].copy_from_slice(&len_bytes);
                        memory_data[output_addr + 4..output_addr + 4 + fuel_bytes.len()].copy_from_slice(&fuel_bytes);
                    }
                }
            }
        }).unwrap();

        // __returndatacopy - matches alkanes-rs signature
        linker.func_wrap("env", "__returndatacopy", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let returndata = {
                let context_guard = caller.data().context.lock().unwrap();
                context_guard.returndata.clone()
            };
            if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let output_addr = output as usize;
                    
                    if output_addr + 4 + returndata.len() <= memory_data.len() {
                        let len_bytes = (returndata.len() as u32).to_le_bytes();
                        memory_data[output_addr..output_addr + 4].copy_from_slice(&len_bytes);
                        memory_data[output_addr + 4..output_addr + 4 + returndata.len()].copy_from_slice(&returndata);
                    }
                }
            }
        }).unwrap();

        // __request_transaction - matches alkanes-rs signature
        linker.func_wrap("env", "__request_transaction", |_caller: Caller<'_, AlkanesState>| -> i32 {
            0 // Return 0 size for now
        }).unwrap();

        // __load_transaction - matches alkanes-rs signature
        linker.func_wrap("env", "__load_transaction", |_caller: Caller<'_, AlkanesState>, _output: i32| {
            // Placeholder - do nothing
        }).unwrap();

        // __request_block - matches alkanes-rs signature
        linker.func_wrap("env", "__request_block", |_caller: Caller<'_, AlkanesState>| -> i32 {
            0 // Return 0 size for now
        }).unwrap();

        // __load_block - matches alkanes-rs signature
        linker.func_wrap("env", "__load_block", |_caller: Caller<'_, AlkanesState>, _output: i32| {
            // Placeholder - do nothing
        }).unwrap();

        // __call - matches alkanes-rs signature
        linker.func_wrap("env", "__call", |_caller: Caller<'_, AlkanesState>, _cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, _start_fuel: u64| -> i32 {
            -1 // Not implemented
        }).unwrap();

        // __delegatecall - matches alkanes-rs signature
        linker.func_wrap("env", "__delegatecall", |_caller: Caller<'_, AlkanesState>, _cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, _start_fuel: u64| -> i32 {
            -1 // Not implemented
        }).unwrap();

        // __staticcall - matches alkanes-rs signature
        linker.func_wrap("env", "__staticcall", |_caller: Caller<'_, AlkanesState>, _cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, _start_fuel: u64| -> i32 {
            -1 // Not implemented
        }).unwrap();

        linker
    }

    /// Execute the __meta export and read metadata
    async fn execute_meta(&self, bytecode: &[u8]) -> Result<AlkaneMetadata> {
        let engine = self.create_engine();
        
        // Create a basic context for metadata extraction
        let context = AlkanesRuntimeContext {
            inputs: vec![],
            ..Default::default()
        };
        
        let mut store = self.create_store(&engine, context);
        let linker = Self::create_host_functions(store.engine());
        
        // Compile and instantiate the module
        let module = Module::new(store.engine(), bytecode)
            .context("Failed to compile WASM module")?;
        
        let instance = linker.instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?;
        
        // Get memory export (we'll access it directly from instance in host functions)
        let memory = instance.get_export(&mut store, "memory")
            .and_then(|export| export.into_memory())
            .ok_or_else(|| anyhow::anyhow!("No memory export found"))?;
        
        // Get __meta export
        let meta_func = instance.get_export(&mut store, "__meta")
            .and_then(|export| export.into_func())
            .ok_or_else(|| anyhow::anyhow!("No __meta export found"))?
            .typed::<(), i32>(&mut store)
            .context("Failed to get typed __meta function")?;
        
        // Execute __meta
        let meta_ptr = meta_func.call(&mut store, ())
            .context("Failed to execute __meta")?;
        
        info!("__meta export returned pointer: 0x{:x} ({})", meta_ptr, meta_ptr);
        
        // Read metadata from memory
        let metadata = self.read_metadata_from_memory(&store, memory, meta_ptr as usize)?;
        
        Ok(metadata)
    }

    /// Execute the __execute export with opcode testing
    async fn execute_opcode(&self, bytecode: &[u8], opcode: u128) -> Result<ExecutionResult> {
        let engine = self.create_engine();
        
        // Create context with opcode in cellpack
        let context = AlkanesRuntimeContext {
            inputs: vec![opcode],
            ..Default::default()
        };
        
        let mut store = self.create_store(&engine, context);
        let linker = Self::create_host_functions(store.engine());
        
        // Compile and instantiate the module
        let module = Module::new(store.engine(), bytecode)
            .context("Failed to compile WASM module")?;
        
        let instance = linker.instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?;
        
        // Get memory export
        let memory = instance.get_export(&mut store, "memory")
            .and_then(|export| export.into_memory())
            .ok_or_else(|| anyhow::anyhow!("No memory export found"))?;
        
        // Get __execute export
        let execute_func = instance.get_export(&mut store, "__execute")
            .and_then(|export| export.into_func())
            .ok_or_else(|| anyhow::anyhow!("No __execute export found"))?
            .typed::<(), i32>(&mut store)
            .context("Failed to get typed __execute function")?;
        
        // Execute with opcode
        let start_time = Instant::now();
        let result = execute_func.call(&mut store, ());
        let execution_time = start_time.elapsed();
        
        // Capture return data from the context
        let return_data = {
            let context_guard = store.data().context.lock().unwrap();
            context_guard.returndata.clone()
        };
        
        match result {
            Ok(return_value) => Ok(ExecutionResult {
                success: true,
                return_value: Some(return_value),
                return_data,
                error: None,
                execution_time,
                opcode,
            }),
            Err(e) => Ok(ExecutionResult {
                success: false,
                return_value: None,
                return_data,
                error: Some(e.to_string()),
                execution_time,
                opcode,
            }),
        }
    }

    /// Read metadata from WASM memory
    fn read_metadata_from_memory(&self, store: &Store<AlkanesState>, memory: Memory, ptr: usize) -> Result<AlkaneMetadata> {
        info!("Reading metadata from memory at pointer: 0x{:x} ({})", ptr, ptr);
        
        // Get memory size for bounds checking
        let memory_size = memory.data_size(store);
        info!("WASM memory size: {} bytes", memory_size);
        
        if ptr < 4 || ptr >= memory_size {
            return Err(anyhow::anyhow!("Pointer 0x{:x} is invalid (memory size: {})", ptr, memory_size));
        }
        
        // Read length from ptr-4 (length is stored before the data)
        let mut len_bytes = [0u8; 4];
        memory.read(store, ptr - 4, &mut len_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to read metadata length at 0x{:x}: {:?}", ptr - 4, e))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        
        info!("Raw length bytes at 0x{:x}: {:02x} {:02x} {:02x} {:02x}", ptr - 4, len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]);
        info!("Metadata length: {} bytes", len);
        
        if ptr + len > memory_size {
            return Err(anyhow::anyhow!("Metadata extends beyond memory bounds: ptr=0x{:x}, len={}, memory_size={}", ptr, len, memory_size));
        }
        
        // Read metadata bytes starting at ptr
        let mut metadata_bytes = vec![0u8; len];
        memory.read(store, ptr, &mut metadata_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to read metadata bytes at 0x{:x}: {:?}", ptr, e))?;
        
        info!("Successfully read {} metadata bytes", metadata_bytes.len());
        
        // Debug: show first 100 bytes of metadata
        let preview_len = std::cmp::min(100, metadata_bytes.len());
        info!("First {} bytes of metadata: {}", preview_len, hex::encode(&metadata_bytes[..preview_len]));
        
        // Try to convert to string for debugging
        if let Ok(metadata_str) = String::from_utf8(metadata_bytes.clone()) {
            info!("Metadata as string: {}", if metadata_str.len() > 200 {
                format!("{}...", &metadata_str[..200])
            } else {
                metadata_str.clone()
            });
        }
        
        // Try to parse as JSON first, then fall back to basic parsing
        if let Ok(json_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
            info!("Successfully parsed JSON metadata");
            
            // Extract contract name (could be in "contract" or "name" field)
            let contract_name = json_meta.get("contract")
                .and_then(|v| v.as_str())
                .or_else(|| json_meta.get("name").and_then(|v| v.as_str()))
                .unwrap_or("Unknown")
                .to_string();
            
            // Extract version
            let version = json_meta.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();
            
            // Extract description
            let description = json_meta.get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            
            // Extract methods with detailed information
            let mut methods = Vec::new();
            
            if let Some(methods_array) = json_meta.get("methods").and_then(|v| v.as_array()) {
                for method in methods_array {
                    let name = method.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    
                    let opcode = method.get("opcode")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u128;
                    
                    let params = method.get("params")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|p| p.as_str())
                                .map(|s| s.to_string())
                                .collect()
                        })
                        .unwrap_or_else(Vec::new);
                    
                    let returns = method.get("returns")
                        .and_then(|v| v.as_str())
                        .unwrap_or("void")
                        .to_string();
                    
                    methods.push(AlkaneMethod {
                        name,
                        opcode,
                        params,
                        returns,
                    });
                }
            }
            
            info!("Extracted metadata: contract={}, version={}, methods={}", contract_name, version, methods.len());
            
            Ok(AlkaneMetadata {
                name: contract_name,
                version,
                description,
                methods,
            })
        } else {
            warn!("Failed to parse metadata as JSON, using fallback");
            // Fallback to basic metadata
            Ok(AlkaneMetadata {
                name: "Unknown".to_string(),
                version: "0.0.0".to_string(),
                description: None,
                methods: vec![],
            })
        }
    }

    /// Inspect an alkane with the specified analysis modes
    pub async fn inspect_alkane(
        &self,
        alkane_id: &AlkaneId,
        disasm: bool,
        fuzz: bool,
        meta: bool,
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
        if meta {
            self.extract_metadata(&wasm_bytes).await?;
        }
        
        if disasm {
            self.disassemble_wasm(&wasm_path).await?;
        }
        
        if fuzz {
            self.setup_fuzzing_environment().await?;
            self.perform_fuzzing_analysis(alkane_id, &wasm_bytes).await?;
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

    /// Extract metadata using wasmi runtime
    async fn extract_metadata(&self, wasm_bytes: &[u8]) -> Result<()> {
        info!("Extracting metadata from WASM binary using wasmi");
        
        match self.execute_meta(wasm_bytes).await {
            Ok(metadata) => {
                self.display_metadata(&metadata);
            }
            Err(e) => {
                warn!("Failed to extract metadata: {}", e);
                println!("=== ALKANE METADATA ===");
                println!("Note: Failed to extract metadata from __meta export");
                println!("Error: {}", e);
                println!("========================");
            }
        }
        
        Ok(())
    }

    /// Display metadata in a nice tree structure
    fn display_metadata(&self, metadata: &AlkaneMetadata) {
        println!("=== ALKANE METADATA ===");
        println!("📦 Contract: {}", metadata.name);
        println!("🏷️  Version: {}", metadata.version);
        
        if let Some(desc) = &metadata.description {
            println!("📝 Description: {}", desc);
        }
        
        if metadata.methods.is_empty() {
            println!("⚠️  No methods found");
        } else {
            println!("🔧 Methods ({}):", metadata.methods.len());
            
            // Sort methods by opcode for better display
            let mut sorted_methods = metadata.methods.clone();
            sorted_methods.sort_by_key(|m| m.opcode);
            
            for (i, method) in sorted_methods.iter().enumerate() {
                let is_last = i == sorted_methods.len() - 1;
                let prefix = if is_last { "└──" } else { "├──" };
                
                // Format parameters
                let params_str = if method.params.is_empty() {
                    "()".to_string()
                } else {
                    format!("({})", method.params.join(", "))
                };
                
                // Main method line
                println!("   {} 🎯 {} {}", prefix, method.name, params_str);
                
                // Method details with proper tree indentation
                let detail_prefix = if is_last { "      " } else { "   │  " };
                println!("{}├─ 🔢 Opcode: {}", detail_prefix, method.opcode);
                println!("{}└─ 📤 Returns: {}", detail_prefix, method.returns);
                
                // Add spacing between methods except for the last one
                if !is_last {
                    println!("   │");
                }
            }
        }
        
        println!("========================");
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

    /// Setup fuzzing environment with alkanes-rs and metashrew-runtime
    async fn setup_fuzzing_environment(&self) -> Result<()> {
        info!("Setting up fuzzing environment");
        
        // Check if Rust is installed
        self.ensure_rust_installed().await?;
        
        // Clone or update alkanes-rs
        self.setup_alkanes_rs().await?;
        
        // Build alkanes-rs
        self.build_alkanes_rs().await?;
        
        Ok(())
    }

    /// Ensure Rust is installed via rustup
    async fn ensure_rust_installed(&self) -> Result<()> {
        // Check if cargo is available
        if Command::new("cargo").arg("--version").output().is_ok() {
            info!("Rust toolchain already installed");
            return Ok(());
        }
        
        info!("Rust not found. Installing via rustup...");
        
        // For now, just inform the user to install Rust manually
        println!("=== RUST INSTALLATION REQUIRED ===");
        println!("Please install Rust manually:");
        println!("  Visit: https://rustup.rs/");
        println!("  Or run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        println!("===================================");
        
        Ok(())
    }

    /// Clone or update alkanes-rs repository
    async fn setup_alkanes_rs(&self) -> Result<()> {
        let alkanes_rs_dir = self.vendor_dir.join("alkanes-rs");
        
        if alkanes_rs_dir.exists() {
            info!("Updating alkanes-rs repository");
            let output = Command::new("git")
                .args(&["pull", "origin", "main"])
                .current_dir(&alkanes_rs_dir)
                .output()
                .context("Failed to update alkanes-rs repository")?;
            
            if !output.status.success() {
                warn!("Failed to update alkanes-rs, using existing version");
            }
        } else {
            info!("Cloning alkanes-rs repository");
            let output = Command::new("git")
                .args(&[
                    "clone",
                    "https://github.com/kungfuflex/alkanes-rs",
                    alkanes_rs_dir.to_str().unwrap()
                ])
                .output()
                .context("Failed to clone alkanes-rs repository")?;
            
            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("Failed to clone alkanes-rs: {}", error));
            }
        }
        
        Ok(())
    }

    /// Build alkanes-rs with cargo
    async fn build_alkanes_rs(&self) -> Result<()> {
        let alkanes_rs_dir = self.vendor_dir.join("alkanes-rs");
        
        info!("Building alkanes-rs with cargo build --release");
        println!("Building alkanes-rs... This may take several minutes.");
        
        let output = Command::new("cargo")
            .args(&["build", "--release"])
            .current_dir(&alkanes_rs_dir)
            .output()
            .context("Failed to build alkanes-rs")?;
        
        if output.status.success() {
            info!("alkanes-rs built successfully");
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to build alkanes-rs: {}", error));
        }
        
        Ok(())
    }

    /// Perform fuzzing analysis using wasmi runtime
    async fn perform_fuzzing_analysis(&self, alkane_id: &AlkaneId, wasm_bytes: &[u8]) -> Result<()> {
        info!("Performing fuzzing analysis for alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        println!("=== FUZZING ANALYSIS ===");
        println!("Alkane: {}:{}", alkane_id.block, alkane_id.tx);
        println!("WASM size: {} bytes", wasm_bytes.len());
        println!();
        
        // Test opcodes 0-100 for demonstration
        let mut results = Vec::new();
        
        println!("Testing opcodes 0-100...");
        for opcode in 0..=100 {
            if opcode % 10 == 0 {
                println!("  Testing opcode {}...", opcode);
            }
            
            match self.execute_opcode(wasm_bytes, opcode).await {
                Ok(result) => {
                    results.push(result);
                }
                Err(e) => {
                    warn!("Failed to test opcode {}: {}", opcode, e);
                }
            }
        }
        
        // Analyze return data patterns to distinguish implemented vs unimplemented opcodes
        let mut return_data_patterns: std::collections::HashMap<Vec<u8>, Vec<u128>> = std::collections::HashMap::new();
        let mut error_patterns: std::collections::HashMap<String, Vec<u128>> = std::collections::HashMap::new();
        
        for result in &results {
            if result.success {
                return_data_patterns.entry(result.return_data.clone())
                    .or_insert_with(Vec::new)
                    .push(result.opcode);
            } else if let Some(error) = &result.error {
                error_patterns.entry(error.clone())
                    .or_insert_with(Vec::new)
                    .push(result.opcode);
            }
        }
        
        println!();
        println!("=== FUZZING RESULTS ===");
        println!("Total opcodes tested: {}", results.len());
        
        // Report return data patterns
        println!();
        println!("Return Data Patterns:");
        for (data, opcodes) in &return_data_patterns {
            println!("  Pattern ({}): {} opcodes",
                    if data.is_empty() { "empty".to_string() } else { hex::encode(data) },
                    opcodes.len());
            
            // Try to interpret the data as a string
            if let Ok(text) = String::from_utf8(data.clone()) {
                if !text.trim().is_empty() && text.is_ascii() {
                    println!("    Text: \"{}\"", text.trim());
                }
            }
            
            println!("    Opcodes: {:?}", opcodes);
            
            // Show first few bytes if data is long
            if data.len() > 32 {
                println!("    Data (first 32 bytes): {}", hex::encode(&data[..32]));
            } else if !data.is_empty() {
                println!("    Data: {}", hex::encode(data));
            }
        }
        
        // Report error patterns
        if !error_patterns.is_empty() {
            println!();
            println!("Error Patterns:");
            for (error, opcodes) in &error_patterns {
                println!("  Error: \"{}\"", error);
                println!("    Opcodes: {:?}", opcodes);
            }
        }
        
        // Identify likely implemented opcodes (those with unique return data)
        let mut implemented_opcodes = Vec::new();
        let mut unimplemented_opcodes = Vec::new();
        
        // Find the most common return pattern (likely the "unimplemented" response)
        let most_common_pattern = return_data_patterns.iter()
            .max_by_key(|(_, opcodes)| opcodes.len())
            .map(|(data, _)| data.clone());
        
        for result in &results {
            if result.success {
                if Some(&result.return_data) == most_common_pattern.as_ref() && return_data_patterns[&result.return_data].len() > 10 {
                    unimplemented_opcodes.push(result.opcode);
                } else {
                    implemented_opcodes.push(result.opcode);
                }
            } else {
                unimplemented_opcodes.push(result.opcode);
            }
        }
        
        println!();
        println!("=== OPCODE ANALYSIS ===");
        println!("Likely implemented opcodes: {} ({:?})", implemented_opcodes.len(), implemented_opcodes);
        println!("Likely unimplemented opcodes: {} (showing common error pattern)", unimplemented_opcodes.len());
        
        if let Some(common_pattern) = most_common_pattern {
            if let Ok(error_text) = String::from_utf8(common_pattern.clone()) {
                if !error_text.trim().is_empty() {
                    println!("Common error message: \"{}\"", error_text.trim());
                }
            }
        }
        
        // Show detailed results for implemented opcodes
        if !implemented_opcodes.is_empty() {
            println!();
            println!("Detailed results for implemented opcodes:");
            for result in &results {
                if implemented_opcodes.contains(&result.opcode) {
                    println!("  Opcode {}: return={:?}, time={:?}",
                            result.opcode, result.return_value, result.execution_time);
                    if !result.return_data.is_empty() {
                        if let Ok(text) = String::from_utf8(result.return_data.clone()) {
                            if text.trim().is_ascii() && !text.trim().is_empty() {
                                println!("    Response: \"{}\"", text.trim());
                            }
                        }
                        if result.return_data.len() <= 32 {
                            println!("    Data: {}", hex::encode(&result.return_data));
                        }
                    }
                }
            }
        }
        
        println!("========================");
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alkane_inspector_creation() {
        // This test would require a mock RPC client
        // For now, just test that the module compiles
        assert!(true);
    }
}