//! Alkane inspection and analysis functionality

use anyhow::{Context, Result};
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::fs;
use std::time::{Duration, Instant};
use sha3::{Digest, Keccak256};
use serde_json;

use crate::rpc::RpcClient;
use super::types::AlkaneId;
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
    pub context: Arc<Mutex<AlkanesRuntimeContext>>,
    pub host_calls: Arc<Mutex<Vec<HostCall>>>,
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
            host_calls: Arc::new(Mutex::new(Vec::new())),
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
                    
                    // Write the serialized context directly (no length prefix)
                    if output_addr + serialized.len() <= memory_data.len() {
                        memory_data[output_addr..output_addr + serialized.len()].copy_from_slice(&serialized);
                        return serialized.len() as i32;
                    }
                }
            }
            -1
        }).unwrap();

        // __request_storage - matches alkanes-rs signature
        linker.func_wrap("env", "__request_storage", |mut caller: Caller<'_, AlkanesState>, k: i32| -> i32 {
            let start_time = std::time::Instant::now();
            
            // Read the storage key from memory
            let key_str = if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data(&caller);
                    let k_addr = k as usize;
                    
                    // Read length from ptr - 4 (4 bytes before the pointer)
                    if k_addr >= 4 && k_addr - 4 + 4 <= memory_data.len() {
                        let len_bytes = &memory_data[k_addr - 4..k_addr];
                        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                        
                        if k_addr + len <= memory_data.len() {
                            // Read key starting from ptr
                            let key_bytes = &memory_data[k_addr..k_addr + len];
                            String::from_utf8_lossy(key_bytes).to_string()
                        } else {
                            format!("invalid_key_bounds_ptr_{}_len_{}", k, len)
                        }
                    } else {
                        format!("invalid_key_ptr_{}", k)
                    }
                } else {
                    format!("no_memory_key_{}", k)
                }
            } else {
                format!("no_memory_export_key_{}", k)
            };
            
            // For now, return 0 size but track the call
            let result_size = 0;
            
            // Record the host call
            let host_call = HostCall {
                function_name: "__request_storage".to_string(),
                parameters: vec![format!("key: \"{}\"", key_str)],
                result: format!("size: {}", result_size),
                timestamp: start_time,
            };
            
            if let Ok(mut calls) = caller.data().host_calls.lock() {
                calls.push(host_call);
            }
            
            result_size
        }).unwrap();

        // __load_storage - matches alkanes-rs signature
        linker.func_wrap("env", "__load_storage", |mut caller: Caller<'_, AlkanesState>, k: i32, v: i32| -> i32 {
            let start_time = std::time::Instant::now();
            
            // Read the storage key from memory
            let key_str = if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data(&caller);
                    let k_addr = k as usize;
                    
                    // Read length from ptr - 4 (4 bytes before the pointer)
                    if k_addr >= 4 && k_addr - 4 + 4 <= memory_data.len() {
                        let len_bytes = &memory_data[k_addr - 4..k_addr];
                        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                        
                        if k_addr + len <= memory_data.len() {
                            // Read key starting from ptr
                            let key_bytes = &memory_data[k_addr..k_addr + len];
                            String::from_utf8_lossy(key_bytes).to_string()
                        } else {
                            format!("invalid_key_bounds_ptr_{}_len_{}", k, len)
                        }
                    } else {
                        format!("invalid_key_ptr_{}", k)
                    }
                } else {
                    format!("no_memory_key_{}", k)
                }
            } else {
                format!("no_memory_export_key_{}", k)
            };
            
            // Simulate storage values based on key patterns
            let storage_value = match key_str.as_str() {
                "/position_count" => 42u128.to_le_bytes().to_vec(),
                "/acc_reward_per_share" => 1000000u128.to_le_bytes().to_vec(),
                "/last_reward_block" => 800000u128.to_le_bytes().to_vec(),
                "/last_update_block" => 800001u128.to_le_bytes().to_vec(),
                "/reward_per_block" => 100u128.to_le_bytes().to_vec(),
                "/start_block" => 750000u128.to_le_bytes().to_vec(),
                "/end_reward_block" => 850000u128.to_le_bytes().to_vec(),
                "/total_assets" => 5000000u128.to_le_bytes().to_vec(),
                "/deposit_token_id" => {
                    // Return a mock AlkaneId (32 bytes: 16 for block, 16 for tx)
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&1u128.to_le_bytes()); // block
                    bytes.extend_from_slice(&100u128.to_le_bytes()); // tx
                    bytes
                },
                "/free_mint_contract_id" => {
                    // Return a mock AlkaneId (32 bytes: 16 for block, 16 for tx)
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&2u128.to_le_bytes()); // block
                    bytes.extend_from_slice(&200u128.to_le_bytes()); // tx
                    bytes
                },
                _ if key_str.starts_with("/registered_children/") => {
                    vec![1u8] // Simulate registered child
                },
                _ => vec![], // Empty for unknown keys
            };
            
            // Write the storage value to memory
            let bytes_written = if let Some(memory) = caller.get_export("memory") {
                if let Some(memory) = memory.into_memory() {
                    let memory_data = memory.data_mut(&mut caller);
                    let v_addr = v as usize;
                    
                    if v_addr + 4 + storage_value.len() <= memory_data.len() {
                        // Write length first
                        let len_bytes = (storage_value.len() as u32).to_le_bytes();
                        memory_data[v_addr..v_addr + 4].copy_from_slice(&len_bytes);
                        // Write storage value
                        memory_data[v_addr + 4..v_addr + 4 + storage_value.len()].copy_from_slice(&storage_value);
                        storage_value.len() as i32
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            };
            
            // Record the host call
            let host_call = HostCall {
                function_name: "__load_storage".to_string(),
                parameters: vec![format!("key: \"{}\"", key_str)],
                result: format!("value: {} bytes ({})", storage_value.len(), hex::encode(&storage_value)),
                timestamp: start_time,
            };
            
            if let Ok(mut calls) = caller.data().host_calls.lock() {
                calls.push(host_call);
            }
            
            bytes_written
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
                    
                    // Read length from ptr - 4 (4 bytes before the pointer)
                    if v_addr >= 4 && v_addr - 4 + 4 <= memory_data.len() {
                        let len_bytes = &memory_data[v_addr - 4..v_addr];
                        let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                        
                        if v_addr + len <= memory_data.len() {
                            // Read message starting from ptr
                            let message_bytes = &memory_data[v_addr..v_addr + len];
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
        linker.func_wrap("env", "__call", |mut caller: Caller<'_, AlkanesState>, cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, start_fuel: u64| -> i32 {
            let start_time = std::time::Instant::now();
            
            // Try to decode the cellpack to see what alkane is being called
            let call_info = Self::decode_cellpack_info(&mut caller, cellpack_ptr);
            
            // Record the host call
            let host_call = HostCall {
                function_name: "__call".to_string(),
                parameters: vec![
                    format!("target: {}", call_info),
                    format!("fuel: {}", start_fuel),
                ],
                result: "not_implemented".to_string(),
                timestamp: start_time,
            };
            
            if let Ok(mut calls) = caller.data().host_calls.lock() {
                calls.push(host_call);
            }
            
            -1 // Not implemented
        }).unwrap();

        // __delegatecall - matches alkanes-rs signature
        linker.func_wrap("env", "__delegatecall", |mut caller: Caller<'_, AlkanesState>, cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, start_fuel: u64| -> i32 {
            let start_time = std::time::Instant::now();
            
            let call_info = Self::decode_cellpack_info(&mut caller, cellpack_ptr);
            
            let host_call = HostCall {
                function_name: "__delegatecall".to_string(),
                parameters: vec![
                    format!("target: {}", call_info),
                    format!("fuel: {}", start_fuel),
                ],
                result: "not_implemented".to_string(),
                timestamp: start_time,
            };
            
            if let Ok(mut calls) = caller.data().host_calls.lock() {
                calls.push(host_call);
            }
            
            -1 // Not implemented
        }).unwrap();

        // __staticcall - matches alkanes-rs signature
        linker.func_wrap("env", "__staticcall", |mut caller: Caller<'_, AlkanesState>, cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, start_fuel: u64| -> i32 {
            let start_time = std::time::Instant::now();
            
            let call_info = Self::decode_cellpack_info(&mut caller, cellpack_ptr);
            
            let host_call = HostCall {
                function_name: "__staticcall".to_string(),
                parameters: vec![
                    format!("target: {}", call_info),
                    format!("fuel: {}", start_fuel),
                ],
                result: "not_implemented".to_string(),
                timestamp: start_time,
            };
            
            if let Ok(mut calls) = caller.data().host_calls.lock() {
                calls.push(host_call);
            }
            
            -1 // Not implemented
        }).unwrap();

        linker
    }

    /// Helper function to decode cellpack information from memory
    fn decode_cellpack_info(caller: &mut Caller<'_, AlkanesState>, cellpack_ptr: i32) -> String {
        if let Some(memory) = caller.get_export("memory") {
            if let Some(memory) = memory.into_memory() {
                let memory_data = memory.data(caller);
                let ptr_addr = cellpack_ptr as usize;
                
                // Read length from ptr - 4 (4 bytes before the pointer)
                if ptr_addr >= 4 && ptr_addr - 4 + 4 <= memory_data.len() {
                    let len_bytes = &memory_data[ptr_addr - 4..ptr_addr];
                    let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                    
                    if ptr_addr + len <= memory_data.len() && len >= 32 {
                        // Try to read target AlkaneId (first 32 bytes starting from ptr)
                        let target_bytes = &memory_data[ptr_addr..ptr_addr + 32];
                        let block = u128::from_le_bytes(target_bytes[0..16].try_into().unwrap_or([0; 16]));
                        let tx = u128::from_le_bytes(target_bytes[16..32].try_into().unwrap_or([0; 16]));
                        
                        // Try to read inputs if available
                        let inputs_info = if len > 32 {
                            let remaining_len = len - 32;
                            let inputs_count = remaining_len / 16; // Each u128 input is 16 bytes
                            format!(" with {} inputs", inputs_count)
                        } else {
                            String::new()
                        };
                        
                        return format!("AlkaneId{{block: {}, tx: {}}}{}", block, tx, inputs_info);
                    }
                }
            }
        }
        format!("unknown_cellpack_{}", cellpack_ptr)
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
    async fn _execute_opcode(&self, bytecode: &[u8], opcode: u128) -> Result<ExecutionResult> {
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
        let _memory = instance.get_export(&mut store, "memory")
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
        
        // Capture host calls before returning
        let host_calls = {
            let calls_guard = store.data().host_calls.lock().unwrap();
            calls_guard.clone()
        };

        match result {
            Ok(return_value) => Ok(ExecutionResult {
                success: true,
                return_value: Some(return_value),
                return_data,
                error: None,
                execution_time,
                opcode,
                host_calls,
            }),
            Err(e) => Ok(ExecutionResult {
                success: false,
                return_value: None,
                return_data,
                error: Some(e.to_string()),
                execution_time,
                opcode,
                host_calls,
            }),
        }
    }

    /// Execute the __execute export with proper alkane context for fuzzing
    async fn execute_opcode_with_context(&self, bytecode: &[u8], opcode: u128, alkane_id: &AlkaneId) -> Result<ExecutionResult> {
        let engine = self.create_engine();
        
        // Create context with the alkane ID and opcode followed by 15 zero parameters
        let mut inputs = vec![opcode]; // First input is the opcode we're testing
        inputs.extend(vec![0u128; 15]); // Add 15 zero u128 elements as additional parameters
        
        let mut context = AlkanesRuntimeContext {
            inputs,
            ..Default::default()
        };
        
        // Set context.myself to the actual alkane ID (block, tx as u128[2])
        context.myself = AlkanesAlkaneId {
            block: alkane_id.block as u128,
            tx: alkane_id.tx as u128,
        };
        
        // Set a placeholder caller (could be the same alkane or a different one)
        context.caller = AlkanesAlkaneId {
            block: alkane_id.block as u128,
            tx: alkane_id.tx as u128,
        };
        
        // Set up message context with proper vout
        context.message.vout = 0; // Default vout
        context.message.height = 800000; // Default height
        context.message.calldata = vec![]; // Empty calldata for fuzzing
        
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
        
        // Capture host calls before returning
        let host_calls = {
            let calls_guard = store.data().host_calls.lock().unwrap();
            calls_guard.clone()
        };

        match result {
            Ok(response_ptr) => {
                // Decode the ExtendedCallResponse from the returned pointer
                let (return_data, error_message) = self.decode_extended_call_response(&store, memory, response_ptr as usize)?;
                
                Ok(ExecutionResult {
                    success: true,
                    return_value: Some(response_ptr),
                    return_data,
                    error: error_message,
                    execution_time,
                    opcode,
                    host_calls,
                })
            },
            Err(e) => Ok(ExecutionResult {
                success: false,
                return_value: None,
                return_data: vec![],
                error: Some(format!("WASM execution failed: {}", e)),
                execution_time,
                opcode,
                host_calls,
            }),
        }
    }

    /// Decode ExtendedCallResponse structure from WASM memory
    fn decode_extended_call_response(&self, store: &Store<AlkanesState>, memory: Memory, ptr: usize) -> Result<(Vec<u8>, Option<String>)> {
        let memory_size = memory.data_size(store);
        
        
        if ptr < 4 || ptr >= memory_size {
            return Err(anyhow::anyhow!("Response pointer 0x{:x} is invalid (memory size: {})", ptr, memory_size));
        }
        
        // Read length from ptr-4 (4 bytes before the pointer)
        let mut len_bytes = [0u8; 4];
        memory.read(store, ptr - 4, &mut len_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to read response length at 0x{:x}: {:?}", ptr - 4, e))?;
        let response_len = u32::from_le_bytes(len_bytes) as usize;
        
        
        if response_len == 0 {
            return Ok((vec![], None));
        }
        
        if ptr + response_len > memory_size {
            return Err(anyhow::anyhow!("Response data extends beyond memory bounds: ptr=0x{:x}, len={}, memory_size={}", ptr, response_len, memory_size));
        }
        
        // Read the ExtendedCallResponse structure starting at ptr
        let mut response_bytes = vec![0u8; response_len];
        memory.read(store, ptr, &mut response_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to read ExtendedCallResponse at 0x{:x}: {:?}", ptr, e))?;
        
        
        // Parse the ExtendedCallResponse structure
        // Based on the user's feedback, we need to extract the data Vec<u8> from this structure
        // For now, let's examine the structure to understand its layout
        
        // The structure likely contains:
        // - success: bool (1 byte)
        // - return_value: Vec<u8> (length-prefixed)
        // - response_data: Vec<u8> (length-prefixed)
        // - error: Option<String> (length-prefixed)
        
        // Let's try to parse it step by step
        let _offset = 0;
        
        // Skip the first part and look for the data Vec<u8>
        // Based on the debugging output, the interesting data seems to start around offset 16-20
        
        // Look for the Solidity error signature pattern
        let mut data_start = 0;
        let mut found_error_sig = false;
        
        for i in 0..response_bytes.len().saturating_sub(4) {
            if response_bytes[i..i+4] == [0x08, 0xc3, 0x79, 0xa0] {
                data_start = i;
                found_error_sig = true;
                break;
            }
        }
        
        if found_error_sig {
            // Extract the error message after the signature
            let message_start = data_start + 4; // Skip the 4-byte signature
            
            if message_start < response_bytes.len() {
                let message_bytes = &response_bytes[message_start..];
                
                // Read everything immediately after the magic bytes (don't skip additional 4 bytes)
                let useful_bytes = message_bytes;
                
                // Try to extract readable text
                let mut error_msg = String::new();
                for &byte in useful_bytes {
                    if byte >= 32 && byte <= 126 { // Printable ASCII
                        error_msg.push(byte as char);
                    } else if byte == 0 {
                        break; // End of string
                    }
                }
                
                let clean_msg = error_msg.trim().to_string();
                if !clean_msg.is_empty() {
                    return Ok((useful_bytes.to_vec(), Some(clean_msg)));
                } else {
                    return Ok((useful_bytes.to_vec(), Some("Unknown error".to_string())));
                }
            }
        }
        
        // If no error signature found, look for other patterns
        // Check if this might be a successful response
        let first_16_zero = response_bytes.len() >= 16 && response_bytes[0..16].iter().all(|&b| b == 0);
        if first_16_zero {
            
            // Look for data after the header
            if response_bytes.len() > 16 {
                let data_part = &response_bytes[16..];
                
                // Use the data directly (don't skip additional 4 bytes)
                let useful_data = data_part;
                
                if useful_data.iter().any(|&b| b != 0) {
                    // Try to interpret as string
                    if let Ok(text) = String::from_utf8(useful_data.to_vec()) {
                        let clean_text = text.trim_matches('\0').trim();
                        if !clean_text.is_empty() && clean_text.is_ascii() {
                            return Ok((useful_data.to_vec(), None));
                        }
                    }
                    
                    return Ok((useful_data.to_vec(), None));
                } else {
                    return Ok((vec![], None));
                }
            }
        }
        
        // Fallback: return the raw response data
        Ok((response_bytes, Some("Unknown response format".to_string())))
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
    async fn _setup_fuzzing_environment(&self) -> Result<()> {
        info!("Setting up fuzzing environment");
        
        // Check if Rust is installed
        self._ensure_rust_installed().await?;
        
        // Clone or update alkanes-rs
        self._setup_alkanes_rs().await?;
        
        // Build alkanes-rs
        self._build_alkanes_rs().await?;
        
        Ok(())
    }

    /// Ensure Rust is installed via rustup
    async fn _ensure_rust_installed(&self) -> Result<()> {
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
    async fn _setup_alkanes_rs(&self) -> Result<()> {
        let alkanes_rs_dir = self._vendor_dir.join("alkanes-rs");
        
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
    async fn _build_alkanes_rs(&self) -> Result<()> {
        let alkanes_rs_dir = self._vendor_dir.join("alkanes-rs");
        
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

    /// Parse opcode ranges from string (e.g., "0-999,2000-2500")
    fn parse_opcode_ranges(ranges_str: &str) -> Result<Vec<u128>> {
        let mut opcodes = Vec::new();
        
        for range_part in ranges_str.split(',') {
            let range_part = range_part.trim();
            if range_part.contains('-') {
                let parts: Vec<&str> = range_part.split('-').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid range format: {}", range_part));
                }
                let start: u128 = parts[0].parse()
                    .with_context(|| format!("Invalid start opcode: {}", parts[0]))?;
                let end: u128 = parts[1].parse()
                    .with_context(|| format!("Invalid end opcode: {}", parts[1]))?;
                
                if start > end {
                    return Err(anyhow::anyhow!("Invalid range: start {} > end {}", start, end));
                }
                
                for opcode in start..=end {
                    opcodes.push(opcode);
                }
            } else {
                let opcode: u128 = range_part.parse()
                    .with_context(|| format!("Invalid opcode: {}", range_part))?;
                opcodes.push(opcode);
            }
        }
        
        opcodes.sort();
        opcodes.dedup();
        Ok(opcodes)
    }

    /// Filter out opcodes with undefined behavior based on response patterns
    fn filter_undefined_behavior_patterns(&self, results: &[ExecutionResult]) -> Result<Vec<ExecutionResult>> {
        let mut response_patterns: std::collections::HashMap<String, Vec<&ExecutionResult>> = std::collections::HashMap::new();
        
        // Group results by normalized response pattern
        for result in results {
            let pattern_key = self.normalize_response_pattern(result);
            response_patterns.entry(pattern_key)
                .or_insert_with(Vec::new)
                .push(result);
        }
        
        // Find the largest group of identical responses (likely undefined behavior)
        let largest_group = response_patterns
            .iter()
            .max_by_key(|(_, opcodes)| opcodes.len())
            .map(|(pattern, opcodes)| (pattern.clone(), opcodes.len()));
        
        if let Some((largest_pattern, largest_count)) = largest_group {
            // If the largest group represents more than 50% of results and contains error messages,
            // it's likely undefined behavior that should be filtered out
            let threshold = results.len() / 2;
            
            if largest_count > threshold && self.is_undefined_behavior_pattern(&largest_pattern) {
                info!("Filtering out {} opcodes with undefined behavior pattern: {}", largest_count, largest_pattern);
                
                // Return only results that don't match the undefined behavior pattern
                let filtered: Vec<ExecutionResult> = results
                    .iter()
                    .filter(|result| {
                        let pattern = self.normalize_response_pattern(result);
                        pattern != largest_pattern
                    })
                    .cloned()
                    .collect();
                
                return Ok(filtered);
            }
        }
        
        // If no clear undefined behavior pattern found, return all results
        Ok(results.to_vec())
    }

    /// Normalize response pattern by removing opcode-specific information
    fn normalize_response_pattern(&self, result: &ExecutionResult) -> String {
        if let Some(error) = &result.error {
            // Normalize error messages by removing opcode numbers
            let normalized = error
                .replace(&result.opcode.to_string(), "OPCODE")
                .replace(&format!("0x{:x}", result.opcode), "OPCODE")
                .replace(&format!("{:#x}", result.opcode), "OPCODE");
            format!("ERROR:{}", normalized)
        } else {
            // For successful results, use return data pattern
            let data_pattern = if result.return_data.is_empty() {
                "EMPTY".to_string()
            } else if result.return_data.len() <= 32 {
                hex::encode(&result.return_data)
            } else {
                format!("{}...({}bytes)", hex::encode(&result.return_data[..16]), result.return_data.len())
            };
            
            // Include host call pattern for more precise matching
            let host_call_pattern = if result.host_calls.is_empty() {
                "NO_CALLS".to_string()
            } else {
                result.host_calls.iter()
                    .map(|call| call.function_name.clone())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            
            format!("SUCCESS:{}:CALLS:{}", data_pattern, host_call_pattern)
        }
    }

    /// Check if a pattern represents undefined behavior
    fn is_undefined_behavior_pattern(&self, pattern: &str) -> bool {
        pattern.contains("Unrecognized opcode") ||
        pattern.contains("Unknown opcode") ||
        pattern.contains("unsupported opcode") ||
        pattern.contains("not implemented") ||
        pattern.contains("invalid opcode") ||
        pattern.contains("undefined opcode")
    }

    /// Perform fuzzing analysis using wasmi runtime
    async fn perform_fuzzing_analysis(&self, alkane_id: &AlkaneId, wasm_bytes: &[u8], fuzz_ranges: Option<&str>, raw: bool) -> Result<()> {
        info!("Performing fuzzing analysis for alkane {}:{}", alkane_id.block, alkane_id.tx);
        
        if !raw {
            println!("=== FUZZING ANALYSIS ===");
            println!("Alkane: {}:{}", alkane_id.block, alkane_id.tx);
            println!("WASM size: {} bytes", wasm_bytes.len());
            println!();
        }
        
        // Determine which opcodes to test
        let opcodes_to_test = if let Some(ranges_str) = fuzz_ranges {
            Self::parse_opcode_ranges(ranges_str)?
        } else {
            // Default: test opcodes 0-999
            (0..1000).collect()
        };
        
        let mut results = Vec::new();
        
        if !raw {
            println!("Testing {} opcodes...", opcodes_to_test.len());
        }
        for opcode in opcodes_to_test {
            match self.execute_opcode_with_context(wasm_bytes, opcode, alkane_id).await {
                Ok(result) => {
                    results.push(result);
                }
                Err(e) => {
                    warn!("Failed to test opcode {}: {}", opcode, e);
                }
            }
        }
        
        // Apply pattern filtering to identify and remove undefined behavior
        let filtered_results = self.filter_undefined_behavior_patterns(&results)?;
        
        let mut success_count = 0;
        let mut error_count = 0;
        
        for result in &filtered_results {
            if result.success {
                success_count += 1;
            } else {
                error_count += 1;
            }
        }
        
        let implemented_opcodes: Vec<u128> = filtered_results.iter().map(|r| r.opcode).collect();
        let total_tested = results.len();
        let filtered_out = total_tested - filtered_results.len();
        
        if raw {
            // JSON output for scripting
            let json_result = serde_json::json!({
                "alkane_id": format!("{}:{}", alkane_id.block, alkane_id.tx),
                "total_opcodes_tested": total_tested,
                "opcodes_filtered_out": filtered_out,
                "successful_executions": success_count,
                "failed_executions": error_count,
                "implemented_opcodes": implemented_opcodes,
                "opcode_results": filtered_results.iter().map(|result| {
                    serde_json::json!({
                        "opcode": result.opcode,
                        "success": result.success,
                        "return_value": result.return_value,
                        "execution_time_micros": result.execution_time.as_micros(),
                        "return_data_hex": hex::encode(&result.return_data),
                        "return_data_utf8": String::from_utf8_lossy(&result.return_data).trim_matches('\0').trim(),
                        "error": result.error,
                        "host_calls": result.host_calls.iter().map(|call| {
                            serde_json::json!({
                                "function_name": call.function_name,
                                "parameters": call.parameters,
                                "result": call.result
                            })
                        }).collect::<Vec<_>>()
                    })
                }).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        } else {
            // Human-readable output
            println!();
            println!("=== FUZZING RESULTS ===");
            println!("📊 Total opcodes tested: {}", total_tested);
            if filtered_out > 0 {
                println!("🔍 Opcodes filtered out (undefined behavior): {}", filtered_out);
            }
            println!("✅ Successful executions: {}", success_count);
            println!("❌ Failed executions: {}", error_count);
            println!("🎯 Implemented opcodes: {} total", implemented_opcodes.len());
            
            if !implemented_opcodes.is_empty() {
                println!();
                println!("🔍 Implemented Opcodes:");
                let ranges = Self::compress_opcode_ranges(&implemented_opcodes);
                println!("   📋 Opcodes: {}", ranges);
                
                println!();
                println!("📊 Detailed Results for Implemented Opcodes:");
                for result in &filtered_results {
                    let status = if result.success { "✅" } else { "❌" };
                    println!("   {} Opcode {}: return={:?}, time={:?}",
                            status, result.opcode, result.return_value, result.execution_time);
                    
                    // Always show data, even if empty, to understand what the opcode returns
                    let decoded_data = Self::decode_data_bytevector(&result.return_data);
                    println!("      📦 Data: {}", decoded_data);
                    
                    // Show host calls made during execution
                    if !result.host_calls.is_empty() {
                        println!("      🔧 Host Calls ({}):", result.host_calls.len());
                        for (i, call) in result.host_calls.iter().enumerate() {
                            let call_prefix = if i == result.host_calls.len() - 1 { "└─" } else { "├─" };
                            println!("         {} {}: {} -> {}", call_prefix, call.function_name,
                                    call.parameters.join(", "), call.result);
                        }
                    }
                    
                    if let Some(error) = &result.error {
                        // Only show full stack trace for unusual panics, not for normal errors
                        if error.contains("WASM execution failed:") && error.contains("panic") {
                            println!("      ⚠️  Error: {}", error);
                        } else {
                            // For normal errors, just show the error message
                            println!("      ⚠️  Error: {}", error);
                        }
                    }
                }
            }
            
            println!("========================");
        }
        
        Ok(())
    }

    /// Decode data bytevector for display
    fn decode_data_bytevector(data: &[u8]) -> String {
        if data.is_empty() {
            return "Empty (0 bytes)".to_string();
        }
        
        // Always show hex first
        let hex_part = if data.len() <= 32 {
            format!("Hex: {}", hex::encode(data))
        } else {
            format!("Hex: {} (first 32 bytes of {})", hex::encode(&data[..32]), data.len())
        };
        
        // Check for Solidity error signature (0x08c379a0)
        if data.len() >= 4 && data[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
            // Skip the 4-byte error signature and try to decode as UTF-8
            let message_bytes = &data[4..];
            if let Ok(utf8_string) = String::from_utf8(message_bytes.to_vec()) {
                let clean_string = utf8_string.trim_matches('\0').trim();
                if !clean_string.is_empty() && clean_string.is_ascii() {
                    return format!("{} | Solidity Error: \"{}\"", hex_part, clean_string);
                }
            }
            // If UTF-8 decoding fails, show as hex
            return format!("{} | Solidity Error", hex_part);
        }
        
        // Try to decode as UTF-8 string for additional context
        if let Ok(utf8_string) = String::from_utf8(data.to_vec()) {
            let clean_string = utf8_string.trim_matches('\0').trim();
            if !clean_string.is_empty() && clean_string.is_ascii() && clean_string.len() > 3 {
                return format!("{} | UTF-8: \"{}\"", hex_part, clean_string);
            }
        }
        
        // Try to interpret as numbers for common data sizes
        if data.len() == 16 {
            // Could be a u128
            let value = u128::from_le_bytes(data.try_into().unwrap_or([0; 16]));
            return format!("{} | u128: {}", hex_part, value);
        } else if data.len() == 8 {
            // Could be a u64
            let value = u64::from_le_bytes(data.try_into().unwrap_or([0; 8]));
            return format!("{} | u64: {}", hex_part, value);
        } else if data.len() == 4 {
            // Could be a u32
            let value = u32::from_le_bytes(data.try_into().unwrap_or([0; 4]));
            return format!("{} | u32: {}", hex_part, value);
        }
        
        // Just show hex
        hex_part
    }

    /// Compress a list of opcodes into readable ranges (e.g., "1-10, 15, 20-25")
    fn compress_opcode_ranges(opcodes: &[u128]) -> String {
        if opcodes.is_empty() {
            return String::new();
        }
        
        let mut ranges = Vec::new();
        let mut start = opcodes[0];
        let mut end = opcodes[0];
        
        for &opcode in opcodes.iter().skip(1) {
            if opcode == end + 1 {
                end = opcode;
            } else {
                if start == end {
                    ranges.push(start.to_string());
                } else {
                    ranges.push(format!("{}-{}", start, end));
                }
                start = opcode;
                end = opcode;
            }
        }
        
        // Add the last range
        if start == end {
            ranges.push(start.to_string());
        } else {
            ranges.push(format!("{}-{}", start, end));
        }
        
        ranges.join(", ")
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_alkane_inspector_creation() {
        // This test would require a mock RPC client
        // For now, just test that the module compiles
        assert!(true);
    }
}