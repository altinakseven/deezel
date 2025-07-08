//! Core alkanes inspector functionality for WASM-compatible environments
//!
//! This module provides the core business logic for alkanes inspection,
//! including fuzzing, metadata extraction, disassembly, and codehash computation.
//! It uses trait abstractions to be platform-agnostic and WASM-compatible.
//!
//! Enhanced with full WASM runtime integration and rich execution details
//! including host call interception, detailed error information, and comprehensive
//! execution context management.

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use alloc::collections::BTreeMap as HashMap;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use ::core::time::Duration;

// WASM-compatible print macros
#[cfg(target_arch = "wasm32")]
macro_rules! println {
    ($($arg:tt)*) => {{}};
}

#[cfg(target_arch = "wasm32")]
macro_rules! print {
    ($($arg:tt)*) => {{}};
}

#[cfg(target_arch = "wasm32")]
struct Instant;

#[cfg(target_arch = "wasm32")]
impl Instant {
    fn now() -> Self { Instant }
    fn elapsed(&self) -> Duration { Duration::from_micros(0) }
}

use crate::{ToString, format};

#[cfg(not(target_arch = "wasm32"))]
use std::{vec, vec::Vec, boxed::Box, string::String};
#[cfg(target_arch = "wasm32")]
use alloc::{vec, vec::Vec, boxed::Box, string::String};

#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};
#[cfg(target_arch = "wasm32")]
use alloc::sync::Arc;
#[cfg(target_arch = "wasm32")]
use spin::Mutex;
use serde::{Serialize, Deserialize};
#[cfg(feature = "wasm-inspection")]
use wasmi::{*, StoreLimits, StoreLimitsBuilder};
#[cfg(feature = "wasm-inspection")]
use anyhow::{Context, Result};
#[cfg(feature = "wasm-inspection")]
use sha3::{Digest, Keccak256};
#[cfg(feature = "wasm-inspection")]
use crate::traits::JsonRpcProvider;
use super::types::AlkaneId;

// Re-export alkanes support types for cross-platform compatibility
pub use alkanes_support::{
    id::AlkaneId as AlkanesAlkaneId,
    parcel::AlkaneTransferParcel,
    trace::Trace,
};

/// Simple message context parcel for alkane execution
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
    #[cfg(feature = "wasm-inspection")]
    pub limiter: StoreLimits,
}

/// Configuration for alkanes inspection
#[derive(Debug, Clone)]
pub struct InspectionConfig {
    pub disasm: bool,
    pub fuzz: bool,
    pub fuzz_ranges: Option<String>,
    pub meta: bool,
    pub codehash: bool,
    pub raw: bool,
}

/// Result of alkanes inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub alkane_id: AlkaneId,
    pub bytecode_length: usize,
    pub codehash: Option<String>,
    pub disassembly: Option<String>,
    pub metadata: Option<AlkaneMetadata>,
    pub fuzzing_results: Option<FuzzingResults>,
}

/// Alkane metadata extracted from __meta export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkaneMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub methods: Vec<AlkaneMethod>,
}

/// Method information from alkane metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkaneMethod {
    pub name: String,
    pub opcode: u128,
    pub params: Vec<String>,
    pub returns: String,
}

/// Results of fuzzing analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingResults {
    pub total_opcodes_tested: usize,
    pub opcodes_filtered_out: usize,
    pub successful_executions: usize,
    pub failed_executions: usize,
    pub implemented_opcodes: Vec<u128>,
    pub opcode_results: Vec<ExecutionResult>,
}

/// Result of opcode execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_value: Option<i32>,
    pub return_data: Vec<u8>,
    pub error: Option<String>,
    pub execution_time_micros: u64,
    pub opcode: u128,
    pub host_calls: Vec<HostCall>,
}

/// Record of a host function call made during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCall {
    pub function_name: String,
    pub parameters: Vec<String>,
    pub result: String,
    pub timestamp_micros: u64,
}

impl HostCall {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(function_name: String, parameters: Vec<String>, result: String, timestamp: Instant) -> Self {
        Self {
            function_name,
            parameters,
            result,
            timestamp_micros: timestamp.elapsed().as_micros() as u64,
        }
    }
    
    #[cfg(target_arch = "wasm32")]
    pub fn new(function_name: String, parameters: Vec<String>, result: String, _timestamp: u64) -> Self {
        Self {
            function_name,
            parameters,
            result,
            timestamp_micros: 0, // WASM doesn't have precise timing
        }
    }
}

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
        let hex_string = if bytecode.starts_with("0x") {
            &bytecode[2..]
        } else {
            &bytecode
        };
        
        let wasm_bytes = hex::decode(hex_string)
            .with_context(|| format!("Failed to decode WASM bytecode from hex"))?;
        
        let mut result = InspectionResult {
            alkane_id: alkane_id.clone(),
            bytecode_length: wasm_bytes.len(),
            codehash: None,
            disassembly: None,
            metadata: None,
            fuzzing_results: None,
        };
        
        // Perform requested analysis
        if config.codehash {
            result.codehash = Some(self.compute_codehash(&wasm_bytes)?);
        }
        
        if config.meta {
            result.metadata = self.extract_metadata(&wasm_bytes).await.ok();
        }
        
        if config.disasm {
            result.disassembly = self.disassemble_wasm(&wasm_bytes)?;
        }
        
        if config.fuzz {
            result.fuzzing_results = Some(self.perform_fuzzing_analysis(
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

    /// Compute SHA3 (Keccak256) hash of the WASM bytecode
    fn compute_codehash(&self, wasm_bytes: &[u8]) -> Result<String> {
        let mut hasher = Keccak256::new();
        hasher.update(wasm_bytes);
        let hash = hasher.finalize();
        Ok(hex::encode(&hash))
    }

    /// Extract metadata using WASM runtime
    async fn extract_metadata(&self, wasm_bytes: &[u8]) -> Result<AlkaneMetadata> {
        let engine = self.create_engine();
        
        // Create a basic context for metadata extraction
        let context = AlkanesRuntimeContext {
            inputs: vec![],
            ..Default::default()
        };
        
        let mut store = self.create_store(&engine, context);
        let linker = Self::create_host_functions(store.engine());
        
        // Compile and instantiate the module
        let module = Module::new(store.engine(), &mut &wasm_bytes[..])
            .context("Failed to compile WASM module")?;
        
        let instance = linker.instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?
            .ensure_no_start(&mut store)
            .context("Failed to ensure no start function")?;
        
        // Get memory export
        let memory = instance.get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("No memory export found"))?;
        
        // Get __meta export
        let meta_func = instance.get_func(&mut store, "__meta")
            .ok_or_else(|| anyhow::anyhow!("No __meta export found"))?
            .typed::<(), i32>(&store)
            .context("Failed to get typed __meta function")?;
        
        // Execute __meta
        let meta_ptr = meta_func.call(&mut store, ())
            .context("Failed to execute __meta")?;
        
        // Read metadata from memory
        let metadata = self.read_metadata_from_memory(&store, memory, meta_ptr as usize)?;
        
        Ok(metadata)
    }

    /// Disassemble WASM to WAT format
    fn disassemble_wasm(&self, wasm_bytes: &[u8]) -> Result<Option<String>> {
        #[cfg(feature = "wasm-inspection")]
        {
            match wasmprinter::print_bytes(wasm_bytes) {
                Ok(wat_content) => Ok(Some(wat_content)),
                Err(_) => Ok(None), // Return None if disassembly fails
            }
        }
        #[cfg(not(feature = "wasm-inspection"))]
        {
            let _ = wasm_bytes; // Suppress unused variable warning
            Ok(None)
        }
    }

    /// Perform fuzzing analysis using optimized batch execution
    async fn perform_fuzzing_analysis(
        &self,
        alkane_id: &AlkaneId,
        wasm_bytes: &[u8],
        fuzz_ranges: Option<&str>,
    ) -> Result<FuzzingResults> {
        // Determine which opcodes to test
        let opcodes_to_test = if let Some(ranges_str) = fuzz_ranges {
            Self::parse_opcode_ranges(ranges_str)?
        } else {
            // Default: test opcodes 0-999
            (0..1000).collect()
        };
        
        // Use optimized batch execution instead of creating new instances for each opcode
        let results = self.execute_opcodes_batch(wasm_bytes, &opcodes_to_test, alkane_id).await?;
        
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
        
        Ok(FuzzingResults {
            total_opcodes_tested: total_tested,
            opcodes_filtered_out: filtered_out,
            successful_executions: success_count,
            failed_executions: error_count,
            implemented_opcodes,
            opcode_results: filtered_results,
        })
    }

    /// Execute multiple opcodes efficiently by reusing the WASM instance
    async fn execute_opcodes_batch(
        &self,
        wasm_bytes: &[u8],
        opcodes: &[u128],
        alkane_id: &AlkaneId,
    ) -> Result<Vec<ExecutionResult>> {
        let engine = self.create_engine();
        
        // Create initial context - we'll update the inputs for each opcode
        let initial_context = AlkanesRuntimeContext {
            inputs: vec![0u128; 16], // Will be updated for each opcode
            myself: AlkanesAlkaneId {
                block: alkane_id.block as u128,
                tx: alkane_id.tx as u128,
            },
            caller: AlkanesAlkaneId {
                block: alkane_id.block as u128,
                tx: alkane_id.tx as u128,
            },
            message: Box::new(MessageContextParcel {
                vout: 0,
                height: 800000,
                calldata: vec![],
            }),
            ..Default::default()
        };
        
        let mut store = self.create_store(&engine, initial_context);
        let linker = Self::create_host_functions(store.engine());
        
        // Compile and instantiate the module once
        let module = Module::new(store.engine(), &mut &wasm_bytes[..])
            .context("Failed to compile WASM module")?;
        
        let instance = linker.instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?
            .ensure_no_start(&mut store)
            .context("Failed to ensure no start function")?;
        
        // Get memory and function exports once
        let memory = instance.get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("No memory export found"))?;
        
        let execute_func = instance.get_func(&mut store, "__execute")
            .ok_or_else(|| anyhow::anyhow!("No __execute export found"))?
            .typed::<(), i32>(&store)
            .context("Failed to get typed __execute function")?;
        
        let mut results = Vec::new();
        
        // Execute each opcode by updating the context inputs
        for &opcode in opcodes {
            // Update the context inputs for this opcode
            {
                let mut context_guard = store.data().context.lock().unwrap();
                context_guard.inputs[0] = opcode; // First input is the opcode
                // Keep the rest as zeros
                for i in 1..16 {
                    context_guard.inputs[i] = 0;
                }
                // Clear return data from previous execution
                context_guard.returndata.clear();
            }
            
            // Clear host calls from previous execution
            {
                let mut calls_guard = store.data().host_calls.lock().unwrap();
                calls_guard.clear();
            }
            
            // Reset failure flag
            store.data_mut().had_failure = false;
            
            // Execute with the updated context
            let start_time = Instant::now();
            let result = execute_func.call(&mut store, ());
            let execution_time = start_time.elapsed();
            
            // Capture host calls for this execution
            let host_calls = {
                let calls_guard = store.data().host_calls.lock().unwrap();
                calls_guard.clone()
            };

            match result {
                Ok(response_ptr) => {
                    // Decode the ExtendedCallResponse from the returned pointer
                    let (return_data, error_message) = self.decode_extended_call_response(&store, memory, response_ptr as usize)?;
                    
                    results.push(ExecutionResult {
                        success: true,
                        return_value: Some(response_ptr),
                        return_data,
                        error: error_message,
                        execution_time_micros: execution_time.as_micros() as u64,
                        opcode,
                        host_calls,
                    });
                },
                Err(e) => {
                    results.push(ExecutionResult {
                        success: false,
                        return_value: None,
                        return_data: vec![],
                        error: Some(format!("WASM execution failed: {}", e)),
                        execution_time_micros: execution_time.as_micros() as u64,
                        opcode,
                        host_calls,
                    });
                },
            }
        }
        
        Ok(results)
    }

    /// Execute an opcode with proper alkane context for fuzzing (single opcode)
    #[allow(dead_code)]
    async fn execute_opcode_with_context(
        &self,
        wasm_bytes: &[u8],
        opcode: u128,
        alkane_id: &AlkaneId,
    ) -> Result<ExecutionResult> {
        // Use the batch execution for single opcodes too for consistency
        let results = self.execute_opcodes_batch(wasm_bytes, &[opcode], alkane_id).await?;
        results.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("No result returned from batch execution"))
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
        let mut response_patterns: HashMap<String, Vec<&ExecutionResult>> = HashMap::new();
        
        // Group results by normalized response pattern
        for result in results {
            let pattern_key = self.normalize_response_pattern(result);
            response_patterns.entry(pattern_key)
                .or_insert_with(Vec::new)
                .push(result);
        }
        
        // Debug: Print pattern analysis (only if there are multiple patterns)
        if response_patterns.len() > 1 {
            println!("🔍 Pattern Analysis:");
            for (pattern, results_with_pattern) in &response_patterns {
                println!("   Pattern: {} -> {} results", pattern, results_with_pattern.len());
            }
        }
        
        // Find the largest group of identical responses (likely undefined behavior)
        let largest_group = response_patterns
            .iter()
            .max_by_key(|(_, opcodes)| opcodes.len())
            .map(|(pattern, opcodes)| (pattern.clone(), opcodes.len()));
        
        if let Some((largest_pattern, largest_count)) = largest_group {
            // Only filter if we have multiple patterns AND the largest represents > 80% of results
            // This prevents filtering when ALL results have the same legitimate error
            let threshold = (results.len() * 8) / 10; // 80% threshold (was 30%)
            let has_multiple_patterns = response_patterns.len() > 1;
            
            if largest_count > threshold && has_multiple_patterns {
                // Check if this is an error pattern that looks like undefined behavior
                let is_undefined_behavior = largest_pattern.contains("unrecognized opcode") ||
                                          largest_pattern.contains("unknown opcode") ||
                                          largest_pattern.contains("invalid opcode") ||
                                          largest_pattern.contains("not implemented");
                
                if is_undefined_behavior {
                    println!("🚫 Filtering {} results with undefined behavior pattern: {}", largest_count, largest_pattern);
                    
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
                } else {
                    println!("📊 Largest pattern doesn't look like undefined behavior, keeping all results");
                }
            } else {
                println!("📊 No filtering needed: {} patterns, largest has {}/{} results ({}%)",
                        response_patterns.len(), largest_count, results.len(),
                        (largest_count * 100) / results.len());
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

    /// Create a wasmi engine with host functions
    fn create_engine(&self) -> Engine {
        let mut config = Config::default();
        config.consume_fuel(true);
        Engine::new(&config)
    }

    /// Create a wasmi store with runtime state
    fn create_store(&self, engine: &Engine, context: AlkanesRuntimeContext) -> Store<AlkanesState> {
        let state = AlkanesState {
            had_failure: false,
            context: Arc::new(Mutex::new(context)),
            host_calls: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "wasm-inspection")]
            limiter: StoreLimitsBuilder::new().memory_size(16 * 1024 * 1024).build(), // 16MB memory limit
        };
        let mut store = Store::new(engine, state);
        #[cfg(feature = "wasm-inspection")]
        store.limiter(|state| &mut state.limiter);
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
            
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let output_addr = output as usize;
                
                // Write the serialized context directly (no length prefix)
                if let Ok(_) = memory.write(&mut caller, output_addr, &serialized) {
                    return serialized.len() as i32;
                }
            }
            -1
        }).unwrap();

        // __request_storage - matches alkanes-rs signature
        linker.func_wrap("env", "__request_storage", |caller: Caller<'_, AlkanesState>, k: i32| -> i32 {
            let start_time = Instant::now();
            
            // Read the storage key from memory
            let key_str = if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let k_addr = k as usize;
                
                // Read length from ptr - 4 (4 bytes before the pointer)
                if k_addr >= 4 {
                    let mut len_bytes = [0u8; 4];
                    if memory.read(&caller, k_addr - 4, &mut len_bytes).is_ok() {
                        let len = u32::from_le_bytes(len_bytes) as usize;
                        
                        let mut key_bytes = vec![0u8; len];
                        if memory.read(&caller, k_addr, &mut key_bytes).is_ok() {
                            String::from_utf8_lossy(&key_bytes).to_string()
                        } else {
                            format!("invalid_key_bounds_ptr_{}_len_{}", k, len)
                        }
                    } else {
                        format!("invalid_key_ptr_{}", k)
                    }
                } else {
                    format!("invalid_key_ptr_{}", k)
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
                timestamp_micros: start_time.elapsed().as_micros() as u64,
            };
            
            {
                let mut calls = caller.data().host_calls.lock().unwrap();
                calls.push(host_call);
            }
            
            result_size
        }).unwrap();

        // __load_storage - matches alkanes-rs signature
        linker.func_wrap("env", "__load_storage", |mut caller: Caller<'_, AlkanesState>, k: i32, v: i32| -> i32 {
            let start_time = Instant::now();
            
            // Read the storage key from memory
            let key_str = if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let k_addr = k as usize;
                
                // Read length from ptr - 4 (4 bytes before the pointer)
                if k_addr >= 4 {
                    let mut len_bytes = [0u8; 4];
                    if memory.read(&caller, k_addr - 4, &mut len_bytes).is_ok() {
                        let len = u32::from_le_bytes(len_bytes) as usize;
                        
                        let mut key_bytes = vec![0u8; len];
                        if memory.read(&caller, k_addr, &mut key_bytes).is_ok() {
                            String::from_utf8_lossy(&key_bytes).to_string()
                        } else {
                            format!("invalid_key_bounds_ptr_{}_len_{}", k, len)
                        }
                    } else {
                        format!("invalid_key_ptr_{}", k)
                    }
                } else {
                    format!("invalid_key_ptr_{}", k)
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
            let bytes_written = if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let v_addr = v as usize;
                
                // Write length first
                let len_bytes = (storage_value.len() as u32).to_le_bytes();
                if memory.write(&mut caller, v_addr, &len_bytes).is_ok() {
                    // Write storage value
                    if memory.write(&mut caller, v_addr + 4, &storage_value).is_ok() {
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
                timestamp_micros: start_time.elapsed().as_micros() as u64,
            };
            
            {
                let mut calls = caller.data().host_calls.lock().unwrap();
                calls.push(host_call);
            }
            
            bytes_written
        }).unwrap();

        // __height - matches alkanes-rs signature
        linker.func_wrap("env", "__height", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let height: u64 = 800000; // Placeholder height
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let output_addr = output as usize;
                let height_bytes = height.to_le_bytes();
                
                // Write length first
                let len_bytes = (height_bytes.len() as u32).to_le_bytes();
                if memory.write(&mut caller, output_addr, &len_bytes).is_ok() {
                    // Write height data
                    let _ = memory.write(&mut caller, output_addr + 4, &height_bytes);
                }
            }
        }).unwrap();

        // __log - matches alkanes-rs signature
        linker.func_wrap("env", "__log", |caller: Caller<'_, AlkanesState>, v: i32| {
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let v_addr = v as usize;
                
                // Read length from ptr - 4 (4 bytes before the pointer)
                if v_addr >= 4 {
                    let mut len_bytes = [0u8; 4];
                    if memory.read(&caller, v_addr - 4, &mut len_bytes).is_ok() {
                        let len = u32::from_le_bytes(len_bytes) as usize;
                        
                        let mut message_bytes = vec![0u8; len];
                        if memory.read(&caller, v_addr, &mut message_bytes).is_ok() {
                            if let Ok(message) = String::from_utf8(message_bytes) {
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
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let output_addr = output as usize;
                let zero_balance = 0u128.to_le_bytes();
                
                let len_bytes = (zero_balance.len() as u32).to_le_bytes();
                if memory.write(&mut caller, output_addr, &len_bytes).is_ok() {
                    let _ = memory.write(&mut caller, output_addr + 4, &zero_balance);
                }
            }
        }).unwrap();

        // __sequence - matches alkanes-rs signature
        linker.func_wrap("env", "__sequence", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let sequence: u128 = 0; // Placeholder sequence
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let output_addr = output as usize;
                let seq_bytes = sequence.to_le_bytes();
                
                let len_bytes = (seq_bytes.len() as u32).to_le_bytes();
                if memory.write(&mut caller, output_addr, &len_bytes).is_ok() {
                    let _ = memory.write(&mut caller, output_addr + 4, &seq_bytes);
                }
            }
        }).unwrap();

        // __fuel - matches alkanes-rs signature
        linker.func_wrap("env", "__fuel", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let fuel: u64 = 1000000; // Placeholder fuel
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let output_addr = output as usize;
                let fuel_bytes = fuel.to_le_bytes();
                
                let len_bytes = (fuel_bytes.len() as u32).to_le_bytes();
                if memory.write(&mut caller, output_addr, &len_bytes).is_ok() {
                    let _ = memory.write(&mut caller, output_addr + 4, &fuel_bytes);
                }
            }
        }).unwrap();

        // __returndatacopy - matches alkanes-rs signature
        linker.func_wrap("env", "__returndatacopy", |mut caller: Caller<'_, AlkanesState>, output: i32| {
            let returndata = {
                let context_guard = caller.data().context.lock().unwrap();
                context_guard.returndata.clone()
            };
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let output_addr = output as usize;
                
                let len_bytes = (returndata.len() as u32).to_le_bytes();
                if memory.write(&mut caller, output_addr, &len_bytes).is_ok() {
                    let _ = memory.write(&mut caller, output_addr + 4, &returndata);
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
            let start_time = Instant::now();
            
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
                timestamp_micros: start_time.elapsed().as_micros() as u64,
            };
            
            {
                let mut calls = caller.data().host_calls.lock().unwrap();
                calls.push(host_call);
            }
            
            -1 // Not implemented
        }).unwrap();

        // __delegatecall - matches alkanes-rs signature
        linker.func_wrap("env", "__delegatecall", |mut caller: Caller<'_, AlkanesState>, cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, start_fuel: u64| -> i32 {
            let start_time = Instant::now();
            
            let call_info = Self::decode_cellpack_info(&mut caller, cellpack_ptr);
            
            let host_call = HostCall {
                function_name: "__delegatecall".to_string(),
                parameters: vec![
                    format!("target: {}", call_info),
                    format!("fuel: {}", start_fuel),
                ],
                result: "not_implemented".to_string(),
                timestamp_micros: start_time.elapsed().as_micros() as u64,
            };
            
            {
                let mut calls = caller.data().host_calls.lock().unwrap();
                calls.push(host_call);
            }
            
            -1 // Not implemented
        }).unwrap();

        // __staticcall - matches alkanes-rs signature
        linker.func_wrap("env", "__staticcall", |mut caller: Caller<'_, AlkanesState>, cellpack_ptr: i32, _incoming_alkanes_ptr: i32, _checkpoint_ptr: i32, start_fuel: u64| -> i32 {
            let start_time = Instant::now();
            
            let call_info = Self::decode_cellpack_info(&mut caller, cellpack_ptr);
            
            let host_call = HostCall {
                function_name: "__staticcall".to_string(),
                parameters: vec![
                    format!("target: {}", call_info),
                    format!("fuel: {}", start_fuel),
                ],
                result: "not_implemented".to_string(),
                timestamp_micros: start_time.elapsed().as_micros() as u64,
            };
            
            {
                let mut calls = caller.data().host_calls.lock().unwrap();
                calls.push(host_call);
            }
            
            -1 // Not implemented
        }).unwrap();
        
        linker
    }

    /// Helper function to decode cellpack information from memory
    fn decode_cellpack_info(caller: &mut Caller<'_, AlkanesState>, cellpack_ptr: i32) -> String {
        if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
            let ptr_addr = cellpack_ptr as usize;
            
            // Read length from ptr - 4 (4 bytes before the pointer)
            if ptr_addr >= 4 {
                let mut len_bytes = [0u8; 4];
                if memory.read(&mut *caller, ptr_addr - 4, &mut len_bytes).is_ok() {
                    let len = u32::from_le_bytes(len_bytes) as usize;
                    
                    if len >= 32 {
                        // Try to read target AlkaneId (first 32 bytes starting from ptr)
                        let mut target_bytes = [0u8; 32];
                        if memory.read(&mut *caller, ptr_addr, &mut target_bytes).is_ok() {
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
        }
        format!("unknown_cellpack_{}", cellpack_ptr)
    }

    /// Decode ExtendedCallResponse structure from WASM memory
    fn decode_extended_call_response(&self, store: &Store<AlkanesState>, memory: Memory, ptr: usize) -> Result<(Vec<u8>, Option<String>)> {
        let memory_size = memory.size(store) as usize;
        
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
                
                // Try to extract readable text
                let mut error_msg = String::new();
                for &byte in message_bytes {
                    if byte >= 32 && byte <= 126 { // Printable ASCII
                        error_msg.push(byte as char);
                    } else if byte == 0 {
                        break; // End of string
                    }
                }
                
                let clean_msg = error_msg.trim().to_string();
                if !clean_msg.is_empty() {
                    return Ok((message_bytes.to_vec(), Some(clean_msg)));
                } else {
                    return Ok((message_bytes.to_vec(), Some("Unknown error".to_string())));
                }
            }
        }
        
        // If no error signature found, look for other patterns
        let first_16_zero = response_bytes.len() >= 16 && response_bytes[0..16].iter().all(|&b| b == 0);
        if first_16_zero {
            // Look for data after the header
            if response_bytes.len() > 16 {
                let data_part = &response_bytes[16..];
                
                if data_part.iter().any(|&b| b != 0) {
                    // Try to interpret as string
                    if let Ok(text) = String::from_utf8(data_part.to_vec()) {
                        let clean_text = text.trim_matches('\0').trim();
                        if !clean_text.is_empty() && clean_text.is_ascii() {
                            return Ok((data_part.to_vec(), None));
                        }
                    }
                    
                    return Ok((data_part.to_vec(), None));
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
        // Get memory size for bounds checking
        let memory_size = memory.size(store) as usize;
        
        if ptr < 4 || ptr >= memory_size {
            return Err(anyhow::anyhow!("Pointer 0x{:x} is invalid (memory size: {})", ptr, memory_size));
        }
        
        // Read length from ptr-4 (length is stored before the data)
        let mut len_bytes = [0u8; 4];
        memory.read(store, ptr - 4, &mut len_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to read metadata length at 0x{:x}: {:?}", ptr - 4, e))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        
        if ptr + len > memory_size {
            return Err(anyhow::anyhow!("Metadata extends beyond memory bounds: ptr=0x{:x}, len={}, memory_size={}", ptr, len, memory_size));
        }
        
        // Read metadata bytes starting at ptr
        let mut metadata_bytes = vec![0u8; len];
        memory.read(store, ptr, &mut metadata_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to read metadata bytes at 0x{:x}: {:?}", ptr, e))?;
        
        // Try to parse as JSON first, then fall back to basic parsing
        if let Ok(json_meta) = serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
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
            
            Ok(AlkaneMetadata {
                name: contract_name,
                version,
                description,
                methods,
            })
        } else {
            // Fallback to basic metadata
            Ok(AlkaneMetadata {
                name: "Unknown".to_string(),
                version: "0.0.0".to_string(),
                description: None,
                methods: vec![],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::JsonRpcProvider;
    use async_trait::async_trait;

    struct MockRpcProvider;

    #[async_trait]
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