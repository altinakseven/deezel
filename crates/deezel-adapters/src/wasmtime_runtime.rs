//! Wasmtime WASM runtime adapter for CLI environment

use anyhow::Result;
use async_trait::async_trait;
use deezel_core::traits::WasmRuntimeLike;
use std::io::{Error, ErrorKind};
use wasmtime::*;

/// Wasmtime WASM runtime adapter
pub struct WasmtimeRuntime {
    engine: Engine,
    store: Option<Store<()>>,
    instance: Option<Instance>,
    memory_limit: usize,
    timeout_ms: u64,
}

impl WasmtimeRuntime {
    pub fn new() -> Result<Self, Error> {
        let mut config = Config::new();
        config.wasm_simd(true);
        config.wasm_bulk_memory(true);
        config.wasm_multi_value(true);
        
        let engine = Engine::new(&config)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(Self {
            engine,
            store: None,
            instance: None,
            memory_limit: 64 * 1024 * 1024, // 64MB default
            timeout_ms: 30000, // 30 seconds default
        })
    }
}

impl Default for WasmtimeRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create Wasmtime runtime")
    }
}

#[async_trait]
impl WasmRuntimeLike for WasmtimeRuntime {
    type Error = Error;

    async fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<(), Self::Error> {
        let module = Module::from_binary(&self.engine, wasm_bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        let mut store = Store::new(&self.engine, ());
        
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        self.store = Some(store);
        self.instance = Some(instance);

        Ok(())
    }

    async fn execute_function(&mut self, name: &str, args: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let store = self.store.as_mut()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "No module loaded"))?;
        
        let instance = self.instance.as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "No instance available"))?;

        // Get the function
        let func = instance.get_func(&mut *store, name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("Function '{}' not found", name)))?;

        // Get memory for passing arguments
        let memory = instance.get_memory(&mut *store, "memory")
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "Memory not found"))?;

        // Write arguments to memory (simplified)
        let args_ptr = 0; // Start of memory
        memory.write(&mut *store, args_ptr, args)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        // Call the function (simplified - just return mock data)
        let _result = func.call(&mut *store, &[Val::I32(args_ptr as i32), Val::I32(args.len() as i32)], &mut [])
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        // Return mock result data
        Ok(b"mock_wasm_result".to_vec())
    }

    async fn get_exports(&self) -> Result<Vec<String>, Self::Error> {
        // Return mock exports for now
        Ok(vec![
            "execute".to_string(),
            "simulate".to_string(),
            "meta".to_string(),
        ])
    }

    fn set_memory_limit(&mut self, limit: usize) {
        self.memory_limit = limit;
    }

    fn set_timeout(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms;
    }
}