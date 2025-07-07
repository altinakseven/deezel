//! Deezel Common Library
//!
//! This library provides the core functionality for the deezel project,
//! designed to be WASM-compatible and platform-agnostic.
//!
//! The library is structured around trait abstractions that allow the same
//! business logic to work across different environments:
//! - Native CLI applications
//! - WASM web applications  
//! - Testing environments
//!
//! ## Architecture
//!
//! The library is organized into several key modules:
//! - `traits`: Core trait abstractions for platform independence
//! - `wallet`: Bitcoin wallet functionality with BDK integration
//! - `alkanes`: Smart contract operations and inspection
//! - `runestone`: Runestone analysis and decoding
//! - `network`: Network parameter management
//! - `rpc`: RPC client abstractions
//! - `address_resolver`: Address identifier resolution
//! - `monitor`: Blockchain monitoring
//! - `transaction`: Transaction construction and signing
//! - `utils`: Common utilities

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

// Core modules
pub mod traits;
pub mod network;
pub mod rpc;
pub mod alkanes;
pub mod wallet;
pub mod address_resolver;
pub mod runestone;
pub mod runestone_enhanced;
pub mod transaction;
pub mod monitor;
pub mod utils;

// Re-export key types and traits for convenience
pub use traits::*;
pub use network::NetworkParams;
pub use rpc::{RpcClient, RpcConfig, RpcRequest, RpcResponse};

// Re-export external types for convenience
pub use bitcoin::{Network, Transaction, Address, ScriptBuf};
pub use ordinals::Runestone;
pub use protorune_support::protostone::Protostone;
pub use serde_json::Value as JsonValue;

/// Error types for the deezel-common library
#[derive(thiserror::Error, Debug)]
pub enum DeezelError {
    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),
    
    #[error("RPC error: {0}")]
    RpcError(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Wallet error: {0}")]
    Wallet(String),
    
    #[error("Alkanes error: {0}")]
    Alkanes(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Address resolution error: {0}")]
    AddressResolution(String),
    
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    #[error("Monitoring error: {0}")]
    Monitor(String),
    
    #[error("WASM execution error: {0}")]
    WasmExecution(String),
    
    #[error("Cryptography error: {0}")]
    Crypto(String),
    
    #[error("I/O error: {0}")]
    Io(String),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Result type for deezel-common operations
pub type Result<T> = core::result::Result<T, DeezelError>;

/// Convert anyhow::Error to DeezelError
impl From<anyhow::Error> for DeezelError {
    fn from(err: anyhow::Error) -> Self {
        DeezelError::Wallet(err.to_string())
    }
}

/// Convert serde_json::Error to DeezelError
impl From<serde_json::Error> for DeezelError {
    fn from(err: serde_json::Error) -> Self {
        DeezelError::Serialization(err.to_string())
    }
}

/// Convert bitcoin::consensus::encode::Error to DeezelError
impl From<bitcoin::consensus::encode::Error> for DeezelError {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        DeezelError::Transaction(err.to_string())
    }
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initialize the library (for WASM compatibility)
#[cfg(target_arch = "wasm32")]
pub fn init() {
    // WASM initialization would go here
    // Set up panic hook, logging, etc.
}

/// Initialize the library (no-op for native)
#[cfg(not(target_arch = "wasm32"))]
pub fn init() {
    // No initialization needed for native
}

/// Utility functions for common operations
pub mod prelude {
    pub use crate::traits::*;
    pub use crate::{DeezelError, Result};
    pub use crate::network::NetworkParams;
    pub use crate::rpc::{RpcClient, RpcConfig};
    pub use bitcoin::{Network, Transaction, Address, ScriptBuf};
    pub use ordinals::Runestone;
    pub use protorune_support::protostone::Protostone;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert_eq!(NAME, "deezel-common");
    }
    
    #[test]
    fn test_error_conversions() {
        let anyhow_err = anyhow::anyhow!("test error");
        let deezel_err: DeezelError = anyhow_err.into();
        assert!(matches!(deezel_err, DeezelError::Wallet(_)));
        
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let deezel_err: DeezelError = json_err.into();
        assert!(matches!(deezel_err, DeezelError::Serialization(_)));
    }
}