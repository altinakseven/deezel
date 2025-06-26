//! Deezel Core - Generic traits and runtime for Bitcoin wallet operations
//!
//! This crate provides the core abstractions that enable deezel to work with
//! different storage backends, RPC clients, and filesystem adapters in a generic way.
//!
//! # Architecture
//!
//! The core library follows the same patterns as metashrew-runtime, implementing
//! generic traits that can be adapted for different environments:
//!
//! - **CLI Environment**: Uses filesystem and network RPC calls
//! - **Web Environment**: Uses browser storage and fetch APIs
//! - **Test Environment**: Uses in-memory storage and mock adapters
//!
//! # Key Components
//!
//! ## Storage Traits
//! - [`WalletStorageLike`]: Generic wallet data persistence
//! - [`ConfigStorageLike`]: Configuration storage abstraction
//!
//! ## RPC Traits
//! - [`RpcClientLike`]: Generic RPC client interface
//! - [`BlockchainClientLike`]: Blockchain data access abstraction
//!
//! ## Runtime
//! - [`DeezelRuntime`]: Main runtime parameterized over adapters
//! - [`DeezelContext`]: Execution context with injected dependencies

pub mod traits;
pub mod runtime;
pub mod context;
pub mod wallet;
pub mod rpc;
pub mod alkanes;
pub mod block_builder;

// Re-export core types and traits
pub use traits::{
    WalletStorageLike, ConfigStorageLike, RpcClientLike, BlockchainClientLike,
    FilesystemLike, BatchLike
};
pub use runtime::{DeezelRuntime, DeezelRuntimeConfig};
pub use context::DeezelContext;

// Re-export wallet types
pub use wallet::{WalletManager, WalletConfig, WalletError};

// Re-export RPC types
pub use rpc::{RpcManager, RpcConfig, RpcError};

// Re-export alkanes types
pub use alkanes::{AlkanesManager, AlkanesConfig, AlkanesError};

// Re-export test utilities when feature is enabled
#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(feature = "test-utils")]
pub use test_utils::*;