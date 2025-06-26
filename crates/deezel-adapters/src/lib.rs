//! Concrete adapter implementations for deezel-core traits
//!
//! This crate provides concrete implementations of the traits defined in deezel-core
//! for different environments:
//!
//! - **CLI Environment**: Filesystem storage, HTTP RPC clients, Wasmtime runtime
//! - **Web Environment**: Browser storage, Fetch API, WebAssembly runtime
//! - **Test Environment**: In-memory storage, Mock clients, Mock runtime

pub mod filesystem;
pub mod http_rpc;
pub mod wasmtime_runtime;
pub mod in_memory;

// Re-export adapters based on features
#[cfg(feature = "filesystem")]
pub use filesystem::{FilesystemWalletStorage, FilesystemConfigStorage, FilesystemAdapter};

#[cfg(feature = "http-rpc")]
pub use http_rpc::{HttpRpcClient, HttpBlockchainClient};

#[cfg(feature = "wasmtime-runtime")]
pub use wasmtime_runtime::WasmtimeRuntime;

#[cfg(feature = "in-memory")]
pub use in_memory::{
    InMemoryWalletStorage, InMemoryConfigStorage, InMemoryFilesystem,
    InMemoryRpcClient, InMemoryBlockchainClient, InMemoryWasmRuntime,
    InMemoryBatch
};

// Re-export test utilities when feature is enabled
#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(feature = "test-utils")]
pub use test_utils::*;

/// Convenience type aliases for common adapter combinations
pub mod presets {
    #[cfg(all(feature = "filesystem", feature = "http-rpc", feature = "wasmtime-runtime"))]
    pub type CliRuntime = deezel_core::DeezelRuntime<
        crate::filesystem::FilesystemWalletStorage,
        crate::filesystem::FilesystemConfigStorage,
        crate::http_rpc::HttpRpcClient,
        crate::http_rpc::HttpBlockchainClient,
        crate::filesystem::FilesystemAdapter,
        crate::wasmtime_runtime::WasmtimeRuntime,
    >;

    #[cfg(feature = "in-memory")]
    pub type TestRuntime = deezel_core::DeezelRuntime<
        crate::in_memory::InMemoryWalletStorage,
        crate::in_memory::InMemoryConfigStorage,
        crate::in_memory::InMemoryRpcClient,
        crate::in_memory::InMemoryBlockchainClient,
        crate::in_memory::InMemoryFilesystem,
        crate::in_memory::InMemoryWasmRuntime,
    >;
}