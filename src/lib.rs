//! DIESEL token minting and management library
//!
//! This library provides functionality for automated DIESEL token minting
//! and management using BDK and Sandshrew RPC.

pub mod wallet;
pub mod monitor;
pub mod transaction;
pub mod rpc;
pub mod runestone;

// Re-export key types for convenience
pub use wallet::WalletManager;
pub use monitor::BlockMonitor;
pub use transaction::TransactionConstructor;
pub use rpc::RpcClient;
pub use runestone::Runestone;