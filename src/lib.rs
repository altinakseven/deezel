//! Deezel - A comprehensive Bitcoin wallet SDK and CLI tool
//!
//! This library provides functionality for Bitcoin wallet management,
//! transaction construction, and support for various Bitcoin protocols
//! including DIESEL tokens, BRC20, Runes, and Collectibles.

// Core modules
pub mod wallet;
pub mod account;
pub mod signer;
pub mod monitor;
pub mod transaction;
pub mod rpc;
pub mod runestone;

// Protocol modules
pub mod alkanes;
pub mod brc20;
pub mod rune;
pub mod collectible;

// Utility modules
pub mod utils;
pub mod cli;

// Re-export key types for convenience
pub use wallet::WalletManager;
pub use account::{Account, encryption::EncryptedAccount};
pub use signer::Signer;
pub use monitor::BlockMonitor;
pub use transaction::TransactionConstructor;
pub use rpc::RpcClient;
pub use runestone::Runestone;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Library description
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
