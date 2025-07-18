//! Deezel alkanes library
//!
//! This library provides functionality for alkanes contract deployment and execution
//! using envelope and cellpack patterns.

pub mod utils;
pub mod wallet;
pub mod monitor;
pub mod network;
pub mod transaction;
pub mod rpc;
pub mod runestone_enhanced;
pub mod alkanes;
pub mod address_resolver;
pub mod build;
pub mod deploy;
 
 // Test modules for e2e testing
 pub mod tests;

// Re-export key types for convenience
pub use wallet::WalletManager;
pub use monitor::BlockMonitor;
pub use transaction::TransactionConstructor;
pub use rpc::RpcClient;
pub use network::NetworkParams;
pub use runestone_enhanced::{decode_runestone, format_runestone, format_runestone_with_decoded_messages, decode_protostone_message, print_human_readable_runestone};
pub use address_resolver::{AddressResolver, AddressIdentifier, AddressType};

// Re-export the Runestone from ordinals crate
pub use ordinals::Runestone;
pub use protorune_support::protostone::Protostone;
