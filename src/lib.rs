//! DIESEL token minting and management library
//!
//! This library provides functionality for automated DIESEL token minting
//! and management using BDK and Sandshrew RPC.

pub mod utils;
pub mod wallet;
pub mod monitor;
pub mod network;
pub mod transaction;
pub mod rpc;
pub mod runestone_enhanced;
pub mod alkanes;
pub mod address_resolver;

// Test modules for e2e testing with mock metashrew
pub mod tests;

// Test module for message decoding verification
#[cfg(test)]
pub mod test_message_decoding;
pub mod test_integration;

// Test module for ordinals crate integration
#[cfg(test)]
pub mod test_ordinals_integration;

// Test module for runestone encoding debugging
#[cfg(test)]
pub mod test_runestone_encoding;

// Test module for protostone parsing debugging
#[cfg(test)]
pub mod test_protostone_parsing;

// Test module for runestone construction debugging
#[cfg(test)]
pub mod test_runestone_construction;

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
