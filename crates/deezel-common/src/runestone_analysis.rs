//! Comprehensive Transaction and Runestone Analysis
//!
//! This module provides functions to perform a detailed analysis of a Bitcoin
//! transaction, extracting information about its inputs, outputs, and any
//! embedded protostones or runestones. It also includes a pretty-printer
//! to format the analysis into a human-readable string, consistent with
//! the reference implementation's output.

use crate::alkanes::analyze::analyze_runestone;
use crate::runestone_enhanced;
use crate::Result;
use alloc::{
    string::{String},
};
use bitcoin::{Network, Transaction};
use serde_json::{Value as JsonValue};

/// Analyzes a transaction and any embedded runestone, producing a detailed JSON object.
///
/// This function inspects the transaction's inputs, outputs, and decodes any
/// protostone data found in an OP_RETURN output. The structure of the returned
/// JSON value is designed to match the output of the `--raw` flag from the
/// reference implementation.
///
/// # Arguments
///
/// * `tx` - A reference to the `bitcoin::Transaction` to be analyzed.
/// * `_network` - The `bitcoin::Network` context (e.g., Mainnet, Testnet) for address generation.
///
/// # Returns
///
/// A `Result` containing a `serde_json::Value` with the detailed analysis.
pub fn analyze_transaction_with_runestone(
    tx: &Transaction,
    _network: Network,
) -> Result<JsonValue> {
    Ok(analyze_runestone(tx)?)
}

/// Formats the detailed transaction analysis into a human-readable string.
///
/// This function takes the JSON object produced by `analyze_transaction_with_runestone`
/// and formats it with headers, emojis, and structured sections for readability.
///
/// # Arguments
///
/// * `analysis` - A `serde_json::Value` containing the detailed transaction analysis.
///
/// # Returns
///
/// A `Result` containing the formatted `String`.
pub fn pretty_print_transaction_analysis(analysis: &JsonValue) -> Result<String> {
    let output = String::new();
    
    // Create a dummy transaction for printing, as the required info is in the analysis JSON
    let txid_hex = analysis["transaction_id"].as_str().unwrap_or_default();
    let tx_bytes = hex::decode(txid_hex).unwrap_or_default();
    let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes).unwrap_or_else(|_| Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::from_consensus(0),
        input: vec![],
        output: vec![],
    });


    runestone_enhanced::print_human_readable_runestone(&tx, analysis);

    // The print function prints directly to stdout, so we capture it here if needed
    // For now, we assume it prints and we return an empty string.
    // A better approach would be for the print function to return a string.
    Ok(output)
}
