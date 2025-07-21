//! # Pretty-printing for transaction and runestone analysis
//!
//! This module provides functions to display transaction and runestone
//! analysis results in a human-readable format for the CLI.

use deezel_common::alkanes::types::ReadyToSignRevealTx;
use tabled::{settings::Style, Table};

/// Pretty-prints the comprehensive transaction analysis.
pub fn pretty_print_analysis(state: &ReadyToSignRevealTx) {
    println!("Transaction Preview:");
    println!(
        "{}",
        Table::new(vec![state.analysis.clone()]).with(Style::markdown())
    );

    if !state.params.protostones.is_empty() {
        println!("\nProtostones Preview:");
        for (i, protostone) in state.params.protostones.iter().enumerate() {
            println!("  Protostone #{}:", i);
            println!(
                "{}",
                serde_json::to_string_pretty(protostone).unwrap_or_else(|e| e.to_string())
            );
        }
    }
}