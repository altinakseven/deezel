//! Pretty-printing functions for deezel CLI output
//!
//! This module contains functions for formatting the various data structures
//! returned by the `ord` server into human-readable output.

use deezel_common::{
    alkanes::protorunes::{ProtoruneOutpointResponse, ProtoruneWalletResponse},
    ord::*,
};

pub fn print_inscription(inscription: &Inscription) {
    println!("{}", serde_json::to_string_pretty(inscription).unwrap());
}

pub fn print_inscriptions(inscriptions: &[Inscription]) {
    println!("{}", serde_json::to_string_pretty(inscriptions).unwrap());
}

pub fn print_address_info(address_info: &AddressInfo) {
    println!("{}", serde_json::to_string_pretty(address_info).unwrap());
}

pub fn print_block_info(block_info: &BlockInfo) {
    println!("{}", serde_json::to_string_pretty(block_info).unwrap());
}

pub fn print_output(output: &Output) {
    println!("{}", serde_json::to_string_pretty(output).unwrap());
}

pub fn print_sat_response(sat_response: &SatResponse) {
    println!("{}", serde_json::to_string_pretty(sat_response).unwrap());
}

pub fn print_children(inscriptions: &[Inscription]) {
    println!("{}", serde_json::to_string_pretty(inscriptions).unwrap());
}

pub fn print_parents(parents: &ParentInscriptions) {
    println!("{}", serde_json::to_string_pretty(parents).unwrap());
}

pub fn print_rune(rune_info: &RuneInfo) {
    println!("{}", serde_json::to_string_pretty(rune_info).unwrap());
}

pub fn print_blocks(blocks: &Blocks) {
    println!("{}", serde_json::to_string_pretty(blocks).unwrap());
}

pub fn print_runes(runes: &Runes) {
    println!("{}", serde_json::to_string_pretty(runes).unwrap());
}

pub fn print_tx_info(tx_info: &TxInfo) {
    println!("{}", serde_json::to_string_pretty(tx_info).unwrap());
}

pub fn print_protorune_outpoint_response(response: &ProtoruneOutpointResponse) {
    println!("📦 Protorune Outpoint Response");
    println!("---------------------------------");
    println!("Outpoint: {}", response.outpoint);
    println!("Value: {} sats", response.output.value);
    println!("Script Pubkey: {}", response.output.script_pubkey);
    println!();
    println!("📜 Balance Sheet");
    println!("-----------------");
    for (rune_id, balance) in &response.balance_sheet.cached.balances {
        println!("  - Rune ID: {}:{}", rune_id.block, rune_id.tx);
        println!("    Balance: {balance}");
    }
}

pub fn print_protorune_wallet_response(response: &ProtoruneWalletResponse) {
    println!("💰 Protorune Wallet Balances");
    println!("===========================");
    for balance in &response.balances {
        print_protorune_outpoint_response(balance);
        println!();
    }
}

pub fn print_inspection_result(result: &deezel_common::alkanes::types::AlkanesInspectResult) {
    println!("🔍 Inspection Result for Alkane: {}:{}", result.alkane_id.block, result.alkane_id.tx);
    println!("══════════════════════════════════════════");
    println!("📏 Bytecode Length: {} bytes", result.bytecode_length);

    if let Some(codehash) = &result.codehash {
        println!("🔑 Code Hash: {codehash}");
    }

    if let Some(disassembly) = &result.disassembly {
        println!("\n disassembled bytecode:\n{disassembly}");
    }

    if let Some(metadata) = &result.metadata {
        println!("\n📝 Metadata:");
        println!("{}", serde_json::to_string_pretty(metadata).unwrap_or_else(|e| e.to_string()));
    }

    if let Some(metadata_error) = &result.metadata_error {
        println!("\n⚠️ Metadata Error: {metadata_error}");
    }

    if let Some(fuzzing_results) = &result.fuzzing_results {
        println!("\n🔬 Fuzzing Results:");
        for result in &fuzzing_results.opcode_results {
            println!("  - Opcode 0x{:02X}: {}", result.opcode, if result.success { "Success" } else { "Failure" });
        }
    }
}
