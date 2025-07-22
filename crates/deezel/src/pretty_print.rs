//! Pretty-printing functions for deezel CLI output
//!
//! This module contains functions for formatting the various data structures
//! returned by the `ord` server into human-readable output.

use deezel_common::{
    alkanes::protorunes::{ProtoruneOutpointResponse, ProtoruneWalletResponse},
    ord::*,
};
use tabled::{builder::Builder, settings::Style, Table};

pub fn print_inscription(inscription: &Inscription) {
    println!("Inscription {}", inscription.id);
    let mut table = Table::new(vec![inscription]);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_inscriptions(inscriptions: &[Inscription]) {
    if inscriptions.is_empty() {
        println!("No inscriptions found.");
        return;
    }
    let mut table = Table::new(inscriptions);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_address_info(address_info: &AddressInfo) {
    let mut table = Table::new(vec![address_info]);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_block_info(block_info: &BlockInfo) {
    let mut table = Table::new(vec![block_info]);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_output(output: &Output) {
    let mut table = Table::new(vec![output]);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_sat_response(sat_response: &SatResponse) {
    let mut table = Table::new(vec![sat_response]);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_children(inscriptions: &[Inscription]) {
    if inscriptions.is_empty() {
        println!("No children found.");
        return;
    }
    println!("Children:");
    let mut table = Table::new(inscriptions);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_parents(parents: &ParentInscriptions) {
    if parents.parents.is_empty() {
        println!("No parents found.");
        return;
    }
    println!("Parents:");
    let mut table = Table::new(&parents.parents);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_rune(rune_info: &RuneInfo) {
    let mut table = Table::new(vec![rune_info]);
    table.with(Style::modern());
    println!("{}", table);
}

pub fn print_blocks(blocks: &Blocks) {
    println!("Last block: {}", blocks.last);
    println!("Blocks:");
    for block_hash in &blocks.blocks {
        println!("  {}", block_hash);
    }
    if !blocks.featured_blocks.is_empty() {
        println!("Featured Blocks:");
        for (block_hash, inscriptions) in &blocks.featured_blocks {
            println!("  {}:", block_hash);
            for inscription_id in inscriptions {
                println!("    {}", inscription_id);
            }
        }
    }
}

pub fn print_runes(runes: &Runes) {
    if runes.runes.is_empty() {
        println!("No runes found.");
        return;
    }
    let rune_infos: Vec<&RuneInfo> = runes.runes.values().collect();
    let mut table = Table::new(rune_infos);
    table.with(Style::modern());
    println!("{}", table);
}


pub fn print_tx_info(tx_info: &TxInfo) {
    let mut table = Table::new(vec![tx_info]);
    table.with(Style::modern());
    println!("{}", table);
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
        println!("    Balance: {}", balance);
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
        println!("🔑 Code Hash: {}", codehash);
    }

    if let Some(disassembly) = &result.disassembly {
        println!("\n disassembled bytecode:\n{}", disassembly);
    }

    if let Some(metadata) = &result.metadata {
        println!("\n📝 Metadata:");
        println!("{}", serde_json::to_string_pretty(metadata).unwrap_or_else(|e| e.to_string()));
    }

    if let Some(metadata_error) = &result.metadata_error {
        println!("\n⚠️ Metadata Error: {}", metadata_error);
    }

    if let Some(fuzzing_results) = &result.fuzzing_results {
        println!("\n🔬 Fuzzing Results:");
        for result in &fuzzing_results.opcode_results {
            println!("  - Opcode 0x{:02X}: {}", result.opcode, if result.success { "Success" } else { "Failure" });
        }
    }
}
