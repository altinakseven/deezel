//! Pretty-printing functions for deezel CLI output
//!
//! This module contains functions for formatting the various data structures
//! returned by the `ord` server into human-readable output.

use deezel_common::ord::*;
use tabled::{settings::Style, Table};
use deezel_common::trace::types::{SerializableTrace, SerializableTraceEvent};

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

pub fn print_trace(trace: &SerializableTrace) {
    for event in &trace.events {
        match event {
            SerializableTraceEvent::EnterCall(context) => {
                println!("➡️  Enter Call: target={:?}, caller={:?}, fuel={}", context.target, context.inner.caller, context.fuel);
            }
            SerializableTraceEvent::EnterDelegatecall(context) => {
                println!("➡️  Enter Delegatecall: target={:?}, caller={:?}, fuel={}", context.target, context.inner.caller, context.fuel);
            }
            SerializableTraceEvent::EnterStaticcall(context) => {
                println!("➡️  Enter Staticcall: target={:?}, caller={:?}, fuel={}", context.target, context.inner.caller, context.fuel);
            }
            SerializableTraceEvent::ReturnContext(response) => {
                println!("⬅️  Return: fuel_used={}, data=0x{}, alkanes={:?}", response.fuel_used, hex::encode(&response.inner.data), response.inner.alkanes);
            }
            SerializableTraceEvent::RevertContext(response) => {
                println!("↩️  Revert: fuel_used={}, data=0x{}", response.fuel_used, hex::encode(&response.inner.data));
            }
            SerializableTraceEvent::CreateAlkane(id) => {
                println!("✨ Create Alkane: {:?}", id);
            }
        }
    }
}

pub fn print_tx_info(tx_info: &TxInfo) {
    let mut table = Table::new(vec![tx_info]);
    table.with(Style::modern());
    println!("{}", table);
}
