//! # Runestone Analysis and Decoding
//!
//! This module provides functionality for analyzing and decoding Runestones
//! from Bitcoin transactions, with a special focus on decoding the `protocol`
//! field which contains cellpack data for Alkanes.

use anyhow::Result;
use bitcoin::Transaction;
use ordinals::{Artifact, Runestone};
use serde_json::{json, Value};
use alkanes_support::cellpack::Cellpack;
use ordinals::varint;
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Instruction;
use std::io::Cursor;


/// Analyzes a transaction to find and decode a Runestone.
///
/// This function will:
/// 1. Decipher the Runestone from the transaction using the `ord` crate.
/// 2. If a Runestone is found, it will decode the `protocol` field into a Cellpack.
/// 3. It returns a `serde_json::Value` containing the decoded information.
pub fn analyze_runestone(tx: &Transaction) -> Result<Value> {
    let artifact = Runestone::decipher(tx);

    let runestone = match artifact {
        Some(Artifact::Runestone(runestone)) => runestone,
        Some(Artifact::Cenotaph(cenotaph)) => {
            return Ok(json!({
                "type": "cenotaph",
                "cenotaph": cenotaph,
            }));
        }
        None => {
            return Ok(json!({
                "type": "none",
                "message": "No runestone found in transaction.",
            }));
        }
    };

    let mut decoded_runestone = json!({
        "type": "runestone",
        "edicts": runestone.edicts,
        "etching": runestone.etching,
        "mint": runestone.mint,
        "pointer": runestone.pointer,
    });

    // Manually extract and decode the protocol tag
    if let Some(payload) = get_runestone_payload(tx) {
        if let Ok(integers) = decode_integers(&payload) {
            if let Some(protocol_tag) = extract_protocol_tag(&integers) {
                let bytes = protocol_tag.to_le_bytes().to_vec();
                let mut cursor = Cursor::new(bytes);
                let cellpack_result = Cellpack::parse(&mut cursor);
                decoded_runestone["decoded_protocol"] = match cellpack_result {
                    Ok(cellpack) => json!({
                        "raw_protocol_tag": protocol_tag,
                        "cellpack": cellpack,
                    }),
                    Err(e) => json!({
                        "raw_protocol_tag": protocol_tag,
                        "error": format!("Failed to parse cellpack: {}", e),
                    })
                };
            }
        }
    }

    Ok(decoded_runestone)
}

fn get_runestone_payload(transaction: &Transaction) -> Option<Vec<u8>> {
    for output in &transaction.output {
        let mut instructions = output.script_pubkey.instructions();

        if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
            continue;
        }

        if instructions.next() != Some(Ok(Instruction::Op(Runestone::MAGIC_NUMBER))) {
            continue;
        }

        let mut payload = Vec::new();
        for result in instructions {
            if let Ok(Instruction::PushBytes(push)) = result {
                payload.extend_from_slice(push.as_bytes());
            } else {
                return None; // Invalid instruction in payload
            }
        }
        return Some(payload);
    }
    None
}

fn decode_integers(payload: &[u8]) -> Result<Vec<u128>> {
    let mut integers = Vec::new();
    let mut i = 0;
    while i < payload.len() {
        let (integer, length) = varint::decode(&payload[i..])?;
        integers.push(integer);
        i += length;
    }
    Ok(integers)
}

fn extract_protocol_tag(integers: &[u128]) -> Option<u128> {
    let mut i = 0;
    while i < integers.len() {
        let tag = integers[i];
        i += 1;
        if tag == 13 { // Protocol tag
            if i < integers.len() {
                return Some(integers[i]);
            }
        }
        // Skip value for other tags
        if i < integers.len() {
            i += 1;
        }
    }
    None
}