//! Runestone decoder for DIESEL token minting
//!
//! This module provides functionality for decoding Runestone transactions
//! based on the ordinals crate from alkanes-rs.

use anyhow::{anyhow, Result};
use ordinals::runestone::{Runestone, Artifact};
use metashrew_support::utils::{consensus_decode};
use std::io::Cursor;
use protorune_support::protostone::{Protostone};
use bdk::bitcoin::Transaction;
use bdk::bitcoin::blockdata::script::Instruction;
use bdk::bitcoin::blockdata::opcodes;
use bdk::bitcoin::Script;
use log::debug;
use serde_json::{json, Value};
use hex;

/// Decode a Runestone from a transaction
pub fn decode_runestone(tx: &Transaction) -> Result<Runestone> {
    match ordinals::runestone::Runestone::decipher(tx).unwrap())).unwrap()).unwrap() { println!("{:?}", protorune_support::protostone::Protostone::from_runestone(runestone).unwrap()) } else { println!("nothing") }
    // Search transaction outputs for Runestone
    for (vout, output) in tx.output.iter().enumerate() {
        let mut instructions = output.script_pubkey.instructions();
        
        // Check for OP_RETURN
        if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
            continue;
        }
        
        // Check for magic number (OP_PUSHNUM_13)
        if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_PUSHNUM_13))) {
            continue;
        }
        
        // Found a Runestone
        debug!("Found Runestone in output {}", vout);
        
        // Construct the payload by concatenating remaining data pushes
        let mut payload = Vec::new();
        
        for result in instructions {
            match result {
                Ok(Instruction::PushBytes(push)) => {
                    payload.extend_from_slice(push);
                }
                Ok(Instruction::Op(_)) => {
                    return Err(anyhow!("Invalid opcode in Runestone payload"));
                }
                Err(_) => {
                    return Err(anyhow!("Invalid script in Runestone payload"));
                }
            }
        }
        
        // Decode the integers from the payload
        let integers = decode_integers(&payload)?;
        
        // Parse the Runestone data
        let runestone_data = parse_runestone_data(&integers, vout)?;
        
        return Ok(runestone_data);
    }
    
    Err(anyhow!("No Runestone found in transaction"))
}

/// Decode integers from a payload
fn decode_integers(payload: &[u8]) -> Result<Vec<u128>> {
    let mut integers = Vec::new();
    let mut i = 0;
    
    while i < payload.len() {
        let (integer, length) = decode_varint(&payload[i..])?;
        integers.push(integer);
        i += length;
    }
    
    Ok(integers)
}

/// Decode a variable-length integer
fn decode_varint(bytes: &[u8]) -> Result<(u128, usize)> {
    let mut result: u128 = 0;
    let mut shift = 0;
    let mut i = 0;
    
    loop {
        if i >= bytes.len() {
            return Err(anyhow!("Truncated varint"));
        }
        
        let byte = bytes[i];
        i += 1;
        
        result |= u128::from(byte & 0x7f) << shift;
        
        if byte & 0x80 == 0 {
            break;
        }
        
        shift += 7;
        
        if shift > 127 {
            return Err(anyhow!("Varint too large"));
        }
    }
    
    Ok((result, i))
}

/// Parse Runestone data from integers
fn parse_runestone_data(integers: &[u128], vout: usize) -> Result<Value> {
    let mut result = json!({
        "output": vout,
        "raw_integers": integers,
    });
    
    // Check if we have protocol data
    if !integers.is_empty() {
        let mut protocol_data = Vec::new();
        let mut i = 0;
        
        while i < integers.len() {
            let tag = integers[i];
            i += 1;
            
            // Tag 13 is the protocol tag
            if tag == 13 {
                if i < integers.len() {
                    protocol_data.push(integers[i]);
                    i += 1;
                }
            } else {
                // Skip other tags and their values
                if i < integers.len() {
                    i += 1;
                }
            }
        }
        
        if !protocol_data.is_empty() {
            result["protocol"] = json!(protocol_data);
            
            // If the first protocol value is 1, it's likely a DIESEL token
            if protocol_data[0] == 1 && protocol_data.len() > 1 {
                result["diesel"] = json!({
                    "protocol_tag": protocol_data[0],
                    "message": protocol_data[1..].iter().map(|&n| n as u8).collect::<Vec<u8>>(),
                });
            }
        }
    }
    
    Ok(result)
}

/// Create a Runestone script for DIESEL token minting
pub fn create_runestone_script() -> bdk::bitcoin::Script {
    let mut builder = bdk::bitcoin::blockdata::script::Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_opcode(opcodes::all::OP_PUSHNUM_13);
    
    // Protocol tag (13) and value (1)
    let mut payload = Vec::new();
    encode_varint(13, &mut payload);
    encode_varint(1, &mut payload);
    
    // Message cellpack [2, 0, 77]
    encode_varint(13, &mut payload);
    encode_varint(2, &mut payload);
    encode_varint(13, &mut payload);
    encode_varint(0, &mut payload);
    encode_varint(13, &mut payload);
    encode_varint(77, &mut payload);
    
    // Add payload in chunks to avoid exceeding max script element size
    for chunk in payload.chunks(520) {
        builder = builder.push_slice(chunk);
    }
    
    builder.into_script()
}

/// Encode a u128 as a variable-length integer
fn encode_varint(mut value: u128, vec: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        
        if value != 0 {
            byte |= 0x80;
        }
        
        vec.push(byte);
        
        if value == 0 {
            break;
        }
    }
}
