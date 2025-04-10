//! Enhanced Runestone decoder
//!
//! This module provides functionality for decoding Runestone transactions
//! and extracting protostone data from them.

use anyhow::{anyhow, Result};
use bdk::bitcoin::Transaction;
use bitcoin;
use bdk::bitcoin::blockdata::script::{Instruction, Script};
use bdk::bitcoin::blockdata::opcodes;
use log::debug;
use serde_json::{json, Value};
use ordinals::{Artifact, runestone::{Runestone}};
use protorune_support::protostone::Protostone;


fn from_packed(v: bdk::bitcoin::absolute::PackedLockTime) -> bitcoin::absolute::LockTime {
  bitcoin::absolute::LockTime::from_consensus(v.to_consensus_u32())
}

fn from_bdk(v: bdk::bitcoin::Transaction) -> bitcoin::Transaction {
    bitcoin::Transaction {
      version: bitcoin::transaction::Version(v.version),
      lock_time: v.lock_time,
      input: v.input.into(),
      output: v.output.into()
    }
}


/// Decode a Runestone from a transaction
pub fn decode_runestone(tx: &Transaction) -> Result<Value> {
    debug!("Decoding Runestone from transaction {}", tx.txid());
    
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
        let mut protocol_data = Vec::new();
        let mut i = 0;
        
        // First pass: collect all protocol data (tag 13)
        while i < integers.len() {
            let tag = integers[i];
            i += 1;
            
            // Tag 13 is the protocol tag
            if tag == 13 && i < integers.len() {
                protocol_data.push(integers[i]);
                i += 1;
            } else {
                // Skip other tags and their values
                if i < integers.len() {
                    i += 1;
                }
            }
        }
        
        // Create the base result
        let mut result = json!({
            "transaction_id": tx.txid().to_string(),
            "output_index": vout,
            "protocol_data": protocol_data,
        });
        
        // Second pass: extract all tags and their values
        let mut all_tags = json!({});
        i = 0;
        while i < integers.len() {
            if i + 1 < integers.len() {
                let tag = integers[i];
                let value = integers[i + 1];
                
                // Add to the all_tags object
                if all_tags[tag.to_string()].is_null() {
                    all_tags[tag.to_string()] = json!([value]);
                } else {
                    all_tags[tag.to_string()].as_array_mut().unwrap().push(json!(value));
                }
                
                i += 2;
            } else {
                // Odd number of integers, skip the last one
                i += 1;
            }
        }
        
        result["all_tags"] = all_tags;
        
        // Process protocol data if available
        if !protocol_data.is_empty() {
            // Extract protocol tag (first element)
            let protocol_tag = protocol_data[0];
            result["protocol_tag"] = json!(protocol_tag);
            
            // Extract message bytes (remaining elements)
            let message_bytes: Vec<u8> = protocol_data.iter().skip(1).map(|&n| n as u8).collect();
            result["message_bytes"] = json!(message_bytes);
            
            // Identify known protocol tags
            match protocol_tag {
                1 => {
                    // DIESEL token minting
                    if message_bytes == [2, 0, 77] {
                        result["protostone"] = json!({
                            "type": "DIESEL",
                            "operation": "mint",
                            "cellpack": {
                                "message_type": 2,
                                "reserved": 0,
                                "action": "M" // ASCII 77 = 'M' for 'Mint'
                            }
                        });
                    } else {
                        result["protostone"] = json!({
                            "type": "DIESEL",
                            "operation": "unknown",
                            "cellpack": message_bytes
                        });
                    }
                },
                2 => {
                    // Alkane contract call
                    result["protostone"] = json!({
                        "type": "Alkane",
                        "operation": "contract_call",
                        "cellpack": message_bytes
                    });
                    
                    // Try to decode the cellpack structure
                    if message_bytes.len() >= 2 {
                        let call_type = message_bytes[0];
                        let data = &message_bytes[1..];
                        
                        result["protostone"]["cellpack"] = json!({
                            "call_type": call_type,
                            "data": data
                        });
                    }
                },
                3 => {
                    // Protorune
                    result["protostone"] = json!({
                        "type": "Protorune",
                        "operation": "token_operation",
                        "cellpack": message_bytes
                    });
                    
                    // Try to decode the cellpack structure
                    if message_bytes.len() >= 2 {
                        let operation_type = message_bytes[0];
                        let data = &message_bytes[1..];
                        
                        let operation_name = match operation_type {
                            1 => "mint",
                            2 => "transfer",
                            3 => "burn",
                            _ => "unknown"
                        };
                        
                        result["protostone"]["cellpack"] = json!({
                            "operation_type": operation_type,
                            "operation_name": operation_name,
                            "data": data
                        });
                    }
                },
                // Add more protocol tags as needed
                _ => {
                    // Unknown protocol tag
                    result["protostone"] = json!({
                        "type": "Unknown",
                        "protocol_tag": protocol_tag,
                        "cellpack": message_bytes
                    });
                }
            }
        }
        
        // Add raw integers for debugging
        result["raw_integers"] = json!(integers);
        
        return Ok(result);
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

pub fn format_runestone(tx: &Transaction) -> Result<Vec<Protostone>> {
  match Runestone::decipher(&from_bdk(tx.clone())).ok_or("").map_err(|_| anyhow!("no runestone"))? {
    Artifact::Runestone(ref runestone) => { Ok(Protostone::from_runestone(runestone)?)  },
    _ => { Err(anyhow!("no runestone")) }
  }
}

