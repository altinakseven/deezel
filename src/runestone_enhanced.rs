//! Enhanced Runestone decoder
//!
//! This module provides functionality for decoding Runestone transactions
//! and extracting protostone data from them.

use anyhow::{anyhow, Result};
use bdk::bitcoin::Transaction;
use bdk::bitcoin::blockdata::script::{Instruction, Script};
use bdk::bitcoin::blockdata::opcodes;
use log::debug;
use serde_json::{json, Value};

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

/// Format a Runestone for display
pub fn format_runestone(tx: &Transaction) -> String {
    match decode_runestone(tx) {
        Ok(data) => {
            let mut output = String::new();
            
            output.push_str(&format!("Transaction ID: {}\n", tx.txid()));
            output.push_str(&format!("Version: {}\n", tx.version));
            output.push_str(&format!("Inputs: {}\n", tx.input.len()));
            output.push_str(&format!("Outputs: {}\n", tx.output.len()));
            
            output.push_str("\nRunestone found!\n");
            output.push_str(&format!("Output Index: {}\n", data["output_index"]));
            
            // Protocol tag
            if let Some(protocol_tag) = data.get("protocol_tag") {
                output.push_str(&format!("\nProtocol Tag: {}\n", protocol_tag));
            }
            
            // Protocol data
            if let Some(protocol_data) = data.get("protocol_data") {
                if let Some(protocol_array) = protocol_data.as_array() {
                    if !protocol_array.is_empty() {
                        output.push_str("\nProtocol data:\n");
                        for (i, value) in protocol_array.iter().enumerate() {
                            if let Some(num) = value.as_u64() {
                                output.push_str(&format!("  Value {}: {} (0x{:x})\n", i, num, num));
                            }
                        }
                    }
                }
            }
            
            // Message bytes
            if let Some(message_bytes) = data.get("message_bytes") {
                if let Some(message_array) = message_bytes.as_array() {
                    if !message_array.is_empty() {
                        output.push_str("\nMessage bytes:\n");
                        for (i, byte) in message_array.iter().enumerate() {
                            if let Some(b) = byte.as_u64() {
                                output.push_str(&format!("  Byte {}: {} (0x{:02x})\n", i, b, b));
                            }
                        }
                    }
                }
            }
            
            // Protostone data
            if let Some(protostone) = data.get("protostone") {
                output.push_str("\nProtostone data:\n");
                
                if let Some(protostone_type) = protostone.get("type") {
                    output.push_str(&format!("  Type: {}\n", protostone_type));
                }
                
                if let Some(operation) = protostone.get("operation") {
                    output.push_str(&format!("  Operation: {}\n", operation));
                }
                
                if let Some(cellpack) = protostone.get("cellpack") {
                    output.push_str("  Cellpack structure:\n");
                    
                    // Handle different cellpack structures based on the protostone type
                    if let Some(protostone_type) = protostone.get("type") {
                        match protostone_type.as_str() {
                            Some("DIESEL") => {
                                if let Some(message_type) = cellpack.get("message_type") {
                                    output.push_str(&format!("    Message type: {}\n", message_type));
                                }
                                
                                if let Some(reserved) = cellpack.get("reserved") {
                                    output.push_str(&format!("    Reserved: {}\n", reserved));
                                }
                                
                                if let Some(action) = cellpack.get("action") {
                                    output.push_str(&format!("    Action: {}\n", action));
                                }
                            },
                            Some("Alkane") => {
                                if let Some(call_type) = cellpack.get("call_type") {
                                    output.push_str(&format!("    Call type: {}\n", call_type));
                                }
                                
                                if let Some(data) = cellpack.get("data") {
                                    if let Some(data_array) = data.as_array() {
                                        output.push_str("    Data bytes:\n");
                                        for (i, byte) in data_array.iter().enumerate() {
                                            if let Some(b) = byte.as_u64() {
                                                output.push_str(&format!("      Byte {}: {} (0x{:02x})\n", i, b, b));
                                            }
                                        }
                                    }
                                }
                            },
                            Some("Protorune") => {
                                if let Some(operation_type) = cellpack.get("operation_type") {
                                    output.push_str(&format!("    Operation type: {}\n", operation_type));
                                }
                                
                                if let Some(operation_name) = cellpack.get("operation_name") {
                                    output.push_str(&format!("    Operation name: {}\n", operation_name));
                                }
                                
                                if let Some(data) = cellpack.get("data") {
                                    if let Some(data_array) = data.as_array() {
                                        output.push_str("    Data bytes:\n");
                                        for (i, byte) in data_array.iter().enumerate() {
                                            if let Some(b) = byte.as_u64() {
                                                output.push_str(&format!("      Byte {}: {} (0x{:02x})\n", i, b, b));
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {
                                // Generic cellpack display for unknown types
                                if let Some(cellpack_array) = cellpack.as_array() {
                                    output.push_str("    Raw bytes:\n");
                                    for (i, byte) in cellpack_array.iter().enumerate() {
                                        if let Some(b) = byte.as_u64() {
                                            output.push_str(&format!("      Byte {}: {} (0x{:02x})\n", i, b, b));
                                        }
                                    }
                                } else {
                                    output.push_str(&format!("    {}\n", cellpack));
                                }
                            }
                        }
                    }
                }
            }
            
            // All tags
            if let Some(all_tags) = data.get("all_tags") {
                if let Some(tags_obj) = all_tags.as_object() {
                    if !tags_obj.is_empty() {
                        output.push_str("\nAll tags:\n");
                        for (tag, values) in tags_obj {
                            output.push_str(&format!("  Tag {}: ", tag));
                            if let Some(values_array) = values.as_array() {
                                let values_str: Vec<String> = values_array.iter()
                                    .map(|v| v.to_string())
                                    .collect();
                                output.push_str(&format!("[{}]\n", values_str.join(", ")));
                            } else {
                                output.push_str(&format!("{}\n", values));
                            }
                        }
                    }
                }
            }
            
            // Output details
            output.push_str("\nOutputs:\n");
            for (i, output_tx) in tx.output.iter().enumerate() {
                output.push_str(&format!("  Output {}: {} sats\n", i, output_tx.value));
                output.push_str(&format!("    Script: {}\n", output_tx.script_pubkey));
            }
            
            output
        },
        Err(e) => {
            format!("Transaction ID: {}\nVersion: {}\nInputs: {}\nOutputs: {}\n\nNo Runestone found: {}\n\nOutputs:\n{}",
                tx.txid(),
                tx.version,
                tx.input.len(),
                tx.output.len(),
                e,
                tx.output.iter().enumerate().map(|(i, o)| {
                    format!("  Output {}: {} sats\n    Script: {}", i, o.value, o.script_pubkey)
                }).collect::<Vec<_>>().join("\n")
            )
        }
    }
}