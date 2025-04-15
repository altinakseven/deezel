//! Enhanced Runestone decoder
//!
//! This module provides functionality for decoding Runestone transactions
//! and extracting protostone data from them. It supports all types of protostones
//! including DIESEL, Alkane contract calls, and Protorune token operations.
//!
//! The module provides two main functions:
//! - `decode_runestone`: Manually extracts and decodes Runestone data from a transaction
//! - `format_runestone`: Uses the ordinals crate to extract Runestones and convert them to Protostones

use anyhow::{anyhow, Context, Result};
use bdk::bitcoin::Transaction;
use bitcoin;
use bdk::bitcoin::blockdata::script::Instruction;
use bdk::bitcoin::blockdata::opcodes;
use log::{debug, trace};
use serde_json::{json, Value};
use ordinals::{Artifact, runestone::{Runestone}};
use protorune_support::protostone::Protostone;
use hex;
use std::str::FromStr;

/// Convert a BDK Transaction to a Bitcoin Transaction
///
/// This function converts a Transaction from the BDK library format to the
/// Bitcoin library format. This is necessary when using functions from the
/// ordinals crate, which expects Bitcoin library types.
///
/// # Arguments
///
/// * `v` - The BDK Transaction to convert
///
/// # Returns
///
/// The equivalent Bitcoin Transaction
fn from_bdk(v: bdk::bitcoin::Transaction) -> bitcoin::Transaction {
    // Create a new Bitcoin transaction with the same properties
    // We need to manually convert each field since they're from different crates
    let mut inputs = Vec::new();
    for input in &v.input {
        // Convert txid to bytes and then to the other Bitcoin library's Txid
        let txid_bytes = input.previous_output.txid.to_string();
        let txid = bitcoin::Txid::from_str(&txid_bytes).unwrap();
        
        // Create the input with converted fields
        inputs.push(bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid,
                vout: input.previous_output.vout,
            },
            script_sig: bitcoin::ScriptBuf::from_bytes(input.script_sig.as_bytes().to_vec()),
            sequence: bitcoin::Sequence(input.sequence.0),
            witness: {
                let mut witness = bitcoin::Witness::new();
                for item in &input.witness {
                    witness.push(item.clone());
                }
                witness
            },
        });
    }
    
    let mut outputs = Vec::new();
    for output in &v.output {
        outputs.push(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(output.value),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(output.script_pubkey.as_bytes().to_vec()),
        });
    }
    
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(v.version),
        lock_time: bitcoin::absolute::LockTime::from_consensus(v.lock_time.to_consensus_u32()),
        input: inputs,
        output: outputs,
    }
}


/// Magic number for Runestone protocol
pub const RUNESTONE_MAGIC_NUMBER: u8 = 13; // OP_PUSHNUM_13

/// Protocol tags for different protostone types
pub mod protocol_tags {
    /// DIESEL token operations
    pub const DIESEL: u128 = 1;
    
    /// Alkane contract calls
    pub const ALKANE: u128 = 2;
    
    /// Protorune token operations
    pub const PROTORUNE: u128 = 3;
    
    /// Alkane state operations
    pub const ALKANE_STATE: u128 = 4;
    
    /// Alkane event operations
    pub const ALKANE_EVENT: u128 = 5;
}

/// Operation types for Protorune token operations
pub mod protorune_operations {
    /// Mint operation
    pub const MINT: u8 = 1;
    
    /// Transfer operation
    pub const TRANSFER: u8 = 2;
    
    /// Burn operation
    pub const BURN: u8 = 3;
    
    /// Split operation
    pub const SPLIT: u8 = 4;
    
    /// Join operation
    pub const JOIN: u8 = 5;
}

/// Operation types for DIESEL token operations
pub mod diesel_operations {
    /// Mint operation (message [2, 0, 77])
    pub const MINT: [u8; 3] = [2, 0, 77];
}

/// Decode a Runestone from a transaction
///
/// This function manually extracts and decodes Runestone data from a transaction.
/// It searches for outputs with OP_RETURN followed by OP_PUSHNUM_13, then decodes
/// the payload to extract protocol data and protostone information.
///
/// # Arguments
///
/// * `tx` - The transaction to decode
///
/// # Returns
///
/// A JSON object containing the decoded Runestone data, or an error if no valid
/// Runestone was found in the transaction.
///
/// # Example
///
/// ```
/// use bdk::bitcoin::Transaction;
/// use deezel::runestone_enhanced::decode_runestone;
///
/// let tx = // get transaction from somewhere
/// let runestone_data = decode_runestone(&tx)?;
/// println!("{}", serde_json::to_string_pretty(&runestone_data)?);
/// ```
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
        
        // Extract payload from script
        let payload = extract_payload_from_instructions(instructions)?;
        
        // Decode the integers from the payload
        let integers = decode_integers(&payload)
            .context("Failed to decode integers from Runestone payload")?;
        
        // Extract protocol data (tag 13)
        let protocol_data = extract_protocol_data(&integers);
        
        // Create the base result
        let mut result = json!({
            "transaction_id": tx.txid().to_string(),
            "output_index": vout,
            "protocol_data": protocol_data,
        });
        
        // Extract all tags and their values
        let all_tags = extract_all_tags(&integers);
        result["all_tags"] = all_tags;
        
        // Process protocol data if available
        if !protocol_data.is_empty() {
            // Extract protocol tag and message bytes
            let protocol_tag = protocol_data[0];
            let message_bytes: Vec<u8> = protocol_data.iter().skip(1).map(|&n| n as u8).collect();
            
            result["protocol_tag"] = json!(protocol_tag);
            result["message_bytes"] = json!(message_bytes);
            
            // Decode protostone based on protocol tag
            result["protostone"] = decode_protostone(protocol_tag, &message_bytes);
        }
        
        // Add raw integers for debugging
        result["raw_integers"] = json!(integers);
        
        return Ok(result);
    }
    
    Err(anyhow!("No Runestone found in transaction"))
}

/// Extract payload from script instructions
fn extract_payload_from_instructions<'a, I>(instructions: I) -> Result<Vec<u8>>
where
    I: Iterator<Item = std::result::Result<Instruction<'a>, bdk::bitcoin::blockdata::script::Error>>
{
    let mut payload = Vec::new();
    
    for result in instructions {
        match result {
            Ok(Instruction::PushBytes(push)) => {
                // Convert PushBytes to a slice before extending
                payload.extend_from_slice(push.as_bytes());
            }
            Ok(Instruction::Op(_)) => {
                return Err(anyhow!("Invalid opcode in Runestone payload"));
            }
            Err(_) => {
                return Err(anyhow!("Invalid script in Runestone payload"));
            }
        }
    }
    
    Ok(payload)
}

/// Extract protocol data (tag 13) from integers
fn extract_protocol_data(integers: &[u128]) -> Vec<u128> {
    let mut protocol_data = Vec::new();
    let mut i = 0;
    
    while i < integers.len() {
        let tag = integers[i];
        i += 1;
        
        // Tag 13 is the protocol tag
        if tag == RUNESTONE_MAGIC_NUMBER as u128 && i < integers.len() {
            protocol_data.push(integers[i]);
            i += 1;
        } else {
            // Skip other tags and their values
            if i < integers.len() {
                i += 1;
            }
        }
    }
    
    protocol_data
}

/// Extract all tags and their values from integers
fn extract_all_tags(integers: &[u128]) -> Value {
    let mut all_tags = json!({});
    let mut i = 0;
    
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
    
    all_tags
}

/// Decode protostone based on protocol tag
fn decode_protostone(protocol_tag: u128, message_bytes: &[u8]) -> Value {
    match protocol_tag {
        protocol_tags::DIESEL => decode_diesel_protostone(message_bytes),
        protocol_tags::ALKANE => decode_alkane_protostone(message_bytes),
        protocol_tags::PROTORUNE => decode_protorune_protostone(message_bytes),
        protocol_tags::ALKANE_STATE => decode_alkane_state_protostone(message_bytes),
        protocol_tags::ALKANE_EVENT => decode_alkane_event_protostone(message_bytes),
        _ => json!({
            "type": "Unknown",
            "protocol_tag": protocol_tag,
            "cellpack": message_bytes
        })
    }
}

/// Decode DIESEL protostone
fn decode_diesel_protostone(message_bytes: &[u8]) -> Value {
    // DIESEL token minting
    if message_bytes == diesel_operations::MINT {
        json!({
            "type": "DIESEL",
            "operation": "mint",
            "cellpack": {
                "message_type": message_bytes[0],
                "reserved": message_bytes[1],
                "action": "M" // ASCII 77 = 'M' for 'Mint'
            }
        })
    } else {
        json!({
            "type": "DIESEL",
            "operation": "unknown",
            "cellpack": message_bytes
        })
    }
}

/// Decode Alkane contract call protostone
fn decode_alkane_protostone(message_bytes: &[u8]) -> Value {
    let mut result = json!({
        "type": "Alkane",
        "operation": "contract_call",
        "cellpack": message_bytes
    });
    
    // Try to decode the cellpack structure
    if message_bytes.len() >= 2 {
        let call_type = message_bytes[0];
        let data = &message_bytes[1..];
        
        let call_type_name = match call_type {
            1 => "deploy",
            2 => "call",
            3 => "upgrade",
            _ => "unknown"
        };
        
        result["cellpack"] = json!({
            "call_type": call_type,
            "call_type_name": call_type_name,
            "data": data
        });
        
        // For contract calls (type 2), try to decode function selector and arguments
        if call_type == 2 && data.len() >= 4 {
            let function_selector = &data[0..4];
            let arguments = &data[4..];
            
            result["cellpack"]["function_selector"] = json!(hex::encode(function_selector));
            result["cellpack"]["arguments"] = json!(hex::encode(arguments));
        }
    }
    
    result
}

/// Decode Protorune token operation protostone
fn decode_protorune_protostone(message_bytes: &[u8]) -> Value {
    let mut result = json!({
        "type": "Protorune",
        "operation": "token_operation",
        "cellpack": message_bytes
    });
    
    // Try to decode the cellpack structure
    if message_bytes.len() >= 2 {
        let operation_type = message_bytes[0];
        let data = &message_bytes[1..];
        
        let operation_name = match operation_type {
            protorune_operations::MINT => "mint",
            protorune_operations::TRANSFER => "transfer",
            protorune_operations::BURN => "burn",
            protorune_operations::SPLIT => "split",
            protorune_operations::JOIN => "join",
            _ => "unknown"
        };
        
        result["cellpack"] = json!({
            "operation_type": operation_type,
            "operation_name": operation_name,
            "data": data
        });
        
        // For mint operations, try to decode token details
        if operation_type == protorune_operations::MINT && data.len() >= 3 {
            let token_id = data[0];
            let amount = data[1];
            let metadata = &data[2..];
            
            result["cellpack"]["token_details"] = json!({
                "token_id": token_id,
                "amount": amount,
                "metadata": metadata
            });
        }
        
        // For transfer operations, try to decode transfer details
        if operation_type == protorune_operations::TRANSFER && data.len() >= 3 {
            let token_id = data[0];
            let amount = data[1];
            let recipient = &data[2..];
            
            result["cellpack"]["transfer_details"] = json!({
                "token_id": token_id,
                "amount": amount,
                "recipient": hex::encode(recipient)
            });
        }
    }
    
    result
}

/// Decode Alkane state operation protostone
fn decode_alkane_state_protostone(message_bytes: &[u8]) -> Value {
    json!({
        "type": "AlkaneState",
        "operation": "state_operation",
        "cellpack": message_bytes
    })
}

/// Decode Alkane event operation protostone
fn decode_alkane_event_protostone(message_bytes: &[u8]) -> Value {
    json!({
        "type": "AlkaneEvent",
        "operation": "event_operation",
        "cellpack": message_bytes
    })
}

/// Decode integers from a payload
///
/// This function decodes a sequence of variable-length integers from a byte payload.
/// It processes the payload sequentially, extracting one integer at a time until
/// the entire payload has been consumed.
///
/// # Arguments
///
/// * `payload` - The byte payload to decode
///
/// # Returns
///
/// A vector of decoded integers, or an error if the payload is invalid.
///
/// # Errors
///
/// Returns an error if:
/// - The payload contains a truncated varint
/// - A varint is too large (exceeds 128 bits)
fn decode_integers(payload: &[u8]) -> Result<Vec<u128>> {
    let mut integers = Vec::new();
    let mut i = 0;
    
    while i < payload.len() {
        let (integer, length) = decode_varint(&payload[i..])
            .context(format!("Failed to decode varint at position {}", i))?;
        integers.push(integer);
        i += length;
    }
    
    Ok(integers)
}

/// Decode a variable-length integer
///
/// This function decodes a single variable-length integer from a byte slice using
/// the LEB128 encoding format. Each byte uses 7 bits for the value and 1 bit to
/// indicate if more bytes follow.
///
/// # Arguments
///
/// * `bytes` - The byte slice to decode from
///
/// # Returns
///
/// A tuple containing the decoded integer and the number of bytes consumed,
/// or an error if the encoding is invalid.
///
/// # Errors
///
/// Returns an error if:
/// - The byte slice is empty or truncated
/// - The varint is too large (exceeds 128 bits)
///
/// # Algorithm
///
/// The LEB128 encoding uses the high bit (0x80) of each byte to indicate if more
/// bytes follow (1) or if this is the last byte (0). The remaining 7 bits contribute
/// to the value, with each successive byte adding 7 more bits of precision.
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

/// Format a Runestone from a transaction using the ordinals crate
///
/// This function uses the ordinals crate to extract a Runestone from a transaction
/// and convert it to a vector of Protostones.
///
/// # Arguments
///
/// * `tx` - The transaction to extract the Runestone from
///
/// # Returns
///
/// A vector of Protostones, or an error if no valid Runestone was found in the transaction.
///
/// # Example
///
/// ```
/// use bdk::bitcoin::Transaction;
/// use deezel::runestone_enhanced::format_runestone;
///
/// let tx = // get transaction from somewhere
/// let protostones = format_runestone(&tx)?;
/// for protostone in protostones {
///     println!("{:?}", protostone);
/// }
/// ```
pub fn format_runestone(tx: &Transaction) -> Result<Vec<Protostone>> {
    trace!("Formatting Runestone from transaction {}", tx.txid());
    
    // Convert BDK transaction to Bitcoin transaction
    let bitcoin_tx = from_bdk(tx.clone());
    
    // Use the ordinals crate to decipher the Runestone
    let artifact = Runestone::decipher(&bitcoin_tx)
        .ok_or_else(|| anyhow!("Failed to decipher Runestone"))
        .context("No Runestone found in transaction")?;
    
    // Extract the Runestone from the artifact
    match artifact {
        Artifact::Runestone(ref runestone) => {
            // Convert the Runestone to Protostones
            Protostone::from_runestone(runestone)
                .context("Failed to convert Runestone to Protostones")
        },
        _ => Err(anyhow!("Artifact is not a Runestone"))
    }
}

