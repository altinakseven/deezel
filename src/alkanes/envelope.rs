// Alkanes envelope implementation based on ord protocol
// Core functionality for creating and managing alkanes envelope transactions
// Uses ord-style envelope pattern with BIN protocol tag instead of ord tag

use anyhow::{Context, Result};
use bitcoin::{
    blockdata::opcodes,
    script::{self, Builder as ScriptBuilder},
    taproot::{ControlBlock, LeafVersion, TapLeafHash},
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

// Alkanes protocol constants - based on ord but with BIN tag
pub const ALKANES_PROTOCOL_ID: [u8; 3] = *b"BIN";
pub const BODY_TAG: [u8; 0] = [];
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Alkanes envelope structure for contract deployment
#[derive(Debug, Clone)]
pub struct AlkanesEnvelope {
    pub content_type: Option<Vec<u8>>,
    pub body: Option<Vec<u8>>,
}

impl AlkanesEnvelope {
    /// Create new alkanes envelope with contract data
    pub fn new(content_type: Option<String>, body: Option<Vec<u8>>) -> Self {
        Self {
            content_type: content_type.map(|ct| ct.into_bytes()),
            body,
        }
    }

    /// Create envelope for alkanes contract deployment
    pub fn for_contract(contract_data: Vec<u8>) -> Self {
        Self::new(Some("application/wasm".to_string()), Some(contract_data))
    }

    /// Build the reveal script following ord pattern with BIN protocol tag
    pub fn build_reveal_script(&self) -> ScriptBuf {
        let mut builder = ScriptBuilder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(&ALKANES_PROTOCOL_ID);

        // Add content type if present
        if let Some(content_type) = &self.content_type {
            builder = builder
                .push_slice(&[1u8]) // Content-Type tag
                .push_slice::<&bitcoin::script::PushBytes>(content_type.as_slice().try_into().unwrap());
        }

        // Add body if present
        if let Some(body) = &self.body {
            builder = builder.push_slice(&BODY_TAG);
            
            // Chunk body data into script-safe pieces
            for chunk in body.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
                builder = builder.push_slice::<&bitcoin::script::PushBytes>(chunk.try_into().unwrap());
            }
        }

        builder
            .push_opcode(opcodes::all::OP_ENDIF)
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .into_script()
    }

    /// Create witness for taproot script-path spending
    pub fn create_witness(&self, control_block: ControlBlock) -> Result<Witness> {
        let reveal_script = self.build_reveal_script();
        
        let mut witness = Witness::new();
        
        // Push the script bytes directly - ensure we're getting the full script
        let script_bytes = reveal_script.as_bytes();
        log::info!("Creating witness with script: {} bytes", script_bytes.len());
        witness.push(script_bytes);
        
        // Push the control block bytes
        let control_block_bytes = control_block.serialize();
        log::info!("Creating witness with control block: {} bytes", control_block_bytes.len());
        witness.push(&control_block_bytes);
        
        // Verify the witness was created correctly
        if witness.len() != 2 {
            return Err(anyhow::anyhow!("Invalid witness length: expected 2 items, got {}", witness.len()));
        }
        
        // Verify the script bytes are not empty
        if witness.nth(0).map_or(true, |item| item.is_empty()) {
            return Err(anyhow::anyhow!("Script witness item is empty"));
        }
        
        // Verify the control block bytes are not empty
        if witness.nth(1).map_or(true, |item| item.is_empty()) {
            return Err(anyhow::anyhow!("Control block witness item is empty"));
        }
        
        // Log final witness details for debugging
        log::info!("Created witness with {} items:", witness.len());
        for (i, item) in witness.iter().enumerate() {
            log::info!("  Witness item {}: {} bytes", i, item.len());
        }
        
        Ok(witness)
    }
}


/// Extract envelope data from transaction witness (for parsing)
pub fn extract_envelope_from_witness(witness: &Witness) -> Option<AlkanesEnvelope> {
    // Extract script from witness using ord pattern
    let script = unversioned_leaf_script_from_witness(witness)?;
    
    // Parse script for alkanes envelope
    parse_alkanes_script(script)
}

/// Extract script from taproot witness (based on ord implementation)
fn unversioned_leaf_script_from_witness(witness: &Witness) -> Option<&bitcoin::Script> {
    #[allow(deprecated)]
    witness.tapscript()
}

/// Parse alkanes envelope from script
fn parse_alkanes_script(script: &bitcoin::Script) -> Option<AlkanesEnvelope> {
    let mut instructions = script.instructions().peekable();
    
    // Expect OP_FALSE OP_IF pattern
    if !matches!(instructions.next()?, Ok(bitcoin::script::Instruction::Op(opcodes::all::OP_PUSHBYTES_0))) {
        return None;
    }
    
    if !matches!(instructions.next()?, Ok(bitcoin::script::Instruction::Op(opcodes::all::OP_IF))) {
        return None;
    }
    
    // Check for BIN protocol tag
    match instructions.next()? {
        Ok(bitcoin::script::Instruction::PushBytes(bytes)) => {
            if bytes.as_bytes() != &ALKANES_PROTOCOL_ID {
                return None;
            }
        }
        _ => return None,
    }
    
    let mut content_type = None;
    let mut body_parts = Vec::new();
    let mut in_body = false;
    
    // Parse fields and body
    while let Some(instruction) = instructions.next() {
        match instruction {
            Ok(bitcoin::script::Instruction::Op(opcodes::all::OP_ENDIF)) => break,
            Ok(bitcoin::script::Instruction::PushBytes(bytes)) => {
                let bytes = bytes.as_bytes();
                
                if !in_body && bytes == &[1u8] {
                    // Content-Type tag
                    if let Some(Ok(bitcoin::script::Instruction::PushBytes(ct_bytes))) = instructions.next() {
                        content_type = Some(ct_bytes.as_bytes().to_vec());
                    }
                } else if bytes == &BODY_TAG {
                    // Body separator
                    in_body = true;
                } else if in_body {
                    // Body data
                    body_parts.push(bytes.to_vec());
                }
            }
            _ => {}
        }
    }
    
    let body = if body_parts.is_empty() {
        None
    } else {
        Some(body_parts.into_iter().flatten().collect())
    };
    
    Some(AlkanesEnvelope { content_type, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{rand, Secp256k1};

    #[test]
    fn test_envelope_script_creation() {
        let envelope = AlkanesEnvelope::new(
            Some("application/wasm".to_string()),
            Some(b"test contract data".to_vec()),
        );
        
        let script = envelope.build_reveal_script();
        
        // Verify script structure
        let instructions: Vec<_> = script.instructions().collect();
        assert!(instructions.len() >= 6); // OP_FALSE, OP_IF, protocol, content-type tag, content-type, body tag, body, OP_ENDIF
        
        // Parse back the envelope
        let parsed = parse_alkanes_script(&script).unwrap();
        assert_eq!(parsed.content_type, Some(b"application/wasm".to_vec()));
        assert_eq!(parsed.body, Some(b"test contract data".to_vec()));
    }

    #[test]
    fn test_envelope_without_content_type() {
        let envelope = AlkanesEnvelope::new(None, Some(b"raw data".to_vec()));
        let script = envelope.build_reveal_script();
        
        let parsed = parse_alkanes_script(&script).unwrap();
        assert_eq!(parsed.content_type, None);
        assert_eq!(parsed.body, Some(b"raw data".to_vec()));
    }

    #[test]
    fn test_empty_envelope() {
        let envelope = AlkanesEnvelope::new(None, None);
        let script = envelope.build_reveal_script();
        
        let parsed = parse_alkanes_script(&script).unwrap();
        assert_eq!(parsed.content_type, None);
        assert_eq!(parsed.body, None);
    }

    #[test]
    fn test_large_body_chunking() {
        let large_data = vec![0u8; 1500]; // Larger than MAX_SCRIPT_ELEMENT_SIZE
        let envelope = AlkanesEnvelope::new(None, Some(large_data.clone()));
        let script = envelope.build_reveal_script();
        
        let parsed = parse_alkanes_script(&script).unwrap();
        assert_eq!(parsed.body, Some(large_data));
    }
}
