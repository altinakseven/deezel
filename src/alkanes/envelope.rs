// Alkanes envelope implementation based on ord protocol
// Core functionality for creating and managing alkanes envelope transactions
// Uses ord-style envelope pattern with BIN protocol tag instead of ord tag
// CRITICAL FIX: Updated to follow ord witness pattern exactly with proper signature handling

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

    /// Create envelope for alkanes contract deployment with BIN protocol data
    /// This envelope will be used as the first input in the reveal transaction
    pub fn for_contract(contract_data: Vec<u8>) -> Self {
        Self::new(Some("application/wasm".to_string()), Some(contract_data))
    }

    /// Build the reveal script following ord pattern EXACTLY with BIN protocol tag
    /// CRITICAL FIX: Follow ord envelope pattern exactly but use BIN instead of ord
    pub fn build_reveal_script(&self) -> ScriptBuf {
        let mut builder = ScriptBuilder::new()
            .push_opcode(opcodes::OP_FALSE) // OP_FALSE like ord (pushes empty bytes)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(&ALKANES_PROTOCOL_ID); // Use BIN instead of ord

        // Add content type if present (using tag 1 like ord)
        if let Some(content_type) = &self.content_type {
            builder = builder
                .push_slice(&[1u8]) // Content-Type tag (same as ord)
                .push_slice::<&bitcoin::script::PushBytes>(content_type.as_slice().try_into().unwrap());
        }

        // Add body if present (using empty BODY_TAG like ord)
        if let Some(body) = &self.body {
            // Push the BODY_TAG (empty array like ord)
            builder = builder.push_slice(&BODY_TAG);
            
            // Chunk body data into script-safe pieces (same as ord)
            for chunk in body.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
                builder = builder.push_slice::<&bitcoin::script::PushBytes>(chunk.try_into().unwrap());
            }
        }

        // End with OP_ENDIF (same as ord)
        builder
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script()
    }

    /// Create witness for taproot script-path spending following ord pattern EXACTLY
    /// CRITICAL FIX: This now returns only [script, control_block] like ord
    /// The signature will be added separately during transaction building
    pub fn create_witness(&self, control_block: ControlBlock) -> Result<Witness> {
        let reveal_script = self.build_reveal_script();
        
        let mut witness = Witness::new();
        
        // CRITICAL FIX: Follow ord witness pattern exactly
        // Ord creates witness with [script, control_block] for script-path spending
        // The signature is added separately during the signing process
        
        // Push the script bytes - this contains the BIN protocol envelope data
        let script_bytes = reveal_script.as_bytes();
        log::info!("Creating ord-style witness with script: {} bytes", script_bytes.len());
        witness.push(script_bytes);
        
        // Push the control block bytes
        let control_block_bytes = control_block.serialize();
        log::info!("Creating ord-style witness with control block: {} bytes", control_block_bytes.len());
        witness.push(&control_block_bytes);
        
        // Verify the witness was created correctly - expecting 2 items like ord
        if witness.len() != 2 {
            return Err(anyhow::anyhow!("Invalid ord-style witness length: expected 2 items (script + control_block), got {}", witness.len()));
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
        log::info!("Created ord-style witness with {} items:", witness.len());
        for (i, item) in witness.iter().enumerate() {
            match i {
                0 => log::info!("  Witness item {}: {} bytes (script with BIN protocol data)", i, item.len()),
                1 => log::info!("  Witness item {}: {} bytes (control block)", i, item.len()),
                _ => log::info!("  Witness item {}: {} bytes", i, item.len()),
            }
        }
        
        Ok(witness)
    }

    /// Create complete witness for taproot script-path spending with signature
    /// CRITICAL FIX: This creates the complete 3-element witness: [signature, script, control_block]
    /// This is what should be used for the final transaction
    pub fn create_complete_witness(&self, signature: &[u8], control_block: ControlBlock) -> Result<Witness> {
        let reveal_script = self.build_reveal_script();
        
        let mut witness = Witness::new();
        
        // CRITICAL FIX: Create complete P2TR script-path witness structure
        // For P2TR script-path spending: [signature, script, control_block]
        
        // 1. Push the signature as the FIRST element
        log::info!("Adding signature as first witness element: {} bytes", signature.len());
        witness.push(signature);
        
        // 2. Push the script bytes - this contains the BIN protocol envelope data
        let script_bytes = reveal_script.as_bytes();
        log::info!("Adding script as second witness element: {} bytes", script_bytes.len());
        witness.push(script_bytes);
        
        // 3. Push the control block bytes
        let control_block_bytes = control_block.serialize();
        log::info!("Adding control block as third witness element: {} bytes", control_block_bytes.len());
        witness.push(&control_block_bytes);
        
        // Verify the witness was created correctly - expecting 3 items for complete P2TR
        if witness.len() != 3 {
            return Err(anyhow::anyhow!("Invalid complete witness length: expected 3 items (signature + script + control_block), got {}", witness.len()));
        }
        
        // Verify all elements are non-empty
        for (i, item) in witness.iter().enumerate() {
            if item.is_empty() {
                return Err(anyhow::anyhow!("Witness item {} is empty", i));
            }
        }
        
        // Log final witness details for debugging
        log::info!("Created complete P2TR witness with {} items:", witness.len());
        for (i, item) in witness.iter().enumerate() {
            match i {
                0 => log::info!("  Witness item {}: {} bytes (schnorr signature)", i, item.len()),
                1 => log::info!("  Witness item {}: {} bytes (script with BIN protocol data)", i, item.len()),
                2 => log::info!("  Witness item {}: {} bytes (control block)", i, item.len()),
                _ => log::info!("  Witness item {}: {} bytes", i, item.len()),
            }
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
    
    // Expect OP_FALSE OP_IF pattern (OP_FALSE pushes empty bytes)
    match instructions.next()? {
        Ok(bitcoin::script::Instruction::PushBytes(bytes)) if bytes.is_empty() => {},
        Ok(bitcoin::script::Instruction::Op(opcodes::all::OP_PUSHBYTES_0)) => {},
        _ => return None,
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
    let mut expecting_content_type = false;
    
    // Parse fields and body
    while let Some(instruction) = instructions.next() {
        match instruction {
            Ok(bitcoin::script::Instruction::Op(opcodes::all::OP_ENDIF)) => break,
            Ok(bitcoin::script::Instruction::PushBytes(bytes)) => {
                let bytes = bytes.as_bytes();
                
                if expecting_content_type {
                    // This is the content-type value following the tag
                    content_type = Some(bytes.to_vec());
                    expecting_content_type = false;
                } else if bytes == &[1u8] {
                    // Content-Type tag - next instruction will be the content-type value
                    expecting_content_type = true;
                } else {
                    // This is body data (any push bytes that's not a content-type tag or value)
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
        assert!(instructions.len() >= 6); // OP_FALSE, OP_IF, protocol, content-type tag, content-type, body, OP_ENDIF
        
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

    #[test]
    fn test_ord_style_witness_creation() {
        let envelope = AlkanesEnvelope::new(
            Some("application/wasm".to_string()),
            Some(b"test contract data".to_vec()),
        );
        
        // Create a dummy control block for testing
        let secp = Secp256k1::new();
        let internal_key = XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap();
        let script = envelope.build_reveal_script();
        
        use bitcoin::taproot::{TaprootBuilder, LeafVersion};
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, script.clone()).unwrap();
        let taproot_spend_info = taproot_builder
            .finalize(&secp, internal_key).unwrap();
        let control_block = taproot_spend_info
            .control_block(&(script, LeafVersion::TapScript)).unwrap();
        
        // Test ord-style witness (2 elements)
        let witness = envelope.create_witness(control_block.clone()).unwrap();
        assert_eq!(witness.len(), 2);
        
        // Test complete witness (3 elements)
        let dummy_signature = vec![0u8; 64]; // 64-byte Schnorr signature
        let complete_witness = envelope.create_complete_witness(&dummy_signature, control_block).unwrap();
        assert_eq!(complete_witness.len(), 3);
    }
}
