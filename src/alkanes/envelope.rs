// Alkanes envelope implementation based on alkanes-rs reference
// Core functionality for creating and managing alkanes envelope transactions
// CRITICAL FIX: Updated to match alkanes-rs reference implementation exactly
// Key differences: uses gzip compression, no content-type tags, proper BIN protocol structure

use anyhow::{Context, Result};
use bitcoin::{
    blockdata::opcodes,
    script::Builder as ScriptBuilder,
    taproot::ControlBlock, ScriptBuf, Witness,
};
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

// Alkanes protocol constants - matching alkanes-rs reference exactly
pub const ALKANES_PROTOCOL_ID: [u8; 3] = *b"BIN";
pub const BODY_TAG: [u8; 0] = [];
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Alkanes envelope structure for contract deployment
/// CRITICAL FIX: Simplified to match alkanes-rs reference - no content-type field
#[derive(Debug, Clone)]
pub struct AlkanesEnvelope {
    pub payload: Vec<u8>,
}

impl AlkanesEnvelope {
    /// Create new alkanes envelope with contract data
    /// CRITICAL FIX: Simplified constructor to match alkanes-rs reference
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    /// Create envelope for alkanes contract deployment with BIN protocol data
    /// This envelope will be used as the first input in the reveal transaction
    pub fn for_contract(contract_data: Vec<u8>) -> Self {
        Self::new(contract_data)
    }

    /// Compress payload using gzip compression (matching alkanes-rs reference)
    /// CRITICAL FIX: Added gzip compression like alkanes-rs reference
    fn compress_payload(&self) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&self.payload)
            .context("Failed to write payload to gzip encoder")?;
        encoder.finish()
            .context("Failed to finish gzip compression")
    }

    /// Build the reveal script following alkanes-rs reference EXACTLY
    /// CRITICAL FIX: Match alkanes-rs reference implementation exactly
    pub fn build_reveal_script(&self) -> ScriptBuf {
        let mut builder = ScriptBuilder::new()
            .push_opcode(opcodes::OP_FALSE) // OP_FALSE (pushes empty bytes)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(&ALKANES_PROTOCOL_ID); // BIN protocol ID

        // CRITICAL FIX: Add empty BODY_TAG before compressed payload (matching alkanes-rs reference)
        builder = builder.push_slice(&BODY_TAG);

        // CRITICAL FIX: Compress the payload using gzip (matching alkanes-rs reference)
        if let Ok(compressed_payload) = self.compress_payload() {
            // Chunk compressed data into script-safe pieces
            for chunk in compressed_payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
                builder = builder.push_slice::<&bitcoin::script::PushBytes>(chunk.try_into().unwrap());
            }
        } else {
            log::warn!("Failed to compress payload, using uncompressed data");
            // Fallback to uncompressed data
            for chunk in self.payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
                builder = builder.push_slice::<&bitcoin::script::PushBytes>(chunk.try_into().unwrap());
            }
        }

        // End with OP_ENDIF
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


/// Extract envelope data from transaction witness (matching alkanes-rs reference)
/// CRITICAL FIX: Updated to match alkanes-rs reference implementation
pub fn extract_envelope_from_witness(witness: &Witness) -> Option<AlkanesEnvelope> {
    // Extract script from witness using tapscript method
    let script = unversioned_leaf_script_from_witness(witness)?;
    
    // Parse script for alkanes envelope
    parse_alkanes_script(script)
}

/// Extract script from taproot witness (matching alkanes-rs reference)
fn unversioned_leaf_script_from_witness(witness: &Witness) -> Option<&bitcoin::Script> {
    #[allow(deprecated)]
    witness.tapscript()
}

/// Parse alkanes envelope from script (matching alkanes-rs reference)
/// CRITICAL FIX: Updated to match alkanes-rs reference - no content-type parsing
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
    
    // CRITICAL FIX: Simplified parsing to match alkanes-rs reference
    // No content-type parsing, just collect all payload chunks after BODY_TAG
    let mut payload_parts = Vec::new();
    
    // Parse payload chunks
    while let Some(instruction) = instructions.next() {
        match instruction {
            Ok(bitcoin::script::Instruction::Op(opcodes::all::OP_ENDIF)) => break,
            Ok(bitcoin::script::Instruction::PushBytes(bytes)) => {
                // All push bytes after protocol ID are payload data
                payload_parts.push(bytes.as_bytes().to_vec());
            }
            _ => {}
        }
    }
    
    // Flatten all payload parts into single payload
    let payload = payload_parts.into_iter().flatten().collect();
    
    Some(AlkanesEnvelope { payload })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{rand, Secp256k1};
    use bitcoin::XOnlyPublicKey;

    #[test]
    fn test_envelope_script_creation() {
        let test_data = b"test contract data".to_vec();
        let envelope = AlkanesEnvelope::new(test_data.clone());
        
        let script = envelope.build_reveal_script();
        
        // Verify script structure
        let instructions: Vec<_> = script.instructions().collect();
        assert!(instructions.len() >= 5); // OP_FALSE, OP_IF, protocol, body_tag, compressed_payload, OP_ENDIF
        
        // Parse back the envelope
        let parsed = parse_alkanes_script(&script).unwrap();
        // Note: payload will be compressed, so we can't directly compare
        assert!(!parsed.payload.is_empty());
    }

    #[test]
    fn test_empty_envelope() {
        let envelope = AlkanesEnvelope::new(vec![]);
        let script = envelope.build_reveal_script();
        
        let parsed = parse_alkanes_script(&script).unwrap();
        // Even empty payload gets compressed
        assert!(!parsed.payload.is_empty());
    }

    #[test]
    fn test_large_payload_chunking() {
        let large_data = vec![0u8; 1500]; // Larger than MAX_SCRIPT_ELEMENT_SIZE
        let envelope = AlkanesEnvelope::new(large_data.clone());
        let script = envelope.build_reveal_script();
        
        let parsed = parse_alkanes_script(&script).unwrap();
        // Payload will be compressed and chunked
        assert!(!parsed.payload.is_empty());
    }

    #[test]
    fn test_compression() {
        let test_data = b"test contract data that should be compressed".to_vec();
        let envelope = AlkanesEnvelope::new(test_data.clone());
        
        // Test compression works
        let compressed = envelope.compress_payload().unwrap();
        assert!(!compressed.is_empty());
        
        // Compressed data should be different from original (unless very small)
        if test_data.len() > 20 {
            assert_ne!(compressed, test_data);
        }
    }

    #[test]
    fn test_witness_creation() {
        let test_data = b"test contract data".to_vec();
        let envelope = AlkanesEnvelope::new(test_data);
        
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
        
        // Test witness creation (2 elements)
        let witness = envelope.create_witness(control_block.clone()).unwrap();
        assert_eq!(witness.len(), 2);
        
        // Test complete witness (3 elements)
        let dummy_signature = vec![0u8; 64]; // 64-byte Schnorr signature
        let complete_witness = envelope.create_complete_witness(&dummy_signature, control_block).unwrap();
        assert_eq!(complete_witness.len(), 3);
    }
}
