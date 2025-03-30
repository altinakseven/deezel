//! Runestone protocol implementation for DIESEL token minting
//!
//! This module provides functionality for creating Runestone transactions
//! with Protostones for DIESEL token minting.

use bdk::bitcoin::{Script as ScriptBuf, Transaction, TxOut};
use bdk::bitcoin::blockdata::script::{Builder, Instruction};
use bdk::bitcoin::blockdata::opcodes;
use log::debug;
use std::convert::TryInto;

/// Maximum size of a script element
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Runestone for DIESEL token minting
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Runestone {
    /// Protocol tag and message
    pub protocol: Option<Vec<u128>>,
}

/// Protocol tag for DIESEL token minting
pub mod tag {
    /// Protocol tag
    pub const PROTOCOL: u128 = 0x0d;
}

/// Varint encoding/decoding utilities
pub mod varint {
    /// Encode a u128 as a variable-length integer
    pub fn encode(mut value: u128) -> Vec<u8> {
        let mut result = Vec::new();
        
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            
            if value != 0 {
                byte |= 0x80;
            }
            
            result.push(byte);
            
            if value == 0 {
                break;
            }
        }
        
        result
    }
    
    /// Encode a u128 to a vector
    pub fn encode_to_vec(value: u128, vec: &mut Vec<u8>) {
        vec.extend(encode(value));
    }
}

impl Runestone {
    /// Magic number for Runestone protocol
    pub const MAGIC_NUMBER: bdk::bitcoin::blockdata::opcodes::All = bdk::bitcoin::blockdata::opcodes::all::OP_PUSHNUM_13;
    
    /// Create a new Runestone with the given protocol tag and message
    pub fn new(protocol_tag: u128, message: &[u8]) -> Self {
        let mut protocol = Vec::new();
        protocol.push(protocol_tag);
        
        // Convert message bytes to u128 values
        for byte in message {
            protocol.push(*byte as u128);
        }
        
        Self {
            protocol: Some(protocol),
        }
    }
    
    /// Create a new DIESEL token minting Runestone
    pub fn new_diesel() -> Self {
        // Protocol tag: 1
        // Message cellpack: [2, 0, 77]
        Self::new(1, &[2, 0, 77])
    }
    
    /// Encode the Runestone as a Bitcoin script
    pub fn encipher(&self) -> ScriptBuf {
        let mut payload = Vec::new();
        
        // Encode protocol tag and message
        if let Some(protostones) = &self.protocol {
            for proto_u128 in protostones {
                varint::encode_to_vec(tag::PROTOCOL, &mut payload);
                varint::encode_to_vec(*proto_u128, &mut payload);
            }
        }
        
        // Create script with OP_RETURN and magic number
        let mut builder = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_opcode(Runestone::MAGIC_NUMBER);
        
        // Add payload in chunks to avoid exceeding max script element size
        for chunk in payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
            builder = builder.push_slice(chunk);
        }
        
        builder.into_script()
    }
    
    /// Extract a Runestone from a transaction if present
    pub fn extract(transaction: &Transaction) -> Option<Self> {
        // Search transaction outputs for Runestone
        for output in &transaction.output {
            let mut instructions = output.script_pubkey.instructions();
            
            // Check for OP_RETURN
            if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
                continue;
            }
            
            // Check for magic number
            if instructions.next() != Some(Ok(Instruction::Op(Runestone::MAGIC_NUMBER))) {
                continue;
            }
            
            // Found a Runestone
            return Some(Self::default());
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk::bitcoin::{Amount, Transaction, TxOut};
use bdk::bitcoin::blockdata::locktime::LockTime;
    
    #[test]
    fn test_new_diesel() {
        let runestone = Runestone::new_diesel();
        assert!(runestone.protocol.is_some());
        
        let protocol = runestone.protocol.unwrap();
        assert_eq!(protocol[0], 1); // Protocol tag
        assert_eq!(protocol[1], 2); // Message byte 1
        assert_eq!(protocol[2], 0); // Message byte 2
        assert_eq!(protocol[3], 77); // Message byte 3
    }
    
    #[test]
    fn test_encipher() {
        let runestone = Runestone::new_diesel();
        let script = runestone.encipher();
        
        // Script should start with OP_RETURN and magic number
        let mut instructions = script.instructions();
        assert_eq!(
            instructions.next(),
            Some(Ok(Instruction::Op(opcodes::all::OP_RETURN)))
        );
        assert_eq!(
            instructions.next(),
            Some(Ok(Instruction::Op(Runestone::MAGIC_NUMBER)))
        );
    }
    
    #[test]
    fn test_extract() {
        let runestone = Runestone::new_diesel();
        let script = runestone.encipher();
        
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO.into(),
            input: Vec::new(),
            output: vec![
                TxOut {
                    value: 0,
                    script_pubkey: script,
                },
            ],
        };
        
        assert!(Runestone::extract(&tx).is_some());
    }
}
