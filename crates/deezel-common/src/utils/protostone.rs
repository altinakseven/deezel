//! Protostone utilities for alkanes
//!
//! This module provides utilities for working with protostones in alkanes transactions.

use crate::{Result, DeezelError};
use serde::{Deserialize, Serialize};

/// Protostone structure for alkanes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protostone {
    pub protocol_tag: u128,
    pub message: Vec<u8>,
}

/// Collection of protostones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protostones {
    pub protostones: Vec<Protostone>,
}

impl Protostones {
    /// Create a new empty protostones collection
    pub fn new() -> Self {
        Self {
            protostones: Vec::new(),
        }
    }
    
    /// Add a protostone to the collection
    pub fn add(&mut self, protostone: Protostone) {
        self.protostones.push(protostone);
    }
    
    /// Create protostones from cellpack data
    pub fn from_cellpack(cellpack: &[u8]) -> Result<Self> {
        // Parse cellpack format - this is a simplified implementation
        // In the real implementation, this would parse the actual cellpack format
        let mut protostones = Vec::new();
        
        // For now, create a single protostone with the cellpack data
        if !cellpack.is_empty() {
            protostones.push(Protostone {
                protocol_tag: 1, // Default protocol tag
                message: cellpack.to_vec(),
            });
        }
        
        Ok(Self { protostones })
    }
    
    /// Encode protostones to cellpack format
    pub fn encipher(&self) -> Vec<u8> {
        // This is a simplified implementation
        // In the real implementation, this would encode to the actual cellpack format
        let mut result = Vec::new();
        
        for protostone in &self.protostones {
            // Add protocol tag (as varint)
            result.extend_from_slice(&encode_varint(protostone.protocol_tag));
            
            // Add message length (as varint)
            result.extend_from_slice(&encode_varint(protostone.message.len() as u128));
            
            // Add message data
            result.extend_from_slice(&protostone.message);
        }
        
        result
    }
    
    /// Parse protostones from string format
    pub fn from_string(input: &str) -> Result<Self> {
        let mut protostones = Vec::new();
        
        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            
            let components: Vec<&str> = part.split(':').collect();
            if components.len() >= 2 {
                let protocol_tag = components[0].parse::<u128>()
                    .map_err(|_| DeezelError::Parse(format!("Invalid protocol tag: {}", components[0])))?;
                
                let message = components[1..].join(":").into_bytes();
                
                protostones.push(Protostone {
                    protocol_tag,
                    message,
                });
            } else {
                return Err(DeezelError::Parse(format!("Invalid protostone format: {}", part)));
            }
        }
        
        Ok(Self { protostones })
    }
    
    /// Convert to string format
    pub fn to_string(&self) -> String {
        self.protostones
            .iter()
            .map(|p| format!("{}:{}", p.protocol_tag, String::from_utf8_lossy(&p.message)))
            .collect::<Vec<_>>()
            .join(",")
    }
    
    /// Check if collection is empty
    pub fn is_empty(&self) -> bool {
        self.protostones.is_empty()
    }
    
    /// Get number of protostones
    pub fn len(&self) -> usize {
        self.protostones.len()
    }
    
    /// Get iterator over protostones
    pub fn iter(&self) -> impl Iterator<Item = &Protostone> {
        self.protostones.iter()
    }
}

impl Default for Protostones {
    fn default() -> Self {
        Self::new()
    }
}

impl Protostone {
    /// Create a new protostone
    pub fn new(protocol_tag: u128, message: Vec<u8>) -> Self {
        Self {
            protocol_tag,
            message,
        }
    }
    
    /// Create protostone from string message
    pub fn from_string(protocol_tag: u128, message: &str) -> Self {
        Self {
            protocol_tag,
            message: message.as_bytes().to_vec(),
        }
    }
    
    /// Get message as string (if valid UTF-8)
    pub fn message_as_string(&self) -> Option<String> {
        String::from_utf8(self.message.clone()).ok()
    }
    
    /// Get message as hex string
    pub fn message_as_hex(&self) -> String {
        hex::encode(&self.message)
    }
}

/// Encode a number as varint (simplified implementation)
fn encode_varint(mut value: u128) -> Vec<u8> {
    let mut result = Vec::new();
    
    while value >= 0x80 {
        result.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    result.push(value as u8);
    
    result
}

/// Decode varint from bytes (simplified implementation)
pub fn decode_varint(bytes: &[u8]) -> Result<(u128, usize)> {
    let mut result = 0u128;
    let mut shift = 0;
    let mut pos = 0;
    
    for &byte in bytes {
        if pos >= bytes.len() {
            return Err(DeezelError::Parse("Incomplete varint".to_string()));
        }
        
        result |= ((byte & 0x7F) as u128) << shift;
        pos += 1;
        
        if byte & 0x80 == 0 {
            return Ok((result, pos));
        }
        
        shift += 7;
        if shift >= 128 {
            return Err(DeezelError::Parse("Varint too long".to_string()));
        }
    }
    
    Err(DeezelError::Parse("Incomplete varint".to_string()))
}

/// Parse cellpack data into protostones
pub fn parse_cellpack(data: &[u8]) -> Result<Protostones> {
    let mut protostones = Vec::new();
    let mut pos = 0;
    
    while pos < data.len() {
        // Decode protocol tag
        let (protocol_tag, tag_len) = decode_varint(&data[pos..])?;
        pos += tag_len;
        
        if pos >= data.len() {
            break;
        }
        
        // Decode message length
        let (message_len, len_len) = decode_varint(&data[pos..])?;
        pos += len_len;
        
        if pos + message_len as usize > data.len() {
            return Err(DeezelError::Parse("Invalid cellpack: message length exceeds data".to_string()));
        }
        
        // Extract message
        let message = data[pos..pos + message_len as usize].to_vec();
        pos += message_len as usize;
        
        protostones.push(Protostone {
            protocol_tag,
            message,
        });
    }
    
    Ok(Protostones { protostones })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protostone_creation() {
        let protostone = Protostone::new(1, b"hello".to_vec());
        assert_eq!(protostone.protocol_tag, 1);
        assert_eq!(protostone.message, b"hello");
        assert_eq!(protostone.message_as_string(), Some("hello".to_string()));
    }
    
    #[test]
    fn test_protostones_from_string() {
        let protostones = Protostones::from_string("1:hello,2:world").unwrap();
        assert_eq!(protostones.len(), 2);
        
        assert_eq!(protostones.protostones[0].protocol_tag, 1);
        assert_eq!(protostones.protostones[0].message_as_string(), Some("hello".to_string()));
        
        assert_eq!(protostones.protostones[1].protocol_tag, 2);
        assert_eq!(protostones.protostones[1].message_as_string(), Some("world".to_string()));
    }
    
    #[test]
    fn test_protostones_to_string() {
        let mut protostones = Protostones::new();
        protostones.add(Protostone::from_string(1, "hello"));
        protostones.add(Protostone::from_string(2, "world"));
        
        let string_repr = protostones.to_string();
        assert_eq!(string_repr, "1:hello,2:world");
    }
    
    #[test]
    fn test_varint_encoding() {
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(127), vec![127]);
        assert_eq!(encode_varint(128), vec![128, 1]);
        assert_eq!(encode_varint(300), vec![172, 2]);
    }
    
    #[test]
    fn test_varint_decoding() {
        assert_eq!(decode_varint(&[0]).unwrap(), (0, 1));
        assert_eq!(decode_varint(&[127]).unwrap(), (127, 1));
        assert_eq!(decode_varint(&[128, 1]).unwrap(), (128, 2));
        assert_eq!(decode_varint(&[172, 2]).unwrap(), (300, 2));
    }
    
    #[test]
    fn test_encipher_decipher() {
        let mut protostones = Protostones::new();
        protostones.add(Protostone::from_string(1, "test"));
        protostones.add(Protostone::from_string(2, "data"));
        
        let encoded = protostones.encipher();
        let decoded = parse_cellpack(&encoded).unwrap();
        
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.protostones[0].protocol_tag, 1);
        assert_eq!(decoded.protostones[0].message_as_string(), Some("test".to_string()));
        assert_eq!(decoded.protostones[1].protocol_tag, 2);
        assert_eq!(decoded.protostones[1].message_as_string(), Some("data".to_string()));
    }
}