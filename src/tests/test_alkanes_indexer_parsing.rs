// Test for alkanes indexer parsing methodology
// This test uses the same code that the alkanes indexer uses to parse a transaction
// to parse the transaction in ./examples/tx.hex and extract the attached envelope and cellpack data

use alkanes_support::envelope::RawEnvelope;
use bitcoin::{Transaction, consensus::deserialize};
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct AlkaneId {
    pub block: u128,
    pub tx: u128,
}

impl Default for AlkaneId {
    fn default() -> Self {
        Self { block: 0, tx: 0 }
    }
}

#[derive(Debug, Clone)]
pub struct Cellpack {
    pub target: AlkaneId,
    pub inputs: Vec<u128>,
}

impl Cellpack {
    /// Parse cellpack from cursor - same as alkanes indexer
    pub fn parse(cursor: &mut Cursor<Vec<u8>>) -> Result<Self, Box<dyn std::error::Error>> {
        // Read target AlkaneId (block and tx as u128)
        let mut block_bytes = [0u8; 16];
        std::io::Read::read_exact(cursor, &mut block_bytes)?;
        let block = u128::from_le_bytes(block_bytes);
        
        let mut tx_bytes = [0u8; 16];
        std::io::Read::read_exact(cursor, &mut tx_bytes)?;
        let tx = u128::from_le_bytes(tx_bytes);
        
        let target = AlkaneId { block, tx };
        
        // Read remaining data as u128 inputs
        let mut inputs = Vec::new();
        while cursor.position() < cursor.get_ref().len() as u64 {
            let mut input_bytes = [0u8; 16];
            if std::io::Read::read_exact(cursor, &mut input_bytes).is_ok() {
                inputs.push(u128::from_le_bytes(input_bytes));
            } else {
                break;
            }
        }
        
        Ok(Cellpack { target, inputs })
    }
    
    /// Convert from Vec<u128> where first two elements are target [block, tx]
    pub fn try_from(data: Vec<u128>) -> Result<Self, Box<dyn std::error::Error>> {
        if data.len() < 2 {
            return Err("Cellpack data must have at least 2 elements for target".into());
        }
        
        let target = AlkaneId {
            block: data[0],
            tx: data[1],
        };
        
        let inputs = if data.len() > 2 {
            data[2..].to_vec()
        } else {
            Vec::new()
        };
        
        Ok(Cellpack { target, inputs })
    }
}

/// Find witness payload from transaction envelopes - same as alkanes indexer
pub fn find_witness_payload(tx: &Transaction, i: usize) -> Option<Vec<u8>> {
    let envelopes = RawEnvelope::from_transaction(tx);
    if envelopes.len() <= i {
        None
    } else {
        Some(
            envelopes[i]
                .payload
                .clone()
                .into_iter()
                .skip(1)
                .flatten()
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_alkanes_indexer_parsing_methodology() {
        println!("=== Alkanes Indexer Parsing Test ===");
        
        // Read transaction hex from examples/tx.hex
        let tx_hex = fs::read_to_string("examples/tx.hex")
            .expect("Failed to read examples/tx.hex")
            .trim()
            .to_string();
        
        println!("Transaction hex length: {}", tx_hex.len());
        
        // Decode hex to bytes
        let tx_bytes = hex::decode(&tx_hex)
            .expect("Failed to decode transaction hex");
        
        println!("Transaction bytes length: {}", tx_bytes.len());
        
        // Deserialize to Bitcoin transaction
        let tx: Transaction = deserialize(&tx_bytes)
            .expect("Failed to deserialize transaction");
        
        println!("Transaction ID: {}", tx.compute_txid());
        println!("Number of inputs: {}", tx.input.len());
        println!("Number of outputs: {}", tx.output.len());
        
        // Use alkanes indexer methodology to extract envelopes
        println!("\n=== Extracting Envelopes using RawEnvelope::from_transaction ===");
        let envelopes = RawEnvelope::from_transaction(&tx);
        
        println!("Found {} envelopes", envelopes.len());
        
        for (i, envelope) in envelopes.iter().enumerate() {
            println!("\nEnvelope {}:", i);
            println!("  Input: {}", envelope.input);
            println!("  Offset: {}", envelope.offset);
            println!("  Payload length: {}", envelope.payload.len());
            println!("  Pushnum: {}", envelope.pushnum);
            println!("  Stutter: {}", envelope.stutter);
            
            if !envelope.payload.is_empty() {
                println!("  Payload (first 100 bytes): {:?}", 
                    &envelope.payload[..std::cmp::min(100, envelope.payload.len())]);
            }
        }
        
        // Extract witness payload using alkanes indexer logic
        println!("\n=== Extracting Witness Payload ===");
        if let Some(payload) = find_witness_payload(&tx, 0) {
            println!("Witness payload length: {}", payload.len());
            
            // Try to parse as cellpack using alkanes indexer methodology
            println!("\n=== Parsing Cellpack ===");
            let mut cursor = Cursor::new(payload.clone());
            
            match Cellpack::parse(&mut cursor) {
                Ok(cellpack) => {
                    println!("Successfully parsed cellpack:");
                    println!("  Target: block={}, tx={}", cellpack.target.block, cellpack.target.tx);
                    println!("  Inputs: {:?}", cellpack.inputs);
                    
                    // Check if this matches expected cellpack [3, 797, 101]
                    if cellpack.inputs.len() >= 1 && cellpack.inputs[0] == 101 {
                        println!("✓ Found expected cellpack data with input 101");
                    }
                    
                    // Check if target follows deployment pattern to [4, 797]
                    if cellpack.target.block == 3 && cellpack.target.tx == 797 {
                        println!("✓ Target [3, 797] would deploy to [4, 797]");
                    }
                }
                Err(e) => {
                    println!("Failed to parse cellpack: {}", e);
                    
                    // Try alternative parsing as Vec<u128>
                    println!("Trying alternative parsing as Vec<u128>...");
                    
                    // Parse payload as sequence of u128 values
                    let mut cursor = Cursor::new(payload.clone());
                    let mut values = Vec::new();
                    
                    while cursor.position() < cursor.get_ref().len() as u64 {
                        let mut bytes = [0u8; 16];
                        if std::io::Read::read_exact(&mut cursor, &mut bytes).is_ok() {
                            values.push(u128::from_le_bytes(bytes));
                        } else {
                            break;
                        }
                    }
                    
                    println!("Parsed {} u128 values: {:?}", values.len(), values);
                    
                    // Check if we have the expected pattern [3, 797, 101]
                    if values.len() >= 3 && values[0] == 3 && values[1] == 797 && values[2] == 101 {
                        println!("✓ Found expected cellpack pattern [3, 797, 101]");
                        
                        if let Ok(cellpack) = Cellpack::try_from(values) {
                            println!("Successfully created cellpack from values:");
                            println!("  Target: block={}, tx={}", cellpack.target.block, cellpack.target.tx);
                            println!("  Inputs: {:?}", cellpack.inputs);
                        }
                    }
                }
            }
        } else {
            println!("No witness payload found");
        }
        
        // Verify we found at least one envelope
        assert!(!envelopes.is_empty(), "Should find at least one envelope in the transaction");
        
        println!("\n=== Test completed successfully ===");
    }
    
    #[test]
    fn test_cellpack_parsing_methodology() {
        println!("=== Testing Cellpack Parsing Methodology ===");
        
        // Test with expected cellpack data [3, 797, 101]
        let test_data = vec![3u128, 797u128, 101u128];
        
        // Convert to bytes as alkanes indexer would store it
        let mut bytes = Vec::new();
        for value in &test_data {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        
        println!("Test data: {:?}", test_data);
        println!("Serialized bytes length: {}", bytes.len());
        
        // Parse using Cellpack::parse
        let mut cursor = Cursor::new(bytes.clone());
        match Cellpack::parse(&mut cursor) {
            Ok(cellpack) => {
                println!("Parsed cellpack:");
                println!("  Target: block={}, tx={}", cellpack.target.block, cellpack.target.tx);
                println!("  Inputs: {:?}", cellpack.inputs);
                
                assert_eq!(cellpack.target.block, 3);
                assert_eq!(cellpack.target.tx, 797);
                assert_eq!(cellpack.inputs, vec![101]);
            }
            Err(e) => {
                panic!("Failed to parse test cellpack: {}", e);
            }
        }
        
        // Test using Cellpack::try_from
        match Cellpack::try_from(test_data.clone()) {
            Ok(cellpack) => {
                println!("Created cellpack from Vec<u128>:");
                println!("  Target: block={}, tx={}", cellpack.target.block, cellpack.target.tx);
                println!("  Inputs: {:?}", cellpack.inputs);
                
                assert_eq!(cellpack.target.block, 3);
                assert_eq!(cellpack.target.tx, 797);
                assert_eq!(cellpack.inputs, vec![101]);
            }
            Err(e) => {
                panic!("Failed to create cellpack from Vec<u128>: {}", e);
            }
        }
        
        println!("✓ Cellpack parsing methodology test passed");
    }
}