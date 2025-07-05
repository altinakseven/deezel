//! Test runestone encoding to debug the OP_RETURN issue
//! 
//! This test file helps us understand what's going wrong with the runestone encoding
//! by comparing our implementation with the expected reference behavior.

#[cfg(test)]
mod tests {
    use super::*;
    use alkanes_support::cellpack::Cellpack;
    use alkanes_support::id::AlkaneId;
    use protorune_support::protostone::Protostone;
    use protorune_support::utils::encode_varint_list;
    use ordinals::Runestone;
    use std::str::FromStr;

    #[test]
    fn test_simple_runestone_encoding() {
        println!("🔍 Testing simple runestone encoding");
        
        // Create a simple cellpack like in the example: [3,797,101]
        let cellpack = Cellpack {
            target: AlkaneId { block: 3, tx: 797 },
            inputs: vec![101],
        };
        
        println!("📦 Created cellpack: target={}:{}, inputs={:?}", 
                 cellpack.target.block, cellpack.target.tx, cellpack.inputs);
        
        // Encode the cellpack
        let cellpack_bytes = cellpack.encipher();
        println!("🔧 Cellpack encoded to {} bytes: {}", cellpack_bytes.len(), hex::encode(&cellpack_bytes));
        
        // Create a protostone with the cellpack message
        let protostone = Protostone {
            burn: None,
            message: cellpack_bytes,
            edicts: Vec::new(),
            refund: Some(0),
            pointer: Some(0),
            from: None,
            protocol_tag: 1, // DIESEL protocol tag
        };
        
        println!("🪨 Created protostone with protocol_tag={}, message_len={}", 
                 protostone.protocol_tag, protostone.message.len());
        
        // Convert to integers
        let integers = protostone.to_integers().expect("Failed to convert protostone to integers");
        println!("🔢 Protostone integers: {:?}", integers);
        
        // Now implement the Protostones::encipher() logic manually
        let mut protocol_values = Vec::<u128>::new();
        protocol_values.push(protostone.protocol_tag); // protocol tag
        protocol_values.push(integers.len() as u128);   // length
        protocol_values.extend(&integers);              // the integers
        
        println!("📊 Protocol values: {:?}", protocol_values);
        
        // Encode using LEB128
        let encoded_bytes = encode_varint_list(&protocol_values);
        println!("🔧 LEB128 encoded to {} bytes: {}", encoded_bytes.len(), hex::encode(&encoded_bytes));
        
        // Split into u128 chunks
        let protocol_data = protorune_support::protostone::split_bytes(&encoded_bytes);
        println!("📦 Split into {} u128 values: {:?}", protocol_data.len(), protocol_data);
        
        // Create the final runestone
        let runestone = Runestone {
            edicts: Vec::new(),
            etching: None,
            mint: None,
            pointer: None,
            protocol: if protocol_data.is_empty() { None } else { Some(protocol_data) },
        };
        
        // Encode the runestone
        let script = runestone.encipher();
        println!("📜 Final runestone script: {} bytes", script.len());
        println!("📄 Script hex: {}", hex::encode(script.as_bytes()));
        
        // Try to decode it back using a mock transaction
        use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Txid};
        
        let mock_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: script.clone(),
            }],
        };
        
        match ordinals::Runestone::decipher(&mock_tx) {
            Some(artifact) => {
                println!("✅ Successfully decoded artifact!");
                
                // Check if it's a runestone
                if let ordinals::Artifact::Runestone(decoded_runestone) = artifact {
                    println!("✅ It's a runestone!");
                    println!("🔍 Decoded protocol field: {:?}", decoded_runestone.protocol);
                    
                    if let Some(protocol_field) = decoded_runestone.protocol {
                        // Try to decode the protostones
                        match protorune_support::protostone::Protostone::decipher(&protocol_field) {
                            Ok(protostones) => {
                                println!("✅ Successfully decoded {} protostones!", protostones.len());
                                for (i, ps) in protostones.iter().enumerate() {
                                    println!("🪨 Protostone {}: protocol_tag={}, message_len={}",
                                             i, ps.protocol_tag, ps.message.len());
                                    if !ps.message.is_empty() {
                                        println!("📨 Message hex: {}", hex::encode(&ps.message));
                                    }
                                }
                            },
                            Err(e) => {
                                println!("❌ Failed to decode protostones: {}", e);
                            }
                        }
                    }
                } else {
                    println!("❌ Artifact is not a runestone: {:?}", artifact);
                }
            },
            None => {
                println!("❌ Failed to decode runestone");
            }
        }
    }
    
    #[test]
    fn test_reference_implementation() {
        println!("🔍 Testing reference implementation pattern");
        
        // Create a simple protostone like in the reference
        let protostone = Protostone {
            burn: None,
            message: vec![1, 2, 3], // Simple test message
            edicts: Vec::new(),
            refund: Some(0),
            pointer: Some(0),
            from: None,
            protocol_tag: 1,
        };
        
        let protostones = vec![protostone];
        
        // Implement the encipher logic from the reference
        let mut values = Vec::<u128>::new();
        for stone in &protostones {
            values.push(stone.protocol_tag);
            let varints = stone.to_integers().expect("Failed to convert to integers");
            values.push(varints.len() as u128);
            values.extend(&varints);
        }
        
        println!("📊 Values before encoding: {:?}", values);
        
        let encoded = encode_varint_list(&values);
        println!("🔧 LEB128 encoded: {}", hex::encode(&encoded));
        
        let split = protorune_support::protostone::split_bytes(&encoded);
        println!("📦 Split bytes: {:?}", split);
        
        // Create runestone
        let runestone = Runestone {
            edicts: Vec::new(),
            etching: None,
            mint: None,
            pointer: None,
            protocol: Some(split),
        };
        
        let script = runestone.encipher();
        println!("📜 Final script: {}", hex::encode(script.as_bytes()));
    }
}