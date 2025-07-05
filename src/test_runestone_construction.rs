//! Test runestone construction to debug the protocol tag issue
//! 
//! This test simulates the exact runestone construction process used in the actual execution
//! to identify where the protocol tag is getting corrupted.

#[cfg(test)]
mod tests {
    use crate::alkanes::execute::{parse_protostones, ProtostoneSpec};
    use alkanes_support::cellpack::Cellpack;
    use alkanes_support::id::AlkaneId;
    use protorune_support::protostone::Protostone;
    use protorune_support::utils::encode_varint_list;
    use ordinals::Runestone;
    use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Txid};
    use std::str::FromStr;

    #[test]
    fn test_full_runestone_construction() {
        println!("🔍 Testing full runestone construction process");
        
        // Step 1: Parse the exact input from the script
        let input = "[3,797,101]:v0:v0";
        let protostone_specs = parse_protostones(input).expect("Failed to parse protostones");
        
        println!("✅ Parsed {} protostone specs", protostone_specs.len());
        
        // Step 2: Simulate the exact construct_runestone logic
        let num_outputs = 2; // Simulate 2 outputs
        let runestone_script = construct_runestone_simulation(&protostone_specs, num_outputs).expect("Failed to construct runestone");
        
        println!("📜 Constructed runestone script: {} bytes", runestone_script.len());
        println!("📄 Script hex: {}", hex::encode(runestone_script.as_bytes()));
        
        // Step 3: Create a mock transaction and test decoding
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
                script_pubkey: runestone_script.clone(),
            }],
        };
        
        // Step 4: Try to decode the runestone
        match ordinals::Runestone::decipher(&mock_tx) {
            Some(artifact) => {
                println!("✅ Successfully decoded artifact!");
                
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
    
    /// Simulate the exact construct_runestone logic from execute.rs
    fn construct_runestone_simulation(protostones: &[ProtostoneSpec], _num_outputs: usize) -> anyhow::Result<bitcoin::ScriptBuf> {
        println!("🔧 Simulating construct_runestone with {} protostones", protostones.len());
        
        // Convert our ProtostoneSpec to proper Protostone structures
        let mut proper_protostones = Vec::<Protostone>::new();
        
        for (i, protostone_spec) in protostones.iter().enumerate() {
            println!("🔄 Converting protostone spec {} to proper Protostone", i);
            
            // Create the message field from cellpack if present
            let message = if let Some(cellpack) = &protostone_spec.cellpack {
                println!("📦 Encoding cellpack for protostone {}: target={}:{}, inputs={:?}",
                          i, cellpack.target.block, cellpack.target.tx, cellpack.inputs);
                
                // Use Cellpack::encipher() to get LEB128 encoded Vec<u8> for the message field
                let cellpack_bytes = cellpack.encipher();
                println!("🔧 Cellpack encoded to {} bytes for message field: {}", cellpack_bytes.len(), hex::encode(&cellpack_bytes));
                cellpack_bytes
            } else {
                Vec::new()
            };
            
            // Create the Protostone with proper structure
            let protostone = Protostone {
                burn: None,
                message,
                edicts: Vec::new(),
                refund: Some(0),
                pointer: Some(0),
                from: None,
                protocol_tag: 1, // DIESEL protocol tag - HARDCODED TO 1
            };
            
            println!("🪨 Created protostone with protocol_tag={}, message_len={}", protostone.protocol_tag, protostone.message.len());
            proper_protostones.push(protostone);
        }
        
        // Implement the Protostones::encipher() logic directly
        let mut protocol_values = Vec::<u128>::new();
        
        for stone in &proper_protostones {
            println!("🔢 Adding protocol_tag={} to protocol_values", stone.protocol_tag);
            protocol_values.push(stone.protocol_tag);
            
            // Get the protostone integers
            let varints = stone.to_integers()
                .map_err(|e| anyhow::anyhow!("Failed to convert protostone to integers: {}", e))?;
            
            println!("🔢 Protostone integers: {:?}", varints);
            protocol_values.push(varints.len() as u128);
            protocol_values.extend(&varints);
        }
        
        println!("📊 Final protocol_values: {:?}", protocol_values);
        
        // Encode the protocol values using LEB128 and split into u128 chunks
        let encoded_bytes = encode_varint_list(&protocol_values);
        println!("🔧 LEB128 encoded to {} bytes: {}", encoded_bytes.len(), hex::encode(&encoded_bytes));
        
        let protocol_data = protorune_support::protostone::split_bytes(&encoded_bytes);
        println!("📦 Split into {} u128 values: {:?}", protocol_data.len(), protocol_data);
        
        // Create the Runestone using the ordinals crate with proper protocol field
        let runestone = Runestone {
            edicts: Vec::new(),
            etching: None,
            mint: None,
            pointer: None,
            protocol: if protocol_data.is_empty() { None } else { Some(protocol_data) },
        };
        
        println!("🪨 Created final runestone with protocol field: {:?}", runestone.protocol);
        
        // Use the ordinals crate's encipher method to create the proper OP_RETURN script
        let script = runestone.encipher();
        
        println!("✅ Constructed runestone script with {} bytes", script.len());
        
        Ok(script)
    }
}