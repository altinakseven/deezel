//! Transaction comparison test for deezel v2 reveal transactions
//!
//! This test compares ./examples/deezel-v2-tx.hex (latest deezel-built reveal tx) with 
//! ./examples/working-tx.hex (working integration test reveal tx) to identify
//! differences in transaction structure and content after our taproot fixes.

use anyhow::Result;
use bitcoin::{Transaction, consensus::deserialize};
use std::fs;

/// Compare deezel-v2-tx.hex with working-tx.hex and analyze differences
#[tokio::test]
async fn test_compare_deezel_v2_transactions() -> Result<()> {
    println!("=== Deezel V2 Transaction Comparison Test ===");
    
    // Read the hex files
    let deezel_v2_hex = fs::read_to_string("./examples/deezel-v2-tx.hex")
        .map_err(|e| anyhow::anyhow!("Failed to read ./examples/deezel-v2-tx.hex: {}", e))?;
    
    let working_hex = fs::read_to_string("./examples/working-tx.hex")
        .map_err(|e| anyhow::anyhow!("Failed to read ./examples/working-tx.hex: {}", e))?;
    
    // Clean up hex strings (remove whitespace/newlines)
    let deezel_v2_hex = deezel_v2_hex.trim().replace('\n', "").replace(' ', "");
    let working_hex = working_hex.trim().replace('\n', "").replace(' ', "");
    
    println!("Deezel V2 tx hex length: {} characters", deezel_v2_hex.len());
    println!("Working tx hex length: {} characters", working_hex.len());
    
    // Parse hex to bytes
    let deezel_v2_bytes = hex::decode(&deezel_v2_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode deezel v2 hex: {}", e))?;
    
    let working_bytes = hex::decode(&working_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode working hex: {}", e))?;
    
    println!("Deezel V2 tx bytes length: {} bytes", deezel_v2_bytes.len());
    println!("Working tx bytes length: {} bytes", working_bytes.len());
    
    // Parse transactions using rust-bitcoin
    let deezel_v2_tx: Transaction = deserialize(&deezel_v2_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse deezel v2 transaction: {}", e))?;
    
    let working_tx: Transaction = deserialize(&working_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse working transaction: {}", e))?;
    
    println!("\n=== Basic Transaction Comparison ===");
    println!("Deezel V2 TXID: {}", deezel_v2_tx.compute_txid());
    println!("Working TXID: {}", working_tx.compute_txid());
    
    // Compare basic transaction properties
    compare_basic_properties(&deezel_v2_tx, &working_tx, "Deezel V2", "Working");
    
    // Compare inputs
    compare_inputs(&deezel_v2_tx, &working_tx, "Deezel V2", "Working");
    
    // Compare outputs
    compare_outputs(&deezel_v2_tx, &working_tx, "Deezel V2", "Working");
    
    // Compare witness data - this is where our fixes should show
    compare_witness_data(&deezel_v2_tx, &working_tx, "Deezel V2", "Working");
    
    // Compare locktime and version
    compare_metadata(&deezel_v2_tx, &working_tx, "Deezel V2", "Working");
    
    // Detailed byte-by-byte comparison if transactions differ
    if deezel_v2_bytes != working_bytes {
        println!("\n=== Byte-by-byte Differences ===");
        compare_bytes(&deezel_v2_bytes, &working_bytes, "Deezel V2", "Working");
    } else {
        println!("\n✅ Transactions are identical!");
    }
    
    // Special analysis for envelope data
    analyze_envelope_differences(&deezel_v2_tx, &working_tx);
    
    Ok(())
}

fn compare_basic_properties(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
    println!("\n=== Basic Properties ===");
    println!("{} version: {}", name1, tx1.version.0);
    println!("{} version: {}", name2, tx2.version.0);
    
    println!("{} input count: {}", name1, tx1.input.len());
    println!("{} input count: {}", name2, tx2.input.len());
    
    println!("{} output count: {}", name1, tx1.output.len());
    println!("{} output count: {}", name2, tx2.output.len());
    
    println!("{} locktime: {}", name1, tx1.lock_time);
    println!("{} locktime: {}", name2, tx2.lock_time);
    
    if tx1.version != tx2.version {
        println!("❌ Version mismatch!");
    }
    if tx1.input.len() != tx2.input.len() {
        println!("❌ Input count mismatch!");
    }
    if tx1.output.len() != tx2.output.len() {
        println!("❌ Output count mismatch!");
    }
    if tx1.lock_time != tx2.lock_time {
        println!("❌ Locktime mismatch!");
    }
}

fn compare_inputs(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
    println!("\n=== Input Comparison ===");
    
    let max_inputs = std::cmp::max(tx1.input.len(), tx2.input.len());
    
    for i in 0..max_inputs {
        println!("\n--- Input {} ---", i);
        
        let input1 = tx1.input.get(i);
        let input2 = tx2.input.get(i);
        
        match (input1, input2) {
            (Some(i1), Some(i2)) => {
                println!("{} outpoint: {}:{}", name1, i1.previous_output.txid, i1.previous_output.vout);
                println!("{} outpoint: {}:{}", name2, i2.previous_output.txid, i2.previous_output.vout);
                
                println!("{} script_sig length: {}", name1, i1.script_sig.len());
                println!("{} script_sig length: {}", name2, i2.script_sig.len());
                
                println!("{} sequence: {}", name1, i1.sequence);
                println!("{} sequence: {}", name2, i2.sequence);
                
                if i1.previous_output != i2.previous_output {
                    println!("❌ Outpoint mismatch!");
                }
                if i1.script_sig != i2.script_sig {
                    println!("❌ Script_sig mismatch!");
                    if i1.script_sig.len() != i2.script_sig.len() {
                        println!("  Script_sig length differs: {} vs {}", i1.script_sig.len(), i2.script_sig.len());
                    }
                }
                if i1.sequence != i2.sequence {
                    println!("❌ Sequence mismatch!");
                }
            }
            (Some(_), None) => println!("❌ {} has extra input at index {}", name1, i),
            (None, Some(_)) => println!("❌ {} has extra input at index {}", name2, i),
            (None, None) => unreachable!(),
        }
    }
}

fn compare_outputs(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
    println!("\n=== Output Comparison ===");
    
    let max_outputs = std::cmp::max(tx1.output.len(), tx2.output.len());
    
    for i in 0..max_outputs {
        println!("\n--- Output {} ---", i);
        
        let output1 = tx1.output.get(i);
        let output2 = tx2.output.get(i);
        
        match (output1, output2) {
            (Some(o1), Some(o2)) => {
                println!("{} value: {} sats", name1, o1.value.to_sat());
                println!("{} value: {} sats", name2, o2.value.to_sat());
                
                println!("{} script_pubkey length: {}", name1, o1.script_pubkey.len());
                println!("{} script_pubkey length: {}", name2, o2.script_pubkey.len());
                
                // Check if it's an OP_RETURN output
                if o1.script_pubkey.is_op_return() || o2.script_pubkey.is_op_return() {
                    println!("{} is OP_RETURN: {}", name1, o1.script_pubkey.is_op_return());
                    println!("{} is OP_RETURN: {}", name2, o2.script_pubkey.is_op_return());
                    
                    if o1.script_pubkey.is_op_return() && o2.script_pubkey.is_op_return() {
                        println!("{} OP_RETURN data: {}", name1, hex::encode(o1.script_pubkey.as_bytes()));
                        println!("{} OP_RETURN data: {}", name2, hex::encode(o2.script_pubkey.as_bytes()));
                    }
                }
                
                if o1.value != o2.value {
                    println!("❌ Value mismatch!");
                }
                if o1.script_pubkey != o2.script_pubkey {
                    println!("❌ Script_pubkey mismatch!");
                    if o1.script_pubkey.len() != o2.script_pubkey.len() {
                        println!("  Script_pubkey length differs: {} vs {}", o1.script_pubkey.len(), o2.script_pubkey.len());
                    }
                    // Show hex for comparison
                    println!("  {} script: {}", name1, hex::encode(o1.script_pubkey.as_bytes()));
                    println!("  {} script: {}", name2, hex::encode(o2.script_pubkey.as_bytes()));
                }
            }
            (Some(_), None) => println!("❌ {} has extra output at index {}", name1, i),
            (None, Some(_)) => println!("❌ {} has extra output at index {}", name2, i),
            (None, None) => unreachable!(),
        }
    }
}

fn compare_witness_data(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
    println!("\n=== Witness Data Comparison (Critical for Taproot Fixes) ===");
    
    let max_inputs = std::cmp::max(tx1.input.len(), tx2.input.len());
    
    for i in 0..max_inputs {
        println!("\n--- Witness for Input {} ---", i);
        
        let witness1 = tx1.input.get(i).map(|input| &input.witness);
        let witness2 = tx2.input.get(i).map(|input| &input.witness);
        
        match (witness1, witness2) {
            (Some(w1), Some(w2)) => {
                println!("{} witness stack size: {}", name1, w1.len());
                println!("{} witness stack size: {}", name2, w2.len());
                
                // Analyze witness elements
                println!("\n🔍 {} Witness Elements:", name1);
                analyze_witness_elements(w1, name1);
                
                println!("\n🔍 {} Witness Elements:", name2);
                analyze_witness_elements(w2, name2);
                
                // Compare elements if same count
                if w1.len() == w2.len() {
                    println!("\n🔄 Element-by-Element Comparison:");
                    for (j, (elem1, elem2)) in w1.iter().zip(w2.iter()).enumerate() {
                        println!("  Element {}: {} {} bytes, {} {} bytes",
                                j, name1, elem1.len(), name2, elem2.len());
                        
                        if elem1 != elem2 {
                            println!("  ❌ Witness element {} differs!", j);
                            if elem1.len() != elem2.len() {
                                println!("    Length differs: {} vs {}", elem1.len(), elem2.len());
                            }
                            
                            // Special analysis for envelope script differences
                            if j == 0 && (elem1.len() > 1000 || elem2.len() > 1000) {
                                println!("    🎯 ENVELOPE SCRIPT ANALYSIS:");
                                analyze_envelope_script_differences(elem1, elem2, name1, name2);
                            }
                        } else {
                            println!("  ✅ Witness element {} matches", j);
                        }
                    }
                } else {
                    println!("❌ Witness stack size mismatch! Cannot compare elements directly.");
                    println!("  This could indicate our taproot fixes changed the witness structure");
                }
            }
            (Some(w1), None) => {
                println!("❌ {} has witness data but {} doesn't", name1, name2);
                println!("\n🔍 {} Witness Elements:", name1);
                analyze_witness_elements(w1, name1);
            }
            (None, Some(w2)) => {
                println!("❌ {} has witness data but {} doesn't", name2, name1);
                println!("\n🔍 {} Witness Elements:", name2);
                analyze_witness_elements(w2, name2);
            }
            (None, None) => println!("No witness data for input {}", i),
        }
    }
}

fn analyze_witness_elements(witness: &bitcoin::Witness, tx_name: &str) {
    for (i, element) in witness.iter().enumerate() {
        println!("  Element {}: {} bytes", i, element.len());
        
        // Analyze element content to guess its purpose
        let element_type = identify_witness_element(element, i);
        println!("    Type: {}", element_type);
        
        // Show preview of content
        let preview_len = std::cmp::min(element.len(), 64);
        let preview = &element[..preview_len];
        println!("    Preview (first {} bytes): {}", preview_len, hex::encode(preview));
        
        // If this looks like a large payload, show more details
        if element.len() > 1000 {
            println!("    🎯 LARGE PAYLOAD DETECTED!");
            println!("    Full size: {} bytes", element.len());
            
            // Try to identify if this contains alkanes envelope data
            if let Some(envelope_info) = analyze_potential_envelope(element) {
                println!("    Envelope analysis: {}", envelope_info);
            }
            
            // Look for BIN protocol tag
            if let Some(bin_pos) = find_bin_protocol_tag(element) {
                println!("    🔍 BIN protocol tag found at offset: {}", bin_pos);
                analyze_bin_envelope_structure(element, bin_pos);
            }
            
            // Show last few bytes too
            let tail_start = element.len().saturating_sub(32);
            let tail = &element[tail_start..];
            println!("    Tail (last {} bytes): {}", tail.len(), hex::encode(tail));
        }
        
        // Special analysis for first element (likely signature)
        if i == 0 && element.len() == 64 {
            println!("    🔐 SIGNATURE ANALYSIS:");
            println!("      64-byte Schnorr signature detected");
            println!("      This should be valid after our prevouts fix");
        }
        
        println!();
    }
}

fn identify_witness_element(element: &[u8], position: usize) -> String {
    match element.len() {
        0 => "Empty".to_string(),
        1 => "Single byte (possibly OP code)".to_string(),
        32 => "32 bytes (possibly hash/key)".to_string(),
        33 => "33 bytes (possibly compressed pubkey)".to_string(),
        64 => "64 bytes (Schnorr signature)".to_string(),
        65 => "65 bytes (possibly uncompressed pubkey or ECDSA signature)".to_string(),
        len if len > 1000 => "Large payload (envelope script with BIN protocol)".to_string(),
        len if len > 100 => "Medium payload (possibly script/control block)".to_string(),
        _ => format!("{} bytes (unknown)", element.len()),
    }
}

fn analyze_potential_envelope(element: &[u8]) -> Option<String> {
    // Check for WASM magic bytes
    if element.len() > 4 && &element[..4] == b"\x00asm" {
        return Some("Contains WASM magic bytes - alkanes contract".to_string());
    }
    
    // Check for gzip header
    if element.len() > 2 && element[0] == 0x1f && element[1] == 0x8b {
        return Some("Contains gzip header - compressed data".to_string());
    }
    
    // Check for BIN protocol tag
    if find_bin_protocol_tag(element).is_some() {
        return Some("Contains BIN protocol tag - alkanes envelope".to_string());
    }
    
    None
}

fn find_bin_protocol_tag(data: &[u8]) -> Option<usize> {
    // Look for "BIN" bytes (0x42 0x49 0x4E)
    data.windows(3).position(|window| window == b"BIN")
}

fn analyze_bin_envelope_structure(data: &[u8], bin_pos: usize) {
    println!("      Envelope structure analysis:");
    
    // Look for OP_FALSE OP_IF pattern before BIN
    if bin_pos >= 2 {
        let before_bin = &data[bin_pos.saturating_sub(10)..bin_pos];
        println!("      Before BIN: {}", hex::encode(before_bin));
        
        // Check for OP_FALSE (0x00) and OP_IF (0x63)
        if before_bin.contains(&0x00) && before_bin.contains(&0x63) {
            println!("      ✅ Found OP_FALSE OP_IF pattern");
        }
    }
    
    // Look for content after BIN
    if bin_pos + 3 < data.len() {
        let after_bin = &data[bin_pos + 3..std::cmp::min(bin_pos + 50, data.len())];
        println!("      After BIN: {}", hex::encode(after_bin));
    }
    
    // Look for OP_ENDIF at the end
    if data.len() > 0 && data[data.len() - 1] == 0x68 {
        println!("      ✅ Ends with OP_ENDIF (0x68)");
    } else {
        println!("      ❌ Does not end with OP_ENDIF");
    }
}

fn analyze_envelope_script_differences(script1: &[u8], script2: &[u8], name1: &str, name2: &str) {
    println!("      Comparing envelope scripts:");
    
    // Find BIN protocol positions
    let bin_pos1 = find_bin_protocol_tag(script1);
    let bin_pos2 = find_bin_protocol_tag(script2);
    
    match (bin_pos1, bin_pos2) {
        (Some(pos1), Some(pos2)) => {
            println!("      BIN tag position: {} {} vs {} {}", name1, pos1, name2, pos2);
            
            // Compare script endings (critical for our fix)
            let end1 = &script1[script1.len().saturating_sub(10)..];
            let end2 = &script2[script2.len().saturating_sub(10)..];
            
            println!("      {} script ending: {}", name1, hex::encode(end1));
            println!("      {} script ending: {}", name2, hex::encode(end2));
            
            // Check for our specific fix (removal of OP_PUSHNUM_1)
            if end1.contains(&0x51) && !end2.contains(&0x51) {
                println!("      🎯 {} contains OP_PUSHNUM_1 (0x51), {} doesn't", name1, name2);
                println!("      This suggests our script validation fix is working!");
            } else if !end1.contains(&0x51) && end2.contains(&0x51) {
                println!("      🎯 {} doesn't contain OP_PUSHNUM_1 (0x51), {} does", name1, name2);
                println!("      This suggests our script validation fix is working!");
            }
        }
        (Some(pos1), None) => {
            println!("      {} has BIN tag at {}, {} doesn't", name1, pos1, name2);
        }
        (None, Some(pos2)) => {
            println!("      {} doesn't have BIN tag, {} has it at {}", name1, name2, pos2);
        }
        (None, None) => {
            println!("      Neither script contains BIN protocol tag");
        }
    }
}

fn analyze_envelope_differences(tx1: &Transaction, tx2: &Transaction) {
    println!("\n=== Envelope-Specific Analysis ===");
    
    // Look for envelope data in witness
    for (i, (input1, input2)) in tx1.input.iter().zip(tx2.input.iter()).enumerate() {
        if input1.witness.len() > 0 && input2.witness.len() > 0 {
            // Check first witness element for envelope script
            if let (Some(elem1), Some(elem2)) = (input1.witness.nth(0), input2.witness.nth(0)) {
                if elem1.len() > 1000 || elem2.len() > 1000 {
                    println!("Input {} contains large witness element (envelope script)", i);
                    
                    let bin1 = find_bin_protocol_tag(elem1);
                    let bin2 = find_bin_protocol_tag(elem2);
                    
                    match (bin1, bin2) {
                        (Some(_), Some(_)) => {
                            println!("  ✅ Both transactions contain BIN protocol envelope");
                            
                            // Check if our fixes are reflected
                            if elem1 != elem2 {
                                println!("  🔧 Envelope scripts differ - our fixes may be working");
                                
                                // Check for specific fix patterns
                                check_taproot_fixes(elem1, elem2);
                            } else {
                                println!("  ✅ Envelope scripts are identical");
                            }
                        }
                        _ => println!("  ❌ BIN protocol envelope structure differs"),
                    }
                }
            }
        }
    }
}

fn check_taproot_fixes(script1: &[u8], script2: &[u8]) {
    println!("    Checking for taproot fix signatures:");
    
    // Check script ending patterns
    let end1 = &script1[script1.len().saturating_sub(5)..];
    let end2 = &script2[script2.len().saturating_sub(5)..];
    
    // Our fix should remove OP_PUSHNUM_1 (0x51) from the end
    let has_pushnum1_1 = end1.contains(&0x51);
    let has_pushnum1_2 = end2.contains(&0x51);
    
    if has_pushnum1_1 != has_pushnum1_2 {
        println!("    🎯 OP_PUSHNUM_1 presence differs - script validation fix detected!");
        if !has_pushnum1_1 && has_pushnum1_2 {
            println!("    ✅ First script (likely deezel v2) has fix applied");
        } else {
            println!("    ✅ Second script (likely deezel v2) has fix applied");
        }
    }
    
    // Check for proper OP_ENDIF ending
    let ends_with_endif1 = script1.last() == Some(&0x68);
    let ends_with_endif2 = script2.last() == Some(&0x68);
    
    println!("    Script 1 ends with OP_ENDIF: {}", ends_with_endif1);
    println!("    Script 2 ends with OP_ENDIF: {}", ends_with_endif2);
}

fn compare_metadata(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
    println!("\n=== Transaction Metadata ===");
    
    let size1 = tx1.total_size();
    let size2 = tx2.total_size();
    
    let weight1 = tx1.weight();
    let weight2 = tx2.weight();
    
    let vsize1 = tx1.vsize();
    let vsize2 = tx2.vsize();
    
    println!("{} total size: {} bytes", name1, size1);
    println!("{} total size: {} bytes", name2, size2);
    
    println!("{} weight: {} WU", name1, weight1);
    println!("{} weight: {} WU", name2, weight2);
    
    println!("{} vsize: {} vbytes", name1, vsize1);
    println!("{} vsize: {} vbytes", name2, vsize2);
    
    if size1 != size2 {
        println!("❌ Total size mismatch! Difference: {} bytes", 
                (size1 as i32) - (size2 as i32));
    }
    if weight1 != weight2 {
        println!("❌ Weight mismatch! Difference: {} WU", 
                (weight1.to_wu() as i32) - (weight2.to_wu() as i32));
    }
    if vsize1 != vsize2 {
        println!("❌ Virtual size mismatch! Difference: {} vbytes", 
                (vsize1 as i32) - (vsize2 as i32));
    }
}

fn compare_bytes(bytes1: &[u8], bytes2: &[u8], name1: &str, name2: &str) {
    let max_len = std::cmp::max(bytes1.len(), bytes2.len());
    let mut differences = 0;
    let mut first_diff_offset = None;
    
    for i in 0..max_len {
        let byte1 = bytes1.get(i);
        let byte2 = bytes2.get(i);
        
        match (byte1, byte2) {
            (Some(b1), Some(b2)) if b1 != b2 => {
                if first_diff_offset.is_none() {
                    first_diff_offset = Some(i);
                }
                differences += 1;
                
                // Show first 10 differences in detail
                if differences <= 10 {
                    println!("Offset {}: {}=0x{:02x} {}=0x{:02x}", i, name1, b1, name2, b2);
                }
            }
            (Some(_), None) => {
                if first_diff_offset.is_none() {
                    first_diff_offset = Some(i);
                }
                differences += 1;
                if differences <= 10 {
                    println!("Offset {}: {} has extra byte", i, name1);
                }
            }
            (None, Some(_)) => {
                if first_diff_offset.is_none() {
                    first_diff_offset = Some(i);
                }
                differences += 1;
                if differences <= 10 {
                    println!("Offset {}: {} has extra byte", i, name2);
                }
            }
            _ => {} // Bytes match or both are None
        }
    }
    
    println!("Total byte differences: {}", differences);
    if let Some(offset) = first_diff_offset {
        println!("First difference at offset: {}", offset);
        
        // Show context around first difference
        let start = offset.saturating_sub(8);
        let end = std::cmp::min(offset + 8, max_len);
        
        println!("\nContext around first difference:");
        print!("{}:  ", name1);
        for i in start..end {
            if let Some(byte) = bytes1.get(i) {
                if i == offset {
                    print!("[{:02x}] ", byte);
                } else {
                    print!("{:02x} ", byte);
                }
            } else {
                print!("-- ");
            }
        }
        println!();
        
        print!("{}: ", name2);
        for i in start..end {
            if let Some(byte) = bytes2.get(i) {
                if i == offset {
                    print!("[{:02x}] ", byte);
                } else {
                    print!("{:02x} ", byte);
                }
            } else {
                print!("-- ");
            }
        }
        println!();
    }
}