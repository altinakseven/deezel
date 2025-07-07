//! Transaction comparison test for deezel reveal transactions
//!
//! This test compares ./examples/tx.hex (deezel-built reveal tx) with 
//! ./examples/working-tx.hex (working integration test reveal tx) to identify
//! differences in transaction structure and content.

use anyhow::Result;
use bitcoin::{Transaction, consensus::deserialize};
use std::fs;

/// Compare two hex-encoded transactions and analyze differences
#[tokio::test]
async fn test_compare_reveal_transactions() -> Result<()> {
    println!("=== Transaction Comparison Test ===");
    
    // Read the hex files
    let deezel_hex = fs::read_to_string("./examples/tx.hex")
        .map_err(|e| anyhow::anyhow!("Failed to read ./examples/tx.hex: {}", e))?;
    
    let working_hex = fs::read_to_string("./examples/working-tx.hex")
        .map_err(|e| anyhow::anyhow!("Failed to read ./examples/working-tx.hex: {}", e))?;
    
    // Clean up hex strings (remove whitespace/newlines)
    let deezel_hex = deezel_hex.trim().replace('\n', "").replace(' ', "");
    let working_hex = working_hex.trim().replace('\n', "").replace(' ', "");
    
    println!("Deezel tx hex length: {} characters", deezel_hex.len());
    println!("Working tx hex length: {} characters", working_hex.len());
    
    // Parse hex to bytes
    let deezel_bytes = hex::decode(&deezel_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode deezel hex: {}", e))?;
    
    let working_bytes = hex::decode(&working_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode working hex: {}", e))?;
    
    println!("Deezel tx bytes length: {} bytes", deezel_bytes.len());
    println!("Working tx bytes length: {} bytes", working_bytes.len());
    
    // Parse transactions using rust-bitcoin
    let deezel_tx: Transaction = deserialize(&deezel_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse deezel transaction: {}", e))?;
    
    let working_tx: Transaction = deserialize(&working_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse working transaction: {}", e))?;
    
    println!("\n=== Basic Transaction Comparison ===");
    println!("Deezel TXID: {}", deezel_tx.compute_txid());
    println!("Working TXID: {}", working_tx.compute_txid());
    
    // Compare basic transaction properties
    compare_basic_properties(&deezel_tx, &working_tx);
    
    // Compare inputs
    compare_inputs(&deezel_tx, &working_tx);
    
    // Compare outputs
    compare_outputs(&deezel_tx, &working_tx);
    
    // Compare witness data
    compare_witness_data(&deezel_tx, &working_tx);
    
    // Compare locktime and version
    compare_metadata(&deezel_tx, &working_tx);
    
    // Detailed byte-by-byte comparison if transactions differ
    if deezel_bytes != working_bytes {
        println!("\n=== Byte-by-byte Differences ===");
        compare_bytes(&deezel_bytes, &working_bytes);
    } else {
        println!("\n✅ Transactions are identical!");
    }
    
    Ok(())
}

fn compare_basic_properties(deezel_tx: &Transaction, working_tx: &Transaction) {
    println!("\n=== Basic Properties ===");
    println!("Deezel version: {}", deezel_tx.version.0);
    println!("Working version: {}", working_tx.version.0);
    
    println!("Deezel input count: {}", deezel_tx.input.len());
    println!("Working input count: {}", working_tx.input.len());
    
    println!("Deezel output count: {}", deezel_tx.output.len());
    println!("Working output count: {}", working_tx.output.len());
    
    println!("Deezel locktime: {}", deezel_tx.lock_time);
    println!("Working locktime: {}", working_tx.lock_time);
    
    if deezel_tx.version != working_tx.version {
        println!("❌ Version mismatch!");
    }
    if deezel_tx.input.len() != working_tx.input.len() {
        println!("❌ Input count mismatch!");
    }
    if deezel_tx.output.len() != working_tx.output.len() {
        println!("❌ Output count mismatch!");
    }
    if deezel_tx.lock_time != working_tx.lock_time {
        println!("❌ Locktime mismatch!");
    }
}

fn compare_inputs(deezel_tx: &Transaction, working_tx: &Transaction) {
    println!("\n=== Input Comparison ===");
    
    let max_inputs = std::cmp::max(deezel_tx.input.len(), working_tx.input.len());
    
    for i in 0..max_inputs {
        println!("\n--- Input {} ---", i);
        
        let deezel_input = deezel_tx.input.get(i);
        let working_input = working_tx.input.get(i);
        
        match (deezel_input, working_input) {
            (Some(d), Some(w)) => {
                println!("Deezel outpoint: {}:{}", d.previous_output.txid, d.previous_output.vout);
                println!("Working outpoint: {}:{}", w.previous_output.txid, w.previous_output.vout);
                
                println!("Deezel script_sig length: {}", d.script_sig.len());
                println!("Working script_sig length: {}", w.script_sig.len());
                
                println!("Deezel sequence: {}", d.sequence);
                println!("Working sequence: {}", w.sequence);
                
                if d.previous_output != w.previous_output {
                    println!("❌ Outpoint mismatch!");
                }
                if d.script_sig != w.script_sig {
                    println!("❌ Script_sig mismatch!");
                    if d.script_sig.len() != w.script_sig.len() {
                        println!("  Script_sig length differs: {} vs {}", d.script_sig.len(), w.script_sig.len());
                    }
                }
                if d.sequence != w.sequence {
                    println!("❌ Sequence mismatch!");
                }
            }
            (Some(_), None) => println!("❌ Deezel has extra input at index {}", i),
            (None, Some(_)) => println!("❌ Working has extra input at index {}", i),
            (None, None) => unreachable!(),
        }
    }
}

fn compare_outputs(deezel_tx: &Transaction, working_tx: &Transaction) {
    println!("\n=== Output Comparison ===");
    
    let max_outputs = std::cmp::max(deezel_tx.output.len(), working_tx.output.len());
    
    for i in 0..max_outputs {
        println!("\n--- Output {} ---", i);
        
        let deezel_output = deezel_tx.output.get(i);
        let working_output = working_tx.output.get(i);
        
        match (deezel_output, working_output) {
            (Some(d), Some(w)) => {
                println!("Deezel value: {} sats", d.value.to_sat());
                println!("Working value: {} sats", w.value.to_sat());
                
                println!("Deezel script_pubkey length: {}", d.script_pubkey.len());
                println!("Working script_pubkey length: {}", w.script_pubkey.len());
                
                // Check if it's an OP_RETURN output
                if d.script_pubkey.is_op_return() || w.script_pubkey.is_op_return() {
                    println!("Deezel is OP_RETURN: {}", d.script_pubkey.is_op_return());
                    println!("Working is OP_RETURN: {}", w.script_pubkey.is_op_return());
                    
                    if d.script_pubkey.is_op_return() && w.script_pubkey.is_op_return() {
                        println!("Deezel OP_RETURN data: {}", hex::encode(d.script_pubkey.as_bytes()));
                        println!("Working OP_RETURN data: {}", hex::encode(w.script_pubkey.as_bytes()));
                    }
                }
                
                if d.value != w.value {
                    println!("❌ Value mismatch!");
                }
                if d.script_pubkey != w.script_pubkey {
                    println!("❌ Script_pubkey mismatch!");
                    if d.script_pubkey.len() != w.script_pubkey.len() {
                        println!("  Script_pubkey length differs: {} vs {}", d.script_pubkey.len(), w.script_pubkey.len());
                    }
                    // Show hex for comparison
                    println!("  Deezel script: {}", hex::encode(d.script_pubkey.as_bytes()));
                    println!("  Working script: {}", hex::encode(w.script_pubkey.as_bytes()));
                }
            }
            (Some(_), None) => println!("❌ Deezel has extra output at index {}", i),
            (None, Some(_)) => println!("❌ Working has extra output at index {}", i),
            (None, None) => unreachable!(),
        }
    }
}

fn compare_witness_data(deezel_tx: &Transaction, working_tx: &Transaction) {
    println!("\n=== Witness Data Comparison ===");
    
    let max_inputs = std::cmp::max(deezel_tx.input.len(), working_tx.input.len());
    
    for i in 0..max_inputs {
        println!("\n--- Witness for Input {} ---", i);
        
        let deezel_witness = deezel_tx.input.get(i).map(|input| &input.witness);
        let working_witness = working_tx.input.get(i).map(|input| &input.witness);
        
        match (deezel_witness, working_witness) {
            (Some(d), Some(w)) => {
                println!("Deezel witness stack size: {}", d.len());
                println!("Working witness stack size: {}", w.len());
                
                // Analyze deezel witness elements
                println!("\n🔍 DEEZEL Witness Elements:");
                analyze_witness_elements(d, "Deezel");
                
                // Analyze working witness elements
                println!("\n🔍 WORKING Witness Elements:");
                analyze_witness_elements(w, "Working");
                
                // Compare elements if same count
                if d.len() == w.len() {
                    println!("\n🔄 Element-by-Element Comparison:");
                    for (j, (d_elem, w_elem)) in d.iter().zip(w.iter()).enumerate() {
                        println!("  Element {}: Deezel {} bytes, Working {} bytes",
                                j, d_elem.len(), w_elem.len());
                        
                        if d_elem != w_elem {
                            println!("  ❌ Witness element {} differs!", j);
                            if d_elem.len() != w_elem.len() {
                                println!("    Length differs: {} vs {}", d_elem.len(), w_elem.len());
                            }
                        } else {
                            println!("  ✅ Witness element {} matches", j);
                        }
                    }
                } else {
                    println!("❌ Witness stack size mismatch! Cannot compare elements directly.");
                }
            }
            (Some(d), None) => {
                println!("❌ Deezel has witness data but working doesn't");
                println!("\n🔍 DEEZEL Witness Elements:");
                analyze_witness_elements(d, "Deezel");
            }
            (None, Some(w)) => {
                println!("❌ Working has witness data but deezel doesn't");
                println!("\n🔍 WORKING Witness Elements:");
                analyze_witness_elements(w, "Working");
            }
            (None, None) => println!("No witness data for input {}", i),
        }
    }
}

/// Analyze witness elements to identify their likely purpose
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
            
            // Show last few bytes too
            let tail_start = element.len().saturating_sub(32);
            let tail = &element[tail_start..];
            println!("    Tail (last {} bytes): {}", tail.len(), hex::encode(tail));
        }
        
        // Special analysis for first element
        if i == 0 {
            println!("    🥇 FIRST ELEMENT ANALYSIS:");
            analyze_first_witness_element(element);
        }
        
        println!();
    }
}

/// Identify what type of witness element this likely is
fn identify_witness_element(element: &[u8], position: usize) -> String {
    match element.len() {
        0 => "Empty".to_string(),
        1 => "Single byte (possibly OP code)".to_string(),
        32 => "32 bytes (possibly hash/key)".to_string(),
        33 => "33 bytes (possibly compressed pubkey)".to_string(),
        64 => "64 bytes (possibly signature)".to_string(),
        65 => "65 bytes (possibly uncompressed pubkey or signature)".to_string(),
        len if len > 1000 => "Large payload (possibly envelope/script)".to_string(),
        len if len > 100 => "Medium payload (possibly script/data)".to_string(),
        _ => format!("{} bytes (unknown)", element.len()),
    }
}

/// Analyze the first witness element specifically
fn analyze_first_witness_element(element: &[u8]) -> String {
    if element.is_empty() {
        return "Empty first element (common for P2TR key path)".to_string();
    }
    
    // Check if it looks like a signature
    if element.len() == 64 || element.len() == 65 {
        println!("      Possible signature (length: {})", element.len());
        if element.len() == 64 {
            println!("      Schnorr signature format");
        } else {
            println!("      ECDSA signature format");
        }
    }
    
    // Check if it's a single byte (possibly for script path)
    if element.len() == 1 {
        println!("      Single byte: 0x{:02x}", element[0]);
        match element[0] {
            0x01 => println!("      Possibly OP_TRUE or script path indicator"),
            0x00 => println!("      Possibly OP_FALSE or empty push"),
            _ => println!("      Unknown single byte value"),
        }
    }
    
    // Check for script-like content
    if element.len() > 10 && element.len() < 1000 {
        println!("      Possible script or control block");
        // Look for common script opcodes
        let has_opcodes = element.iter().any(|&b| {
            matches!(b, 0x51..=0x60 | 0x6a | 0x76 | 0x87 | 0x88 | 0xa9 | 0xac)
        });
        if has_opcodes {
            println!("      Contains potential script opcodes");
        }
    }
    
    "Analyzed".to_string()
}

/// Try to analyze if this element contains alkanes envelope data
fn analyze_potential_envelope(element: &[u8]) -> Option<String> {
    // Look for common patterns in alkanes envelopes
    
    // Check for WASM magic bytes
    if element.len() > 4 && &element[..4] == b"\x00asm" {
        return Some("Contains WASM magic bytes - likely alkanes contract".to_string());
    }
    
    // Check for gzip header
    if element.len() > 2 && element[0] == 0x1f && element[1] == 0x8b {
        return Some("Contains gzip header - likely compressed data".to_string());
    }
    
    // Check for high entropy (compressed/encrypted data)
    let entropy = calculate_entropy(element);
    if entropy > 7.5 {
        return Some(format!("High entropy ({:.2}) - likely compressed/encrypted", entropy));
    }
    
    // Check for repeated patterns
    let mut pattern_count = 0;
    for window in element.windows(4) {
        if element.windows(4).filter(|w| *w == window).count() > 1 {
            pattern_count += 1;
        }
    }
    
    if pattern_count > element.len() / 20 {
        return Some("Contains repeated patterns - possibly structured data".to_string());
    }
    
    None
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

fn compare_metadata(deezel_tx: &Transaction, working_tx: &Transaction) {
    println!("\n=== Transaction Metadata ===");
    
    let deezel_size = deezel_tx.total_size();
    let working_size = working_tx.total_size();
    
    let deezel_weight = deezel_tx.weight();
    let working_weight = working_tx.weight();
    
    let deezel_vsize = deezel_tx.vsize();
    let working_vsize = working_tx.vsize();
    
    println!("Deezel total size: {} bytes", deezel_size);
    println!("Working total size: {} bytes", working_size);
    
    println!("Deezel weight: {} WU", deezel_weight);
    println!("Working weight: {} WU", working_weight);
    
    println!("Deezel vsize: {} vbytes", deezel_vsize);
    println!("Working vsize: {} vbytes", working_vsize);
    
    if deezel_size != working_size {
        println!("❌ Total size mismatch! Difference: {} bytes", 
                (deezel_size as i32) - (working_size as i32));
    }
    if deezel_weight != working_weight {
        println!("❌ Weight mismatch! Difference: {} WU", 
                (deezel_weight.to_wu() as i32) - (working_weight.to_wu() as i32));
    }
    if deezel_vsize != working_vsize {
        println!("❌ Virtual size mismatch! Difference: {} vbytes", 
                (deezel_vsize as i32) - (working_vsize as i32));
    }
}

fn compare_bytes(deezel_bytes: &[u8], working_bytes: &[u8]) {
    let max_len = std::cmp::max(deezel_bytes.len(), working_bytes.len());
    let mut differences = 0;
    let mut first_diff_offset = None;
    
    for i in 0..max_len {
        let deezel_byte = deezel_bytes.get(i);
        let working_byte = working_bytes.get(i);
        
        match (deezel_byte, working_byte) {
            (Some(d), Some(w)) if d != w => {
                if first_diff_offset.is_none() {
                    first_diff_offset = Some(i);
                }
                differences += 1;
                
                // Show first 10 differences in detail
                if differences <= 10 {
                    println!("Offset {}: deezel=0x{:02x} working=0x{:02x}", i, d, w);
                }
            }
            (Some(_), None) => {
                if first_diff_offset.is_none() {
                    first_diff_offset = Some(i);
                }
                differences += 1;
                if differences <= 10 {
                    println!("Offset {}: deezel has extra byte", i);
                }
            }
            (None, Some(_)) => {
                if first_diff_offset.is_none() {
                    first_diff_offset = Some(i);
                }
                differences += 1;
                if differences <= 10 {
                    println!("Offset {}: working has extra byte", i);
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
        print!("Deezel:  ");
        for i in start..end {
            if let Some(byte) = deezel_bytes.get(i) {
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
        
        print!("Working: ");
        for i in start..end {
            if let Some(byte) = working_bytes.get(i) {
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

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test that we can parse a simple transaction hex
    #[test]
    fn test_parse_simple_transaction() {
        // Simple P2PKH transaction hex (mainnet)
        let hex = "0100000001a1b2c3d4e5f6071819202122232425262728293031323334353637383940414243000000006a47304402203e4516da7253cf068effec6b95c41221c0cf3a8e6ccb8cbf1725b562e9afde2c022054e1c258c2981cdfba5df64e841288f76c5c0a8b0e0b2e3f4d5c6b7a8f9e0d1c0121038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508ffffffff02809698000000000017a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2687006a18230000000017a9148f33a914c5f6d3c6b7a8f9e0d1c2b3a4c5d6e7f8876500000000";
        
        let bytes = hex::decode(hex).expect("Failed to decode hex");
        let _tx: Transaction = deserialize(&bytes).expect("Failed to parse transaction");
        
        // If we get here, parsing worked
        assert!(true);
    }
}