//! Comprehensive transaction comparison: Working vs Deezel V2 vs Deezel V3
//! 
//! This test analyzes the structural differences between:
//! - ./examples/working-tx.hex (known working transaction)
//! - ./examples/deezel-v2-tx.hex (broken deezel transaction)  
//! - ./examples/deezel-v3-tex.hex (fixed deezel transaction)
//!
//! Key analysis points:
//! - Input count and witness structure
//! - Witness element sizes and content
//! - Transaction size and efficiency
//! - Alkanes indexer compatibility

use anyhow::Result;
use bitcoin::{Transaction, Witness};
use hex;
use std::fs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comprehensive_transaction_comparison() {
        println!("🔍 === COMPREHENSIVE TRANSACTION COMPARISON ===");
        println!();

        // Load all three transactions
        let working_tx = load_transaction("./examples/working-tx.hex", "Working Transaction").unwrap();
        let deezel_v2_tx = load_transaction("./examples/deezel-v2-tx.hex", "Deezel V2 Transaction").unwrap();
        let deezel_v3_tx = load_transaction("./examples/deezel-v3-tex.hex", "Deezel V3 Transaction").unwrap();

        println!("📊 === BASIC TRANSACTION METRICS ===");
        compare_basic_metrics(&working_tx, &deezel_v2_tx, &deezel_v3_tx);
        println!();

        println!("🔧 === INPUT STRUCTURE ANALYSIS ===");
        compare_input_structure(&working_tx, &deezel_v2_tx, &deezel_v3_tx);
        println!();

        println!("👁️ === WITNESS STRUCTURE ANALYSIS ===");
        compare_witness_structure(&working_tx, &deezel_v2_tx, &deezel_v3_tx);
        println!();

        println!("🏷️ === ALKANES INDEXER COMPATIBILITY ===");
        analyze_alkanes_compatibility(&working_tx, &deezel_v2_tx, &deezel_v3_tx);
        println!();

        println!("📈 === IMPROVEMENT ANALYSIS ===");
        analyze_improvements(&working_tx, &deezel_v2_tx, &deezel_v3_tx);
        println!();

        println!("✅ === SUMMARY ===");
        print_summary(&working_tx, &deezel_v2_tx, &deezel_v3_tx);
    }

    fn load_transaction(path: &str, name: &str) -> Result<Transaction> {
        let hex_content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;
        
        let cleaned_hex = hex_content.trim().trim_start_matches("0x");
        let tx_bytes = hex::decode(cleaned_hex)
            .map_err(|e| anyhow::anyhow!("Failed to decode hex for {}: {}", name, e))?;
        
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize {}: {}", name, e))?;
        
        println!("✅ Loaded {}: {} bytes", name, tx_bytes.len());
        Ok(tx)
    }

    fn compare_basic_metrics(working: &Transaction, v2: &Transaction, v3: &Transaction) {
        println!("Transaction Sizes:");
        println!("  Working:   {:6} bytes ({:5} vbytes, {:6} WU)", 
                 working.total_size(), working.vsize(), working.weight().to_wu());
        println!("  Deezel V2: {:6} bytes ({:5} vbytes, {:6} WU)", 
                 v2.total_size(), v2.vsize(), v2.weight().to_wu());
        println!("  Deezel V3: {:6} bytes ({:5} vbytes, {:6} WU)", 
                 v3.total_size(), v3.vsize(), v3.weight().to_wu());
        
        println!();
        println!("Input/Output Counts:");
        println!("  Working:   {} inputs, {} outputs", working.input.len(), working.output.len());
        println!("  Deezel V2: {} inputs, {} outputs", v2.input.len(), v2.output.len());
        println!("  Deezel V3: {} inputs, {} outputs", v3.input.len(), v3.output.len());
    }

    fn compare_input_structure(working: &Transaction, v2: &Transaction, v3: &Transaction) {
        println!("Input Structure Comparison:");
        
        // Working transaction
        println!("  Working Transaction:");
        for (i, input) in working.input.iter().enumerate() {
            println!("    Input {}: {} witness items", i, input.witness.len());
        }
        
        // Deezel V2 transaction  
        println!("  Deezel V2 Transaction:");
        for (i, input) in v2.input.iter().enumerate() {
            println!("    Input {}: {} witness items", i, input.witness.len());
        }
        
        // Deezel V3 transaction
        println!("  Deezel V3 Transaction:");
        for (i, input) in v3.input.iter().enumerate() {
            println!("    Input {}: {} witness items", i, input.witness.len());
        }
        
        // Analysis
        println!();
        println!("Structure Analysis:");
        if working.input.len() == 1 && v2.input.len() == 2 && v3.input.len() == 1 {
            println!("  ✅ V3 FIXED: Reduced from 2 inputs (V2) back to 1 input (like working)");
        } else if v3.input.len() == 1 {
            println!("  ✅ V3 has correct single input structure");
        } else {
            println!("  ⚠️  V3 still has multiple inputs: {}", v3.input.len());
        }
    }

    fn compare_witness_structure(working: &Transaction, v2: &Transaction, v3: &Transaction) {
        println!("Detailed Witness Analysis:");
        
        // Analyze working transaction
        println!("  Working Transaction (Reference):");
        if !working.input.is_empty() {
            analyze_witness_elements(&working.input[0].witness, "Working");
        }
        
        // Analyze Deezel V2
        println!("  Deezel V2 Transaction:");
        for (i, input) in v2.input.iter().enumerate() {
            println!("    Input {} witness:", i);
            analyze_witness_elements(&input.witness, &format!("V2-Input{}", i));
        }
        
        // Analyze Deezel V3
        println!("  Deezel V3 Transaction:");
        for (i, input) in v3.input.iter().enumerate() {
            println!("    Input {} witness:", i);
            analyze_witness_elements(&input.witness, &format!("V3-Input{}", i));
        }
    }

    fn analyze_witness_elements(witness: &Witness, tx_name: &str) {
        if witness.is_empty() {
            println!("      No witness data");
            return;
        }
        
        for (i, element) in witness.iter().enumerate() {
            let element_type = identify_witness_element(element, i);
            println!("      Element {}: {} bytes - {}", i, element.len(), element_type);
            
            // Show first few bytes for identification
            if element.len() > 0 {
                let preview_len = std::cmp::min(element.len(), 16);
                let preview = hex::encode(&element[..preview_len]);
                println!("        Preview: {}...", preview);
            }
        }
    }

    fn identify_witness_element(element: &[u8], position: usize) -> String {
        match position {
            0 => {
                if element.is_empty() {
                    "Empty signature".to_string()
                } else if element.len() == 64 || element.len() == 65 {
                    "Schnorr signature".to_string()
                } else {
                    format!("Unknown signature-like ({} bytes)", element.len())
                }
            },
            1 => {
                if element.len() > 1000 {
                    if element.windows(3).any(|w| w == b"BIN") {
                        "Large script with BIN protocol".to_string()
                    } else {
                        "Large script (unknown content)".to_string()
                    }
                } else {
                    "Small script".to_string()
                }
            },
            2 => {
                if element.len() >= 33 {
                    "Control block".to_string()
                } else {
                    format!("Invalid control block ({} bytes)", element.len())
                }
            },
            _ => "Unknown element".to_string()
        }
    }

    fn analyze_alkanes_compatibility(working: &Transaction, v2: &Transaction, v3: &Transaction) {
        println!("Alkanes Indexer Compatibility Analysis:");
        
        // Check working transaction
        let working_compatible = check_alkanes_compatibility(working, "Working");
        let v2_compatible = check_alkanes_compatibility(v2, "Deezel V2");
        let v3_compatible = check_alkanes_compatibility(v3, "Deezel V3");
        
        println!();
        println!("Compatibility Summary:");
        println!("  Working:   {}", if working_compatible { "✅ Compatible" } else { "❌ Not Compatible" });
        println!("  Deezel V2: {}", if v2_compatible { "✅ Compatible" } else { "❌ Not Compatible" });
        println!("  Deezel V3: {}", if v3_compatible { "✅ Compatible" } else { "❌ Not Compatible" });
    }

    fn check_alkanes_compatibility(tx: &Transaction, name: &str) -> bool {
        println!("  {} Analysis:", name);
        
        if tx.input.is_empty() {
            println!("    ❌ No inputs");
            return false;
        }
        
        let first_input = &tx.input[0];
        if first_input.witness.is_empty() {
            println!("    ❌ No witness data in first input");
            return false;
        }
        
        if first_input.witness.len() < 2 {
            println!("    ❌ Insufficient witness elements (need at least 2 for alkanes)");
            return false;
        }
        
        // Check if first element can be skipped (signature)
        let first_element = &first_input.witness[0];
        let can_skip_first = first_element.is_empty() || 
                           first_element.len() == 64 || 
                           first_element.len() == 65;
        
        if !can_skip_first {
            println!("    ❌ First witness element cannot be skipped by alkanes indexer");
            return false;
        }
        
        // Check if second element contains envelope data
        let second_element = &first_input.witness[1];
        let has_envelope = second_element.len() > 100 && 
                          second_element.windows(3).any(|w| w == b"BIN");
        
        if !has_envelope {
            println!("    ❌ Second witness element doesn't contain BIN envelope data");
            return false;
        }
        
        println!("    ✅ Compatible: Can skip first element, has BIN envelope in second");
        true
    }

    fn analyze_improvements(working: &Transaction, v2: &Transaction, v3: &Transaction) {
        println!("Improvement Analysis (V2 → V3):");
        
        // Size comparison
        let v2_size = v2.total_size();
        let v3_size = v3.total_size();
        let size_change = v3_size as i32 - v2_size as i32;
        
        println!("  Size Change: {} bytes ({:+} from V2)", v3_size, size_change);
        
        // Input count
        let input_change = v3.input.len() as i32 - v2.input.len() as i32;
        println!("  Input Count: {} ({:+} from V2)", v3.input.len(), input_change);
        
        // Witness structure
        if !v3.input.is_empty() && !v2.input.is_empty() {
            let v3_witness_items = v3.input[0].witness.len();
            let v2_first_witness_items = v2.input[0].witness.len();
            println!("  First Input Witness: {} items (V2 had {} in first input)", 
                     v3_witness_items, v2_first_witness_items);
        }
        
        // Efficiency comparison with working transaction
        let working_size = working.total_size();
        let efficiency_vs_working = ((v3_size as f64 / working_size as f64) - 1.0) * 100.0;
        println!("  Efficiency vs Working: {:.1}% size difference", efficiency_vs_working);
    }

    fn print_summary(working: &Transaction, v2: &Transaction, v3: &Transaction) {
        println!("Final Assessment:");
        
        // Structure comparison
        let v3_structure_correct = v3.input.len() == 1 && 
                                  !v3.input.is_empty() && 
                                  v3.input[0].witness.len() >= 2;
        
        let matches_working_structure = v3.input.len() == working.input.len();
        
        println!("  Structure: {}", 
                 if v3_structure_correct { "✅ V3 has correct single-input structure" } 
                 else { "❌ V3 structure still incorrect" });
        
        println!("  Working Match: {}", 
                 if matches_working_structure { "✅ V3 matches working transaction input count" } 
                 else { "❌ V3 doesn't match working transaction structure" });
        
        // Alkanes compatibility
        let v3_alkanes_compatible = check_alkanes_compatibility(v3, "V3");
        println!("  Alkanes Ready: {}", 
                 if v3_alkanes_compatible { "✅ V3 should work with alkanes indexer" } 
                 else { "❌ V3 may still have alkanes compatibility issues" });
        
        // Overall assessment
        if v3_structure_correct && matches_working_structure && v3_alkanes_compatible {
            println!();
            println!("🎉 OVERALL: V3 appears to be a successful fix!");
            println!("   - Correct single-input structure");
            println!("   - Matches working transaction pattern");
            println!("   - Compatible with alkanes indexer expectations");
        } else {
            println!();
            println!("⚠️  OVERALL: V3 may need additional fixes");
        }
    }
}