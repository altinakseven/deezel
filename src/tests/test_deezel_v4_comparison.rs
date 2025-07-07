//! Comprehensive transaction comparison analysis for Deezel V4
//!
//! This module analyzes the new deezel-v4-tx.hex transaction and compares it with:
//! - working-tx.hex (the reference working transaction)
//! - deezel-v2-tx.hex (previous version)
//! - deezel-v3-tx.hex (previous version)
//!
//! The goal is to understand what changes were made in V4 and whether it matches
//! the working transaction structure.

use bitcoin::{Transaction, Witness};
use bitcoin::consensus::deserialize;
use anyhow::{Result, Context};

#[cfg(test)]
mod tests {
    use super::*;

    /// Comprehensive comparison of all transaction versions including V4
    #[test]
    fn test_comprehensive_v4_transaction_comparison() {
        println!("🔍 ═══════════════════════════════════════════════════════════════");
        println!("🧪                DEEZEL V4 TRANSACTION ANALYSIS                🧪");
        println!("🔍 ═══════════════════════════════════════════════════════════════");
        
        // Load all transaction versions
        let working_tx = load_transaction("examples/working-tx.hex")
            .expect("Failed to load working transaction");
        let v2_tx = load_transaction("examples/deezel-v2-tx.hex")
            .expect("Failed to load deezel V2 transaction");
        let v3_tx = load_transaction("examples/deezel-v3-tex.hex")
            .expect("Failed to load deezel V3 transaction");
        let v4_tx = load_transaction("examples/deezel-v4-tx.hex")
            .expect("Failed to load deezel V4 transaction");
        
        println!("\n📊 TRANSACTION OVERVIEW");
        println!("═══════════════════════");
        print_transaction_summary(&working_tx, "Working");
        print_transaction_summary(&v2_tx, "Deezel V2");
        print_transaction_summary(&v3_tx, "Deezel V3");
        print_transaction_summary(&v4_tx, "Deezel V4");
        
        println!("\n🔍 DETAILED V4 ANALYSIS");
        println!("═══════════════════════");
        
        // Compare V4 with working transaction
        println!("\n🎯 V4 vs Working Transaction:");
        compare_transactions(&v4_tx, &working_tx, "V4", "Working");
        
        // Compare V4 with previous versions
        println!("\n📈 V4 vs Previous Versions:");
        compare_transactions(&v4_tx, &v3_tx, "V4", "V3");
        compare_transactions(&v4_tx, &v2_tx, "V4", "V2");
        
        // Analyze what changed in V4
        println!("\n🔧 V4 IMPROVEMENTS ANALYSIS");
        println!("═══════════════════════════");
        analyze_v4_improvements(&v4_tx, &v3_tx, &working_tx);
        
        // Check if V4 matches working transaction structure
        println!("\n✅ V4 COMPATIBILITY CHECK");
        println!("═════════════════════════");
        check_v4_compatibility(&v4_tx, &working_tx);
        
        println!("\n🎯 ═══════════════════════════════════════════════════════════════");
        println!("✨                    ANALYSIS COMPLETE                         ✨");
        println!("🎯 ═══════════════════════════════════════════════════════════════");
    }

    /// Load and parse a transaction from hex file
    fn load_transaction(file_path: &str) -> Result<Transaction> {
        let hex_content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read transaction file: {}", file_path))?;
        
        let hex_clean = hex_content.trim().replace('\n', "").replace('\r', "");
        let tx_bytes = hex::decode(&hex_clean)
            .with_context(|| format!("Failed to decode hex from file: {}", file_path))?;
        
        let transaction: Transaction = deserialize(&tx_bytes)
            .with_context(|| format!("Failed to deserialize transaction from file: {}", file_path))?;
        
        Ok(transaction)
    }

    /// Print a summary of transaction properties
    fn print_transaction_summary(tx: &Transaction, name: &str) {
        let total_size = bitcoin::consensus::serialize(tx).len();
        let vsize = tx.vsize();
        let weight = tx.weight().to_wu();
        
        println!("📋 {}: {} inputs, {} outputs", name, tx.input.len(), tx.output.len());
        println!("   Size: {} bytes, VSize: {} vbytes, Weight: {} WU", total_size, vsize, weight);
        
        // Analyze witness data
        let total_witness_size: usize = tx.input.iter()
            .map(|input| input.witness.iter().map(|item| item.len()).sum::<usize>())
            .sum();
        println!("   Witness data: {} bytes total", total_witness_size);
        
        // Check for envelope data (large witness elements)
        let has_large_witness = tx.input.iter().any(|input| 
            input.witness.iter().any(|item| item.len() > 10000)
        );
        if has_large_witness {
            println!("   🔍 Contains large witness elements (likely envelope data)");
        }
    }

    /// Compare two transactions in detail
    fn compare_transactions(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
        println!("\n🔍 Comparing {} vs {}:", name1, name2);
        
        // Basic structure comparison
        if tx1.input.len() != tx2.input.len() {
            println!("  📥 Input count: {} has {}, {} has {}", 
                     name1, tx1.input.len(), name2, tx2.input.len());
        } else {
            println!("  ✅ Input count: both have {} inputs", tx1.input.len());
        }
        
        if tx1.output.len() != tx2.output.len() {
            println!("  📤 Output count: {} has {}, {} has {}", 
                     name1, tx1.output.len(), name2, tx2.output.len());
        } else {
            println!("  ✅ Output count: both have {} outputs", tx1.output.len());
        }
        
        // Size comparison
        let size1 = bitcoin::consensus::serialize(tx1).len();
        let size2 = bitcoin::consensus::serialize(tx2).len();
        let size_diff = size1 as i64 - size2 as i64;
        let size_percent = if size2 > 0 { (size_diff as f64 / size2 as f64) * 100.0 } else { 0.0 };
        
        println!("  📊 Size: {} = {} bytes, {} = {} bytes", name1, size1, name2, size2);
        if size_diff != 0 {
            println!("     Difference: {} bytes ({:+.1}%)", size_diff, size_percent);
        }
        
        // Witness comparison
        compare_witness_structures(tx1, tx2, name1, name2);
    }

    /// Compare witness structures between transactions
    fn compare_witness_structures(tx1: &Transaction, tx2: &Transaction, name1: &str, name2: &str) {
        println!("  🔍 Witness comparison:");
        
        for (i, (input1, input2)) in tx1.input.iter().zip(tx2.input.iter()).enumerate() {
            let witness1_items = input1.witness.len();
            let witness2_items = input2.witness.len();
            
            if witness1_items != witness2_items {
                println!("    Input {}: {} has {} items, {} has {} items", 
                         i, name1, witness1_items, name2, witness2_items);
            } else if witness1_items > 0 {
                println!("    Input {}: both have {} witness items", i, witness1_items);
                
                // Compare witness item sizes
                for (j, (item1, item2)) in input1.witness.iter().zip(input2.witness.iter()).enumerate() {
                    if item1.len() != item2.len() {
                        println!("      Item {}: {} = {} bytes, {} = {} bytes", 
                                 j, name1, item1.len(), name2, item2.len());
                    } else if item1 != item2 {
                        println!("      Item {}: same size ({} bytes) but different content", j, item1.len());
                    }
                }
            }
        }
    }

    /// Analyze what improvements were made in V4
    fn analyze_v4_improvements(v4_tx: &Transaction, v3_tx: &Transaction, working_tx: &Transaction) {
        println!("🔧 Analyzing V4 improvements over V3:");
        
        // Check if input count changed
        if v4_tx.input.len() != v3_tx.input.len() {
            println!("  📥 Input count changed: V3 had {}, V4 has {}", v3_tx.input.len(), v4_tx.input.len());
            
            if v4_tx.input.len() == working_tx.input.len() {
                println!("     ✅ V4 now matches working transaction input count!");
            }
        }
        
        // Check if transaction size improved
        let v4_size = bitcoin::consensus::serialize(v4_tx).len();
        let v3_size = bitcoin::consensus::serialize(v3_tx).len();
        let working_size = bitcoin::consensus::serialize(working_tx).len();
        
        if v4_size != v3_size {
            let size_change = v4_size as i64 - v3_size as i64;
            let percent_change = (size_change as f64 / v3_size as f64) * 100.0;
            println!("  📊 Size changed: V3 = {} bytes, V4 = {} bytes ({:+.1}%)", 
                     v3_size, v4_size, percent_change);
            
            let working_diff = v4_size as i64 - working_size as i64;
            let working_percent = (working_diff as f64 / working_size as f64) * 100.0;
            println!("     Compared to working: V4 is {} bytes larger ({:+.1}%)", 
                     working_diff, working_percent);
        }
        
        // Analyze witness structure changes
        analyze_witness_improvements(v4_tx, v3_tx, working_tx);
    }

    /// Analyze witness structure improvements in V4
    fn analyze_witness_improvements(v4_tx: &Transaction, v3_tx: &Transaction, working_tx: &Transaction) {
        println!("  🔍 Witness structure analysis:");
        
        // Check if V4 has the same witness pattern as working transaction
        if v4_tx.input.len() == working_tx.input.len() {
            for (i, (v4_input, working_input)) in v4_tx.input.iter().zip(working_tx.input.iter()).enumerate() {
                let v4_items = v4_input.witness.len();
                let working_items = working_input.witness.len();
                
                if v4_items == working_items {
                    println!("    Input {}: ✅ V4 matches working witness item count ({})", i, v4_items);
                    
                    // Check if witness item sizes match
                    let sizes_match = v4_input.witness.iter().zip(working_input.witness.iter())
                        .all(|(v4_item, working_item)| v4_item.len() == working_item.len());
                    
                    if sizes_match {
                        println!("      ✅ All witness item sizes match working transaction");
                    } else {
                        println!("      ⚠️  Witness item sizes differ from working transaction");
                        for (j, (v4_item, working_item)) in v4_input.witness.iter().zip(working_input.witness.iter()).enumerate() {
                            if v4_item.len() != working_item.len() {
                                println!("        Item {}: V4 = {} bytes, Working = {} bytes", 
                                         j, v4_item.len(), working_item.len());
                            }
                        }
                    }
                } else {
                    println!("    Input {}: ❌ V4 has {} items, working has {} items", 
                             i, v4_items, working_items);
                }
            }
        }
        
        // Check for envelope data consolidation
        let v4_envelope_inputs = count_envelope_inputs(v4_tx);
        let v3_envelope_inputs = count_envelope_inputs(v3_tx);
        let working_envelope_inputs = count_envelope_inputs(working_tx);
        
        println!("  📦 Envelope data distribution:");
        println!("     V3: {} inputs with envelope data", v3_envelope_inputs);
        println!("     V4: {} inputs with envelope data", v4_envelope_inputs);
        println!("     Working: {} inputs with envelope data", working_envelope_inputs);
        
        if v4_envelope_inputs == working_envelope_inputs {
            println!("     ✅ V4 matches working transaction envelope distribution!");
        }
    }

    /// Count inputs that contain envelope data (large witness elements)
    fn count_envelope_inputs(tx: &Transaction) -> usize {
        tx.input.iter()
            .filter(|input| input.witness.iter().any(|item| item.len() > 10000))
            .count()
    }

    /// Check if V4 is compatible with the working transaction structure
    fn check_v4_compatibility(v4_tx: &Transaction, working_tx: &Transaction) {
        let mut compatibility_score = 0;
        let mut total_checks = 0;
        
        // Check 1: Input count
        total_checks += 1;
        if v4_tx.input.len() == working_tx.input.len() {
            compatibility_score += 1;
            println!("✅ Input count matches working transaction ({} inputs)", v4_tx.input.len());
        } else {
            println!("❌ Input count differs: V4 has {}, working has {}", 
                     v4_tx.input.len(), working_tx.input.len());
        }
        
        // Check 2: Output count
        total_checks += 1;
        if v4_tx.output.len() == working_tx.output.len() {
            compatibility_score += 1;
            println!("✅ Output count matches working transaction ({} outputs)", v4_tx.output.len());
        } else {
            println!("❌ Output count differs: V4 has {}, working has {}", 
                     v4_tx.output.len(), working_tx.output.len());
        }
        
        // Check 3: Transaction size efficiency
        total_checks += 1;
        let v4_size = bitcoin::consensus::serialize(v4_tx).len();
        let working_size = bitcoin::consensus::serialize(working_tx).len();
        let size_ratio = v4_size as f64 / working_size as f64;
        
        if size_ratio <= 1.1 { // Within 10% of working transaction size
            compatibility_score += 1;
            println!("✅ Transaction size is efficient ({:.1}% of working transaction)", size_ratio * 100.0);
        } else {
            println!("⚠️  Transaction size is larger ({:.1}% of working transaction)", size_ratio * 100.0);
        }
        
        // Check 4: Witness structure
        total_checks += 1;
        if v4_tx.input.len() == working_tx.input.len() {
            let witness_matches = v4_tx.input.iter().zip(working_tx.input.iter())
                .all(|(v4_input, working_input)| v4_input.witness.len() == working_input.witness.len());
            
            if witness_matches {
                compatibility_score += 1;
                println!("✅ Witness structure matches working transaction");
            } else {
                println!("❌ Witness structure differs from working transaction");
            }
        }
        
        // Final compatibility assessment
        let compatibility_percent = (compatibility_score as f64 / total_checks as f64) * 100.0;
        println!("\n🎯 COMPATIBILITY SCORE: {}/{} ({:.0}%)", 
                 compatibility_score, total_checks, compatibility_percent);
        
        if compatibility_score == total_checks {
            println!("🎉 V4 is FULLY COMPATIBLE with working transaction structure!");
        } else if compatibility_score >= total_checks * 3 / 4 {
            println!("✅ V4 is MOSTLY COMPATIBLE with working transaction structure");
        } else {
            println!("⚠️  V4 has SIGNIFICANT DIFFERENCES from working transaction structure");
        }
    }

    /// Detailed analysis of witness elements for alkanes compatibility
    fn analyze_witness_elements(witness: &Witness, tx_name: &str) {
        println!("🔍 Analyzing {} witness elements:", tx_name);
        
        for (i, item) in witness.iter().enumerate() {
            let item_type = match i {
                0 => identify_first_element(item),
                1 => identify_script_element(item),
                2 => identify_control_block(item),
                _ => "unknown_element".to_string(),
            };
            
            println!("  Item {}: {} bytes - {}", i, item.len(), item_type);
            
            // Additional analysis for large elements (potential envelope data)
            if item.len() > 1000 {
                analyze_large_witness_element(item, i);
            }
        }
    }

    /// Identify the type of the first witness element
    fn identify_first_element(element: &[u8]) -> String {
        match element.len() {
            0 => "empty_signature".to_string(),
            64 => "schnorr_signature_64".to_string(),
            65 => "schnorr_signature_65".to_string(),
            _ if element.len() < 10 => "small_data".to_string(),
            _ => format!("unknown_signature_{}_bytes", element.len()),
        }
    }

    /// Identify script elements in witness
    fn identify_script_element(element: &[u8]) -> String {
        if element.len() > 1000 {
            // Check for alkanes envelope markers
            if element.windows(3).any(|w| w == b"BIN") {
                "alkanes_envelope_with_bin".to_string()
            } else if element.windows(16).any(|w| w == b"application/wasm") {
                "alkanes_envelope_with_wasm".to_string()
            } else {
                "large_script_data".to_string()
            }
        } else {
            "script_element".to_string()
        }
    }

    /// Identify control block elements
    fn identify_control_block(element: &[u8]) -> String {
        if element.len() >= 33 {
            "taproot_control_block".to_string()
        } else {
            format!("invalid_control_block_{}_bytes", element.len())
        }
    }

    /// Analyze large witness elements for envelope data
    fn analyze_large_witness_element(element: &[u8], position: usize) {
        println!("    📦 Large element analysis:");
        
        // Check for envelope markers
        if element.windows(3).any(|w| w == b"BIN") {
            println!("      ✅ Contains BIN protocol marker");
        }
        
        if element.windows(16).any(|w| w == b"application/wasm") {
            println!("      ✅ Contains application/wasm content type");
        }
        
        // Check script structure
        if element.len() > 0 && element[0] == 0x00 {
            println!("      ✅ Starts with OP_PUSHBYTES_0 (envelope pattern)");
        }
        
        if element.len() > 1 && element[1] == 0x63 {
            println!("      ✅ Contains OP_IF (envelope pattern)");
        }
        
        // Check for OP_ENDIF at the end
        if element.len() > 0 && element[element.len()-1] == 0x68 {
            println!("      ✅ Ends with OP_ENDIF (envelope pattern)");
        }
    }

    /// Print final summary comparing all versions
    fn print_final_summary(working: &Transaction, v2: &Transaction, v3: &Transaction, v4: &Transaction) {
        println!("\n📊 FINAL SUMMARY");
        println!("═══════════════");
        
        let working_size = bitcoin::consensus::serialize(working).len();
        let v2_size = bitcoin::consensus::serialize(v2).len();
        let v3_size = bitcoin::consensus::serialize(v3).len();
        let v4_size = bitcoin::consensus::serialize(v4).len();
        
        println!("Transaction sizes:");
        println!("  Working: {} bytes (baseline)", working_size);
        println!("  V2:      {} bytes ({:+.1}%)", v2_size, ((v2_size as f64 / working_size as f64) - 1.0) * 100.0);
        println!("  V3:      {} bytes ({:+.1}%)", v3_size, ((v3_size as f64 / working_size as f64) - 1.0) * 100.0);
        println!("  V4:      {} bytes ({:+.1}%)", v4_size, ((v4_size as f64 / working_size as f64) - 1.0) * 100.0);
        
        println!("\nInput/Output structure:");
        println!("  Working: {} inputs, {} outputs", working.input.len(), working.output.len());
        println!("  V2:      {} inputs, {} outputs", v2.input.len(), v2.output.len());
        println!("  V3:      {} inputs, {} outputs", v3.input.len(), v3.output.len());
        println!("  V4:      {} inputs, {} outputs", v4.input.len(), v4.output.len());
        
        // Determine which version is closest to working
        let v2_diff = (v2_size as i64 - working_size as i64).abs();
        let v3_diff = (v3_size as i64 - working_size as i64).abs();
        let v4_diff = (v4_size as i64 - working_size as i64).abs();
        
        let closest = if v4_diff <= v3_diff && v4_diff <= v2_diff {
            "V4"
        } else if v3_diff <= v2_diff {
            "V3"
        } else {
            "V2"
        };
        
        println!("\n🎯 {} is closest to working transaction structure", closest);
        
        if v4.input.len() == working.input.len() && v4.output.len() == working.output.len() {
            println!("✅ V4 has achieved the same input/output structure as working transaction!");
        }
    }
}