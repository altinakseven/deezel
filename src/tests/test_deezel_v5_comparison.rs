// Test comparison between deezel v5 transaction and working transaction
// Based on analysis of deezel-v5-tx.hex vs working-tx.hex

#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use bitcoin::Transaction;
    use std::fs;

    #[test]
    fn test_comprehensive_v5_transaction_comparison() {
        println!("🔍 ═══════════════════════════════════════════════════════════════");
        println!("🔍 COMPREHENSIVE DEEZEL V5 vs WORKING TRANSACTION COMPARISON");
        println!("🔍 ═══════════════════════════════════════════════════════════════");

        // Load transaction hex files
        let working_hex = fs::read_to_string("./examples/working-tx.hex")
            .expect("Failed to read working-tx.hex")
            .trim()
            .replace('\n', "")
            .replace(' ', "");

        let v5_hex = fs::read_to_string("./examples/deezel-v5-tx.hex")
            .expect("Failed to read deezel-v5-tx.hex")
            .trim()
            .replace('\n', "")
            .replace(' ', "");

        // Parse transactions
        let working_bytes = hex::decode(&working_hex).expect("Failed to decode working hex");
        let v5_bytes = hex::decode(&v5_hex).expect("Failed to decode v5 hex");

        let working_tx: Transaction = deserialize(&working_bytes).expect("Failed to deserialize working tx");
        let v5_tx: Transaction = deserialize(&v5_bytes).expect("Failed to deserialize v5 tx");

        println!("\n📊 BASIC TRANSACTION COMPARISON:");
        println!("Working Transaction:");
        println!("  TXID: {}", working_tx.compute_txid());
        println!("  Size: {} bytes", working_bytes.len());
        println!("  Virtual Size: {} vbytes", working_tx.vsize());
        println!("  Weight: {} WU", working_tx.weight().to_wu());
        println!("  Inputs: {}", working_tx.input.len());
        println!("  Outputs: {}", working_tx.output.len());

        println!("\nDeezel V5 Transaction:");
        println!("  TXID: {}", v5_tx.compute_txid());
        println!("  Size: {} bytes", v5_bytes.len());
        println!("  Virtual Size: {} vbytes", v5_tx.vsize());
        println!("  Weight: {} WU", v5_tx.weight().to_wu());
        println!("  Inputs: {}", v5_tx.input.len());
        println!("  Outputs: {}", v5_tx.output.len());

        // Key findings from analysis
        println!("\n🎯 KEY FINDINGS:");
        
        // Size efficiency
        let size_ratio = v5_bytes.len() as f64 / working_bytes.len() as f64;
        let vsize_ratio = v5_tx.vsize() as f64 / working_tx.vsize() as f64;
        println!("  📏 Size Efficiency:");
        println!("    V5 is {:.2}x larger than working transaction", size_ratio);
        println!("    V5 is {:.2}x larger in virtual size", vsize_ratio);
        println!("    Size difference: {} bytes", v5_bytes.len() - working_bytes.len());
        println!("    VSize difference: {} vbytes", v5_tx.vsize() - working_tx.vsize());

        // Input/Output structure
        println!("  🔗 Structure Differences:");
        println!("    Working: {} inputs, {} outputs", working_tx.input.len(), working_tx.output.len());
        println!("    V5: {} inputs, {} outputs", v5_tx.input.len(), v5_tx.output.len());
        println!("    V5 has {} extra input(s)", v5_tx.input.len() - working_tx.input.len());
        println!("    V5 has {} extra output(s)", v5_tx.output.len() - working_tx.output.len());

        // Witness structure analysis
        println!("  🔍 Witness Structure Analysis:");
        
        // Working transaction witness
        if !working_tx.input.is_empty() {
            let working_witness = &working_tx.input[0].witness;
            println!("    Working transaction (Input 0): {} witness items", working_witness.len());
            for (i, item) in working_witness.iter().enumerate() {
                let item_type = classify_witness_item(item);
                println!("      Item {}: {} bytes ({})", i, item.len(), item_type);
            }
        }

        // V5 transaction witness
        for (input_idx, input) in v5_tx.input.iter().enumerate() {
            println!("    V5 transaction (Input {}): {} witness items", input_idx, input.witness.len());
            for (i, item) in input.witness.iter().enumerate() {
                let item_type = classify_witness_item(item);
                println!("      Item {}: {} bytes ({})", i, item.len(), item_type);
            }
        }

        // Critical analysis
        println!("\n🚨 CRITICAL ANALYSIS:");
        
        // Check if V5 has the correct witness structure
        let working_has_correct_structure = working_tx.input.len() == 1 && 
            working_tx.input[0].witness.len() == 3;
        
        let v5_has_single_input_structure = v5_tx.input.len() == 1 && 
            v5_tx.input[0].witness.len() == 3;

        if working_has_correct_structure {
            println!("  ✅ Working transaction has ideal structure: 1 input with 3 witness items");
        }

        if v5_has_single_input_structure {
            println!("  ✅ V5 transaction matches working structure: 1 input with 3 witness items");
        } else {
            println!("  ❌ V5 transaction does NOT match working structure:");
            println!("     Expected: 1 input with 3 witness items");
            println!("     Actual: {} inputs", v5_tx.input.len());
            for (i, input) in v5_tx.input.iter().enumerate() {
                println!("     Input {}: {} witness items", i, input.witness.len());
            }
        }

        // Witness pattern comparison
        if working_has_correct_structure && v5_has_single_input_structure {
            let working_pattern = get_witness_pattern(&working_tx.input[0].witness);
            let v5_pattern = get_witness_pattern(&v5_tx.input[0].witness);
            
            if working_pattern == v5_pattern {
                println!("  ✅ V5 witness pattern MATCHES working transaction!");
                println!("     Pattern: {}", working_pattern);
            } else {
                println!("  ❌ V5 witness pattern differs from working transaction");
                println!("     Working: {}", working_pattern);
                println!("     V5: {}", v5_pattern);
            }
        }

        // Progress assessment
        println!("\n📈 PROGRESS ASSESSMENT:");
        
        // Compare with previous versions
        println!("  🔄 Evolution from previous versions:");
        println!("    V2/V3/V4: 2 inputs, 5 outputs, ~119,000 bytes");
        println!("    V5: {} inputs, {} outputs, {} bytes", 
                v5_tx.input.len(), v5_tx.output.len(), v5_bytes.len());
        
        if v5_tx.input.len() < 2 {
            println!("    ✅ V5 reduced input count (progress toward single input)");
        } else {
            println!("    ❌ V5 still has multiple inputs (no progress)");
        }

        if v5_tx.output.len() < 5 {
            println!("    ✅ V5 reduced output count");
        } else {
            println!("    ❌ V5 still has many outputs");
        }

        if v5_bytes.len() < 119_000 {
            println!("    ✅ V5 reduced transaction size");
        } else {
            println!("    ❌ V5 size similar to previous versions");
        }

        // Final verdict
        println!("\n🏆 FINAL VERDICT:");
        if v5_has_single_input_structure {
            println!("  ✅ SUCCESS: V5 achieves single input structure like working transaction!");
            println!("  🎯 V5 represents significant progress toward optimal transaction structure");
        } else {
            println!("  ❌ V5 still does not match the optimal single input structure");
            println!("  🎯 Further optimization needed to match working transaction efficiency");
        }

        println!("\n🔍 ═══════════════════════════════════════════════════════════════");
        println!("🔍 END V5 COMPARISON ANALYSIS");
        println!("🔍 ═══════════════════════════════════════════════════════════════");
    }

    fn classify_witness_item(item: &[u8]) -> &'static str {
        match item.len() {
            0 => "empty",
            64 => "schnorr_signature",
            33 => "control_block", 
            len if len > 1000 => {
                if item.windows(3).any(|w| w == b"BIN") {
                    "large_script_with_BIN"
                } else {
                    "large_script"
                }
            },
            _ => "unknown_data"
        }
    }

    fn get_witness_pattern(witness: &bitcoin::Witness) -> String {
        let pattern: Vec<String> = witness.iter()
            .enumerate()
            .map(|(i, item)| format!("{}:{}", i, classify_witness_item(item)))
            .collect();
        format!("[{}]", pattern.join(", "))
    }
}