//! Simple fee calculation debug test
//!
//! This test focuses on understanding the "absurdly high fee rate" issue
//! without depending on complex alkanes infrastructure.

use anyhow::Result;
use bitcoin::{Transaction, TxIn, TxOut, Amount, ScriptBuf, OutPoint, Txid, Sequence, Witness};
use std::str::FromStr;

/// Simple transaction analysis for fee debugging
#[derive(Debug)]
struct FeeAnalysis {
    pub total_input_value: u64,
    pub total_output_value: u64,
    pub calculated_fee: u64,
    pub vsize: usize,
    pub weight: usize,
    pub fee_rate_sat_vb: f64,
    pub witness_size: usize,
    pub base_size: usize,
}

impl FeeAnalysis {
    fn analyze(tx: &Transaction, input_values: &[u64]) -> Self {
        let total_input_value: u64 = input_values.iter().sum();
        let total_output_value: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();
        let calculated_fee = total_input_value.saturating_sub(total_output_value);
        let vsize = tx.vsize();
        let weight = tx.weight().to_wu() as usize;
        let fee_rate_sat_vb = if vsize > 0 {
            calculated_fee as f64 / vsize as f64
        } else {
            0.0
        };

        // Calculate witness size
        let witness_size: usize = tx.input.iter()
            .map(|input| input.witness.iter().map(|item| item.len()).sum::<usize>())
            .sum();

        // Calculate base size (transaction without witness data)
        let base_size = bitcoin::consensus::serialize(tx).len() - witness_size;

        Self {
            total_input_value,
            total_output_value,
            calculated_fee,
            vsize,
            weight,
            fee_rate_sat_vb,
            witness_size,
            base_size,
        }
    }

    fn print_analysis(&self) {
        println!("\n🔍 FEE ANALYSIS");
        println!("═══════════════════════════════════════");
        println!("💰 Input Value: {} sats", self.total_input_value);
        println!("💰 Output Value: {} sats", self.total_output_value);
        println!("💰 Calculated Fee: {} sats", self.calculated_fee);
        println!("📏 VSize: {} vbytes", self.vsize);
        println!("⚖️  Weight: {} WU", self.weight);
        println!("📊 Fee Rate: {:.2} sat/vB", self.fee_rate_sat_vb);
        println!("👁️  Witness Size: {} bytes", self.witness_size);
        println!("📦 Base Size: {} bytes", self.base_size);
        
        if self.fee_rate_sat_vb > 1000.0 {
            println!("❌ EXTREMELY HIGH FEE RATE!");
        }
        
        // Verify vsize calculation
        let calculated_vsize = self.base_size + (self.witness_size / 4);
        println!("🧮 Calculated VSize: {} vbytes", calculated_vsize);
        if calculated_vsize != self.vsize {
            println!("⚠️  VSize calculation mismatch!");
        }
        println!("═══════════════════════════════════════\n");
    }
}

/// Create a mock transaction that simulates the alkanes execute scenario
fn create_mock_alkanes_transaction() -> Result<(Transaction, Vec<u64>)> {
    // Create inputs
    let mut inputs = Vec::new();
    let mut input_values = Vec::new();

    // Input 1: Commit UTXO (dust)
    inputs.push(TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")?,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    input_values.push(546u64); // Dust

    // Input 2: Funding UTXO (large amount)
    inputs.push(TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str("2222222222222222222222222222222222222222222222222222222222222222")?,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    input_values.push(5000000000u64); // 50 BTC

    // Create outputs
    let mut outputs = Vec::new();

    // Output 1: Recipient (dust)
    outputs.push(TxOut {
        value: Amount::from_sat(546),
        script_pubkey: ScriptBuf::from_hex(&format!("5120{}", "a".repeat(64)))?,
    });

    // Output 2: Change (most of the input)
    let total_input: u64 = input_values.iter().sum();
    let target_fee = 5000u64; // Reasonable fee
    let change_amount = total_input - 546 - target_fee;
    outputs.push(TxOut {
        value: Amount::from_sat(change_amount),
        script_pubkey: ScriptBuf::from_hex(&format!("5120{}", "b".repeat(64)))?,
    });

    // Output 3: OP_RETURN (protostone)
    let mut op_return_script = Vec::new();
    op_return_script.push(0x6a); // OP_RETURN
    op_return_script.push(0x4c); // OP_PUSHDATA1
    op_return_script.push(100); // 100 bytes of data
    op_return_script.extend_from_slice(&vec![0x5d; 100]); // Mock runestone data

    outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from(op_return_script),
    });

    // Create transaction
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Add large witness data to first input (envelope data)
    let mut witness_stack = Vec::new();
    witness_stack.push(vec![0u8; 64]); // Signature
    witness_stack.push(vec![0u8; 117826]); // Large envelope data (117KB)
    witness_stack.push(vec![0u8; 100]); // Script
    witness_stack.push(vec![0u8; 33]); // Control block
    tx.input[0].witness = Witness::from_slice(&witness_stack);

    // Add normal witness to second input
    let mut normal_witness = Vec::new();
    normal_witness.push(vec![0u8; 64]); // Signature
    normal_witness.push(vec![0u8; 33]); // Pubkey
    tx.input[1].witness = Witness::from_slice(&normal_witness);

    Ok((tx, input_values))
}

#[tokio::test]
async fn test_fee_calculation_debug() -> Result<()> {
    println!("\n🧪 FEE CALCULATION DEBUG TEST");
    println!("═══════════════════════════════════════════════════════════════");

    // Create mock transaction
    let (tx, input_values) = create_mock_alkanes_transaction()?;
    
    // Analyze the transaction
    let analysis = FeeAnalysis::analyze(&tx, &input_values);
    analysis.print_analysis();

    // Test different scenarios
    println!("🧮 TESTING DIFFERENT SCENARIOS");
    println!("═══════════════════════════════════════════════════════════════");

    // Scenario 1: What if input values are wrong?
    println!("Scenario 1: Input values are 0 (not fetched correctly)");
    let wrong_input_values = vec![0u64; input_values.len()];
    let wrong_analysis = FeeAnalysis::analyze(&tx, &wrong_input_values);
    wrong_analysis.print_analysis();

    // Scenario 2: What if we have the right fee but wrong calculation?
    println!("Scenario 2: Correct fee (5000 sats) but wrong vsize");
    let correct_fee = 5000u64;
    let correct_rate = correct_fee as f64 / analysis.vsize as f64;
    println!("Correct fee rate would be: {:.2} sat/vB", correct_rate);

    // Scenario 3: What if the issue is in the transaction construction?
    println!("\nScenario 3: Transaction construction analysis");
    println!("  Total witness size: {} bytes", analysis.witness_size);
    println!("  Witness discount: {} bytes", analysis.witness_size / 4);
    println!("  Effective size increase: {} bytes", analysis.witness_size * 3 / 4);

    // Check if the issue is the large witness data
    if analysis.witness_size > 100000 {
        println!("❌ ISSUE IDENTIFIED: Large witness data ({}KB)", analysis.witness_size / 1024);
        println!("   This creates a very large transaction with high vsize");
        println!("   Even a small fee becomes a high rate when divided by large vsize");
    }

    // Root cause analysis
    println!("\n🔍 ROOT CAUSE ANALYSIS");
    println!("═══════════════════════════════════════════════════════════════");
    
    if analysis.fee_rate_sat_vb > 1000.0 {
        println!("❌ Fee rate is absurdly high: {:.2} sat/vB", analysis.fee_rate_sat_vb);
        
        if analysis.calculated_fee > 100000 {
            println!("   Cause: Fee amount is too high ({} sats)", analysis.calculated_fee);
            println!("   Solution: Fix fee calculation in transaction construction");
        } else if analysis.vsize > 50000 {
            println!("   Cause: Transaction is too large ({} vbytes)", analysis.vsize);
            println!("   Solution: Optimize witness data or use different approach");
        } else {
            println!("   Cause: Unknown - both fee and vsize seem reasonable");
        }
    } else {
        println!("✅ Fee rate is reasonable: {:.2} sat/vB", analysis.fee_rate_sat_vb);
    }

    // Recommendations
    println!("\n💡 RECOMMENDATIONS");
    println!("═══════════════════════════════════════════════════════════════");
    
    if analysis.witness_size > 100000 {
        println!("1. Consider splitting large envelope data across multiple transactions");
        println!("2. Use commit/reveal pattern more efficiently");
        println!("3. Compress envelope data if possible");
    }
    
    if analysis.calculated_fee > 10000 {
        println!("4. Review fee calculation logic in transaction construction");
        println!("5. Ensure input values are calculated correctly");
    }

    println!("6. Add fee rate validation before transaction broadcast");
    println!("7. Implement maximum fee rate limits (e.g., 1000 sat/vB)");

    Ok(())
}

#[tokio::test]
async fn test_witness_size_impact() -> Result<()> {
    println!("\n🧪 WITNESS SIZE IMPACT TEST");
    println!("═══════════════════════════════════════════════════════════════");

    let test_sizes = vec![
        (0, "No witness"),
        (1000, "Small witness (1KB)"),
        (10000, "Medium witness (10KB)"),
        (117826, "Actual envelope (117KB)"),
        (500000, "Large witness (500KB)"),
    ];

    for (witness_size, description) in test_sizes {
        println!("\n📊 Testing {}: {} bytes", description, witness_size);

        // Create transaction with specific witness size
        let (mut tx, input_values) = create_mock_alkanes_transaction()?;
        
        // Modify witness size
        let mut witness_stack = Vec::new();
        witness_stack.push(vec![0u8; 64]); // Signature
        witness_stack.push(vec![0u8; witness_size]); // Variable size data
        witness_stack.push(vec![0u8; 100]); // Script
        witness_stack.push(vec![0u8; 33]); // Control block
        tx.input[0].witness = Witness::from_slice(&witness_stack);

        let analysis = FeeAnalysis::analyze(&tx, &input_values);
        
        println!("  VSize: {} vbytes", analysis.vsize);
        println!("  Fee rate (5000 sats): {:.2} sat/vB", 5000.0 / analysis.vsize as f64);
        
        if 5000.0 / analysis.vsize as f64 > 1000.0 {
            println!("  ❌ Would be rejected as absurdly high fee rate!");
        } else {
            println!("  ✅ Reasonable fee rate");
        }
    }

    Ok(())
}