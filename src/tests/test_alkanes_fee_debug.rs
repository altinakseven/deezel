//! Unit test to debug the alkanes execute fee calculation issue
//!
//! This test replicates the exact scenario from ./examples/run-alkanes-execute.sh
//! to analyze where the "absurdly high fee rate" is coming from.

use anyhow::Result;
use bitcoin::{Transaction, TxOut, Amount, ScriptBuf};
use std::sync::Arc;
use tokio;

use crate::alkanes::execute::{EnhancedAlkanesExecutor, EnhancedExecuteParams, InputRequirement, parse_protostones};
use crate::alkanes::envelope::EnvelopeManager;
use crate::rpc::{RpcClient, RpcConfig};
use crate::wallet::WalletManager;
use crate::wallet::bitcoin_wallet::{BitcoinWallet, BitcoinWalletConfig};

/// Test data structure to hold transaction analysis
#[derive(Debug)]
struct TransactionAnalysis {
    pub transaction: Transaction,
    pub total_input_value: u64,
    pub total_output_value: u64,
    pub calculated_fee: u64,
    pub fee_rate_sat_vb: f64,
    pub vsize: usize,
    pub weight: usize,
    pub input_details: Vec<InputDetail>,
    pub output_details: Vec<OutputDetail>,
}

#[derive(Debug)]
struct InputDetail {
    pub outpoint: String,
    pub value: u64,
    pub script_type: String,
    pub witness_items: usize,
    pub witness_size: usize,
}

#[derive(Debug)]
struct OutputDetail {
    pub index: usize,
    pub value: u64,
    pub script_type: String,
    pub script_size: usize,
}

impl TransactionAnalysis {
    /// Create a detailed analysis of a transaction
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

        let input_details: Vec<InputDetail> = tx.input.iter().enumerate().map(|(i, input)| {
            let witness_items = input.witness.len();
            let witness_size: usize = input.witness.iter().map(|item| item.len()).sum();
            
            InputDetail {
                outpoint: format!("{}:{}", input.previous_output.txid, input.previous_output.vout),
                value: input_values.get(i).copied().unwrap_or(0),
                script_type: "unknown".to_string(), // Would need more analysis
                witness_items,
                witness_size,
            }
        }).collect();

        let output_details: Vec<OutputDetail> = tx.output.iter().enumerate().map(|(i, output)| {
            let script_type = if output.script_pubkey.is_op_return() {
                "OP_RETURN".to_string()
            } else if output.script_pubkey.is_p2tr() {
                "P2TR".to_string()
            } else if output.script_pubkey.is_p2wpkh() {
                "P2WPKH".to_string()
            } else if output.script_pubkey.is_p2pkh() {
                "P2PKH".to_string()
            } else if output.script_pubkey.is_p2sh() {
                "P2SH".to_string()
            } else {
                "UNKNOWN".to_string()
            };

            OutputDetail {
                index: i,
                value: output.value.to_sat(),
                script_type,
                script_size: output.script_pubkey.len(),
            }
        }).collect();

        Self {
            transaction: tx.clone(),
            total_input_value,
            total_output_value,
            calculated_fee,
            fee_rate_sat_vb,
            vsize,
            weight,
            input_details,
            output_details,
        }
    }

    /// Print detailed analysis
    fn print_analysis(&self) {
        println!("\n🔍 TRANSACTION ANALYSIS");
        println!("═══════════════════════════════════════════════════════════════");
        
        println!("📋 Basic Info:");
        println!("  TXID: {}", self.transaction.compute_txid());
        println!("  Version: {}", self.transaction.version);
        println!("  Lock Time: {}", self.transaction.lock_time);
        println!("  Size: {} bytes", bitcoin::consensus::serialize(&self.transaction).len());
        println!("  Virtual Size: {} vbytes", self.vsize);
        println!("  Weight: {} WU", self.weight);
        
        println!("\n💰 Fee Analysis:");
        println!("  Total Input Value: {} sats", self.total_input_value);
        println!("  Total Output Value: {} sats", self.total_output_value);
        println!("  Calculated Fee: {} sats", self.calculated_fee);
        println!("  Fee Rate: {:.2} sat/vB", self.fee_rate_sat_vb);
        
        if self.fee_rate_sat_vb > 1000.0 {
            println!("  ⚠️  WARNING: Fee rate is extremely high!");
        }
        
        println!("\n📥 Inputs ({}):", self.input_details.len());
        for (i, input) in self.input_details.iter().enumerate() {
            println!("  {}. {}", i, input.outpoint);
            println!("     Value: {} sats", input.value);
            println!("     Script Type: {}", input.script_type);
            println!("     Witness Items: {}", input.witness_items);
            println!("     Witness Size: {} bytes", input.witness_size);
        }
        
        println!("\n📤 Outputs ({}):", self.output_details.len());
        for output in &self.output_details {
            println!("  {}. {} sats ({})", output.index, output.value, output.script_type);
            println!("     Script Size: {} bytes", output.script_size);
        }
        
        println!("\n🔍 Potential Issues:");
        if self.calculated_fee > 100_000 {
            println!("  ❌ Fee is extremely high (> 100,000 sats)");
        }
        if self.fee_rate_sat_vb > 1000.0 {
            println!("  ❌ Fee rate is extremely high (> 1000 sat/vB)");
        }
        if self.total_input_value == 0 {
            println!("  ❌ Total input value is 0 - input values not calculated correctly");
        }
        
        // Check for envelope transaction patterns
        let has_large_witness = self.input_details.iter().any(|input| input.witness_size > 10000);
        if has_large_witness {
            println!("  ℹ️  Large witness data detected (envelope transaction)");
        }
        
        let has_op_return = self.output_details.iter().any(|output| output.script_type == "OP_RETURN");
        if has_op_return {
            println!("  ℹ️  OP_RETURN output detected (likely runestone/protostone)");
        }
        
        println!("═══════════════════════════════════════════════════════════════\n");
    }
}

/// Mock transaction builder that replicates the alkanes execute scenario
struct MockTransactionBuilder {
    commit_outpoint: bitcoin::OutPoint,
    additional_utxos: Vec<(bitcoin::OutPoint, u64)>,
    envelope_data: Vec<u8>,
}

impl MockTransactionBuilder {
    fn new() -> Self {
        // Create mock commit outpoint (dust amount)
        let commit_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
            vout: 0,
        };
        
        // Create mock additional UTXO (funding UTXO)
        let funding_utxo = (
            bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
                vout: 0,
            },
            5000000000u64, // 50 BTC in sats
        );
        
        // Load envelope data (mock)
        let envelope_data = vec![0u8; 117826]; // Same size as free_mint.wasm.gz
        
        Self {
            commit_outpoint,
            additional_utxos: vec![funding_utxo],
            envelope_data,
        }
    }
    
    /// Build a mock reveal transaction that replicates the alkanes execute scenario
    fn build_reveal_transaction(&self) -> Result<(Transaction, Vec<u64>)> {
        use bitcoin::{TxIn, TxOut, Transaction, Sequence, Witness, ScriptBuf};
        
        // Create inputs
        let mut inputs = Vec::new();
        let mut input_values = Vec::new();
        
        // First input: commit outpoint (dust)
        inputs.push(TxIn {
            previous_output: self.commit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        input_values.push(546u64); // Dust amount
        
        // Additional inputs: funding UTXOs
        for (outpoint, value) in &self.additional_utxos {
            inputs.push(TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            input_values.push(*value);
        }
        
        // Create outputs
        let mut outputs = Vec::new();
        
        // Output 1: Recipient (dust)
        outputs.push(TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::from_hex("5120" + &"a".repeat(64)).unwrap(), // Mock P2TR
        });
        
        // Output 2: Change (large amount)
        let total_input: u64 = input_values.iter().sum();
        let target_fee = 5000u64;
        let change_amount = total_input - 546 - target_fee;
        outputs.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: ScriptBuf::from_hex("5120" + &"b".repeat(64)).unwrap(), // Mock P2TR
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
        
        // Create base transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };
        
        // Add envelope witness data to first input (this is where the large data goes)
        let mut witness_stack = Vec::new();
        
        // Add signature placeholder
        witness_stack.push(vec![0u8; 64]); // Mock signature
        
        // Add envelope data (this is the large witness item)
        witness_stack.push(self.envelope_data.clone());
        
        // Add script and control block placeholders
        witness_stack.push(vec![0u8; 100]); // Mock script
        witness_stack.push(vec![0u8; 33]); // Mock control block
        
        tx.input[0].witness = Witness::from_slice(&witness_stack);
        
        // Add normal witness to second input
        let mut normal_witness = Vec::new();
        normal_witness.push(vec![0u8; 64]); // Mock signature
        normal_witness.push(vec![0u8; 33]); // Mock pubkey
        tx.input[1].witness = Witness::from_slice(&normal_witness);
        
        Ok((tx, input_values))
    }
}

#[tokio::test]
async fn test_alkanes_fee_calculation_debug() -> Result<()> {
    println!("\n🧪 ALKANES FEE CALCULATION DEBUG TEST");
    println!("═══════════════════════════════════════════════════════════════");
    
    // Build mock transaction that replicates the alkanes execute scenario
    let builder = MockTransactionBuilder::new();
    let (tx, input_values) = builder.build_reveal_transaction()?;
    
    // Analyze the transaction
    let analysis = TransactionAnalysis::analyze(&tx, &input_values);
    analysis.print_analysis();
    
    // Test different fee calculation methods
    println!("🧮 TESTING DIFFERENT FEE CALCULATION METHODS");
    println!("═══════════════════════════════════════════════════════════════");
    
    // Method 1: Simple input - output
    let method1_fee = analysis.total_input_value.saturating_sub(analysis.total_output_value);
    let method1_rate = method1_fee as f64 / analysis.vsize as f64;
    println!("Method 1 (Input - Output):");
    println!("  Fee: {} sats", method1_fee);
    println!("  Rate: {:.2} sat/vB", method1_rate);
    
    // Method 2: Fixed fee approach
    let method2_fee = 5000u64;
    let method2_rate = method2_fee as f64 / analysis.vsize as f64;
    println!("Method 2 (Fixed 5000 sats):");
    println!("  Fee: {} sats", method2_fee);
    println!("  Rate: {:.2} sat/vB", method2_rate);
    
    // Method 3: Fee rate based calculation
    let target_rate = 1.0f64; // 1 sat/vB
    let method3_fee = (target_rate * analysis.vsize as f64) as u64;
    let method3_rate = method3_fee as f64 / analysis.vsize as f64;
    println!("Method 3 (1 sat/vB target):");
    println!("  Fee: {} sats", method3_fee);
    println!("  Rate: {:.2} sat/vB", method3_rate);
    
    // Check what Bitcoin Core would see
    println!("\n🏦 BITCOIN CORE PERSPECTIVE");
    println!("═══════════════════════════════════════════════════════════════");
    println!("Bitcoin Core calculates fee as: (sum_inputs - sum_outputs) / vsize");
    println!("  Sum of inputs: {} sats", analysis.total_input_value);
    println!("  Sum of outputs: {} sats", analysis.total_output_value);
    println!("  Difference: {} sats", analysis.calculated_fee);
    println!("  VSize: {} vbytes", analysis.vsize);
    println!("  Bitcoin Core fee rate: {:.2} sat/vB", analysis.fee_rate_sat_vb);
    
    if analysis.fee_rate_sat_vb > 1000.0 {
        println!("  ❌ This is why Bitcoin Core rejects with 'absurdly high fee rate'!");
    }
    
    // Identify the root cause
    println!("\n🔍 ROOT CAUSE ANALYSIS");
    println!("═══════════════════════════════════════════════════════════════");
    
    if analysis.total_input_value == 0 {
        println!("❌ ISSUE: Input values are not being calculated correctly");
        println!("   The transaction builder is not setting proper input values");
    } else if analysis.calculated_fee > 100_000 {
        println!("❌ ISSUE: Fee calculation is incorrect");
        println!("   The difference between inputs and outputs is too large");
        println!("   Expected fee: ~5000 sats");
        println!("   Actual fee: {} sats", analysis.calculated_fee);
        println!("   Excess: {} sats", analysis.calculated_fee.saturating_sub(5000));
    } else {
        println!("✅ Fee calculation appears correct");
    }
    
    // Test assertions
    assert!(analysis.vsize > 0, "Transaction should have non-zero vsize");
    assert!(analysis.total_input_value > 0, "Should have non-zero input value");
    assert!(analysis.total_output_value > 0, "Should have non-zero output value");
    
    // This test should help us identify exactly where the fee calculation goes wrong
    println!("\n✅ Test completed - check output above for fee calculation issues");
    
    Ok(())
}

#[tokio::test]
async fn test_envelope_witness_size_impact() -> Result<()> {
    println!("\n🧪 ENVELOPE WITNESS SIZE IMPACT TEST");
    println!("═══════════════════════════════════════════════════════════════");
    
    let builder = MockTransactionBuilder::new();
    
    // Test with different envelope sizes
    let test_sizes = vec![
        (0, "No envelope"),
        (1000, "Small envelope (1KB)"),
        (10000, "Medium envelope (10KB)"),
        (117826, "Actual envelope (117KB)"),
        (1000000, "Large envelope (1MB)"),
    ];
    
    for (size, description) in test_sizes {
        println!("\n📊 Testing {}: {} bytes", description, size);
        
        // Build transaction with specific envelope size
        let mut test_builder = builder.clone();
        test_builder.envelope_data = vec![0u8; size];
        
        let (tx, input_values) = test_builder.build_reveal_transaction()?;
        let analysis = TransactionAnalysis::analyze(&tx, &input_values);
        
        println!("  VSize: {} vbytes", analysis.vsize);
        println!("  Weight: {} WU", analysis.weight);
        println!("  Fee (5000 sats): {:.2} sat/vB", 5000.0 / analysis.vsize as f64);
        
        // Check witness discount calculation
        let base_size = bitcoin::consensus::serialize(&tx).len();
        let witness_size: usize = tx.input.iter()
            .map(|input| input.witness.iter().map(|item| item.len()).sum::<usize>())
            .sum();
        
        println!("  Base size: {} bytes", base_size);
        println!("  Witness size: {} bytes", witness_size);
        println!("  Witness discount: {} bytes", witness_size / 4);
        
        // Verify vsize calculation: base_size + (witness_size / 4)
        let calculated_vsize = base_size + (witness_size / 4);
        println!("  Calculated vsize: {} vbytes", calculated_vsize);
        
        if calculated_vsize != analysis.vsize {
            println!("  ⚠️  VSize calculation mismatch!");
        }
    }
    
    Ok(())
}

// Helper to clone MockTransactionBuilder
impl Clone for MockTransactionBuilder {
    fn clone(&self) -> Self {
        Self {
            commit_outpoint: self.commit_outpoint,
            additional_utxos: self.additional_utxos.clone(),
            envelope_data: self.envelope_data.clone(),
        }
    }
}

use std::str::FromStr;