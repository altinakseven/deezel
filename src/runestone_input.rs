//! Runestone input implementation
//!
//! This module provides functionality for creating Runestone transactions
//! with inputs for more complex operations beyond basic DIESEL token minting.

use anyhow::{Context, Result};
use bdk::bitcoin::{ScriptBuf, Transaction};
use log::{debug, info};
use std::convert::TryInto;
use crate::runestone::{Runestone, varint};

/// Execute parameters for alkane operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteParams {
    /// Namespace
    pub namespace: u128,
    /// Contract ID
    pub contract_id: u128,
    /// Operation code
    pub opcode: u128,
}

/// Input structure representing a token transfer/operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// ID of the token/alkane
    pub id: u128,
    /// Amount to transfer/operate on
    pub amount: u128,
    /// Output index to send to (0-based)
    pub output: u8,
}

/// Complete transaction execution context
#[derive(Debug, Clone)]
pub struct ExecuteContext {
    /// Execute parameters (namespace, contract ID, opcode)
    pub params: ExecuteParams,
    /// Input specifications (optional)
    pub inputs: Option<Vec<Input>>,
}

impl Runestone {
    /// Create a new Runestone with execute parameters and optional inputs
    pub fn new_execute(context: &ExecuteContext) -> Self {
        // Start with protocol tag 1
        let mut protocol = vec![1];
        
        // Add execute parameters
        protocol.push(context.params.namespace);
        protocol.push(context.params.contract_id);
        protocol.push(context.params.opcode);
        
        // Add input data if provided
        if let Some(inputs) = &context.inputs {
            for input in inputs {
                // Add input ID
                protocol.push(input.id);
                // Add input amount
                protocol.push(input.amount);
                // Add output index
                protocol.push(input.output as u128);
            }
        }
        
        Self {
            protocol: Some(protocol),
        }
    }
    
    
    /// Parse execute parameters from string format "namespace,contract_id,opcode"
    pub fn parse_execute_params(param_str: &str) -> Result<ExecuteParams> {
        let parts: Vec<&str> = param_str.split(',').collect();
        
        if parts.len() != 3 {
            return Err(anyhow::anyhow!(
                "Invalid execute format. Expected 'namespace,contract_id,opcode'"
            ));
        }
        
        let namespace = parts[0].parse::<u128>()
            .context(format!("Failed to parse namespace from '{}'", parts[0]))?;
            
        let contract_id = parts[1].parse::<u128>()
            .context(format!("Failed to parse contract ID from '{}'", parts[1]))?;
            
        let opcode = parts[2].parse::<u128>()
            .context(format!("Failed to parse opcode from '{}'", parts[2]))?;
        
        Ok(ExecuteParams {
            namespace,
            contract_id,
            opcode,
        })
    }
    
    /// Parse execute context (params and optional inputs) from a string
    /// Format: "namespace,contract_id,opcode[,id1,amount1,output1,id2,amount2,output2,...]"
    /// The first three values are the execute parameters, followed by optional input triplets
    pub fn parse_execute_context(input_str: &str) -> Result<ExecuteContext> {
        let parts: Vec<&str> = input_str.split(',').collect();
        
        // Need at least the three execute parameters
        if parts.len() < 3 {
            return Err(anyhow::anyhow!(
                "Invalid execute format. Expected at least 'namespace,contract_id,opcode'"
            ));
        }
        
        // Parse execute parameters (first three values)
        let exec_param_str = format!("{},{},{}", parts[0], parts[1], parts[2]);
        let params = Self::parse_execute_params(&exec_param_str)?;
        
        // If there are more parts, parse them as inputs
        let inputs = if parts.len() > 3 {
            // Must have complete triplets after the execute parameters
            if (parts.len() - 3) % 3 != 0 {
                return Err(anyhow::anyhow!(
                    "Invalid input format. Expected triplets of id,amount,output after execute parameters"
                ));
            }
            
            // Extract the input part of the string and parse it
            let input_part = parts[3..].join(",");
            Some(Self::parse_inputs(&input_part)?)
        } else {
            None
        };
        
        Ok(ExecuteContext {
            params,
            inputs,
        })
    }
    
    /// Parse inputs from input string of format "id1,amount1,output1,id2,amount2,output2,..."
    pub fn parse_inputs(input: &str) -> Result<Vec<Input>> {
        let parts: Vec<&str> = input.split(',').collect();
        
        if parts.len() % 3 != 0 {
            return Err(anyhow::anyhow!("Invalid input format. Expected triplets of id,amount,output"));
        }
        
        let mut inputs = Vec::new();
        let mut i = 0;
        
        while i < parts.len() {
            let id = parts[i].parse::<u128>()
                .context(format!("Failed to parse input ID from '{}'", parts[i]))?;
            
            let amount = parts[i + 1].parse::<u128>()
                .context(format!("Failed to parse input amount from '{}'", parts[i + 1]))?;
            
            let output = parts[i + 2].parse::<u8>()
                .context(format!("Failed to parse input output from '{}'", parts[i + 2]))?;
            
            inputs.push(Input {
                id,
                amount,
                output,
            });
            
            i += 3;
        }
        
        Ok(inputs)
    }
    
    /// Validate that the provided inputs are allowed with the user's alkane holdings
    pub async fn validate_inputs_with_alkanes(
        inputs: &[Input], 
        address: &str, 
        rpc_client: &crate::rpc::RpcClient
    ) -> Result<bool> {
        info!("Validating inputs against user alkane holdings");
        
        // Get user's alkane holdings
        let alkanes = rpc_client.get_protorunes_by_address(address).await?;
        
        // Convert to a more usable format
        let alkanes_array = alkanes.as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid alkanes response format"))?;
        
        // Check each input against alkane holdings
        for input in inputs {
            let mut found = false;
            
            for alkane in alkanes_array {
                // Extract alkane ID and balance
                let alkane_obj = alkane.as_object()
                    .ok_or_else(|| anyhow::anyhow!("Invalid alkane object format"))?;
                
                let alkane_id = alkane_obj.get("id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow::anyhow!("Invalid or missing alkane ID"))?;
                
                let alkane_balance = alkane_obj.get("balance")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Invalid or missing alkane balance"))?
                    .parse::<u128>()
                    .context("Failed to parse alkane balance")?;
                
                // Check if this alkane matches the input
                if alkane_id as u128 == input.id {
                    // Check if balance is sufficient
                    if alkane_balance >= input.amount {
                        found = true;
                        break;
                    }
                }
            }
            
            if !found {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// UTXO structure for transaction inputs
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: u64,
    /// Script pubkey
    pub script_pubkey: String,
}

/// Extract UTXOs from spendables response
fn extract_utxos_from_spendables(spendables: &serde_json::Value) -> Result<Vec<Utxo>> {
    let spendables_array = spendables.as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid spendables response format"))?;
    
    let mut utxos = Vec::new();
    
    for spendable in spendables_array {
        let spendable_obj = spendable.as_object()
            .ok_or_else(|| anyhow::anyhow!("Invalid spendable object format"))?;
        
        // Extract outpoint (txid:vout)
        let outpoint = spendable_obj.get("outpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid or missing outpoint"))?;
        
        let parts: Vec<&str> = outpoint.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid outpoint format. Expected 'txid:vout'"));
        }
        
        let txid = parts[0].to_string();
        let vout = parts[1].parse::<u32>()
            .context("Invalid vout in outpoint")?;
        
        // Extract value
        let value = spendable_obj.get("value")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Invalid or missing value"))?;
        
        // Extract script_pubkey with proper error handling
        let script_pubkey = spendable_obj.get("script_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid script_pubkey for outpoint {}", outpoint))?
            .to_string();
        
        utxos.push(Utxo {
            txid,
            vout,
            value,
            script_pubkey,
        });
    }
    
    Ok(utxos)
}

/// Calculate the exact virtual size of a transaction in vbytes using Bitcoin consensus rules
fn estimate_virtual_size(tx: &Transaction) -> usize {
    use bdk::bitcoin::consensus::{Encodable, serialize};
    
    // Get the base transaction without witnesses
    let mut base_tx = tx.clone();
    for input in &mut base_tx.input {
        input.witness.clear(); // Remove all witness data
    }
    
    // Serialize the base transaction to calculate its size
    let base_tx_bytes = serialize(&base_tx);
    let base_size = base_tx_bytes.len();
    
    // Serialize the full transaction with witnesses to get total size
    let full_tx_bytes = serialize(tx);
    let total_size = full_tx_bytes.len();
    
    // Calculate witness size (difference between full tx and base tx)
    let witness_size = total_size - base_size;
    
    // Calculate weight as defined by BIP 141: (base_size * 3) + total_size
    let weight = (base_size * 3) + total_size;
    
    // Calculate virtual size (vsize): weight / 4, rounded up
    (weight + 3) / 4
}

/// Extended functionality for transaction construction with inputs
pub mod transaction_input {
    use super::*;
    use crate::transaction::TransactionConstructor;
    use std::sync::Arc;
    use crate::wallet::WalletManager;
    use crate::rpc::RpcClient;
    use bdk::bitcoin::{Address, Transaction, TxOut};
    use std::str::FromStr;
    use std::collections::HashMap;
    
    /// Extend TransactionConstructor with input functionality
    impl TransactionConstructor {
        
        /// Create a transaction with execute context
        pub async fn create_transaction_with_execute(&self, execute_str: &str) -> Result<Transaction> {
            info!("Creating transaction with execute parameters");
            
            // Parse execute context from string
            let context = Runestone::parse_execute_context(execute_str)?;
            
            // Get a new address for the dust output
            let dust_address = self.wallet_manager.get_address().await?;
            let address = Address::from_str(&dust_address)
                .context("Failed to parse dust address")?;
            let dust_script = address.assume_checked().script_pubkey();
            
            // Create Runestone with execute context
            let runestone = Runestone::new_execute(&context);
            let runestone_script = runestone.encipher();
            
            // Constants for transaction
            const DUST_OUTPUT_VALUE: u64 = 546;
            let fee_rate = self.tx_config.fee_rate;
            
            // Get dust output address
            // (Already got it above, no need to get it again)
            
            // Create initial outputs (dust output and OP_RETURN) to estimate their size
            let mut tx_outputs = vec![
                // Dust output for protocol
                TxOut {
                    value: DUST_OUTPUT_VALUE,
                    script_pubkey: dust_script.clone(),
                },
                // OP_RETURN output with Runestone
                TxOut {
                    value: 0,
                    script_pubkey: runestone_script.clone(),
                },
            ];
            
            // Add outputs for each input if provided
            let mut output_map = std::collections::HashMap::new();
            
            // Process inputs if they exist in the context
            if let Some(inputs) = &context.inputs {
                for input in inputs {
                    // Skip output 0 (which is the dust output)
                    if input.output == 0 {
                        continue;
                    }
                    
                    // Ensure input amount is within valid range for bitcoin values
                    if input.amount > u64::MAX as u128 {
                        return Err(anyhow::anyhow!(
                            "Input amount {} exceeds maximum Bitcoin value", input.amount
                        ));
                    }
                    
                    // Convert the amount for Bitcoin transaction (capped at u64 max)
                    let amount = input.amount as u64;
                    
                    // Add to output map
                    if !output_map.contains_key(&input.output) {
                        output_map.insert(input.output, amount);
                    } else {
                        let existing = output_map.get(&input.output).unwrap();
                        output_map.insert(input.output, existing.checked_add(amount)
                            .ok_or_else(|| anyhow::anyhow!("Output amount overflow"))?);
                    }
                }
            }
            
            // Calculate total output amount required
            let mut total_output_amount = DUST_OUTPUT_VALUE; // Start with dust output
            
            // Add the output amounts from the map
            for (_, value) in &output_map {
                let final_value = std::cmp::max(*value, DUST_OUTPUT_VALUE);
                total_output_amount = total_output_amount.checked_add(final_value)
                    .ok_or_else(|| anyhow::anyhow!("Output amount overflow"))?;
            }
            
            // Initial fee estimate for UTXO selection calculations (will refine later)
            let initial_fee_estimate = 1000; // A conservative estimate
            let target_amount = total_output_amount.checked_add(initial_fee_estimate)
                .ok_or_else(|| anyhow::anyhow!("Output amount overflow"))?;
            
            // Select UTXOs using optimal coin selection
            info!("Selecting UTXOs for transaction");
            let address = self.wallet_manager.get_address().await?;
            
            // Get all spendable UTXOs via RPC
            let spendables = self.rpc_client.get_spendables_by_address(&address).await?;
            let all_utxos = extract_utxos_from_spendables(&spendables)
                .context("Failed to extract UTXOs from spendables")?;
            
            if all_utxos.is_empty() {
                return Err(anyhow::anyhow!("No spendable UTXOs found"));
            }
            
            info!("Found {} UTXOs to select from", all_utxos.len());
            
            // Sort UTXOs by value (for optimal selection)
            let mut sorted_utxos = all_utxos.clone();
            sorted_utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.value)); // Sort in descending order
            
            // Try to find a single UTXO that meets our needs
            let mut selected_utxos = Vec::new();
            let mut total_input_amount = 0;
            
            // First try: find a single UTXO that covers the amount
            for utxo in &sorted_utxos {
                if utxo.value >= target_amount {
                    selected_utxos.push(utxo.clone());
                    total_input_amount = utxo.value;
                    info!("Selected single UTXO that covers the entire amount");
                    break;
                }
            }
            
            // Second try: if no single UTXO works, select multiple UTXOs
            if selected_utxos.is_empty() {
                // Sort by value ascending for this approach
                let mut ascending_utxos = all_utxos.clone();
                ascending_utxos.sort_by_key(|utxo| utxo.value);
                
                // Try to find the smallest set of UTXOs that meet our target
                // Start with smallest UTXOs to help consolidate wallet
                for utxo in &ascending_utxos {
                    selected_utxos.push(utxo.clone());
                    total_input_amount += utxo.value;
                    
                    if total_input_amount >= target_amount {
                        break;
                    }
                }
                
                // If we still don't have enough funds
                if total_input_amount < target_amount {
                    return Err(anyhow::anyhow!(
                        "Insufficient funds: need at least {} sats but only have {} sats",
                        target_amount, total_input_amount
                    ));
                }
                
                info!("Selected {} UTXOs with total value {}", selected_utxos.len(), total_input_amount);
            }
            
            // Create transaction inputs from selected UTXOs
            let mut tx_inputs = Vec::new();
            
            for utxo in &selected_utxos {
                let txid = bdk::bitcoin::Txid::from_str(&utxo.txid)
                    .context(format!("Invalid TXID: {}", utxo.txid))?;
                
                let outpoint = bdk::bitcoin::OutPoint {
                    txid,
                    vout: utxo.vout,
                };
                
                // Set sequence for RBF if enabled
                let sequence = if self.tx_config.enable_rbf {
                    // Use RBF signal as defined in BIP125
                    bdk::bitcoin::Sequence(0xFFFFFFFD) 
                } else {
                    bdk::bitcoin::Sequence::MAX
                };
                
                tx_inputs.push(bdk::bitcoin::TxIn {
                    previous_output: outpoint,
                    script_sig: bdk::bitcoin::ScriptBuf::new(),
                    sequence,
                    witness: bdk::bitcoin::Witness::new(),
                });
            }
            
            // Create initial outputs: dust output and OP_RETURN
            let mut tx_outputs = vec![
                // Dust output for DIESEL protocol
                TxOut {
                    value: DUST_OUTPUT_VALUE,
                    script_pubkey: dust_script.clone(),
                },
                // OP_RETURN output with Runestone
                TxOut {
                    value: 0,
                    script_pubkey: runestone_script,
                },
            ];
            
            // Create additional outputs based on input specifications (if any)
            // Map to track which outputs have been created (to avoid duplicates)
            let mut output_map = std::collections::HashMap::new();
            
            // Process inputs if they exist in the context
            if let Some(inputs) = &context.inputs {
                for input in inputs {
                    // Skip output 0 (which is the dust output)
                    if input.output == 0 {
                        continue;
                    }
                    
                    // Ensure input amount is within valid range for bitcoin values
                    if input.amount > u64::MAX as u128 {
                        return Err(anyhow::anyhow!(
                            "Input amount {} exceeds maximum Bitcoin value", input.amount
                        ));
                    }
                    
                    // Convert the amount for Bitcoin transaction (capped at u64 max)
                    let amount = input.amount as u64;
                    
                    // Check if we need to create this output
                    if !output_map.contains_key(&input.output) {
                        // Create new address for this output
                        let output_address = self.wallet_manager.get_address().await?;
                        let output_script = Address::from_str(&output_address)
                            .context("Failed to parse output address")?
                            .assume_checked()
                            .script_pubkey();
                        
                        // Add it to our map with initial amount value
                        output_map.insert(input.output, (output_script, amount));
                    } else {
                        // Add to the existing output's amount
                        let (_, existing_amount) = output_map.get(&input.output).unwrap();
                        let new_amount = existing_amount.checked_add(amount)
                            .ok_or_else(|| anyhow::anyhow!(
                                "Output amount overflow for output {}", input.output
                            ))?;
                        
                        // Update the map with the new total amount
                        let script = output_map.get(&input.output).unwrap().0.clone();
                        output_map.insert(input.output, (script, new_amount));
                    }
                }
            }
            
            // Track how much we need to spend from inputs
            let mut total_output_amount = DUST_OUTPUT_VALUE; // Start with dust output
            
            // Now add all the outputs to the transaction (if any were created)
            // Sort by output index for consistency
            let mut sorted_outputs: Vec<(u8, (ScriptBuf, u64))> = output_map
                .into_iter()
                .collect();
            sorted_outputs.sort_by_key(|(idx, _)| *idx);
            
            // Add outputs to transaction in sorted order
            for (idx, (script, value)) in sorted_outputs {
                // Ensure we have a minimum dust value
                let final_value = if value < DUST_OUTPUT_VALUE {
                    DUST_OUTPUT_VALUE
                } else {
                    value
                };
                
                // Add to total output amount
                total_output_amount = total_output_amount.checked_add(final_value)
                    .ok_or_else(|| anyhow::anyhow!("Output amount overflow"))?;
                
                // Add the output to transaction
                tx_outputs.push(TxOut {
                    value: final_value,
                    script_pubkey: script,
                });
            }
            
            // Check if we have enough funds
            if total_output_amount > total_input_amount {
                return Err(anyhow::anyhow!(
                    "Insufficient funds: need {} sats but only have {} sats",
                    total_output_amount, total_input_amount
                ));
            }
            
            // Create the transaction with outputs (for size estimation and final)
            let mut tx = Transaction {
                version: 2,
                lock_time: bdk::bitcoin::absolute::LockTime::ZERO,
                input: tx_inputs,
                output: tx_outputs,
            };
            
            // Calculate fee more accurately now that we know output count
            let tx_size = estimate_virtual_size(&tx);
            let fee = (tx_size as f64 * fee_rate).ceil() as u64;
            
            // Calculate change amount after accounting for all outputs and fee
            let change_amount = total_input_amount.checked_sub(total_output_amount)
                .and_then(|amount| amount.checked_sub(fee))
                .ok_or_else(|| anyhow::anyhow!(
                    "Insufficient funds after accounting for fee"
                ))?;
            if change_amount > DUST_OUTPUT_VALUE {
                // Get change address
                let change_address = self.wallet_manager.get_address().await?;
                let change_script = Address::from_str(&change_address)
                    .context("Failed to parse change address")?
                    .assume_checked()
                    .script_pubkey();
                
                // Add change output
                tx.output.push(TxOut {
                    value: change_amount,
                    script_pubkey: change_script,
                });
            }
            
            // Sign the transaction with the wallet
            info!("Signing transaction");
            
            // Create signing data for wallet manager
            let mut psbt = bdk::bitcoin::psbt::Psbt::from_unsigned_tx(tx.clone())?;
            
            // Add input UTXOs to the PSBT
            for (i, utxo) in selected_utxos.iter().enumerate() {
                // Parse script into proper ScriptBuf
                let script = if !utxo.script_pubkey.is_empty() {
                    // Parse hex script to bytes
                    let script_bytes = hex::decode(&utxo.script_pubkey.trim_start_matches("0x"))
                        .context("Failed to decode script_pubkey")?;
                    ScriptBuf::from_bytes(script_bytes)
                } else {
                    // If script is empty, create a default address script
                    let addr = self.wallet_manager.get_address().await?;
                    Address::from_str(&addr)
                        .context("Failed to parse address")?
                        .assume_checked()
                        .script_pubkey()
                };
                
                // Create witness UTXO
                let witness_utxo = TxOut {
                    value: utxo.value,
                    script_pubkey: script,
                };
                
                // Add witness UTXO to the PSBT input
                psbt.inputs[i].witness_utxo = Some(witness_utxo);
            }
            
            // Sign the PSBT
            self.wallet_manager.sign_transaction(&mut psbt)
                .await
                .context("Failed to sign transaction")?;
            
            // Extract the final transaction
            let signed_tx = psbt.extract_tx()
                .context("Failed to extract signed transaction")?;
            
            info!("Transaction with inputs created and signed successfully");
            debug!("Transaction: {:?}", signed_tx);
            Ok(signed_tx)
        }
        
        
        /// Validate inputs against user's alkane holdings
        pub async fn validate_inputs(&self, input_str: &str) -> Result<bool> {
            // Parse inputs from string
            let inputs = Runestone::parse_inputs(input_str)?;
            
            // Get user's address
            let address = self.wallet_manager.get_address().await?;
            
            // Validate inputs against alkane holdings
            Runestone::validate_inputs_with_alkanes(&inputs, &address, &self.rpc_client).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_execute_params() {
        let param_str = "2,0,77";
        let params = Runestone::parse_execute_params(param_str).unwrap();
        
        assert_eq!(params.namespace, 2);
        assert_eq!(params.contract_id, 0);
        assert_eq!(params.opcode, 77);
    }
    
    #[test]
    fn test_parse_execute_context() {
        // Test with just execute parameters
        let input = "2,0,77";
        let context = Runestone::parse_execute_context(input).unwrap();
        
        assert_eq!(context.params.namespace, 2);
        assert_eq!(context.params.contract_id, 0);
        assert_eq!(context.params.opcode, 77);
        assert!(context.inputs.is_none());
        
        // Test with execute parameters and inputs
        let input = "2,0,77,1010,100000000,2,1011,500000000,3";
        let context = Runestone::parse_execute_context(input).unwrap();
        
        assert_eq!(context.params.namespace, 2);
        assert_eq!(context.params.contract_id, 0);
        assert_eq!(context.params.opcode, 77);
        
        let inputs = context.inputs.unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].id, 1010);
        assert_eq!(inputs[0].amount, 100000000);
        assert_eq!(inputs[0].output, 2);
        assert_eq!(inputs[1].id, 1011);
        assert_eq!(inputs[1].amount, 500000000);
        assert_eq!(inputs[1].output, 3);
    }
    
    #[test]
    fn test_parse_inputs() {
        let input = "1010,100000000,2,1011,500000000,3";
        let inputs = Runestone::parse_inputs(input).unwrap();
        
        assert_eq!(inputs.len(), 2);
        
        assert_eq!(inputs[0].id, 1010);
        assert_eq!(inputs[0].amount, 100000000);
        assert_eq!(inputs[0].output, 2);
        
        assert_eq!(inputs[1].id, 1011);
        assert_eq!(inputs[1].amount, 500000000);
        assert_eq!(inputs[1].output, 3);
    }
    
}
