// This file is part of the deezel project.
// Copyright (c) 2023, Casey Rodarmor, all rights reserved.
// Copyright (c) 2024, The Deezel Developers, all rights reserved.
// Deezel is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

//! Enhanced alkanes execute functionality with commit/reveal transaction support
//!
//! This module implements the complex alkanes execute command that supports:
//! - Commit/reveal transaction pattern for envelope data
//! - Complex protostone parsing with cellpacks and edicts
//! - UTXO selection based on alkanes and Bitcoin requirements
//! - Runestone construction with multiple protostones
//! - Address identifier resolution for outputs and change
//! - Transaction tracing with metashrew synchronization

use crate::{Result, DeezelError, DeezelProvider, JsonValue};
use crate::traits::{WalletProvider, UtxoInfo};
use bitcoin::{Transaction, ScriptBuf, OutPoint, TxOut, Address, XOnlyPublicKey};
use core::str::FromStr;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};
#[cfg(feature = "std")]
use std::{vec, vec::Vec, string::{String, ToString}, format};
use tokio::time::{sleep, Duration};
pub use super::types::{EnhancedExecuteParams, EnhancedExecuteResult, InputRequirement, ProtostoneSpec, OutputTarget};
use super::envelope::AlkanesEnvelope;
use anyhow::anyhow;
use protorune_support::protostone::{Protostone, into_protostone_edicts};
use crate::utils::protostone::Protostones;

const MAX_FEE_SATS: u64 = 100_000; // 0.001 BTC. Cap to avoid "absurdly high fee rate" errors.


/// Enhanced alkanes executor
pub struct EnhancedAlkanesExecutor<'a, T: DeezelProvider> {
    pub provider: &'a mut T,
}

impl<'a, T: DeezelProvider> EnhancedAlkanesExecutor<'a, T> {
    /// Create a new enhanced alkanes executor
    pub fn new(provider: &'a mut T) -> Self {
        Self { provider }
    }

    /// Execute an enhanced alkanes transaction with commit/reveal pattern
    pub async fn execute(&mut self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        log::info!("Starting enhanced alkanes execution");
        
        self.validate_envelope_cellpack_usage(&params)?;

        if let Some(envelope_data) = &params.envelope_data {
            log::info!("CONTRACT DEPLOYMENT: Using envelope with BIN data for contract deployment");
            log::info!("Envelope data size: {} bytes", envelope_data.len());
            let envelope = AlkanesEnvelope::for_contract(envelope_data.clone());
            log::info!("Created AlkanesEnvelope with BIN protocol tag and gzip compression");
            self.execute_commit_reveal_pattern(params, &envelope).await
        } else {
            log::info!("CONTRACT EXECUTION: Single transaction without envelope");
            self.execute_single_transaction(&params).await
        }
    }

    /// Execute commit/reveal transaction pattern with proper script-path spending
    async fn execute_commit_reveal_pattern(
        &mut self,
        params: EnhancedExecuteParams,
        envelope: &AlkanesEnvelope,
    ) -> Result<EnhancedExecuteResult> {
        log::info!("Using commit/reveal pattern with script-path spending");

        // Step 1: Create and broadcast commit transaction
        let (commit_txid, commit_fee, commit_outpoint, commit_output_value) =
            self.create_and_broadcast_commit_transaction(envelope, &params).await?;

        log::info!("✅ Commit transaction broadcast: {}", commit_txid);
        log::info!("💰 Commit fee: {} sats", commit_fee);
        log::info!("🎯 Commit output created at: {}:{}", commit_outpoint.txid, commit_outpoint.vout);

        // Step 2: Wait for commit transaction to be available
        self.provider.sleep_ms(1000).await;

        // Step 3: Create reveal transaction
        let (reveal_tx, reveal_fee) =
            self.create_script_path_reveal_transaction(&params, envelope, commit_outpoint, commit_output_value).await?;
        
        let reveal_txid = self.provider.broadcast_transaction(bitcoin::consensus::encode::serialize_hex(&reveal_tx)).await?;

        log::info!("✅ Reveal transaction broadcast: {}", reveal_txid);
        log::info!("💰 Reveal fee: {} sats", reveal_fee);
        log::info!("🎯 Total fees: {} sats (commit: {}, reveal: {})", commit_fee + reveal_fee, commit_fee, reveal_fee);

        // Step 4: Handle tracing if enabled
        let traces = if params.trace_enabled {
            self.trace_reveal_transaction(&reveal_txid, &params).await?
        } else {
            None
        };

        Ok(EnhancedExecuteResult {
            commit_txid: Some(commit_txid),
            reveal_txid,
            commit_fee: Some(commit_fee),
            reveal_fee,
            inputs_used: vec![commit_outpoint.to_string()], // Simplified for now
            outputs_created: reveal_tx.output.iter().map(|o| o.script_pubkey.to_string()).collect(),
            traces,
        })
    }

    /// Creates and broadcasts the commit transaction.
    ///
    /// The commit transaction creates an output that locks funds to a taproot address.
    /// The taproot script path contains the envelope data, which will be revealed
    /// in the reveal transaction.
    async fn create_and_broadcast_commit_transaction(
        &mut self,
        envelope: &AlkanesEnvelope,
        params: &EnhancedExecuteParams,
    ) -> Result<(String, u64, OutPoint, u64)> {
        log::info!("Creating commit transaction");

        let internal_key = self.provider.get_internal_key().await?;
        let commit_address = self.create_commit_address_for_envelope(envelope, internal_key).await?;

        log::info!("Envelope commit address: {}", commit_address);

        // Determine the amount needed for the commit output to fund the reveal transaction
        let mut required_bitcoin = 546u64; // Dust for the reveal output
        for requirement in &params.input_requirements {
            if let InputRequirement::Bitcoin { amount } = requirement {
                required_bitcoin += amount;
            }
        }
        let estimated_reveal_fee = 50_000u64; // Conservative fee estimate
        required_bitcoin += estimated_reveal_fee;
        required_bitcoin += params.to_addresses.len() as u64 * 546;

        // Select UTXOs to fund the commit transaction
        let funding_utxos = self.select_utxos(&[InputRequirement::Bitcoin { amount: required_bitcoin }]).await?;

        let commit_output = TxOut {
            value: bitcoin::Amount::from_sat(required_bitcoin),
            script_pubkey: commit_address.script_pubkey(),
        };

        // Build and sign the commit transaction
        let (commit_tx, commit_fee) = self.build_commit_transaction(funding_utxos, commit_output, params.fee_rate).await?;
        
        // Broadcast the commit transaction
        let commit_txid = self.provider.broadcast_transaction(bitcoin::consensus::encode::serialize_hex(&commit_tx)).await?;

        let commit_outpoint = OutPoint {
            txid: commit_tx.compute_txid(),
            vout: 0, // The commit output is always the first output
        };

        let commit_output_value = commit_tx.output[0].value.to_sat();
        Ok((commit_txid, commit_fee, commit_outpoint, commit_output_value))
    }

    /// Creates the reveal transaction.
    ///
    /// The reveal transaction spends the commit output, revealing the envelope
    /// data in the witness. It also creates the outputs for the recipients and
    /// the runestone.
    ///
    /// CORRECTED: Now properly selects additional UTXOs to meet input requirements
    /// from the Spec objects, not just the commit outpoint alone.
    async fn create_script_path_reveal_transaction(
        &mut self,
        params: &EnhancedExecuteParams,
        envelope: &AlkanesEnvelope,
        commit_outpoint: OutPoint,
        commit_output_value: u64,
    ) -> Result<(Transaction, u64)> {
        log::info!("Creating script-path reveal transaction with proper UTXO selection");
        log::info!("🎯 Commit input: {}:{}", commit_outpoint.txid, commit_outpoint.vout);

        self.validate_protostones(&params.protostones, params.to_addresses.len())?;

        // CRITICAL FIX: Select additional UTXOs to meet input requirements from Spec objects
        // This matches the reference implementation pattern where we don't just use commit alone
        let mut selected_utxos = Vec::new();

        // Step 1: Calculate total Bitcoin needed for reveal transaction
        let mut total_bitcoin_needed = 0u64;
        for requirement in &params.input_requirements {
            if let InputRequirement::Bitcoin { amount } = requirement {
                total_bitcoin_needed += amount;
            }
        }

        // Add output values (dust amounts for recipients)
        total_bitcoin_needed += params.to_addresses.len() as u64 * 546;

        // Add estimated fee
        let estimated_fee = 50_000u64; // Conservative estimate
        total_bitcoin_needed += estimated_fee;

        log::info!("💡 Total Bitcoin needed for reveal: {} sats", total_bitcoin_needed);
        log::info!("💡 Commit output value: {} sats", commit_output_value);

        // Step 2: Check if commit output has sufficient value for single input optimization
        if commit_output_value >= total_bitcoin_needed {
            // Single input optimization: commit output has enough value
            log::info!("🎯 SINGLE INPUT OPTIMIZATION: Using only commit input");
            selected_utxos.push(commit_outpoint);
        } else {
            // Need additional inputs: select UTXOs to meet requirements
            log::info!("🎯 MULTIPLE INPUT MODE: Selecting additional UTXOs to meet requirements");
            
            // Start with commit outpoint as first input
            selected_utxos.push(commit_outpoint);
            
            // Calculate how much more Bitcoin we need beyond the commit output
            let additional_bitcoin_needed = total_bitcoin_needed.saturating_sub(commit_output_value);
            
            if additional_bitcoin_needed > 0 {
                log::info!("Need additional {} sats beyond commit output", additional_bitcoin_needed);
                
                // Create a modified input requirements list for the additional UTXOs
                let mut additional_requirements = params.input_requirements.clone();
                
                // Adjust Bitcoin requirement to account for what commit output provides
                for requirement in &mut additional_requirements {
                    if let InputRequirement::Bitcoin { amount } = requirement {
                        *amount = additional_bitcoin_needed;
                        break;
                    }
                }
                
                // If no Bitcoin requirement exists, add one
                if !additional_requirements.iter().any(|r| matches!(r, InputRequirement::Bitcoin { .. })) {
                    additional_requirements.push(InputRequirement::Bitcoin { amount: additional_bitcoin_needed });
                }
                
                // Select additional UTXOs to meet the requirements
                let additional_utxos = self.select_utxos(&additional_requirements).await?;
                
                // Add additional UTXOs to our selection (commit is already first)
                for utxo in additional_utxos {
                    if utxo != commit_outpoint {
                        selected_utxos.push(utxo);
                    }
                }
                
                log::info!("Selected {} additional UTXOs", selected_utxos.len() - 1);
            }
        }

        log::info!("🎯 Total inputs for reveal transaction: {}", selected_utxos.len());

        let outputs = self.create_outputs(&params.to_addresses, &params.change_address).await?;

        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;

        let (signed_tx, final_fee) = self.build_script_path_reveal_transaction(
            selected_utxos,
            outputs,
            runestone_script,
            params.fee_rate,
            envelope,
            commit_output_value,
        )
        .await?;

        Ok((signed_tx, final_fee))
    }
    
    /// Creates a taproot address for the commit transaction.
    ///
    /// The address is a P2TR address with the envelope's reveal script
    /// in the taproot tree.
    async fn create_commit_address_for_envelope(
        &self,
        envelope: &AlkanesEnvelope,
        internal_key: XOnlyPublicKey,
    ) -> Result<Address> {
        use bitcoin::taproot::TaprootBuilder;
        let network = self.provider.get_network();

        let reveal_script = envelope.build_reveal_script();

        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone()).map_err(|e| DeezelError::Other(format!("{:?}", e)))?;

        let taproot_spend_info = taproot_builder
            .finalize(&self.provider.secp(), internal_key).map_err(|e| DeezelError::Other(format!("{:?}", e)))?;

        let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

        Ok(commit_address)
    }

    /// Execute single transaction (no envelope)
    async fn execute_single_transaction(&mut self, params: &EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        log::info!("Executing single transaction (no envelope)");
        
        // Step 1: Validate protostone specifications
        self.validate_protostones(&params.protostones, params.to_addresses.len())?;
        
        // Step 2: Find UTXOs that meet input requirements
        let selected_utxos = self.select_utxos(&params.input_requirements).await?;
        
        // Step 3: Create transaction with outputs for each address
        let outputs = self.create_outputs(&params.to_addresses, &params.change_address).await?;
        
        // Step 4: Construct runestone with protostones
        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;
        
        // Step 5: Build and sign transaction
        let (tx, fee) = self.build_transaction(selected_utxos.clone(), outputs, runestone_script, params.fee_rate).await?;
        
        // Step 6: Broadcast transaction
        let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
        let txid = self.provider.broadcast_transaction(tx_hex).await?;
        
        if !params.raw_output {
            log::info!("✅ Transaction broadcast successfully!");
            log::info!("🔗 TXID: {}", txid);
        }
        
        // Step 7: Handle tracing if enabled
        let traces = if params.trace_enabled {
            self.trace_reveal_transaction(&txid, params).await?
        } else {
            None
        };
        
        Ok(EnhancedExecuteResult {
            commit_txid: None,
            reveal_txid: txid,
            commit_fee: None,
            reveal_fee: fee,
            inputs_used: selected_utxos.into_iter().map(|o| o.to_string()).collect(),
            outputs_created: tx.output.iter().map(|o| o.script_pubkey.to_string()).collect(),
            traces,
        })
    }

    pub fn validate_protostones(&self, protostones: &[ProtostoneSpec], num_outputs: usize) -> Result<()> {
        log::info!("Validating {} protostones against {} outputs", protostones.len(), num_outputs);
        
        for (i, protostone) in protostones.iter().enumerate() {
            // Validate that no protostone refers to a pN value <= current protostone index
            for edict in &protostone.edicts {
                if let OutputTarget::Protostone(p) = edict.target {
                    if p <= i as u32 {
                        return Err(DeezelError::Validation(format!(
                            "Protostone {} refers to protostone {} which is not allowed (must be > {})",
                            i, p, i
                        )));
                    }
                }
            }
            
            // Validate that Bitcoin transfers don't target protostones
            if let Some(bitcoin_transfer) = &protostone.bitcoin_transfer {
                if matches!(bitcoin_transfer.target, OutputTarget::Protostone(_)) {
                    return Err(DeezelError::Validation(format!(
                        "Bitcoin transfer in protostone {} cannot target another protostone",
                        i
                    )));
                }
            }
            
            // Validate output targets are within bounds
            for edict in &protostone.edicts {
                match edict.target {
                    OutputTarget::Output(v) => {
                        if v as usize >= num_outputs {
                            return Err(DeezelError::Validation(format!(
                                "Edict in protostone {} targets output v{} but only {} outputs exist",
                                i, v, num_outputs
                            )));
                        }
                    },
                    OutputTarget::Protostone(p) => {
                        if p as usize >= protostones.len() {
                            return Err(DeezelError::Validation(format!(
                                "Edict in protostone {} targets protostone p{} but only {} protostones exist",
                                i, p, protostones.len()
                            )));
                        }
                    },
                    OutputTarget::Split => {
                        // Split is always valid
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn select_utxos(&self, requirements: &[InputRequirement]) -> Result<Vec<OutPoint>> {
        log::info!("Selecting UTXOs for {} requirements", requirements.len());

        let utxos = self.provider.get_utxos(true, None).await?; // Include frozen to check reasons
        log::debug!("Found {} total wallet UTXOs", utxos.len());

        let spendable_utxos: Vec<(OutPoint, UtxoInfo)> = utxos.into_iter()
            .filter(|(_, info)| !info.frozen)
            .collect();
        
        log::info!("Found {} spendable (non-frozen) wallet UTXOs", spendable_utxos.len());

        let mut selected_outpoints = Vec::new();
        let mut bitcoin_needed = 0u64;
        let mut alkanes_needed = alloc::collections::BTreeMap::new();

        for requirement in requirements {
            match requirement {
                InputRequirement::Bitcoin { amount } => {
                    bitcoin_needed += amount;
                }
                InputRequirement::Alkanes { block, tx, amount } => {
                    let key = (*block, *tx);
                    *alkanes_needed.entry(key).or_insert(0) += amount;
                }
            }
        }

        log::info!("Need {} sats Bitcoin and {} different alkanes tokens", bitcoin_needed, alkanes_needed.len());

        let mut bitcoin_collected = 0u64;
        // TODO: Implement alkanes balance checking for each UTXO
        // For now, we just select enough UTXOs to cover the Bitcoin requirement.

        for (outpoint, utxo) in spendable_utxos {
            if bitcoin_collected < bitcoin_needed {
                bitcoin_collected += utxo.amount;
                selected_outpoints.push(outpoint);
            } else {
                break;
            }
        }

        if bitcoin_collected < bitcoin_needed {
            return Err(DeezelError::Wallet(format!(
                "Insufficient funds: need {} sats, have {}",
                bitcoin_needed, bitcoin_collected
            )));
        }

        log::info!("Selected {} UTXOs meeting Bitcoin requirements", selected_outpoints.len());
        Ok(selected_outpoints)
    }

    async fn create_outputs(&self, to_addresses: &[String], change_address: &Option<String>) -> Result<Vec<TxOut>> {
        let mut outputs = Vec::new();
        let network = self.provider.get_network();

        for addr_str in to_addresses {
            log::debug!("Parsing to_address in create_outputs: '{}'", addr_str);
            let address = Address::from_str(addr_str)?.require_network(network)?;
            outputs.push(TxOut {
                value: bitcoin::Amount::from_sat(546), // Dust
                script_pubkey: address.script_pubkey(),
            });
        }

        if let Some(change_addr_str) = change_address {
            log::debug!("Parsing change_address in create_outputs: '{}'", change_addr_str);
            let address = Address::from_str(change_addr_str)?.require_network(network)?;
            outputs.push(TxOut {
                value: bitcoin::Amount::from_sat(0), // Placeholder, will be set later
                script_pubkey: address.script_pubkey(),
            });
        }

        Ok(outputs)
    }

    fn construct_runestone(&self, protostones: &[ProtostoneSpec], _num_outputs: usize) -> Result<ScriptBuf> {
        log::info!("Constructing runestone with {} protostones", protostones.len());

        let mut edicts = Vec::new();
        let mut all_protostones = Vec::new();

        for spec in protostones {
            for edict_spec in &spec.edicts {
                let id = ordinals::RuneId {
                    block: edict_spec.alkane_id.block,
                    tx: edict_spec.alkane_id.tx as u32,
                };
                let amount = edict_spec.amount as u128;
                let output = match edict_spec.target {
                    OutputTarget::Output(v) => v,
                    _ => 0, // Other cases not handled yet
                };
                edicts.push(ordinals::Edict { id, amount, output });
            }

            let message = if let Some(cellpack) = &spec.cellpack {
                // Use the real cellpack enciphering logic
                let cellpack_bytes = cellpack.encipher();
                log::info!("Encoded cellpack to {} bytes", cellpack_bytes.len());
                cellpack_bytes
            } else {
                Vec::new()
            };

            let edicts_clone = edicts.iter().map(|e| ordinals::Edict {
                id: ordinals::RuneId {
                    block: e.id.block,
                    tx: e.id.tx,
                },
                amount: e.amount,
                output: e.output,
            }).collect();

            all_protostones.push(Protostone {
                protocol_tag: 1, // ALKANES protocol tag
                message,
                edicts: into_protostone_edicts(edicts_clone),
                burn: None,
                refund: None,
                pointer: None,
                from: None,
            });
        }

        let protocol_payload = if !all_protostones.is_empty() {
            let enciphered = all_protostones.encipher()?;
            Some(enciphered)
        } else {
            None
        };

        let runestone = ordinals::Runestone {
            edicts,
            etching: None,
            mint: None,
            pointer: None,
            protocol: protocol_payload,
        };

        Ok(runestone.encipher())
    }

    async fn build_transaction(
        &mut self,
        utxos: Vec<OutPoint>,
        mut outputs: Vec<TxOut>,
        runestone_script: ScriptBuf,
        fee_rate: Option<f32>
    ) -> Result<(Transaction, u64)> {
        log::info!("Building and signing transaction using wallet provider");
    
        use bitcoin::psbt::Psbt;
        use bitcoin::transaction::Version;
    
        // Add OP_RETURN output if a runestone is present
        if !runestone_script.is_empty() {
            outputs.push(TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: runestone_script,
            });
        }
    
        // --- Fee Calculation and Output Adjustment (BEFORE SIGNING) ---
    
        // 1. Get total input value by fetching each UTXO
        let mut total_input_value = 0;
        let mut input_txouts = Vec::new();
        for outpoint in &utxos {
            let utxo = self.provider.get_utxo(outpoint).await?
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
            total_input_value += utxo.value.to_sat();
            input_txouts.push(utxo);
        }
    
        // 2. Create a temporary transaction to estimate size
        let mut temp_tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(), // Placeholder for witness
            }).collect(),
            output: outputs.clone(),
        };
    
        // Add placeholder witness for size estimation (P2TR key-path spend is common)
        for input in &mut temp_tx.input {
            input.witness.push(&[0u8; 65]); // 64-byte signature + 1-byte sighash type
        }
    
        // 3. Calculate and cap the fee
        let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
        let estimated_fee = (fee_rate_sat_vb * temp_tx.vsize() as f32).ceil() as u64;
        let capped_fee = estimated_fee.min(MAX_FEE_SATS);
        log::info!("Estimated fee: {}, Capped fee: {}", estimated_fee, capped_fee);
    
        // 4. Adjust outputs
        let total_output_value_sans_change: u64 = outputs.iter()
            .filter(|o| o.value.to_sat() > 0) // Exclude the placeholder change output
            .map(|o| o.value.to_sat())
            .sum();
    
        let change_value = total_input_value.saturating_sub(total_output_value_sans_change).saturating_sub(capped_fee);
    
        // Find and update the change output, or the last output if no explicit change
        if let Some(change_output) = outputs.iter_mut().find(|o| o.value.to_sat() == 0 && !o.script_pubkey.is_op_return()) {
            change_output.value = bitcoin::Amount::from_sat(change_value);
        } else if let Some(last_output) = outputs.iter_mut().last() {
             if !last_output.script_pubkey.is_op_return() {
                last_output.value = bitcoin::Amount::from_sat(last_output.value.to_sat() + change_value);
             }
        }
    
        // --- PSBT Creation and Signing ---
    
        // 5. Create the final PSBT with correct output values
        let mut psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: outputs, // Use the adjusted outputs
        })?;
    
        // 6. Configure inputs for signing
        for (i, utxo) in input_txouts.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(utxo.clone());
            
            if utxo.script_pubkey.is_p2tr() {
                let internal_key = self.provider.get_internal_key().await?;
                psbt.inputs[i].tap_internal_key = Some(internal_key);
            }
        }
        
        // 7. Sign the PSBT
        let signed_psbt = self.provider.sign_psbt(&mut psbt).await?;
        
        // 8. Finalize the transaction
        let mut tx = signed_psbt.clone().extract_tx()?;
        for (i, psbt_input) in signed_psbt.inputs.iter().enumerate() {
            if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                tx.input[i].witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
            } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                tx.input[i].witness = final_script_witness.clone();
            }
        }
        
        Ok((tx, capped_fee))
    }

    async fn build_commit_transaction(
        &mut self,
        funding_utxos: Vec<OutPoint>,
        commit_output: TxOut,
        fee_rate: Option<f32>,
    ) -> Result<(Transaction, u64)> {
        // 1. Get total input value
        let mut total_input_value = 0;
        let mut input_txouts = Vec::new();
        for outpoint in &funding_utxos {
            let utxo = self.provider.get_utxo(outpoint).await?
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
            total_input_value += utxo.value.to_sat();
            input_txouts.push(utxo);
        }
    
        // 2. Create a temporary transaction to estimate size
        let change_address_str = WalletProvider::get_address(self.provider).await?;
        let change_address = Address::from_str(&change_address_str)?.require_network(self.provider.get_network())?;
        let temp_change_output = TxOut { value: bitcoin::Amount::from_sat(0), script_pubkey: change_address.script_pubkey() };
        let temp_outputs = vec![commit_output.clone(), temp_change_output];
    
        let mut temp_tx_for_size = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: funding_utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: temp_outputs,
        };
        for input in &mut temp_tx_for_size.input {
            input.witness.push(&[0u8; 65]); // Placeholder witness
        }
    
        // 3. Calculate fee
        let fee_rate_sat_vb = fee_rate.unwrap_or(1.0);
        let fee = (fee_rate_sat_vb * temp_tx_for_size.vsize() as f32).ceil() as u64;
    
        // 4. Calculate change
        let change_value = total_input_value.saturating_sub(commit_output.value.to_sat()).saturating_sub(fee);
        if change_value < 546 { // Dust threshold
            return Err(DeezelError::Wallet("Not enough funds for commit and change".to_string()));
        }
    
        // 5. Create final outputs
        let final_change_output = TxOut { value: bitcoin::Amount::from_sat(change_value), script_pubkey: change_address.script_pubkey() };
        let final_outputs = vec![commit_output, final_change_output];
    
        // 6. Build and sign PSBT
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: funding_utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: final_outputs,
        };
        let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx)?;
    
        for (i, utxo) in input_txouts.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(utxo.clone());
            if utxo.script_pubkey.is_p2tr() {
                psbt.inputs[i].tap_internal_key = Some(self.provider.get_internal_key().await?);
            }
        }
    
        let signed_psbt = self.provider.sign_psbt(&mut psbt).await?;
        let mut tx = signed_psbt.clone().extract_tx()?;
        // Finalize witness
        for (i, psbt_input) in signed_psbt.inputs.iter().enumerate() {
            if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                tx.input[i].witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
            } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                tx.input[i].witness = final_script_witness.clone();
            }
        }
    
        Ok((tx, fee))
    }
    
    /// Builds the reveal transaction with script-path spending.
    ///
    /// This function constructs the reveal transaction, which spends the commit
    /// output and includes the envelope data in the witness. It also handles
    /// the creation of the runestone and the final outputs.
    ///
    /// CRITICAL FIX: Based on reference implementation pattern for commit/reveal transactions
    /// - Manually creates commit UTXO instead of fetching from provider
    /// - Separates script-path signing (commit input) from key-path signing (wallet inputs)
    /// - Uses proper prevouts handling for multiple inputs
    async fn build_script_path_reveal_transaction(
        &mut self,
        all_inputs: Vec<OutPoint>,
        mut outputs: Vec<TxOut>,
        runestone_script: ScriptBuf,
        fee_rate: Option<f32>,
        envelope: &AlkanesEnvelope,
        commit_output_value: u64,
    ) -> Result<(Transaction, u64)> {
        log::info!("Building script-path reveal transaction with {} inputs", all_inputs.len());
        use bitcoin::psbt::Psbt;

        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: runestone_script,
        };
        outputs.push(op_return_output);

        // Create transaction structure first
        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: all_inputs.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: outputs,
        };

        let internal_key = self.provider.get_internal_key().await?;

        // CRITICAL FIX: Build ALL prevouts manually to match reference implementation
        // This ensures proper sighash calculation for taproot script-path spending
        let mut all_prevouts = Vec::new();
        
        for (i, outpoint) in all_inputs.iter().enumerate() {
            if i == 0 {
                // CRITICAL FIX: First input is the commit output - create it manually from known values
                // This matches the reference implementation where commit UTXO is created locally
                log::info!("Creating commit UTXO manually with value {} sats", commit_output_value);
                let commit_address = self.create_commit_address_for_envelope(envelope, internal_key).await?;
                let commit_utxo = TxOut {
                    value: bitcoin::Amount::from_sat(commit_output_value),
                    script_pubkey: commit_address.script_pubkey(),
                };
                all_prevouts.push(commit_utxo);
                log::info!("Added commit prevout for input {}: {} sats", i, commit_output_value);
            } else {
                // Additional inputs are regular wallet UTXOs
                log::info!("Fetching wallet UTXO for input {}: {}:{}", i, outpoint.txid, outpoint.vout);
                let utxo_info = self.provider.get_utxo(outpoint).await?
                    .ok_or_else(|| DeezelError::Wallet(format!("Wallet UTXO not found: {}", outpoint)))?;
                all_prevouts.push(utxo_info.clone());
                log::info!("Added wallet prevout for input {}: {} sats", i, utxo_info.value.to_sat());
            }
        }

        log::info!("Using Prevouts::All with {} prevouts for sighash calculation", all_prevouts.len());

        // CRITICAL FIX: Handle signing differently for commit input vs wallet inputs
        // Based on reference implementation pattern at lines 2250-2320
        
        // STEP 1: Manually create the script-path signature for the commit input (index 0)
        if !all_inputs.is_empty() {
            let reveal_script = envelope.build_reveal_script();
            let (_, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
            let signature = self.create_taproot_script_signature(&tx, 0, reveal_script.as_bytes(), &control_block.serialize(), &all_prevouts).await?;
            tx.input[0].witness = envelope.create_complete_witness(&signature, control_block)?;
            log::info!("✅ Created script-path witness for commit input with {} items", tx.input[0].witness.len());
        }
        
        // STEP 2: Sign additional wallet inputs (if any) using the provider
        if all_inputs.len() > 1 {
            log::info!("Signing {} additional wallet inputs using provider", all_inputs.len() - 1);
            
            // Create a separate PSBT with only the wallet inputs for provider signing
            let wallet_inputs = all_inputs[1..].to_vec();
            if !wallet_inputs.is_empty() {
                let mut wallet_psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: wallet_inputs.iter().map(|outpoint| bitcoin::TxIn {
                        previous_output: *outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    }).collect(),
                    output: tx.output.clone(),
                })?;
                
                // Configure the wallet inputs for signing
                for (i, outpoint) in wallet_inputs.iter().enumerate() {
                    let utxo_info = self.provider.get_utxo(outpoint).await?
                        .ok_or_else(|| DeezelError::Wallet(format!("Wallet UTXO not found: {}", outpoint)))?;
                    wallet_psbt.inputs[i].witness_utxo = Some(utxo_info.clone());
                    if utxo_info.script_pubkey.is_p2tr() {
                        wallet_psbt.inputs[i].tap_internal_key = Some(internal_key);
                    }
                }
                
                // Sign the wallet inputs using provider
                let signed_wallet_psbt = self.provider.sign_psbt(&mut wallet_psbt).await?;
                
                // Apply the wallet input witnesses to the main transaction
                for (i, psbt_input) in signed_wallet_psbt.inputs.iter().enumerate() {
                    let tx_input_index = i + 1; // Wallet inputs start at index 1
                    if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                        tx.input[tx_input_index].witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
                        log::info!("Applied taproot key-path witness to input {}", tx_input_index);
                    } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                        tx.input[tx_input_index].witness = final_script_witness.clone();
                        log::info!("Applied final script witness to input {}", tx_input_index);
                    }
                }
                
                log::info!("✅ Applied wallet input witnesses to {} inputs", wallet_inputs.len());
            }
        }

        let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
        let fee = (fee_rate_sat_vb * tx.vsize() as f32).ceil() as u64;

        // Cap the fee to avoid "absurdly high fee rate" errors, especially for large witness transactions
        let capped_fee = fee.min(MAX_FEE_SATS);
        if fee > capped_fee {
            log::warn!("Reveal transaction fee {} was capped to {}", fee, capped_fee);
        }

        // Adjust transaction outputs to match the capped fee
        let total_input_value: u64 = all_prevouts.iter().map(|utxo| utxo.value.to_sat()).sum();
        let total_output_value: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();
        let current_fee = total_input_value.saturating_sub(total_output_value);

        if current_fee > capped_fee {
            let fee_difference = current_fee - capped_fee;
            // Find a suitable change output to adjust. We need to *increase* the output value to *decrease* the fee.
            if let Some(change_output) = tx.output.iter_mut().rfind(|o| !o.script_pubkey.is_op_return()) {
                let new_value = change_output.value.to_sat() + fee_difference;
                change_output.value = bitcoin::Amount::from_sat(new_value);
                log::info!("Adjusted change output by +{} to meet capped fee", fee_difference);
            } else {
                log::warn!("Could not find a suitable output to adjust for fee capping in reveal tx.");
            }
        } else if capped_fee > current_fee {
            let fee_difference = capped_fee - current_fee;
            // Find a suitable change output to adjust. We need to *decrease* the output value to *increase* the fee.
            if let Some(change_output) = tx.output.iter_mut().rfind(|o| !o.script_pubkey.is_op_return()) {
                 if change_output.value.to_sat() > fee_difference {
                    let new_value = change_output.value.to_sat() - fee_difference;
                    change_output.value = bitcoin::Amount::from_sat(new_value);
                    log::info!("Adjusted change output by -{} to meet capped fee", fee_difference);
                 } else {
                    log::warn!("Change output would be dust after fee adjustment, leaving as is.");
                 }
            } else {
                log::warn!("Could not find a suitable output to adjust for fee capping in reveal tx (or change would be dust).");
            }
        }

        log::info!("✅ Successfully built script-path reveal transaction with proper signing separation");
        log::info!("Transaction: {} inputs, {} outputs, fee: {} sats", tx.input.len(), tx.output.len(), capped_fee);

        Ok((tx, capped_fee))
    }

    /// Creates the taproot spend info and control block for an envelope.
    ///
    /// This is a crucial step in creating the commit transaction. The spend info
    /// contains the necessary details for spending the taproot output, and the
    /// control block is required for the script-path spend in the reveal transaction.
    async fn create_taproot_spend_info_for_envelope(
        &self,
        envelope: &AlkanesEnvelope,
        internal_key: XOnlyPublicKey,
    ) -> Result<(bitcoin::taproot::TaprootSpendInfo, bitcoin::taproot::ControlBlock)> {
        use bitcoin::taproot::{TaprootBuilder, LeafVersion};

        let reveal_script = envelope.build_reveal_script();

        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .map_err(|e| DeezelError::Other(format!("{:?}", e)))?;

        let taproot_spend_info = taproot_builder
            .finalize(&self.provider.secp(), internal_key)
            .map_err(|e| DeezelError::Other(format!("{:?}", e)))?;

        let control_block = taproot_spend_info
            .control_block(&(reveal_script, LeafVersion::TapScript))
            .ok_or_else(|| DeezelError::Other("Failed to create control block".to_string()))?;

        Ok((taproot_spend_info, control_block))
    }

    /// Creates a Schnorr signature for a P2TR script-path spend.
    ///
    /// This function generates the signature required to spend a taproot output
    /// via the script path. It constructs the correct sighash message and uses
    /// the provider to sign it.
    ///
    /// CRITICAL FIX: Based on reference implementation pattern at lines 2254-2320
    /// - Uses Prevouts::All for proper taproot sighash calculation with multiple inputs
    /// - Handles script-path spending for commit transactions correctly
    pub async fn create_taproot_script_signature(
        &self,
        tx: &Transaction,
        input_index: usize,
        script: &[u8],
        _control_block: &[u8],
        prevouts: &[TxOut],
    ) -> Result<Vec<u8>> {
        use bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
        use bitcoin::taproot;

        log::info!("Creating taproot script-path signature for input {}", input_index);
        
        // CRITICAL FIX: For taproot sighash calculation with DEFAULT sighash type,
        // we MUST provide ALL prevouts, not just the single input being signed.
        // This fixes the error: "single prevout provided but all prevouts are needed without ANYONECANPAY"
        let prevouts_len = prevouts.len();
        let prevouts_all = Prevouts::All(prevouts);
        
        log::info!("Using Prevouts::All with {} prevouts for sighash calculation", prevouts_len);

        let mut sighash_cache = SighashCache::new(tx);

        // Parse the script for sighash calculation
        let script_buf = ScriptBuf::from(script.to_vec());
        let leaf_hash = taproot::TapLeafHash::from_script(&script_buf, taproot::LeafVersion::TapScript);

        // Compute taproot script-path sighash
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &prevouts_all,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| DeezelError::Transaction(e.to_string()))?;

        log::info!("Computed taproot script-path sighash for input {}", input_index);

        // Sign the sighash using the provider's taproot script spend method
        let signature = self.provider.sign_taproot_script_spend(sighash.into()).await?;
        
        // Create taproot signature with sighash type
        let taproot_signature = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        // Convert to bytes
        let signature_bytes = taproot_signature.to_vec();
        
        log::info!("✅ Created taproot script-path signature: {} bytes", signature_bytes.len());

        Ok(signature_bytes)
    }

    /// Traces the reveal transaction to get the results of protostone execution.
    ///
    /// This function handles the post-broadcast logic, including mining blocks
    /// on regtest, waiting for synchronization with various services, and then
    /// calling the `trace_outpoint` provider method for each protostone.
    async fn trace_reveal_transaction(&self, txid: &str, params: &EnhancedExecuteParams) -> Result<Option<Vec<JsonValue>>> {
        log::info!("Starting enhanced transaction tracing for reveal transaction: {}", txid);
        
        if params.mine_enabled {
            self.mine_blocks_if_regtest(params).await?;
        }
        
        self.wait_for_transaction_mined(txid, params).await?;
        self.wait_for_metashrew_sync_enhanced(params).await?;
        self.wait_for_esplora_sync_enhanced(params).await?;
        
        let tx_hex = self.provider.get_transaction_hex(txid).await?;
        let tx_bytes = hex::decode(&tx_hex).map_err(|e| DeezelError::Hex(e.to_string()))?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes).map_err(|e| DeezelError::Serialization(e.to_string()))?;
        
        let mut traces = Vec::new();
        let mut protostone_count = 0;
        
        for (_vout, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.is_op_return() {
                protostone_count += 1;
                let trace_vout = tx.output.len() as u32 + protostone_count - 1;
                
                match self.provider.trace_outpoint(txid, trace_vout).await {
                    Ok(trace_result) => {
                        if params.raw_output {
                            traces.push(trace_result);
                        } else {
                            let trace: crate::alkanes::trace::Trace = serde_json::from_value(trace_result.clone())?;
                            println!("\n📊 Trace for protostone #{}:", protostone_count);
                            println!("{}", trace);
                            traces.push(trace_result);
                        }
                    },
                    Err(e) => {
                        log::warn!("Failed to trace protostone #{}: {}", protostone_count, e);
                    }
                }
            }
        }
        
        if traces.is_empty() {
            Ok(None)
        } else {
            Ok(Some(traces))
        }
    }

    /// Mines blocks on the regtest network if the provider is configured for it.
    ///
    /// This is a utility function to ensure transactions are confirmed during
    /// testing or local development on a regtest network.
    async fn mine_blocks_if_regtest(&self, params: &EnhancedExecuteParams) -> Result<()> {
        if self.provider.get_network() == bitcoin::Network::Regtest {
            log::info!("Mining blocks on regtest network...");
            // Add a delay to allow the node to process transactions in the mempool
            sleep(Duration::from_secs(2)).await;
            let address = if let Some(change_address) = &params.change_address {
                change_address.clone()
            } else {
                WalletProvider::get_address(self.provider).await?
            };
            self.provider.generate_to_address(1, &address).await?;
        }
        Ok(())
    }

    /// Waits for a transaction to be mined.
    ///
    /// This function polls the provider's `get_tx_status` method until the
    /// transaction is confirmed.
    async fn wait_for_transaction_mined(&self, txid: &str, _params: &EnhancedExecuteParams) -> Result<()> {
        loop {
            match self.provider.get_tx_status(txid).await {
                Ok(status) => {
                    if status.get("confirmed").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Ok(());
                    }
                }
                Err(_) => { /* ignore and retry */ }
            }
            self.provider.sleep_ms(1000).await;
        }
    }

    /// Waits for the metashrew indexer to be synchronized with the Bitcoin node.
    ///
    /// This is essential for accurate tracing, as the metashrew service provides
    /// the state required to interpret the transaction's effects.
    async fn wait_for_metashrew_sync_enhanced(&self, _params: &EnhancedExecuteParams) -> Result<()> {
        loop {
            let bitcoin_height = self.provider.get_block_count().await?;
            let metashrew_height = self.provider.get_metashrew_height().await?;
            if metashrew_height >= bitcoin_height {
                return Ok(());
            }
            self.provider.sleep_ms(1000).await;
        }
    }

    fn validate_envelope_cellpack_usage(&self, params: &EnhancedExecuteParams) -> Result<()> {
        let has_envelope = params.envelope_data.is_some();
        let has_cellpacks = params.protostones.iter().any(|p| p.cellpack.is_some());

        if has_envelope && !has_cellpacks {
            return Err(DeezelError::Other(anyhow!(
                "Incomplete deployment: Envelope provided but no cellpack to trigger deployment."
            ).to_string()));
        }

        if !has_envelope && has_cellpacks {
            // This is a valid execution of an existing contract
            return Ok(());
        }
        
        if !has_envelope && !has_cellpacks && !params.protostones.is_empty() {
             return Err(DeezelError::Other(anyhow!(
                "No operation: Protostones provided without envelope or cellpack."
            ).to_string()));
        }
        
        Ok(())
    }

    /// Waits for the Esplora indexer to be synchronized with the Bitcoin node.
    ///
    /// This ensures that any API calls to an Esplora-based service will have
    /// access to the latest block data.
    async fn wait_for_esplora_sync_enhanced(&self, _params: &EnhancedExecuteParams) -> Result<()> {
        loop {
            let bitcoin_height = self.provider.get_block_count().await?;
            let esplora_height = self.provider.get_blocks_tip_height().await?;
            if esplora_height >= bitcoin_height {
                return Ok(());
            }
            self.provider.sleep_ms(1000).await;
        }
    }
}
