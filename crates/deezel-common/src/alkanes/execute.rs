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
pub use super::types::{EnhancedExecuteParams, EnhancedExecuteResult, InputRequirement, ProtostoneSpec, OutputTarget};
use super::envelope::AlkanesEnvelope;
use anyhow::anyhow;
use protorune_support::protostone::{Protostone, into_protostone_edicts};
use crate::utils::protostone::Protostones;
use ordinals::{RuneId, Runestone, Edict};

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
        let (commit_txid, commit_fee, commit_outpoint) =
            self.create_and_broadcast_commit_transaction(envelope, &params).await?;

        log::info!("✅ Commit transaction broadcast: {}", commit_txid);
        log::info!("💰 Commit fee: {} sats", commit_fee);
        log::info!("🎯 Commit output created at: {}:{}", commit_outpoint.txid, commit_outpoint.vout);

        // Step 2: Wait for commit transaction to be available
        self.provider.sleep_ms(1000).await;

        // Step 3: Create reveal transaction
        let (reveal_tx, reveal_fee) =
            self.create_script_path_reveal_transaction(&params, envelope, commit_outpoint).await?;
        
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
    ) -> Result<(String, u64, OutPoint)> {
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
        let (commit_tx, commit_fee) = self.build_transaction(funding_utxos, vec![commit_output], ScriptBuf::new(), params.fee_rate).await?;
        
        // Broadcast the commit transaction
        let commit_txid = self.provider.broadcast_transaction(bitcoin::consensus::encode::serialize_hex(&commit_tx)).await?;

        let commit_outpoint = OutPoint {
            txid: commit_tx.compute_txid(),
            vout: 0, // The commit output is always the first output
        };

        Ok((commit_txid, commit_fee, commit_outpoint))
    }

    /// Creates the reveal transaction.
    ///
    /// The reveal transaction spends the commit output, revealing the envelope
    /// data in the witness. It also creates the outputs for the recipients and
    /// the runestone.
    async fn create_script_path_reveal_transaction(
        &mut self,
        params: &EnhancedExecuteParams,
        envelope: &AlkanesEnvelope,
        commit_outpoint: OutPoint,
    ) -> Result<(Transaction, u64)> {
        log::info!("Creating script-path reveal transaction");

        self.validate_protostones(&params.protostones, params.to_addresses.len())?;

        let selected_utxos = self.select_utxos_for_reveal(&params.input_requirements, commit_outpoint).await?;

        let outputs = self.create_outputs(&params.to_addresses, &params.change_address).await?;

        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;

        let (signed_tx, final_fee) = self.build_script_path_reveal_transaction(
            selected_utxos,
            outputs,
            runestone_script,
            params.fee_rate,
            envelope,
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

    /// Selects UTXOs for the reveal transaction.
    ///
    /// This function is similar to `select_utxos`, but it also includes the
    /// commit outpoint in the list of selected UTXOs.
    async fn select_utxos_for_reveal(
        &self,
        requirements: &[InputRequirement],
        commit_outpoint: OutPoint,
    ) -> Result<Vec<OutPoint>> {
        log::info!("Selecting UTXOs for reveal transaction");

        let mut selected_utxos = self.select_utxos(requirements).await?;

        // Ensure the commit outpoint is the first input
        if let Some(pos) = selected_utxos.iter().position(|o| *o == commit_outpoint) {
            selected_utxos.remove(pos);
        }
        selected_utxos.insert(0, commit_outpoint);

        Ok(selected_utxos)
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
    
        // 1. Get total input value
        let all_wallet_utxos = self.provider.get_utxos(true, None).await?;
        let all_wallet_utxos_map: alloc::collections::BTreeMap<OutPoint, UtxoInfo> = all_wallet_utxos.into_iter().collect();
        let total_input_value: u64 = utxos.iter()
            .map(|outpoint| all_wallet_utxos_map.get(outpoint).map_or(0, |utxo| utxo.amount))
            .sum();
    
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
        for (i, outpoint) in utxos.iter().enumerate() {
            let utxo_info = all_wallet_utxos_map.get(outpoint)
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
            
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: bitcoin::Amount::from_sat(utxo_info.amount),
                script_pubkey: utxo_info.script_pubkey.clone().ok_or(DeezelError::Wallet("Missing script_pubkey".to_string()))?,
            });
            
            if utxo_info.script_pubkey.as_ref().map_or(false, |s| s.is_p2tr()) {
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

    /// Builds the reveal transaction with script-path spending.
    ///
    /// This function constructs the reveal transaction, which spends the commit
    /// output and includes the envelope data in the witness. It also handles
    /// the creation of the runestone and the final outputs.
    async fn build_script_path_reveal_transaction(
        &mut self,
        all_inputs: Vec<OutPoint>,
        mut outputs: Vec<TxOut>,
        runestone_script: ScriptBuf,
        fee_rate: Option<f32>,
        envelope: &AlkanesEnvelope,
    ) -> Result<(Transaction, u64)> {
        log::info!("Building script-path reveal transaction with {} inputs", all_inputs.len());
        use bitcoin::psbt::Psbt;

        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: runestone_script,
        };
        outputs.push(op_return_output);

        let mut psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: all_inputs.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: outputs,
        })?;

        let internal_key = self.provider.get_internal_key().await?;

        for (i, outpoint) in all_inputs.iter().enumerate() {
            if i == 0 {
                // First input is the commit output, configure for script-path spend
                let commit_utxo = self.provider.get_utxo(outpoint).await?
                    .ok_or_else(|| DeezelError::Wallet(format!("Commit UTXO not found: {}", outpoint)))?;

                psbt.inputs[i].witness_utxo = Some(commit_utxo);
                psbt.inputs[i].tap_internal_key = Some(internal_key);

                let (taproot_spend_info, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
                let script_map = taproot_spend_info.script_map();
                if let Some(((script, leaf_version), _)) = script_map.iter().next() {
                    use alloc::collections::BTreeMap;
                    let mut tap_scripts = BTreeMap::new();
                    tap_scripts.insert(control_block, (script.clone(), *leaf_version));
                    psbt.inputs[i].tap_scripts = tap_scripts;
                } else {
                    return Err(DeezelError::Other("No script found in taproot spend info for envelope".to_string()));
                }
            } else {
                // Additional inputs are regular wallet UTXOs for key-path spend
                let utxo_info = self.provider.get_utxo(outpoint).await?
                    .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
                if utxo_info.script_pubkey.is_p2tr() {
                    psbt.inputs[i].tap_internal_key = Some(internal_key);
                }
                psbt.inputs[i].witness_utxo = Some(utxo_info);
            }
        }

        let signed_psbt = self.provider.sign_psbt(&mut psbt).await?;
        let mut tx = signed_psbt.clone().extract_tx()?;

        // Manually construct witnesses
        for (i, _) in all_inputs.iter().enumerate() {
            if i == 0 {
                // First input: script-path spend with 3-element witness
                let reveal_script = envelope.build_reveal_script();
                let (_, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
                let signature = self.create_taproot_script_signature(&tx, i, reveal_script.as_bytes(), &control_block.serialize()).await?;
                tx.input[i].witness = envelope.create_complete_witness(&signature, control_block)?;
            } else {
                // Other inputs: key-path spend
                if let Some(psbt_input) = signed_psbt.inputs.get(i) {
                    if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                        tx.input[i].witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
                    } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                        tx.input[i].witness = final_script_witness.clone();
                    }
                }
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
        let total_input_value: u64 = signed_psbt.inputs.iter()
            .filter_map(|input| input.witness_utxo.as_ref())
            .map(|utxo| utxo.value.to_sat())
            .sum();
        
        let total_output_value: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();
        
        let current_fee = total_input_value.saturating_sub(total_output_value);

        if current_fee > capped_fee {
            let fee_difference = current_fee - capped_fee;
            // Find a suitable change output to adjust
            if let Some(change_output) = tx.output.iter_mut().find(|o| !o.script_pubkey.is_op_return() && o.value.to_sat() > fee_difference) {
                change_output.value = bitcoin::Amount::from_sat(change_output.value.to_sat() - fee_difference);
            } else {
                log::warn!("Could not find a suitable output to adjust for fee capping in reveal tx.");
            }
        }

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
    pub async fn create_taproot_script_signature(
        &self,
        tx: &Transaction,
        input_index: usize,
        script: &[u8],
        _control_block: &[u8],
    ) -> Result<Vec<u8>> {
        use bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
        use bitcoin::taproot;

        let mut prevouts = Vec::new();
        for input in &tx.input {
            let utxo = self.provider.get_utxo(&input.previous_output).await?
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", input.previous_output)))?;
            prevouts.push(utxo);
        }

        let prevouts = Prevouts::All(&prevouts);

        let mut sighash_cache = SighashCache::new(tx);

        let script_buf = ScriptBuf::from(script.to_vec());
        let leaf_hash = taproot::TapLeafHash::from_script(&script_buf, taproot::LeafVersion::TapScript);

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &prevouts,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| DeezelError::Transaction(e.to_string()))?;

        let signature = self.provider.sign_taproot_script_spend(sighash.into()).await?;
        
        let taproot_signature = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        Ok(taproot_signature.to_vec())
    }

    /// Traces the reveal transaction to get the results of protostone execution.
    ///
    /// This function handles the post-broadcast logic, including mining blocks
    /// on regtest, waiting for synchronization with various services, and then
    /// calling the `trace_outpoint` provider method for each protostone.
    async fn trace_reveal_transaction(&self, txid: &str, params: &EnhancedExecuteParams) -> Result<Option<Vec<JsonValue>>> {
        log::info!("Starting enhanced transaction tracing for reveal transaction: {}", txid);
        
        if params.mine_enabled {
            self.mine_blocks_if_regtest().await?;
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
                        traces.push(trace_result);
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
    async fn mine_blocks_if_regtest(&self) -> Result<()> {
        if self.provider.get_network() == bitcoin::Network::Regtest {
            log::info!("Mining blocks on regtest network...");
            let address = WalletProvider::get_address(self.provider).await?;
            self.provider.generate_to_address(101, &address).await?;
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
