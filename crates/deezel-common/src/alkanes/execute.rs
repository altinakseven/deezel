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
use crate::traits::WalletProvider;
use bitcoin::{Transaction, ScriptBuf, OutPoint, TxOut, Address, XOnlyPublicKey};
use crate::vendored_ord::{Edict, RuneId, Runestone};
use core::str::FromStr;
use alloc::{vec, vec::Vec, string::{String, ToString}, format};
pub use super::types::{EnhancedExecuteParams, EnhancedExecuteResult, InputRequirement, ProtostoneSpec, OutputTarget};
use super::envelope::AlkanesEnvelope;
use crate::utils::protostone::{Protostone, Protostones};

/// Enhanced alkanes executor
pub struct EnhancedAlkanesExecutor<'a, T: DeezelProvider> {
    pub provider: &'a T,
}

impl<'a, T: DeezelProvider> EnhancedAlkanesExecutor<'a, T> {
    /// Create a new enhanced alkanes executor
    pub fn new(provider: &'a T) -> Self {
        Self { provider }
    }

    /// Execute an enhanced alkanes transaction with commit/reveal pattern
    pub async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        log::info!("Starting enhanced alkanes execution");
        
        if params.envelope_data.is_some() {
            // Contract deployment with envelope BIN data
            log::info!("CONTRACT DEPLOYMENT: Using envelope with BIN data for contract deployment");
            let envelope_data = params.envelope_data.as_ref().unwrap();
            log::info!("Envelope data size: {} bytes", envelope_data.len());
            
            let envelope = AlkanesEnvelope::for_contract(envelope_data.clone());
            log::info!("Created AlkanesEnvelope with BIN protocol tag and gzip compression");
            
            self.execute_commit_reveal_pattern(params, &envelope).await
        } else {
            // Contract execution without envelope
            log::info!("CONTRACT EXECUTION: Single transaction without envelope");
            self.execute_single_transaction(&params).await
        }
    }

    /// Execute commit/reveal transaction pattern with proper script-path spending
    async fn execute_commit_reveal_pattern(
        &self,
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
        &self,
        envelope: &AlkanesEnvelope,
        params: &EnhancedExecuteParams,
    ) -> Result<(String, u64, OutPoint)> {
        log::info!("Creating commit transaction");

        let internal_key = self.provider.get_internal_key().await?;
        let network = self.provider.get_network();
        let commit_address = self.create_commit_address_for_envelope(envelope, network, internal_key).await?;

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
        &self,
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
        network: bitcoin::Network,
        internal_key: XOnlyPublicKey,
    ) -> Result<Address> {
        use bitcoin::taproot::TaprootBuilder;

        let reveal_script = envelope.build_reveal_script();

        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone()).map_err(|e| DeezelError::Other(format!("{:?}", e)))?;

        let taproot_spend_info = taproot_builder
            .finalize(&self.provider.secp(), internal_key).map_err(|e| DeezelError::Other(format!("{:?}", e)))?;

        let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

        Ok(commit_address)
    }

    /// Execute single transaction (no envelope)
    async fn execute_single_transaction(&self, params: &EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
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

        let utxos = self.provider.get_utxos(false, None).await?;
        log::debug!("Found {} spendable wallet UTXOs", utxos.len());

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
        // In a full implementation, we would check the alkanes balance of each UTXO.
        // For now, we just select enough UTXOs to cover the Bitcoin requirement.
        // The logic for selecting specific alkanes is a TODO.

        for utxo in utxos {
            if bitcoin_collected < bitcoin_needed {
                bitcoin_collected += utxo.amount;
                selected_outpoints.push(OutPoint::from_str(&format!("{}:{}", utxo.txid, utxo.vout))?);
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
            let address = Address::from_str(addr_str)?.require_network(network)?;
            outputs.push(TxOut {
                value: bitcoin::Amount::from_sat(546), // Dust
                script_pubkey: address.script_pubkey(),
            });
        }

        if let Some(change_addr_str) = change_address {
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
        let mut protostone_messages = Protostones::new();

        for spec in protostones {
            for edict_spec in &spec.edicts {
                let id = RuneId {
                    block: edict_spec.alkane_id.block,
                    tx: edict_spec.alkane_id.tx as u32,
                };
                let amount = edict_spec.amount as u128;
                let output = match edict_spec.target {
                    OutputTarget::Output(v) => v,
                    _ => 0, // Other cases not handled yet
                };
                edicts.push(Edict { id, amount, output });
            }

            let message = if let Some(cellpack) = &spec.cellpack {
                // TODO: Implement proper cellpack enciphering
                log::warn!("Cellpack enciphering not yet implemented, using placeholder.");
                cellpack.inputs.iter().map(|&x| x as u8).collect()
            } else {
                Vec::new()
            };

            protostone_messages.add(Protostone {
                protocol_tag: 1, // ALKANES protocol tag
                message,
            });
        }

        let mut protocol_payload_u8 = Vec::new();
        for p in protostone_messages.iter() {
            leb128::write::unsigned(&mut protocol_payload_u8, p.protocol_tag as u64).unwrap();
            leb128::write::unsigned(&mut protocol_payload_u8, p.message.len() as u64).unwrap();
            protocol_payload_u8.extend(&p.message);
        }
        
        let protocol_payload = protocol_payload_u8.into_iter().map(u128::from).collect();

        let runestone = Runestone {
            edicts,
            etching: None,
            mint: None,
            pointer: None,
            protocol: Some(protocol_payload),
        };

        Ok(runestone.encipher())
    }

    async fn build_transaction(
        &self,
        utxos: Vec<OutPoint>,
        mut outputs: Vec<TxOut>,
        runestone_script: ScriptBuf,
        fee_rate: Option<f32>
    ) -> Result<(Transaction, u64)> {
        log::info!("Building and signing transaction using wallet provider");
        
        use bitcoin::psbt::Psbt;
        
        // Add OP_RETURN output with runestone
        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: runestone_script,
        };
        outputs.push(op_return_output);
        
        // Create PSBT
        let mut psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: outputs,
        })?;
        
        // Configure inputs for signing
        let all_wallet_utxos = self.provider.get_utxos(true, None).await?;
        for (i, outpoint) in utxos.iter().enumerate() {
            let utxo_info = all_wallet_utxos.iter()
                .find(|u| u.txid == outpoint.txid.to_string() && u.vout == outpoint.vout)
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
        
        // Sign the PSBT
        let signed_psbt = self.provider.sign_psbt(&psbt).await?;
        
        // Extract the transaction and manually add witnesses
        let mut tx = signed_psbt.clone().extract_tx()?;
        for (i, psbt_input) in signed_psbt.inputs.iter().enumerate() {
            if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                tx.input[i].witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
            } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                tx.input[i].witness = final_script_witness.clone();
            }
        }
        
        // Calculate fee
        let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
        let fee = (fee_rate_sat_vb * tx.vsize() as f32).ceil() as u64;
        
        Ok((tx, fee))
    }

    /// Builds the reveal transaction with script-path spending.
    ///
    /// This function constructs the reveal transaction, which spends the commit
    /// output and includes the envelope data in the witness. It also handles
    /// the creation of the runestone and the final outputs.
    async fn build_script_path_reveal_transaction(
        &self,
        all_inputs: Vec<OutPoint>,
        mut outputs: Vec<TxOut>,
        runestone_script: ScriptBuf,
        fee_rate: Option<f32>,
        envelope: &AlkanesEnvelope,
    ) -> Result<(Transaction, u64)> {
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
        let network = self.provider.get_network();

        for (i, outpoint) in all_inputs.iter().enumerate() {
            if i == 0 {
                let commit_address = self.create_commit_address_for_envelope(envelope, network, internal_key).await?;
                let commit_output_value = 50_546u64; // Placeholder
                psbt.inputs[i].witness_utxo = Some(TxOut {
                    value: bitcoin::Amount::from_sat(commit_output_value),
                    script_pubkey: commit_address.script_pubkey(),
                });

                let (taproot_spend_info, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
                psbt.inputs[i].tap_internal_key = Some(internal_key);
                
                let script_map = taproot_spend_info.script_map();
                if let Some(((script, leaf_version), _)) = script_map.iter().next() {
                    use alloc::collections::BTreeMap;
                    let mut tap_scripts = BTreeMap::new();
                    tap_scripts.insert(control_block.clone(), (script.clone(), *leaf_version));
                    psbt.inputs[i].tap_scripts = tap_scripts;
                }
            } else {
                let utxo_info = self.provider.get_utxo(outpoint).await?.ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
                if utxo_info.script_pubkey.is_p2tr() {
                    psbt.inputs[i].tap_internal_key = Some(internal_key);
                }
                psbt.inputs[i].witness_utxo = Some(utxo_info);
            }
        }

        let signed_psbt = self.provider.sign_psbt(&psbt).await?;
        let mut tx = signed_psbt.clone().extract_tx()?;

        for (i, _) in all_inputs.iter().enumerate() {
            if i == 0 {
                let reveal_script = envelope.build_reveal_script();
                let (_, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
                let signature = self.create_taproot_script_signature(&tx, i, reveal_script.as_bytes(), &control_block.serialize()).await?;
                tx.input[i].witness = envelope.create_complete_witness(&signature, control_block)?;
            } else {
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

        Ok((tx, fee))
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

        Ok(signature.as_ref().to_vec())
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
                let trace_vout = tx.output.len() as u32 + protostone_count + 1;
                
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
