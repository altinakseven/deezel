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

use crate::{Result, DeezelError, DeezelProvider};
use crate::traits::{WalletProvider, UtxoInfo};
use bitcoin::{Transaction, ScriptBuf, OutPoint, TxOut, Address, XOnlyPublicKey, psbt::Psbt};
use core::str::FromStr;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};
#[cfg(feature = "std")]
use std::{vec, vec::Vec, string::{String, ToString}, format};
use tokio::time::{sleep, Duration};
pub use super::types::{
    EnhancedExecuteParams, EnhancedExecuteResult, ExecutionState, InputRequirement, OutputTarget,
    ProtostoneSpec, ReadyToSignCommitTx, ReadyToSignRevealTx, ReadyToSignTx,
};
use super::envelope::AlkanesEnvelope;
use anyhow::anyhow;
use protorune_support::protostone::{Protostone, into_protostone_edicts};
use crate::utils::protostone::Protostones;

const MAX_FEE_SATS: u64 = 100_000; // 0.001 BTC. Cap to avoid "absurdly high fee rate" errors.
const DUST_LIMIT: u64 = 546;


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
    pub async fn execute(&mut self, params: EnhancedExecuteParams) -> Result<ExecutionState> {
        log::info!("Starting enhanced alkanes execution");

        self.validate_envelope_cellpack_usage(&params)?;

        if let Some(envelope_data) = &params.envelope_data {
            log::info!("CONTRACT DEPLOYMENT: Using envelope with BIN data for contract deployment");
            log::info!("Envelope data size: {} bytes", envelope_data.len());
            let envelope = AlkanesEnvelope::for_contract(envelope_data.clone());
            log::info!("Created AlkanesEnvelope with BIN protocol tag and gzip compression");
            self.build_commit_reveal_pattern(params, &envelope).await
        } else {
            log::info!("CONTRACT EXECUTION: Single transaction without envelope");
            self.build_single_transaction(&params).await
        }
    }

    pub async fn resume_execution(&mut self, state: ReadyToSignTx, params: &EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        let tx = self.sign_and_finalize_psbt(state.psbt).await?;
        
        let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
        let txid = self.provider.broadcast_transaction(tx_hex).await?;
        
        if !params.raw_output {
            log::info!("✅ Transaction broadcast successfully!");
            log::info!("🔗 TXID: {}", txid);
        }
        
        let traces = if params.trace_enabled {
            self.trace_reveal_transaction(&txid, params).await?
        } else {
            None
        };
        
        Ok(EnhancedExecuteResult {
            commit_txid: None,
            reveal_txid: txid,
            commit_fee: None,
            reveal_fee: state.fee,
            inputs_used: tx.input.iter().map(|i| i.previous_output.to_string()).collect(),
            outputs_created: tx.output.iter().map(|o| o.script_pubkey.to_string()).collect(),
            traces,
        })
    }

    pub async fn resume_commit_execution(
        &mut self,
        state: ReadyToSignCommitTx,
    ) -> Result<ExecutionState> {
        // 1. Sign and broadcast the commit transaction
        let commit_tx = self.sign_and_finalize_psbt(state.psbt).await?;
        let commit_txid = self
            .provider
            .broadcast_transaction(bitcoin::consensus::encode::serialize_hex(&commit_tx))
            .await?;
        log::info!("✅ Commit transaction broadcast successfully: {}", commit_txid);

        // 2. Build the reveal transaction PSBT
        let commit_outpoint = bitcoin::OutPoint { txid: commit_tx.compute_txid(), vout: 0 };
        let (reveal_psbt, reveal_fee) = self
            .build_reveal_psbt(
                &state.params,
                &state.envelope,
                commit_outpoint,
                state.required_reveal_amount,
            )
            .await?;

        // 3. Analyze the reveal transaction
        let analysis =
            crate::transaction::analysis::analyze_transaction(&reveal_psbt.unsigned_tx);

        let inspection_result = self.inspect_from_envelope(&state.envelope).await.ok();

        // 4. Return the next state
        Ok(ExecutionState::ReadyToSignReveal(ReadyToSignRevealTx {
            psbt: reveal_psbt,
            fee: reveal_fee,
            analysis,
            commit_txid,
            commit_fee: state.fee,
            params: state.params,
            inspection_result,
        }))
    }

    pub async fn resume_reveal_execution(
        &mut self,
        state: ReadyToSignRevealTx,
    ) -> Result<EnhancedExecuteResult> {
        let reveal_tx = self.sign_and_finalize_psbt(state.psbt).await?;
        let reveal_txid = self
            .provider
            .broadcast_transaction(bitcoin::consensus::encode::serialize_hex(&reveal_tx))
            .await?;

        if !state.params.raw_output {
            log::info!("✅ Reveal transaction broadcast successfully!");
            log::info!("🔗 TXID: {}", reveal_txid);
        }

        let traces = if state.params.trace_enabled {
            self.trace_reveal_transaction(&reveal_txid, &state.params).await?
        } else {
            None
        };

        Ok(EnhancedExecuteResult {
            commit_txid: Some(state.commit_txid),
            reveal_txid,
            commit_fee: Some(state.commit_fee),
            reveal_fee: state.fee,
            inputs_used: reveal_tx.input.iter().map(|i| i.previous_output.to_string()).collect(),
            outputs_created: reveal_tx.output.iter().map(|o| o.script_pubkey.to_string()).collect(),
            traces,
        })
    }

    /// Build the commit transaction and return it in a ready-to-sign state.
    async fn build_commit_reveal_pattern(
        &mut self,
        params: EnhancedExecuteParams,
        envelope: &AlkanesEnvelope,
    ) -> Result<ExecutionState> {
        log::info!("Building commit transaction");

        let internal_key = self.provider.get_internal_key().await?;
        let commit_address = self.create_commit_address_for_envelope(envelope, internal_key).await?;
        log::info!("Envelope commit address: {}", commit_address);

        let mut required_reveal_amount = 546u64;
        for requirement in &params.input_requirements {
            if let InputRequirement::Bitcoin { amount } = requirement {
                required_reveal_amount += amount;
            }
        }
        let estimated_reveal_fee = 50_000u64;
        required_reveal_amount += estimated_reveal_fee;
        required_reveal_amount += params.to_addresses.len() as u64 * 546;

        let funding_utxos = self
            .select_utxos(&[InputRequirement::Bitcoin { amount: required_reveal_amount }], &params.from_addresses)
            .await?;

        let commit_output = TxOut {
            value: bitcoin::Amount::from_sat(required_reveal_amount),
            script_pubkey: commit_address.script_pubkey(),
        };

        let (commit_psbt, commit_fee) = self
            .build_commit_psbt(funding_utxos, commit_output, params.fee_rate)
            .await?;

        Ok(ExecutionState::ReadyToSignCommit(ReadyToSignCommitTx {
            psbt: commit_psbt,
            fee: commit_fee,
            required_reveal_amount,
            params,
            envelope: envelope.clone(),
        }))
    }

    /// Creates a taproot address for the commit transaction.
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
    async fn build_single_transaction(&mut self, params: &EnhancedExecuteParams) -> Result<ExecutionState> {
        log::info!("Building single transaction (no envelope)");

        self.validate_protostones(&params.protostones, params.to_addresses.len())?;
        let mut outputs = self.create_outputs(&params.to_addresses, &params.change_address, &params.input_requirements).await?;
        for protostone in &params.protostones {
            if let Some(transfer) = &protostone.bitcoin_transfer {
                if let OutputTarget::Output(vout) = transfer.target {
                    if let Some(output) = outputs.get_mut(vout as usize) {
                        output.value = bitcoin::Amount::from_sat(transfer.amount);
                    }
                }
            }
        }
        let total_bitcoin_needed: u64 = outputs.iter().filter(|o| o.value.to_sat() > 0).map(|o| o.value.to_sat()).sum();
        let mut final_requirements = params.input_requirements.iter().filter(|req| !matches!(req, InputRequirement::Bitcoin {..})).cloned().collect::<Vec<_>>();
        if total_bitcoin_needed > 0 {
            final_requirements.push(InputRequirement::Bitcoin { amount: total_bitcoin_needed });
        }
        let selected_utxos = self.select_utxos(&final_requirements, &params.from_addresses).await?;
        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;
        let (psbt, fee) = self.build_psbt_and_fee(selected_utxos.clone(), outputs, runestone_script, params.fee_rate).await?;

        let unsigned_tx = &psbt.unsigned_tx;
        let analysis = crate::transaction::analysis::analyze_transaction(unsigned_tx);
        let inspection_result = self.inspect_from_protostones(&params.protostones).await.ok();

        Ok(ExecutionState::ReadyToSign(ReadyToSignTx {
            psbt,
            analysis,
            fee,
            inspection_result,
        }))
    }

    pub fn validate_protostones(&self, protostones: &[ProtostoneSpec], num_outputs: usize) -> Result<()> {
        log::info!("Validating {} protostones against {} outputs", protostones.len(), num_outputs);
        
        for (i, protostone) in protostones.iter().enumerate() {
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
            
            if let Some(bitcoin_transfer) = &protostone.bitcoin_transfer {
                if matches!(bitcoin_transfer.target, OutputTarget::Protostone(_)) {
                    return Err(DeezelError::Validation(format!(
                        "Bitcoin transfer in protostone {} cannot target another protostone",
                        i
                    )));
                }
            }
            
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
                    OutputTarget::Split => {}
                }
            }
        }
        
        Ok(())
    }

    async fn select_utxos(&self, requirements: &[InputRequirement], from_addresses: &Option<Vec<String>>) -> Result<Vec<OutPoint>> {
        log::info!("Selecting UTXOs for {} requirements", requirements.len());
        if let Some(addrs) = from_addresses {
            log::info!("Sourcing UTXOs from: {:?}", addrs);
        }

        let utxos = self.provider.get_utxos(true, from_addresses.clone()).await?;
        log::debug!("Found {} total wallet UTXOs from specified sources", utxos.len());

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

    async fn create_outputs(
        &self,
        to_addresses: &[String],
        change_address: &Option<String>,
        input_requirements: &[InputRequirement],
    ) -> Result<Vec<TxOut>> {
        let mut outputs = Vec::new();
        let network = self.provider.get_network();

        let total_explicit_bitcoin: u64 = input_requirements.iter().filter_map(|req| {
            if let InputRequirement::Bitcoin { amount } = req { Some(*amount) } else { None }
        }).sum();

        if total_explicit_bitcoin > 0 && to_addresses.is_empty() {
            return Err(DeezelError::Validation("Bitcoin input requirement provided but no recipient addresses.".to_string()));
        }

        let amount_per_recipient = if total_explicit_bitcoin > 0 {
            total_explicit_bitcoin / to_addresses.len() as u64
        } else {
            DUST_LIMIT
        };

        for addr_str in to_addresses {
            log::debug!("Parsing to_address in create_outputs: '{}'", addr_str);
            let address = Address::from_str(addr_str)?.require_network(network)?;
            outputs.push(TxOut {
                value: bitcoin::Amount::from_sat(amount_per_recipient.max(DUST_LIMIT)),
                script_pubkey: address.script_pubkey(),
            });
        }

        if let Some(change_addr_str) = change_address {
            log::debug!("Parsing change_address in create_outputs: '{}'", change_addr_str);
            let address = Address::from_str(change_addr_str)?.require_network(network)?;
            outputs.push(TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: address.script_pubkey(),
            });
        }

        Ok(outputs)
    }

    fn construct_runestone(&self, protostones: &[ProtostoneSpec], _num_outputs: usize) -> Result<ScriptBuf> {
        log::info!("Constructing runestone with {} protostones", protostones.len());
        log::debug!("Protostone Specs: {:#?}", protostones);

        let mut edicts = Vec::new();
        let mut all_protostones = Vec::new();

        for spec in protostones {
            let mut current_edicts = Vec::new();
            for edict_spec in &spec.edicts {
                let id = ordinals::RuneId {
                    block: edict_spec.alkane_id.block,
                    tx: edict_spec.alkane_id.tx as u32,
                };
                let amount = edict_spec.amount as u128;
                let output = match edict_spec.target {
                    OutputTarget::Output(v) => v,
                    _ => 0,
                };
                current_edicts.push(ordinals::Edict { id, amount, output });
            }
            edicts.extend(current_edicts.clone());

            let message = if let Some(cellpack) = &spec.cellpack {
                let cellpack_bytes = cellpack.encipher();
                log::info!("Encoded cellpack to {} bytes", cellpack_bytes.len());
                cellpack_bytes
            } else {
                Vec::new()
            };

            all_protostones.push(Protostone {
                protocol_tag: 1,
                message,
                edicts: into_protostone_edicts(current_edicts),
                burn: None,
                refund: None,
                pointer: None,
                from: None,
            });
        }

        let protocol_payload = if !all_protostones.is_empty() {
            let enciphered = all_protostones.encipher()?;
            log::info!("Enciphered protostones into payload: {:?}", enciphered);
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

        log::debug!("Constructed Runestone: {:#?}", runestone);
        if let Ok(decoded) = crate::alkanes::analyze::analyze_runestone(&Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: runestone.encipher(),
            }],
        }) {
            log::debug!("Decoded Runestone for logging: {:#?}", decoded);
        }
        Ok(runestone.encipher())
    }

    async fn build_psbt_and_fee(
        &mut self,
        utxos: Vec<OutPoint>,
        mut outputs: Vec<TxOut>,
        runestone_script: ScriptBuf,
        fee_rate: Option<f32>
    ) -> Result<(Psbt, u64)> {
        use bitcoin::transaction::Version;
    
        if !runestone_script.is_empty() {
            outputs.push(TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: runestone_script,
            });
        }
    
        let mut total_input_value = 0;
        let mut input_txouts = Vec::new();
        for outpoint in &utxos {
            let utxo = self.provider.get_utxo(outpoint).await?
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
            total_input_value += utxo.value.to_sat();
            input_txouts.push(utxo);
        }
    
        let mut temp_tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: outputs.clone(),
        };
    
        for input in &mut temp_tx.input {
            input.witness.push(&[0u8; 65]);
        }
    
        let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
        let estimated_fee = (fee_rate_sat_vb * temp_tx.vsize() as f32).ceil() as u64;
        let capped_fee = estimated_fee.min(MAX_FEE_SATS);
        log::info!("Estimated fee: {}, Capped fee: {}", estimated_fee, capped_fee);
    
        let total_output_value_sans_change: u64 = outputs.iter()
            .filter(|o| o.value.to_sat() > 0)
            .map(|o| o.value.to_sat())
            .sum();
    
        let change_value = total_input_value.saturating_sub(total_output_value_sans_change).saturating_sub(capped_fee);
    
        if let Some(change_output) = outputs.iter_mut().find(|o| o.value.to_sat() == 0 && !o.script_pubkey.is_op_return()) {
            change_output.value = bitcoin::Amount::from_sat(change_value);
        } else if let Some(last_output) = outputs.iter_mut().last() {
             if !last_output.script_pubkey.is_op_return() {
                last_output.value = bitcoin::Amount::from_sat(last_output.value.to_sat() + change_value);
             }
        }
    
        let mut psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: utxos.iter().map(|outpoint| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }).collect(),
            output: outputs,
        })?;
    
        for (i, utxo) in input_txouts.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(utxo.clone());
            if utxo.script_pubkey.is_p2tr() {
                let internal_key = self.provider.get_internal_key().await?;
                psbt.inputs[i].tap_internal_key = Some(internal_key);
            }
        }
        
        Ok((psbt, capped_fee))
    }

    async fn sign_and_finalize_psbt(&mut self, mut psbt: bitcoin::psbt::Psbt) -> Result<Transaction> {
        let signed_psbt = self.provider.sign_psbt(&mut psbt).await?;
        let mut tx = signed_psbt.clone().extract_tx()?;
        for (i, psbt_input) in signed_psbt.inputs.iter().enumerate() {
            if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                tx.input[i].witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
            } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                tx.input[i].witness = final_script_witness.clone();
            }
        }
        Ok(tx)
    }

    async fn build_commit_psbt(
        &mut self,
        funding_utxos: Vec<OutPoint>,
        commit_output: TxOut,
        fee_rate: Option<f32>,
    ) -> Result<(bitcoin::psbt::Psbt, u64)> {
        let mut total_input_value = 0;
        let mut input_txouts = Vec::new();
        for outpoint in &funding_utxos {
            let utxo = self.provider.get_utxo(outpoint).await?
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", outpoint)))?;
            total_input_value += utxo.value.to_sat();
            input_txouts.push(utxo);
        }
    
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
            input.witness.push(&[0u8; 65]);
        }
    
        let fee_rate_sat_vb = fee_rate.unwrap_or(1.0);
        let fee = (fee_rate_sat_vb * temp_tx_for_size.vsize() as f32).ceil() as u64;
    
        let change_value = total_input_value.saturating_sub(commit_output.value.to_sat()).saturating_sub(fee);
        if change_value < 546 {
            return Err(DeezelError::Wallet("Not enough funds for commit and change".to_string()));
        }
    
        let final_change_output = TxOut { value: bitcoin::Amount::from_sat(change_value), script_pubkey: change_address.script_pubkey() };
        let final_outputs = vec![commit_output, final_change_output];
    
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
    
        Ok((psbt, fee))
    }
    
    async fn build_reveal_psbt(
        &mut self,
        params: &EnhancedExecuteParams,
        envelope: &AlkanesEnvelope,
        commit_outpoint: OutPoint,
        commit_output_value: u64,
    ) -> Result<(bitcoin::psbt::Psbt, u64)> {
        self.validate_protostones(&params.protostones, params.to_addresses.len())?;

        let mut selected_utxos = vec![commit_outpoint];
        let mut total_bitcoin_needed = params.to_addresses.len() as u64 * DUST_LIMIT;
        for req in &params.input_requirements {
            if let InputRequirement::Bitcoin { amount } = req {
                total_bitcoin_needed += amount;
            }
        }
        total_bitcoin_needed += 50_000;

        if commit_output_value < total_bitcoin_needed {
            let additional_needed = total_bitcoin_needed - commit_output_value;
            let additional_reqs = vec![InputRequirement::Bitcoin { amount: additional_needed }];
            let additional_utxos = self.select_utxos(&additional_reqs, &params.from_addresses).await?;
            selected_utxos.extend(additional_utxos);
        }

        let outputs = self.create_outputs(&params.to_addresses, &params.change_address, &params.input_requirements).await?;
        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;
        
        let (mut psbt, fee) = self.build_psbt_and_fee(selected_utxos, outputs, runestone_script, params.fee_rate).await?;
        
        let internal_key = self.provider.get_internal_key().await?;
        let reveal_script = envelope.build_reveal_script();
        let (spend_info, _) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
        psbt.inputs[0].tap_scripts.insert(
            spend_info.control_block(&(reveal_script.clone(), bitcoin::taproot::LeafVersion::TapScript)).unwrap(),
            (reveal_script, bitcoin::taproot::LeafVersion::TapScript)
        );

        Ok((psbt, fee))
    }

    /// Creates the taproot spend info and control block for an envelope.
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
        
        let prevouts_len = prevouts.len();
        let prevouts_all = Prevouts::All(prevouts);
        
        log::info!("Using Prevouts::All with {} prevouts for sighash calculation", prevouts_len);

        let mut sighash_cache = SighashCache::new(tx);

        let script_buf = ScriptBuf::from(script.to_vec());
        let leaf_hash = taproot::TapLeafHash::from_script(&script_buf, taproot::LeafVersion::TapScript);

        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &prevouts_all,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| DeezelError::Transaction(e.to_string()))?;

        log::info!("Computed taproot script-path sighash for input {}", input_index);

        let signature = self.provider.sign_taproot_script_spend(sighash.into()).await?;
        
        let taproot_signature = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        let signature_bytes = taproot_signature.to_vec();
        
        log::info!("✅ Created taproot script-path signature: {} bytes", signature_bytes.len());

        Ok(signature_bytes)
    }

    /// Traces the reveal transaction to get the results of protostone execution.
    async fn trace_reveal_transaction(&self, txid: &str, params: &EnhancedExecuteParams) -> Result<Option<Vec<serde_json::Value>>> {
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
        
        if let Ok(decoded) = crate::alkanes::analyze::analyze_runestone(&tx) {
            log::info!("Decoded Runestone for debugging:\n{:#?}", decoded);
        }

        let mut traces = Vec::new();
        for (protostone_idx, _) in params.protostones.iter().enumerate() {
            let trace_vout = (tx.output.len() + protostone_idx) as u32;
            
            log::info!("Tracing protostone #{} at virtual outpoint: {}:{}", protostone_idx, txid, trace_vout);

            match self.provider.trace_outpoint(txid, trace_vout).await {
                Ok(trace_result) => {
                    if let Some(events) = trace_result.get("events").and_then(|e| e.as_array()) {
                        if events.is_empty() {
                            log::warn!("Trace for {}:{} came back with an empty 'events' array.", txid, trace_vout);
                        }
                    } else {
                        log::warn!("Trace for {}:{} did not contain an 'events' array.", txid, trace_vout);
                    }
                    log::debug!("Trace result for protostone #{}: {:?}", protostone_idx, trace_result);
                    traces.push(trace_result);
                },
                Err(e) => {
                    log::warn!("Failed to trace protostone #{} at vout {}: {}", protostone_idx, trace_vout, e);
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
    async fn mine_blocks_if_regtest(&self, params: &EnhancedExecuteParams) -> Result<()> {
        if self.provider.get_network() == bitcoin::Network::Regtest {
            log::info!("Mining blocks on regtest network...");
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
    async fn wait_for_transaction_mined(&self, txid: &str, _params: &EnhancedExecuteParams) -> Result<()> {
        loop {
            match self.provider.get_tx_status(txid).await {
                Ok(status) => {
                    if status.get("confirmed").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return Ok(());
                    }
                }
                Err(_) => {}
            }
            self.provider.sleep_ms(1000).await;
        }
    }

    /// Waits for the metashrew indexer to be synchronized with the Bitcoin node.
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
    async fn inspect_from_protostones(&self, protostones: &[ProtostoneSpec]) -> Result<super::types::AlkanesInspectResult> {
        use super::types::{AlkaneId, AlkanesInspectConfig};
        use crate::utils::u128_from_slice;

        let cellpack_data = protostones
            .iter()
            .find_map(|p| p.cellpack.as_ref())
            .map(|c| c.encipher())
            .ok_or_else(|| DeezelError::Other("No cellpack found in protostones for inspection.".to_string()))?;

        if cellpack_data.len() < 48 {
            return Err(DeezelError::Other("Cellpack data is too short for inspection.".to_string()));
        }

        let alkane_id = AlkaneId {
            block: u128_from_slice(&cellpack_data[0..16]) as u64,
            tx: u128_from_slice(&cellpack_data[16..32]) as u64,
        };
        let opcode = u128_from_slice(&cellpack_data[32..48]);

        let config = AlkanesInspectConfig {
            disasm: false,
            fuzz: true,
            fuzz_ranges: Some(opcode.to_string()),
            meta: true,
            codehash: false,
            raw: false,
        };

        self.provider.inspect(&format!("{}:{}", alkane_id.block, alkane_id.tx), config).await
    }

    async fn inspect_from_envelope(&self, envelope: &AlkanesEnvelope) -> Result<super::types::AlkanesInspectResult> {
        use super::types::{AlkaneId, AlkanesInspectResult};
        use wasmparser::{Parser, Payload};

        let wasm = &envelope.payload;
        let mut metadata = None;
        let mut metadata_error = None;

        let parser = Parser::new(0);
        for payload in parser.parse_all(wasm) {
            if let Ok(Payload::CustomSection(reader)) = payload {
                if reader.name() == "__meta" {
                    match serde_json::from_slice(reader.data()) {
                        Ok(m) => metadata = Some(m),
                        Err(e) => metadata_error = Some(e.to_string()),
                    }
                    break;
                }
            }
        }

        Ok(AlkanesInspectResult {
            alkane_id: AlkaneId { block: 0, tx: 0 }, // Not applicable for pre-deployment inspection
            bytecode_length: wasm.len(),
            disassembly: None,
            metadata,
            metadata_error,
            codehash: None,
            fuzzing_results: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alkanes::execute::EnhancedAlkanesExecutor;
    use crate::mock_provider::MockProvider;
    use bitcoin::{Amount, Network};

    #[tokio::test]
    async fn test_create_outputs_dust_limit() {
        let mut provider = MockProvider::new(Network::Regtest);
        let addr1 = WalletProvider::get_address(&provider).await.unwrap();
        let executor = EnhancedAlkanesExecutor::new(&mut provider);
        let to_addresses = vec![addr1.clone(), addr1];
        let input_requirements = vec![];

        let outputs = executor.create_outputs(&to_addresses, &None, &input_requirements).await.unwrap();

        assert_eq!(outputs.len(), 2);
        for output in outputs {
            assert_eq!(output.value, Amount::from_sat(546));
        }
    }

    #[tokio::test]
    async fn test_create_outputs_with_explicit_bitcoin() {
        let mut provider = MockProvider::new(Network::Regtest);
        let addr1 = WalletProvider::get_address(&provider).await.unwrap();
        let executor = EnhancedAlkanesExecutor::new(&mut provider);
        let to_addresses = vec![addr1.clone(), addr1];
        let input_requirements = vec![InputRequirement::Bitcoin { amount: 20000 }];

        let outputs = executor.create_outputs(&to_addresses, &None, &input_requirements).await.unwrap();

        assert_eq!(outputs.len(), 2);
        for output in outputs {
            assert_eq!(output.value, Amount::from_sat(10000));
        }
    }
}
