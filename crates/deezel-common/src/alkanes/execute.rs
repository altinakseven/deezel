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
use bitcoin::{Transaction, ScriptBuf, OutPoint, TxOut, Address};
use crate::vendored_ord::{Edict, RuneId, Runestone};
use core::str::FromStr;
use alloc::{vec, vec::Vec, string::{String, ToString}, format};
use super::types::{EnhancedExecuteParams, EnhancedExecuteResult, InputRequirement, ProtostoneSpec, OutputTarget};
use super::envelope::AlkanesEnvelope;

/// Enhanced alkanes executor
pub struct EnhancedAlkanesExecutor<'a, T: DeezelProvider> {
    provider: &'a T,
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
            
            self.execute_commit_reveal_pattern(&params, &envelope).await
        } else {
            // Contract execution without envelope
            log::info!("CONTRACT EXECUTION: Single transaction without envelope");
            self.execute_single_transaction(&params).await
        }
    }

    /// Execute commit/reveal transaction pattern with proper script-path spending
    async fn execute_commit_reveal_pattern(
        &self,
        _params: &EnhancedExecuteParams,
        _envelope: &AlkanesEnvelope
    ) -> Result<EnhancedExecuteResult> {
        Err(DeezelError::NotImplemented("Commit/reveal pattern not yet implemented".to_string()))
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

    fn validate_protostones(&self, protostones: &[ProtostoneSpec], num_outputs: usize) -> Result<()> {
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
        
        let mut selected_outpoints = vec![];
        let mut total_sats: u64 = 0;

        let mut bitcoin_needed = 0;
        for req in requirements {
            if let InputRequirement::Bitcoin{amount} = req {
                bitcoin_needed += amount;
            }
            // TODO: Handle Alkanes requirements
        }

        for utxo in utxos {
            if total_sats < bitcoin_needed {
                total_sats += utxo.amount;
                selected_outpoints.push(OutPoint::from_str(&format!("{}:{}", utxo.txid, utxo.vout))?);
            } else {
                break;
            }
        }

        if total_sats < bitcoin_needed {
            return Err(DeezelError::Wallet("Insufficient funds".to_string()));
        }

        Ok(selected_outpoints)
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
        for spec in protostones {
            for edict_spec in &spec.edicts {
                let id = RuneId { block: edict_spec.alkane_id.block, tx: edict_spec.alkane_id.tx as u32 };
                let amount = edict_spec.amount as u128;
                let output = match edict_spec.target {
                    OutputTarget::Output(v) => v,
                    _ => 0, // Other cases not handled yet
                };
                edicts.push(Edict { id, amount, output });
            }
        }

        let runestone = Runestone {
            edicts,
            etching: None,
            mint: None,
            pointer: None,
            // protocol field doesn't exist in our vendored Runestone
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
        }).map_err(|e| DeezelError::Transaction(e.to_string()))?;
        
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
        let mut tx = signed_psbt.clone().extract_tx().map_err(|e| DeezelError::Transaction(e.to_string()))?;
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
                let trace_vout = tx.output.len() as u32 + protostone_count;
                
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

    async fn mine_blocks_if_regtest(&self) -> Result<()> {
        if self.provider.get_network() == bitcoin::Network::Regtest {
            log::info!("Mining blocks on regtest network...");
            let address = WalletProvider::get_address(self.provider).await?;
            self.provider.generate_to_address(101, &address).await?;
        }
        Ok(())
    }

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
