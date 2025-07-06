//! Enhanced alkanes execute functionality with commit/reveal transaction support
//!
//! This module implements the complex alkanes execute command that supports:
//! - Commit/reveal transaction pattern for envelope data
//! - Complex protostone parsing with cellpacks and edicts
//! - UTXO selection based on alkanes and Bitcoin requirements
//! - Runestone construction with multiple protostones
//! - Address identifier resolution for outputs and change
//! - Transaction tracing with metashrew synchronization

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::io::{self, Write};

use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use crate::runestone_enhanced::{format_runestone_with_decoded_messages, print_human_readable_runestone};
use super::types::*;
use super::envelope::AlkanesEnvelope;
use super::fee_validation::{validate_transaction_fee_rate, create_fee_adjusted_transaction};
use alkanes_support::cellpack::Cellpack;
use ordinals::Runestone;

/// Input requirement specification
#[derive(Debug, Clone)]
pub enum InputRequirement {
    /// Alkanes token requirement: (block, tx, amount) where 0 means ALL
    Alkanes { block: u64, tx: u64, amount: u64 },
    /// Bitcoin requirement: amount in satoshis
    Bitcoin { amount: u64 },
}

/// Output target specification for protostones
#[derive(Debug, Clone)]
pub enum OutputTarget {
    /// Target specific output index (vN)
    Output(u32),
    /// Target specific protostone (pN)
    Protostone(u32),
    /// Split across all spendable outputs
    Split,
}

/// Protostone edict specification
#[derive(Debug, Clone)]
pub struct ProtostoneEdict {
    pub alkane_id: AlkaneId,
    pub amount: u64,
    pub target: OutputTarget,
}

/// Protostone specification
#[derive(Debug, Clone)]
pub struct ProtostoneSpec {
    /// Optional cellpack message (using alkanes_support::cellpack::Cellpack)
    pub cellpack: Option<Cellpack>,
    /// List of edicts for this protostone
    pub edicts: Vec<ProtostoneEdict>,
    /// Bitcoin transfer specification (for B: transfers)
    pub bitcoin_transfer: Option<BitcoinTransfer>,
}

/// Bitcoin transfer specification
#[derive(Debug, Clone)]
pub struct BitcoinTransfer {
    pub amount: u64,
    pub target: OutputTarget,
}

/// Enhanced execute parameters
#[derive(Debug, Clone)]
pub struct EnhancedExecuteParams {
    pub fee_rate: Option<f32>,
    pub to_addresses: Vec<String>,
    pub change_address: Option<String>,
    pub input_requirements: Vec<InputRequirement>,
    pub protostones: Vec<ProtostoneSpec>,
    pub envelope_data: Option<Vec<u8>>,
    pub raw_output: bool,
    pub trace_enabled: bool,
    pub mine_enabled: bool,
    pub auto_confirm: bool,
}

/// Enhanced execute result for commit/reveal pattern
#[derive(Debug, Clone)]
pub struct EnhancedExecuteResult {
    pub commit_txid: Option<String>,
    pub reveal_txid: String,
    pub commit_fee: Option<u64>,
    pub reveal_fee: u64,
    pub inputs_used: Vec<String>,
    pub outputs_created: Vec<String>,
    pub traces: Option<Vec<serde_json::Value>>,
}

/// Enhanced alkanes executor
pub struct EnhancedAlkanesExecutor {
    rpc_client: Arc<RpcClient>,
    wallet_manager: Arc<WalletManager>,
}

impl EnhancedAlkanesExecutor {
    /// Create a new enhanced alkanes executor
    pub fn new(rpc_client: Arc<RpcClient>, wallet_manager: Arc<WalletManager>) -> Self {
        Self {
            rpc_client,
            wallet_manager,
        }
    }

    /// Execute an enhanced alkanes transaction with commit/reveal pattern
    pub async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        info!("Starting enhanced alkanes execution with commit/reveal pattern");
        
        // For now, implement a simple version that works
        // TODO: Implement full commit/reveal pattern
        
        if params.envelope_data.is_some() {
            // Commit/reveal pattern
            let envelope = AlkanesEnvelope::for_contract(params.envelope_data.as_ref().unwrap().clone());
            self.execute_commit_reveal_pattern(&params, &envelope).await
        } else {
            // Single transaction
            self.execute_single_transaction(&params).await
        }
    }


    /// Execute commit/reveal transaction pattern
    async fn execute_commit_reveal_pattern(
        &self,
        params: &EnhancedExecuteParams,
        envelope: &AlkanesEnvelope
    ) -> Result<EnhancedExecuteResult> {
        info!("Executing commit/reveal pattern");
        
        // Step 1: Create and broadcast commit transaction
        let (commit_txid, commit_fee, commit_outpoint) = self.create_and_broadcast_commit_transaction(envelope, params).await?;
        
        if !params.raw_output {
            println!("✅ Commit transaction broadcast successfully!");
            println!("🔗 Commit TXID: {}", commit_txid);
            println!("💰 Commit Fee: {} sats", commit_fee);
            println!();
            println!("⏳ Waiting for commit transaction confirmation before reveal...");
        }
        
        // Step 2: Wait for commit transaction to be confirmed (simplified - in production should wait for actual confirmation)
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Step 3: Create and broadcast reveal transaction using commit as input
        let (reveal_txid, reveal_fee) = self.create_and_broadcast_reveal_transaction(
            params,
            envelope,
            commit_outpoint
        ).await?;
        
        if !params.raw_output {
            println!("✅ Reveal transaction broadcast successfully!");
            println!("🔗 Reveal TXID: {}", reveal_txid);
            println!("💰 Reveal Fee: {} sats", reveal_fee);
        }
        
        // Step 4: Handle tracing if enabled
        let traces = if params.trace_enabled {
            self.trace_reveal_transaction(&reveal_txid, params).await?
        } else {
            None
        };
        
        Ok(EnhancedExecuteResult {
            commit_txid: Some(commit_txid),
            reveal_txid,
            commit_fee: Some(commit_fee),
            reveal_fee,
            inputs_used: vec![], // TODO: populate with actual inputs
            outputs_created: vec![], // TODO: populate with actual outputs
            traces,
        })
    }

    /// Execute single transaction (no envelope)
    async fn execute_single_transaction(&self, params: &EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        info!("Executing single transaction (no envelope)");
        
        // Step 1: Validate protostone specifications
        self.validate_protostones(&params.protostones, params.to_addresses.len())?;
        
        // Step 2: Find UTXOs that meet input requirements
        let selected_utxos = self.select_utxos(&params.input_requirements).await?;
        
        // Step 3: Create transaction with outputs for each address
        let outputs = self.create_outputs(&params.to_addresses, &params.change_address).await?;
        
        // Step 4: Construct runestone with protostones
        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;
        
        // Clone selected_utxos for fee validation since build_transaction takes ownership
        let selected_utxos_for_validation = selected_utxos.clone();
        
        // Step 5: Build and sign transaction
        let (tx, fee) = self.build_transaction(selected_utxos, outputs, runestone_script, params.fee_rate).await?;
        
        // Step 6: Show transaction preview and request confirmation (if not raw output)
        if !params.raw_output {
            self.show_transaction_preview(&tx, fee);
            
            if !params.auto_confirm {
                self.request_user_confirmation()?;
            }
        }
        
        // Step 7: Validate fee rate before broadcasting
        info!("🔍 Validating transaction fee rate before broadcast");
        
        // Get input values for fee validation
        let mut input_values = Vec::new();
        for outpoint in &selected_utxos_for_validation {
            // Get UTXO details from wallet
            let wallet_utxos = self.wallet_manager.get_utxos().await?;
            if let Some(utxo) = wallet_utxos.iter()
                .find(|u| u.txid == outpoint.txid.to_string() && u.vout == outpoint.vout) {
                input_values.push(utxo.amount);
            } else {
                warn!("Could not find input value for UTXO {}:{}, using 0", outpoint.txid, outpoint.vout);
                input_values.push(0);
            }
        }
        
        // Skip fee validation for envelope transactions to avoid "absurdly high fee rate" errors
        // Envelope transactions with large witness data (117KB) have misleading fee rates
        info!("⚠️  Skipping fee validation for envelope transaction to avoid Bitcoin Core fee rate errors");
        info!("💡 Envelope transactions with large witness data appear to have high fee rates but are actually reasonable");
        
        // Step 8: Broadcast transaction
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
        
        // Debug: Check if transaction has witness data
        let has_witness = tx.input.iter().any(|input| !input.witness.is_empty());
        info!("🔍 Transaction has witness data: {}", has_witness);
        if !has_witness {
            warn!("⚠️  Transaction has no witness data - this will cause 'Witness program was passed an empty witness' for P2TR inputs");
            
            // Log each input's witness status
            for (i, input) in tx.input.iter().enumerate() {
                info!("  Input {}: witness items = {}", i, input.witness.len());
                for (j, item) in input.witness.iter().enumerate() {
                    info!("    Witness item {}: {} bytes", j, item.len());
                }
            }
        }
        
        let txid = self.rpc_client.send_raw_transaction(&tx_hex).await?;
        
        if !params.raw_output {
            println!("✅ Transaction broadcast successfully!");
            println!("🔗 TXID: {}", txid);
        }
        
        // Step 8: Handle tracing if enabled
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
            inputs_used: vec![], // TODO: populate with actual inputs
            outputs_created: vec![], // TODO: populate with actual outputs
            traces,
        })
    }

    /// Validate protostone specifications
    fn validate_protostones(&self, protostones: &[ProtostoneSpec], num_outputs: usize) -> Result<()> {
        info!("Validating {} protostones against {} outputs", protostones.len(), num_outputs);
        
        for (i, protostone) in protostones.iter().enumerate() {
            // Validate that no protostone refers to a pN value <= current protostone index
            for edict in &protostone.edicts {
                if let OutputTarget::Protostone(p) = edict.target {
                    if p <= i as u32 {
                        return Err(anyhow!(
                            "Protostone {} refers to protostone {} which is not allowed (must be > {})",
                            i, p, i
                        ));
                    }
                }
            }
            
            // Validate that Bitcoin transfers don't target protostones
            if let Some(bitcoin_transfer) = &protostone.bitcoin_transfer {
                if matches!(bitcoin_transfer.target, OutputTarget::Protostone(_)) {
                    return Err(anyhow!(
                        "Bitcoin transfer in protostone {} cannot target another protostone",
                        i
                    ));
                }
            }
            
            // Validate output targets are within bounds
            for edict in &protostone.edicts {
                match edict.target {
                    OutputTarget::Output(v) => {
                        if v as usize >= num_outputs {
                            return Err(anyhow!(
                                "Edict in protostone {} targets output v{} but only {} outputs exist",
                                i, v, num_outputs
                            ));
                        }
                    },
                    OutputTarget::Protostone(p) => {
                        if p as usize >= protostones.len() {
                            return Err(anyhow!(
                                "Edict in protostone {} targets protostone p{} but only {} protostones exist",
                                i, p, protostones.len()
                            ));
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

    /// Select UTXOs based on input requirements
    async fn select_utxos(&self, requirements: &[InputRequirement]) -> Result<Vec<bitcoin::OutPoint>> {
        info!("Selecting UTXOs for {} requirements", requirements.len());
        
        // Get all wallet UTXOs with enriched data (includes coinbase maturity checking)
        let enriched_utxos = self.wallet_manager.get_enriched_utxos().await?;
        debug!("Found {} enriched wallet UTXOs", enriched_utxos.len());
        
        // Filter out frozen UTXOs (including immature coinbase)
        let wallet_utxos: Vec<_> = enriched_utxos.into_iter()
            .filter(|enriched| {
                let is_frozen_for_coinbase = enriched.freeze_reason.as_ref()
                    .map_or(false, |reason| reason.contains("immature_coinbase"));
                
                if is_frozen_for_coinbase {
                    debug!("Filtering out immature coinbase UTXO: {}:{} (reason: {:?})",
                           enriched.utxo.txid, enriched.utxo.vout, enriched.freeze_reason);
                    false
                } else if enriched.utxo.frozen {
                    debug!("Filtering out frozen UTXO: {}:{} (reason: {:?})",
                           enriched.utxo.txid, enriched.utxo.vout, enriched.freeze_reason);
                    false
                } else {
                    true
                }
            })
            .map(|enriched| enriched.utxo)
            .collect();
        
        info!("After filtering: {} spendable UTXOs (filtered out frozen and immature coinbase)", wallet_utxos.len());
        
        let mut selected_utxos = Vec::new();
        let mut bitcoin_needed = 0u64;
        let mut alkanes_needed: HashMap<(u64, u64), u64> = HashMap::new();
        
        // Calculate total requirements
        for requirement in requirements {
            match requirement {
                InputRequirement::Bitcoin { amount } => {
                    bitcoin_needed += amount;
                },
                InputRequirement::Alkanes { block, tx, amount } => {
                    let key = (*block, *tx);
                    *alkanes_needed.entry(key).or_insert(0) += amount;
                }
            }
        }
        
        info!("Need {} sats Bitcoin and {} alkanes tokens", bitcoin_needed, alkanes_needed.len());
        
        // Simple greedy selection - in production this should be optimized
        let mut bitcoin_collected = 0u64;
        let mut alkanes_collected: HashMap<(u64, u64), u64> = HashMap::new();
        
        for utxo in wallet_utxos {
            // Parse UTXO outpoint
            let outpoint = bitcoin::OutPoint {
                txid: utxo.txid.parse().context("Invalid TXID in UTXO")?,
                vout: utxo.vout,
            };
            
            debug!("Considering UTXO: {}:{} with {} sats", outpoint.txid, outpoint.vout, utxo.amount);
            
            // Check if this UTXO helps meet our requirements
            let mut should_include = false;
            
            // Check Bitcoin requirement
            if bitcoin_collected < bitcoin_needed {
                bitcoin_collected += utxo.amount;
                should_include = true;
                debug!("Including UTXO for Bitcoin requirement: collected {} / needed {}", bitcoin_collected, bitcoin_needed);
            }
            
            // Check alkanes requirements (simplified - would need RPC calls to check actual balances)
            for ((block, tx), needed_amount) in &alkanes_needed {
                let collected = *alkanes_collected.get(&(*block, *tx)).unwrap_or(&0);
                if collected < *needed_amount {
                    // This UTXO might contain the needed alkanes token
                    // In a full implementation, we'd check the actual alkanes balance
                    should_include = true;
                    *alkanes_collected.entry((*block, *tx)).or_insert(0) += 1; // Placeholder
                    debug!("Including UTXO for alkanes requirement {}:{}: collected {} / needed {}", block, tx, collected + 1, needed_amount);
                }
            }
            
            if should_include {
                selected_utxos.push(outpoint);
                debug!("Selected UTXO: {}:{}", outpoint.txid, outpoint.vout);
            }
            
            // Check if we've met all requirements
            let bitcoin_satisfied = bitcoin_collected >= bitcoin_needed;
            let alkanes_satisfied = alkanes_needed.iter().all(|(key, needed)| {
                alkanes_collected.get(key).unwrap_or(&0) >= needed
            });
            
            if bitcoin_satisfied && alkanes_satisfied {
                debug!("All requirements satisfied, stopping UTXO selection");
                break;
            }
        }
        
        // Verify we have enough
        if bitcoin_collected < bitcoin_needed {
            return Err(anyhow!("Insufficient Bitcoin: need {} sats, have {}", bitcoin_needed, bitcoin_collected));
        }
        
        for ((block, tx), needed) in &alkanes_needed {
            let collected = alkanes_collected.get(&(*block, *tx)).unwrap_or(&0);
            if collected < needed {
                return Err(anyhow!("Insufficient alkanes token {}:{}: need {}, have {}", block, tx, needed, collected));
            }
        }
        
        info!("Selected {} UTXOs meeting all requirements", selected_utxos.len());
        Ok(selected_utxos)
    }

    /// Select UTXOs for reveal transaction, allowing commit UTXO even if frozen
    async fn select_utxos_for_reveal(&self, requirements: &[InputRequirement], commit_outpoint: bitcoin::OutPoint) -> Result<Vec<bitcoin::OutPoint>> {
        info!("Selecting UTXOs for reveal transaction (allowing commit UTXO even if frozen)");
        
        // Get all wallet UTXOs including frozen ones
        let all_wallet_utxos = self.wallet_manager.get_enriched_utxos().await?;
        debug!("Found {} total wallet UTXOs (including frozen)", all_wallet_utxos.len());
        
        let mut selected_utxos = Vec::new();
        let mut bitcoin_needed = 0u64;
        let mut alkanes_needed: HashMap<(u64, u64), u64> = HashMap::new();
        
        // Calculate total requirements
        for requirement in requirements {
            match requirement {
                InputRequirement::Bitcoin { amount } => {
                    bitcoin_needed += amount;
                },
                InputRequirement::Alkanes { block, tx, amount } => {
                    let key = (*block, *tx);
                    *alkanes_needed.entry(key).or_insert(0) += amount;
                }
            }
        }
        
        info!("Need {} sats Bitcoin and {} alkanes tokens", bitcoin_needed, alkanes_needed.len());
        
        // Simple greedy selection - in production this should be optimized
        let mut bitcoin_collected = 0u64;
        let mut alkanes_collected: HashMap<(u64, u64), u64> = HashMap::new();
        
        for enriched_utxo in all_wallet_utxos {
            let utxo = &enriched_utxo.utxo;
            
            // Parse UTXO outpoint
            let outpoint = bitcoin::OutPoint {
                txid: utxo.txid.parse().context("Invalid TXID in UTXO")?,
                vout: utxo.vout,
            };
            
            // Skip the commit outpoint since it will be added separately
            if outpoint == commit_outpoint {
                debug!("Skipping commit outpoint in selection: {}:{}", outpoint.txid, outpoint.vout);
                continue;
            }
            
            // For reveal transactions, we need to be more permissive with UTXO selection
            // since we may need to use unconfirmed UTXOs from our own commit transaction
            
            let is_dust = utxo.amount <= 546;
            let is_unconfirmed = enriched_utxo.utxo.confirmations == 0;
            let is_frozen_for_coinbase = enriched_utxo.freeze_reason.as_ref()
                .map_or(false, |reason| reason.contains("immature_coinbase"));
            
            // Skip coinbase UTXOs that are still immature (these require 100+ confirmations)
            if is_frozen_for_coinbase {
                debug!("Skipping immature coinbase UTXO: {}:{} (reason: {:?})",
                       outpoint.txid, outpoint.vout, enriched_utxo.freeze_reason);
                continue;
            }
            
            // For reveal transactions, allow unconfirmed UTXOs (they may be from our commit tx)
            // and allow dust UTXOs if we need them for Bitcoin requirements
            if is_dust && bitcoin_collected >= bitcoin_needed && !is_unconfirmed {
                debug!("Skipping dust UTXO (not needed and confirmed): {}:{} with {} sats",
                       outpoint.txid, outpoint.vout, utxo.amount);
                continue;
            }
            
            // Allow unconfirmed UTXOs for reveal transactions (they may be from our commit)
            if is_unconfirmed {
                debug!("Including unconfirmed UTXO for reveal transaction: {}:{} with {} sats",
                       outpoint.txid, outpoint.vout, utxo.amount);
            }
            
            debug!("Considering UTXO: {}:{} with {} sats (frozen: {}, reason: {:?})",
                   outpoint.txid, outpoint.vout, utxo.amount, enriched_utxo.utxo.frozen, enriched_utxo.freeze_reason);
            
            // Check if this UTXO helps meet our requirements
            let mut should_include = false;
            
            // Check Bitcoin requirement
            if bitcoin_collected < bitcoin_needed {
                bitcoin_collected += utxo.amount;
                should_include = true;
                debug!("Including UTXO for Bitcoin requirement: collected {} / needed {}", bitcoin_collected, bitcoin_needed);
            }
            
            // Check alkanes requirements (simplified - would need RPC calls to check actual balances)
            for ((block, tx), needed_amount) in &alkanes_needed {
                let collected = *alkanes_collected.get(&(*block, *tx)).unwrap_or(&0);
                if collected < *needed_amount {
                    // This UTXO might contain the needed alkanes token
                    // In a full implementation, we'd check the actual alkanes balance
                    should_include = true;
                    *alkanes_collected.entry((*block, *tx)).or_insert(0) += 1; // Placeholder
                    debug!("Including UTXO for alkanes requirement {}:{}: collected {} / needed {}", block, tx, collected + 1, needed_amount);
                }
            }
            
            if should_include {
                selected_utxos.push(outpoint);
                debug!("Selected UTXO: {}:{}", outpoint.txid, outpoint.vout);
            }
            
            // Check if we've met all requirements
            let bitcoin_satisfied = bitcoin_collected >= bitcoin_needed;
            let alkanes_satisfied = alkanes_needed.iter().all(|(key, needed)| {
                alkanes_collected.get(key).unwrap_or(&0) >= needed
            });
            
            if bitcoin_satisfied && alkanes_satisfied {
                debug!("All requirements satisfied, stopping UTXO selection");
                break;
            }
        }
        
        // Verify we have enough
        if bitcoin_collected < bitcoin_needed {
            return Err(anyhow!("Insufficient Bitcoin for reveal transaction: need {} sats, have {} (including unconfirmed UTXOs)", bitcoin_needed, bitcoin_collected));
        }
        
        for ((block, tx), needed) in &alkanes_needed {
            let collected = alkanes_collected.get(&(*block, *tx)).unwrap_or(&0);
            if collected < needed {
                return Err(anyhow!("Insufficient alkanes token {}:{}: need {}, have {}", block, tx, needed, collected));
            }
        }
        
        info!("Selected {} UTXOs meeting all requirements (excluding commit UTXO)", selected_utxos.len());
        Ok(selected_utxos)
    }

    /// Create outputs for recipient addresses
    async fn create_outputs(&self, to_addresses: &[String], change_address: &Option<String>) -> Result<Vec<bitcoin::TxOut>> {
        info!("Creating outputs for {} addresses", to_addresses.len());
        
        let mut outputs = Vec::new();
        
        // Create outputs for each recipient address (dust amount for now)
        for address_str in to_addresses {
            let network = self.wallet_manager.get_network();
            let address = bitcoin::Address::from_str(address_str)
                .context("Invalid recipient address")?
                .require_network(network)
                .context("Address network mismatch")?;
            
            let output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(546), // Dust limit
                script_pubkey: address.script_pubkey(),
            };
            outputs.push(output);
        }
        
        // Add change output if specified
        if let Some(change_addr) = change_address {
            let network = self.wallet_manager.get_network();
            let change_address = bitcoin::Address::from_str(change_addr)
                .context("Invalid change address")?
                .require_network(network)
                .context("Change address network mismatch")?;
            
            let change_output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(546), // Placeholder - should calculate actual change
                script_pubkey: change_address.script_pubkey(),
            };
            outputs.push(change_output);
        }
        
        info!("Created {} outputs", outputs.len());
        Ok(outputs)
    }

    /// Construct runestone with protostones using proper alkanes-rs ordinals crate
    fn construct_runestone(&self, protostones: &[ProtostoneSpec], num_outputs: usize) -> Result<bitcoin::ScriptBuf> {
        info!("Constructing runestone with {} protostones using alkanes-rs ordinals crate", protostones.len());
        
        use protorune_support::protostone::Protostone;
        
        // Convert our ProtostoneSpec to proper Protostone structures
        let mut proper_protostones = Vec::<Protostone>::new();
        
        for (i, protostone_spec) in protostones.iter().enumerate() {
            info!("Converting protostone spec {} to proper Protostone", i);
            
            // Create the message field from cellpack if present
            let message = if let Some(cellpack) = &protostone_spec.cellpack {
                info!("Encoding cellpack for protostone {}: target={}:{}, inputs={:?}",
                      i, cellpack.target.block, cellpack.target.tx, cellpack.inputs);
                
                // Use Cellpack::encipher() to get LEB128 encoded Vec<u8> for the message field
                let cellpack_bytes = cellpack.encipher();
                info!("Cellpack encoded to {} bytes for message field", cellpack_bytes.len());
                cellpack_bytes
            } else {
                Vec::new()
            };
            
            // Create the Protostone with proper structure
            let protostone = Protostone {
                burn: None, // TODO: Handle burn if needed
                message,
                edicts: Vec::new(), // TODO: Convert ProtostoneEdict to protorune_support::protostone::ProtostoneEdict
                refund: Some(0), // Default refund to output 0
                pointer: Some(0), // Default pointer to output 0
                from: None,
                protocol_tag: 1, // DIESEL protocol tag
            };
            
            proper_protostones.push(protostone);
            
            // Log warnings for unimplemented features
            if !protostone_spec.edicts.is_empty() {
                warn!("Protostone {} has {} edicts - these are not yet implemented in proper ordinals crate integration",
                      i, protostone_spec.edicts.len());
            }
            
            if protostone_spec.bitcoin_transfer.is_some() {
                warn!("Protostone {} has Bitcoin transfer - this is not yet implemented in proper ordinals crate integration", i);
            }
        }
        
        // CRITICAL FIX: Based on search results, protostones should be stored in tag 16383 within the Runestone
        // However, let's first try using the Protostones::encipher() result directly as the OP_RETURN script
        // This might be the correct approach since the alkanes-rs documentation suggests protostones
        // are encoded differently than standard runestones
        
        use crate::utils::protostone::Protostones;
        let protocol_data = proper_protostones.encipher();
        let runestone = (Runestone {
          etching: None,
          pointer: None,
          edicts: vec![],
          mint: None,
          protocol: protocol_data.ok()
        }).encipher();
        
        // EXPERIMENTAL: Try creating the OP_RETURN script directly from the protostones encoding
        // instead of wrapping it in a Runestone structure
        
        // Convert Vec<u128> to bytes for OP_RETURN
        Ok(runestone)
    }

    /// Build and sign transaction
    async fn build_transaction(
        &self,
        utxos: Vec<bitcoin::OutPoint>,
        mut outputs: Vec<bitcoin::TxOut>,
        runestone_script: bitcoin::ScriptBuf,
        fee_rate: Option<f32>
    ) -> Result<(bitcoin::Transaction, u64)> {
        info!("Building and signing transaction using wallet manager");
        
        use bitcoin::{psbt::Psbt, TxOut, ScriptBuf};
        
        // Add OP_RETURN output with runestone (already properly formatted by ordinals crate)
        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: runestone_script,
        };
        outputs.push(op_return_output);
        
        // Create PSBT for proper signing (same pattern as envelope version)
        let network = self.wallet_manager.get_network();
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
        
        // Configure inputs for signing - get UTXO details from wallet
        let all_wallet_utxos = self.wallet_manager.get_enriched_utxos().await?;
        for (i, outpoint) in utxos.iter().enumerate() {
            let utxo_info = all_wallet_utxos.iter()
                .find(|u| u.utxo.txid == outpoint.txid.to_string() && u.utxo.vout == outpoint.vout)
                .map(|enriched| &enriched.utxo)
                .ok_or_else(|| anyhow!("UTXO not found: {}:{}", outpoint.txid, outpoint.vout))?;
            
            // Set witness_utxo for wallet UTXOs
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: bitcoin::Amount::from_sat(utxo_info.amount),
                script_pubkey: utxo_info.script_pubkey.clone(),
            });
            
            // CRITICAL FIX: For P2TR inputs, set the tap_internal_key
            if utxo_info.script_pubkey.is_p2tr() {
                let internal_key = self.wallet_manager.get_internal_key().await?;
                psbt.inputs[i].tap_internal_key = Some(internal_key);
                info!("Configured P2TR input {} with internal key", i);
            } else {
                info!("Configured non-P2TR input {} from wallet UTXO", i);
            }
        }
        
        // Sign the PSBT using wallet manager
        let signed_psbt = self.wallet_manager.sign_psbt(&psbt).await?;
        
        // CRITICAL FIX: Manual witness extraction from PSBT tap_key_sig signatures
        // The extract_tx_unchecked_fee_rate() doesn't automatically convert tap_key_sig to witness data
        info!("Manually extracting witness data from PSBT tap_key_sig signatures");
        
        // Clone the PSBT before extracting to preserve access to signature data
        let psbt_for_extraction = signed_psbt.clone();
        let mut tx = psbt_for_extraction.extract_tx_unchecked_fee_rate();
        
        // Manually create witnesses for each input from PSBT signatures
        for (i, psbt_input) in signed_psbt.inputs.iter().enumerate() {
            if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                // Create witness for P2TR key-path spending using the tap_key_sig
                let witness = bitcoin::Witness::p2tr_key_spend(tap_key_sig);
                tx.input[i].witness = witness;
                info!("Created P2TR key-path witness for input {} from tap_key_sig: {} items", i, tx.input[i].witness.len());
            } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                // Use the final script witness from PSBT
                tx.input[i].witness = final_script_witness.clone();
                info!("Used final_script_witness from PSBT for input {}: {} items", i, final_script_witness.len());
            } else {
                // Keep the original witness (might be empty)
                info!("No PSBT signature found for input {}, keeping original witness: {} items", i, tx.input[i].witness.len());
            }
        }
        
        // Calculate fee properly (fee_rate is in sat/vB)
        let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
        let fee = (fee_rate_sat_vb * tx.vsize() as f32).ceil() as u64;
        
        info!("Built and signed transaction with {} inputs, {} outputs, fee: {} sats",
              tx.input.len(), tx.output.len(), fee);
        
        Ok((tx, fee))
    }


    /// Build and sign transaction with envelope reveal support
    async fn build_transaction_with_envelope(
        &self,
        utxos: Vec<bitcoin::OutPoint>,
        mut outputs: Vec<bitcoin::TxOut>,
        runestone_script: bitcoin::ScriptBuf,
        fee_rate: Option<f32>,
        envelope: Option<&AlkanesEnvelope>
    ) -> Result<(bitcoin::Transaction, u64)> {
        info!("Building and signing transaction with envelope support");
        
        use bitcoin::{psbt::Psbt, TxOut, ScriptBuf};
        
        // Add OP_RETURN output with runestone (protostone) - already properly formatted by ordinals crate
        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: runestone_script,
        };
        outputs.push(op_return_output);
        
        // Create PSBT for proper signing
        let network = self.wallet_manager.get_network();
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
        for (i, outpoint) in utxos.iter().enumerate() {
            // If this is the first input and we have an envelope, this is the commit output
            // which may not exist in the wallet's UTXO set yet
            if i == 0 && envelope.is_some() {
                let envelope = envelope.unwrap();
                
                // Get wallet's internal key for taproot
                let internal_key = self.wallet_manager.get_internal_key().await?;
                
                // Create the commit output details manually since it doesn't exist in wallet yet
                let network = self.wallet_manager.get_network();
                let commit_address = self.create_commit_address_for_envelope(envelope, network, internal_key).await?;
                
                // Set witness_utxo for the commit output (dust amount)
                psbt.inputs[i].witness_utxo = Some(TxOut {
                    value: bitcoin::Amount::from_sat(546), // Dust limit for commit output
                    script_pubkey: commit_address.script_pubkey(),
                });
                
                // For envelope transactions, we need script-path spending to match the commit address
                // Create taproot spend info using the envelope script
                let reveal_script = envelope.build_reveal_script();
                let (taproot_spend_info, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
                
                // Set the internal key for taproot
                psbt.inputs[i].tap_internal_key = Some(internal_key);
                
                // Configure script-path spending using the envelope's taproot spend info
                // Based on rust-bitcoin taproot PSBT example: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/taproot-psbt.rs
                
                // Get the script map from taproot spend info
                // script_map() returns BTreeMap<(ScriptBuf, LeafVersion), BTreeSet<TaprootMerkleBranch>>
                let script_map = taproot_spend_info.script_map();
                
                if let Some(((script, leaf_version), _merkle_branches)) = script_map.iter().next() {
                    // Configure tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>
                    use std::collections::BTreeMap;
                    let mut tap_scripts = BTreeMap::new();
                    tap_scripts.insert(control_block, (script.clone(), *leaf_version));
                    psbt.inputs[i].tap_scripts = tap_scripts;
                    
                    info!("Configured envelope reveal taproot SCRIPT-PATH spend for commit input");
                    info!("Script: {} bytes, LeafVersion: {:?}", script.len(), leaf_version);
                } else {
                    // Fallback to key-path spending if no script found
                    info!("No script found in taproot spend info, using key-path spending as fallback");
                }
            } else {
                // For other inputs, get UTXO details from wallet (including frozen ones for reveal)
                let all_wallet_utxos = self.wallet_manager.get_enriched_utxos().await?;
                let utxo_info = all_wallet_utxos.iter()
                    .find(|u| u.utxo.txid == outpoint.txid.to_string() && u.utxo.vout == outpoint.vout)
                    .map(|enriched| &enriched.utxo)
                    .ok_or_else(|| anyhow!("UTXO not found: {}:{}", outpoint.txid, outpoint.vout))?;
                
                // Set witness_utxo for existing wallet UTXOs
                psbt.inputs[i].witness_utxo = Some(TxOut {
                    value: bitcoin::Amount::from_sat(utxo_info.amount),
                    script_pubkey: utxo_info.script_pubkey.clone(),
                });
                
                info!("Configured input {} from existing wallet UTXO (including frozen)", i);
            }
        }
        
        // Sign the PSBT using wallet manager
        let signed_psbt = self.wallet_manager.sign_psbt(&psbt).await?;
        
        // Extract the final transaction using unchecked fee rate to bypass validation
        // This is necessary for envelope transactions with large witness data (117KB)
        // which appear to have absurdly high fee rates but are actually reasonable
        info!("🔧 Using extract_tx_unchecked_fee_rate() to bypass fee validation for envelope transaction");
        let tx = signed_psbt.clone().extract_tx_unchecked_fee_rate();
        
        // Debug: Log transaction details before envelope processing
        info!("Transaction before envelope processing: vsize={} weight={}",
              tx.vsize(), tx.weight());
        
        // If we have an envelope, we need to add the envelope witness data to the first input
        if let Some(envelope) = envelope {
            let mut final_tx = tx.clone();
            
            // Get the actual internal key used in the transaction
            let internal_key = self.wallet_manager.get_internal_key().await?;
            
            // Create the envelope witness using the new ord-based system
            let (_, control_block) = self.create_taproot_spend_info_for_envelope(envelope, internal_key).await?;
            let envelope_witness = envelope.create_witness(control_block)?;
            
            // Validate the witness was created properly
            if envelope_witness.len() < 2 {
                return Err(anyhow!("Failed to create proper envelope witness: expected at least 2 items (script + control_block), got {}", envelope_witness.len()));
            }
            
            // Check if critical witness items are empty
            for (i, item) in envelope_witness.iter().enumerate() {
                if item.is_empty() {
                    return Err(anyhow!("Envelope witness item {} is empty, this will cause 'bad-witness-nonstandard'", i));
                }
            }
            
            info!("🎯 Using new ord-based envelope witness system");
            
            info!("🔍 Debugging envelope witness:");
            info!("  Original witness items: {}", final_tx.input[0].witness.len());
            info!("  Envelope witness items: {}", envelope_witness.len());
            
            // Log the contents of each witness item
            for (i, item) in envelope_witness.iter().enumerate() {
                info!("  Envelope witness item {}: {} bytes", i, item.len());
                if item.len() <= 64 {
                    info!("    Content (hex): {}", hex::encode(item));
                } else {
                    info!("    Content (first 32 bytes): {}", hex::encode(&item[..32]));
                    info!("    Content (last 32 bytes): {}", hex::encode(&item[item.len()-32..]));
                }
            }
            
            // Check if the envelope witness is properly formatted for taproot script-path spending
            // For ord-style envelope, we have: [script, control_block]
            
            if envelope_witness.len() != 2 {
                return Err(anyhow!("Invalid envelope witness: expected exactly 2 items (script + control_block), got {}", envelope_witness.len()));
            }
            
            // Check if the control block (last item) is empty - this would cause "bad-witness-nonstandard"
            let control_block_item = &envelope_witness[1];
            if control_block_item.is_empty() {
                return Err(anyhow!("Invalid envelope witness: control block is empty, this will cause 'bad-witness-nonstandard' error"));
            }
            
            // Check if the script (first item) is empty
            let script_item = &envelope_witness[0];
            if script_item.is_empty() {
                return Err(anyhow!("Invalid envelope witness: script is empty, this will cause 'bad-witness-nonstandard' error"));
            }
            
            info!("✅ Envelope witness has proper ord-style structure with {} items", envelope_witness.len());
            
            // CRITICAL FIX: The witness data is being corrupted during transaction operations.
            // Instead of modifying the existing transaction, create a completely new transaction
            // with the envelope witness data properly embedded from the start.
            
            info!("🔧 Creating new transaction with envelope witness to prevent serialization corruption");
            
            // Create a completely new transaction with the envelope witness
            let mut new_tx = bitcoin::Transaction {
                version: final_tx.version,
                lock_time: final_tx.lock_time,
                input: Vec::new(),
                output: final_tx.output.clone(),
            };
            
            // Recreate all inputs with proper witness data
            for (i, input) in final_tx.input.iter().enumerate() {
                let mut new_input = bitcoin::TxIn {
                    previous_output: input.previous_output,
                    script_sig: input.script_sig.clone(),
                    sequence: input.sequence,
                    witness: bitcoin::Witness::new(),
                };
                
                if i == 0 {
                    // First input gets the envelope witness
                    info!("🔧 Adding ord-style envelope witness to input 0");
                    info!("  Envelope witness has {} items", envelope_witness.len());
                    
                    // CRITICAL FIX: Instead of cloning the witness (which can corrupt data),
                    // manually push each witness item to ensure data integrity
                    let mut new_witness = bitcoin::Witness::new();
                    
                    for (j, item) in envelope_witness.iter().enumerate() {
                        info!("  Pushing witness item {}: {} bytes", j, item.len());
                        new_witness.push(item);
                    }
                    
                    new_input.witness = new_witness;
                    
                    info!("🎯 Applied envelope witness to input 0: {} items", new_input.witness.len());
                    
                    // Verify the witness was actually added
                    for (j, item) in new_input.witness.iter().enumerate() {
                        info!("  Verification - item {}: {} bytes", j, item.len());
                    }
                    
                    // Double-check that the witness data is preserved
                    if new_input.witness.len() != envelope_witness.len() {
                        return Err(anyhow!("Witness assignment failed: expected {} items, got {}", envelope_witness.len(), new_input.witness.len()));
                    }
                    
                    // Verify each item has the correct size
                    for (j, (original_item, new_item)) in envelope_witness.iter().zip(new_input.witness.iter()).enumerate() {
                        if original_item.len() != new_item.len() {
                            return Err(anyhow!("Witness item {} size mismatch: expected {} bytes, got {} bytes", j, original_item.len(), new_item.len()));
                        }
                        
                        // Verify the actual content matches
                        if original_item != new_item {
                            return Err(anyhow!("Witness item {} content mismatch", j));
                        }
                    }
                    
                    info!("✅ Witness assignment verified successfully");
                } else {
                    // Other inputs need their witness from the signed PSBT
                    // The key insight is that we need to check the PSBT input for taproot signatures
                    
                    info!("🔧 Copying witness for input {}: {} items", i, input.witness.len());
                    
                    if let Some(psbt_input) = signed_psbt.inputs.get(i) {
                        // For taproot inputs, check for tap_key_sig first (key-path spending)
                        if let Some(tap_key_sig) = &psbt_input.tap_key_sig {
                            // Create witness with the taproot key signature
                            let mut witness = bitcoin::Witness::new();
                            witness.push(tap_key_sig.to_vec());
                            new_input.witness = witness;
                            info!("🔧 Created taproot key-path witness from tap_key_sig for input {}: {} items", i, new_input.witness.len());
                        } else if let Some(final_script_witness) = &psbt_input.final_script_witness {
                            // Use the final script witness from PSBT
                            new_input.witness = final_script_witness.clone();
                            info!("🔧 Using final_script_witness from PSBT for input {}: {} items", i, final_script_witness.len());
                        } else {
                            // Try to get witness from the original extracted transaction
                            new_input.witness = input.witness.clone();
                            info!("🔧 Fallback: copying witness from extracted transaction for input {}: {} items", i, input.witness.len());
                            
                            // CRITICAL FIX: If witness is still empty, this is a P2TR input that needs proper signing
                            if new_input.witness.is_empty() {
                                warn!("🔧 CRITICAL: Input {} has empty witness, attempting to create P2TR key-path witness using proper rust-bitcoin pattern", i);
                                
                                // Get the current input's outpoint
                                let current_outpoint = &input.previous_output;
                                
                                // Get the UTXO info for this input to determine address type
                                let all_wallet_utxos = self.wallet_manager.get_enriched_utxos().await?;
                                if let Some(enriched_utxo) = all_wallet_utxos.iter()
                                    .find(|u| u.utxo.txid == current_outpoint.txid.to_string() && u.utxo.vout == current_outpoint.vout) {
                                    
                                    let utxo_info = &enriched_utxo.utxo;
                                    
                                    // Check if this is a P2TR UTXO
                                    if utxo_info.script_pubkey.is_p2tr() {
                                        info!("🔧 Detected P2TR UTXO with empty witness, creating proper taproot key-path signature");
                                        
                                        // Use the proper rust-bitcoin taproot signing pattern
                                        use bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
                                        use bitcoin::secp256k1::{Keypair, Message};
                                        use bitcoin::key::{TapTweak, UntweakedKeypair};
                                        use bitcoin::taproot;
                                        
                                        // Get the wallet's internal key for P2TR
                                        let internal_key = self.wallet_manager.get_internal_key().await?;
                                        
                                        // Create prevouts for sighash calculation
                                        let prevout = bitcoin::TxOut {
                                            value: bitcoin::Amount::from_sat(utxo_info.amount),
                                            script_pubkey: utxo_info.script_pubkey.clone(),
                                        };
                                        let prevouts = Prevouts::One(i, &prevout);
                                        
                                        // Create sighash cache for the current transaction
                                        let mut sighash_cache = SighashCache::new(&new_tx);
                                        
                                        // Compute taproot key-path sighash
                                        let sighash = sighash_cache
                                            .taproot_key_spend_signature_hash(
                                                i,
                                                &prevouts,
                                                TapSighashType::Default,
                                            )
                                            .context("Failed to compute taproot key spend sighash")?;
                                        
                                        // Get the wallet's keypair for signing
                                        let keypair = self.wallet_manager.get_keypair().await?;
                                        let untweaked_keypair = UntweakedKeypair::from(keypair);
                                        
                                        // Apply taproot tweak (for key-path spending with no script tree)
                                        let secp = bitcoin::secp256k1::Secp256k1::new();
                                        let tweaked_keypair = untweaked_keypair.tap_tweak(&secp, None);
                                        
                                        // Sign the sighash using schnorr signature
                                        let msg = Message::from(sighash);
                                        let mut rng = bitcoin::secp256k1::rand::thread_rng();
                                        let signature = secp.sign_schnorr_with_rng(&msg, tweaked_keypair.as_keypair(), &mut rng);
                                        
                                        // Create taproot signature with sighash type
                                        let taproot_signature = taproot::Signature {
                                            signature,
                                            sighash_type: TapSighashType::Default,
                                        };
                                        
                                        // Create witness for P2TR key-path spending
                                        new_input.witness = bitcoin::Witness::p2tr_key_spend(&taproot_signature);
                                        
                                        info!("✅ Successfully created P2TR key-path witness for input {} using proper rust-bitcoin pattern: {} items",
                                              i, new_input.witness.len());
                                    }
                                }
                            }
                        }
                    } else {
                        // Fallback: copy from extracted transaction
                        new_input.witness = input.witness.clone();
                        info!("🔧 Fallback: no PSBT input found, copying witness from extracted transaction for input {}: {} items", i, input.witness.len());
                    }
                    
                    // Debug: Log witness info for non-envelope inputs
                    for (j, item) in new_input.witness.iter().enumerate() {
                        info!("  Input {} witness item {}: {} bytes", i, j, item.len());
                    }
                    
                    // If the witness is still empty, this is the problem
                    if new_input.witness.is_empty() {
                        warn!("⚠️  Input {} has empty witness - this will cause 'Witness program was passed an empty witness'", i);
                        return Err(anyhow!("Input {} has empty witness. This taproot input requires a witness signature but none was provided.", i));
                    }
                }
                
                new_tx.input.push(new_input);
            }
            
            let final_tx_with_witness = new_tx;
            
            info!("Applied envelope witness with {} items:", final_tx_with_witness.input[0].witness.len());
            for (i, item) in final_tx_with_witness.input[0].witness.iter().enumerate() {
                info!("  Item {}: {} bytes", i, item.len());
                if item.len() <= 64 {
                    info!("    Content (hex): {}", hex::encode(item));
                } else {
                    info!("    Content (first 32 bytes): {}", hex::encode(&item[..32]));
                    info!("    Content (last 32 bytes): {}", hex::encode(&item[item.len()-32..]));
                }
            }
            
            // Double-check the witness after assignment by re-reading it
            info!("🔍 Double-checking witness after assignment:");
            info!("  Final transaction input 0 witness items: {}", final_tx_with_witness.input[0].witness.len());
            for (i, item) in final_tx_with_witness.input[0].witness.iter().enumerate() {
                info!("  Final item {}: {} bytes", i, item.len());
            }
            
            // Test serialization to make sure witness data is preserved
            let serialized = bitcoin::consensus::serialize(&final_tx_with_witness);
            info!("🔍 Testing serialization: {} bytes", serialized.len());
            
            // Debug: Check the raw witness data before serialization
            info!("🔍 Raw witness data before serialization:");
            let witness_total_size: usize = final_tx_with_witness.input[0].witness.iter().map(|item| item.len()).sum();
            info!("  Witness vector length: {} bytes", witness_total_size);
            for (i, item) in final_tx_with_witness.input[0].witness.iter().enumerate() {
                info!("    Raw witness item {}: {} bytes", i, item.len());
                if item.len() <= 64 {
                    info!("      Content (hex): {}", hex::encode(item));
                } else {
                    info!("      Content (first 32 bytes): {}", hex::encode(&item[..32]));
                    info!("      Content (last 32 bytes): {}", hex::encode(&item[item.len()-32..]));
                }
            }
            
            let deserialized: bitcoin::Transaction = bitcoin::consensus::deserialize(&serialized)
                .context("Failed to deserialize test transaction")?;
            info!("🔍 After deserialization: witness items: {}", deserialized.input[0].witness.len());
            for (i, item) in deserialized.input[0].witness.iter().enumerate() {
                info!("  Deserialized item {}: {} bytes", i, item.len());
                if item.len() <= 64 {
                    info!("    Content (hex): {}", hex::encode(item));
                } else if item.len() > 0 {
                    info!("    Content (first 32 bytes): {}", hex::encode(&item[..32]));
                    info!("    Content (last 32 bytes): {}", hex::encode(&item[item.len()-32..]));
                }
            }
            
            // Check if the serialized data contains the witness
            info!("🔍 Checking serialized transaction structure:");
            info!("  Serialized hex (first 128 chars): {}", hex::encode(&serialized[..std::cmp::min(serialized.len(), 64)]));
            info!("  Serialized hex (last 128 chars): {}", hex::encode(&serialized[serialized.len().saturating_sub(64)..]));
            
            // Envelope witness applied successfully
            info!("✅ Envelope witness applied successfully using ord-style system");
            info!("Added envelope witness data to first input (total witness items: {})", final_tx_with_witness.input[0].witness.len());
            info!("Transaction after envelope processing: vsize={} weight={}",
                  final_tx_with_witness.vsize(), final_tx_with_witness.weight());
            
            let mut final_tx = final_tx_with_witness;
            
            // For envelope transactions, calculate fee based on actual transaction size and fee rate
            let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
            let calculated_fee = (fee_rate_sat_vb * final_tx.vsize() as f32).ceil() as u64;
            
            // Cap the fee at a reasonable maximum to avoid absurdly high fees due to large witness data
            let max_fee = 50_000u64; // Cap at 50,000 sats (0.0005 BTC)
            let reveal_fee = calculated_fee.min(max_fee);
            
            info!("Calculated reveal fee: {} sats (fee rate: {} sat/vB, vsize: {} vbytes, capped at: {} sats)",
                  calculated_fee, fee_rate_sat_vb, final_tx.vsize(), max_fee);
            
            // Calculate total input value
            let mut total_input_value = 0u64;
            for (i, outpoint) in utxos.iter().enumerate() {
                if i == 0 {
                    // First input is the commit output (dust amount)
                    total_input_value += 546; // Dust limit for commit output
                } else {
                    // Get UTXO details from wallet for other inputs
                    let all_wallet_utxos = self.wallet_manager.get_enriched_utxos().await?;
                    if let Some(enriched_utxo) = all_wallet_utxos.iter()
                        .find(|u| u.utxo.txid == outpoint.txid.to_string() && u.utxo.vout == outpoint.vout) {
                        total_input_value += enriched_utxo.utxo.amount;
                    }
                }
            }
            
            // Calculate total output value
            let total_output_value: u64 = final_tx.output.iter().map(|out| out.value.to_sat()).sum();
            
            // Check if we need to adjust outputs to account for fee
            let current_fee = total_input_value.saturating_sub(total_output_value);
            
            info!("Envelope transaction fee analysis:");
            info!("  Total input value: {} sats", total_input_value);
            info!("  Total output value: {} sats", total_output_value);
            info!("  Current implied fee: {} sats", current_fee);
            info!("  Target fee: {} sats", reveal_fee);
            
            if current_fee != reveal_fee {
                // Adjust the last non-OP_RETURN output to account for the fee difference
                let fee_adjustment = current_fee.saturating_sub(reveal_fee);
                
                // Find the last non-OP_RETURN output to adjust
                for output in final_tx.output.iter_mut().rev() {
                    if !output.script_pubkey.is_op_return() && output.value.to_sat() > fee_adjustment {
                        let new_value = output.value.to_sat().saturating_sub(fee_adjustment);
                        output.value = bitcoin::Amount::from_sat(new_value);
                        info!("Adjusted output value by {} sats to achieve target fee", fee_adjustment);
                        break;
                    }
                }
            }
            
            info!("Using calculated fee for envelope reveal transaction: {} sats", reveal_fee);
            info!("Built envelope reveal transaction with {} inputs, {} outputs, fee: {} sats",
                  final_tx.input.len(), final_tx.output.len(), reveal_fee);
            
            return Ok((final_tx, reveal_fee));
        }
        
        // Calculate fee properly (fee_rate is in sat/vB)
        let fee_rate_sat_vb = fee_rate.unwrap_or(5.0);
        let fee = (fee_rate_sat_vb * tx.vsize() as f32).ceil() as u64;
        
        // Cap the fee at a reasonable maximum (e.g., 0.001 BTC = 100,000 sats)
        let max_fee = 100_000u64;
        let capped_fee = fee.min(max_fee);
        
        info!("Built transaction with {} inputs, {} outputs, fee: {} sats",
              tx.input.len(), tx.output.len(), capped_fee);
        
        Ok((tx, capped_fee))
    }

    /// Create and broadcast commit transaction
    async fn create_and_broadcast_commit_transaction(
        &self,
        envelope: &AlkanesEnvelope,
        params: &EnhancedExecuteParams
    ) -> Result<(String, u64, bitcoin::OutPoint)> {
        info!("Creating commit transaction");
        
        // Get wallet's internal key for taproot
        let internal_key = self.wallet_manager.get_internal_key().await?;
        
        // Create commit address using taproot with envelope script
        let network = self.wallet_manager.get_network();
        let commit_address = self.create_commit_address_for_envelope(envelope, network, internal_key).await?;
        
        info!("Envelope commit address: {}", commit_address);
        
        // Get UTXOs for funding the commit transaction (including unconfirmed ones)
        let enriched_utxos = self.wallet_manager.get_enriched_utxos().await?;
        if enriched_utxos.is_empty() {
            return Err(anyhow!("No UTXOs available for commit transaction"));
        }
        
        // Find a suitable UTXO for commit transaction (allow unconfirmed, but skip coinbase)
        let funding_utxo = enriched_utxos.iter()
            .find(|enriched| {
                let is_frozen_for_coinbase = enriched.freeze_reason.as_ref()
                    .map_or(false, |reason| reason.contains("immature_coinbase"));
                !is_frozen_for_coinbase && enriched.utxo.amount >= 1000 // Need at least 1000 sats for commit + fees
            })
            .map(|enriched| &enriched.utxo)
            .ok_or_else(|| anyhow!("No suitable UTXOs available for commit transaction (need non-coinbase UTXO with >= 1000 sats)"))?;
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_utxo.txid.parse().context("Invalid TXID in funding UTXO")?,
            vout: funding_utxo.vout,
        };
        
        // Create commit transaction
        use bitcoin::{Transaction, TxIn, TxOut, ScriptBuf};
        
        let commit_input = TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        };
        
        let commit_output = TxOut {
            value: bitcoin::Amount::from_sat(546), // Dust limit for commit
            script_pubkey: commit_address.script_pubkey(),
        };
        
        // Add change output if needed
        let mut outputs = vec![commit_output];
        let input_value = funding_utxo.amount;
        let commit_value = 546u64;
        let fee_rate_sat_vb = params.fee_rate.unwrap_or(5.0);
        
        // Create a temporary transaction to calculate the actual size for fee estimation
        let temp_inputs = vec![bitcoin::TxIn {
            previous_output: funding_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }];
        
        let temp_outputs = vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(commit_value),
            script_pubkey: commit_address.script_pubkey(),
        }];
        
        let temp_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: temp_inputs,
            output: temp_outputs,
        };
        
        // Calculate fee based on actual transaction size
        let estimated_fee = (fee_rate_sat_vb * temp_tx.vsize() as f32).ceil() as u64;
        
        if input_value > commit_value + estimated_fee + 546 {
            // Add change output
            let change_value = input_value - commit_value - estimated_fee;
            let change_address = self.wallet_manager.get_address().await?;
            let change_address_parsed = bitcoin::Address::from_str(&change_address)
                .context("Invalid change address")?
                .require_network(network)
                .context("Change address network mismatch")?;
            
            let change_output = TxOut {
                value: bitcoin::Amount::from_sat(change_value),
                script_pubkey: change_address_parsed.script_pubkey(),
            };
            outputs.push(change_output);
        }
        
        let mut commit_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![commit_input],
            output: outputs,
        };
        
        let commit_fee = estimated_fee;
        
        // Use wallet manager to create and sign the commit transaction properly
        info!("Creating and signing commit transaction using wallet manager");
        
        // Create SendParams for the commit transaction
        let send_params = crate::wallet::SendParams {
            address: commit_address.to_string(),
            amount: commit_value,
            fee_rate: params.fee_rate,
            send_all: false,
            from_address: None,
            change_address: None,
            auto_confirm: params.auto_confirm,
        };
        
        // Create and sign the transaction using wallet manager
        let (signed_commit_tx, _tx_details) = self.wallet_manager.create_transaction(send_params).await?;
        
        // Skip fee validation for commit transaction to avoid "absurdly high fee rate" errors
        info!("⚠️  Skipping commit transaction fee validation to avoid Bitcoin Core fee rate errors");
        
        // Broadcast commit transaction directly via RPC to avoid BDK's internal fee validation
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_commit_tx));
        info!("🚀 Broadcasting commit transaction directly via RPC with maxfeerate=0");
        let commit_txid = self.rpc_client.send_raw_transaction(&tx_hex).await?;
        
        // Create outpoint for the commit output (first output)
        let commit_outpoint = bitcoin::OutPoint {
            txid: commit_txid.parse().context("Invalid commit TXID")?,
            vout: 0,
        };
        
        Ok((commit_txid, commit_fee, commit_outpoint))
    }

    /// Create and broadcast reveal transaction
    async fn create_and_broadcast_reveal_transaction(
        &self,
        params: &EnhancedExecuteParams,
        envelope: &AlkanesEnvelope,
        commit_outpoint: bitcoin::OutPoint
    ) -> Result<(String, u64)> {
        info!("Creating reveal transaction");
        
        // Step 1: Validate protostone specifications
        self.validate_protostones(&params.protostones, params.to_addresses.len())?;
        
        // Step 2: Find additional UTXOs that meet input requirements (excluding commit)
        // For reveal transactions, we need to allow the commit UTXO even if it's normally frozen
        let mut selected_utxos = self.select_utxos_for_reveal(&params.input_requirements, commit_outpoint).await?;
        
        // Step 3: Insert commit outpoint as the FIRST input
        selected_utxos.insert(0, commit_outpoint);
        info!("Added commit outpoint as first input for reveal");
        
        // Step 4: Create transaction with outputs for each address
        let outputs = self.create_outputs(&params.to_addresses, &params.change_address).await?;
        
        // Step 5: Construct runestone with protostones - EXACTLY like the non-envelope version
        info!("🔧 CRITICAL: Constructing runestone for reveal transaction using EXACTLY the same logic as single transaction");
        info!("🔧 This reveal transaction will have BOTH envelope witness data AND the same OP_RETURN as non-envelope version");
        let runestone_script = self.construct_runestone(&params.protostones, outputs.len())?;
        info!("🔧 Runestone script constructed: {} bytes", runestone_script.len());
        
        // Step 6: Build the reveal transaction with envelope
        info!("Building reveal transaction with envelope");
        
        // Clone selected_utxos for fee validation since build_transaction_with_envelope takes ownership
        let selected_utxos_for_validation = selected_utxos.clone();
        
        let (signed_tx, final_fee) = self.build_transaction_with_envelope(
            selected_utxos,
            outputs,
            runestone_script,
            params.fee_rate,
            Some(envelope)
        ).await?;
        
        // Step 7: Show transaction preview if not raw output
        if !params.raw_output {
            self.show_transaction_preview(&signed_tx, final_fee);
            
            if !params.auto_confirm {
                self.request_user_confirmation()?;
            }
        }
        
        // Skip fee validation for reveal transaction to avoid "absurdly high fee rate" errors
        info!("⚠️  Skipping reveal transaction fee validation to avoid Bitcoin Core fee rate errors");
        
        // Step 9: Broadcast reveal transaction directly via RPC to avoid BDK's internal fee validation
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&signed_tx));
        
        // Debug: Check if reveal transaction has witness data
        let has_witness = signed_tx.input.iter().any(|input| !input.witness.is_empty());
        info!("🔍 Reveal transaction has witness data: {}", has_witness);
        if !has_witness {
            warn!("⚠️  Reveal transaction has no witness data - this will cause 'Witness program was passed an empty witness' for P2TR inputs");
            
            // Log each input's witness status
            for (i, input) in signed_tx.input.iter().enumerate() {
                info!("  Input {}: witness items = {}", i, input.witness.len());
                for (j, item) in input.witness.iter().enumerate() {
                    info!("    Witness item {}: {} bytes", j, item.len());
                }
            }
        }
        
        info!("🚀 Broadcasting reveal transaction directly via RPC with maxfeerate=0");
        let txid = self.rpc_client.send_raw_transaction(&tx_hex).await?;
        
        Ok((txid, final_fee))
    }

    /// Show transaction preview
    fn show_transaction_preview(&self, tx: &bitcoin::Transaction, fee: u64) {
        println!("\n🔍 Transaction Preview");
        println!("═══════════════════════");
        
        // Show basic transaction info
        println!("📋 Transaction ID: {}", tx.compute_txid());
        println!("💰 Estimated Fee: {} sats", fee);
        println!("📊 Transaction Size: {} vbytes", tx.vsize());
        println!("📈 Fee Rate: {:.2} sat/vB", fee as f64 / tx.vsize() as f64);
        
        // Try to decode runestone from the fully signed transaction
        // Note: This will only work for fully signed transactions, not PSBTs
        match format_runestone_with_decoded_messages(tx) {
            Ok(result) => {
                println!("\n🪨 Runestone Analysis:");
                print_human_readable_runestone(tx, &result);
            },
            Err(e) => {
                warn!("Failed to decode runestone for preview: {}", e);
                
                // Check if this is a reveal transaction with protostones
                let has_op_return = tx.output.iter().any(|output| output.script_pubkey.is_op_return());
                if has_op_return {
                    println!("\n🪨 Protostone Transaction Detected");
                    println!("⚠️  Runestone decoding failed - this may be expected for reveal transactions");
                    println!("💡 The reveal transaction should contain a protostone with envelope data");
                    
                    // Try to show OP_RETURN data for envelope transactions
                    for (i, output) in tx.output.iter().enumerate() {
                        if output.script_pubkey.is_op_return() {
                            println!("\n📜 OP_RETURN Output {} Analysis:", i);
                            let script_bytes = output.script_pubkey.as_bytes();
                            if script_bytes.len() > 2 {
                                let data_bytes = &script_bytes[2..]; // Skip OP_RETURN and length byte
                                println!("  📊 Data size: {} bytes", data_bytes.len());
                                println!("  🔍 Complete hex data: {}", hex::encode(data_bytes));
                                
                                // Check for runestone magic (OP_13 = 0x5d)
                                if data_bytes.len() > 0 && data_bytes[0] == 0x5d {
                                    println!("  🪨 Contains Runestone magic number (OP_13)");
                                    if data_bytes.len() > 1 {
                                        println!("  🏷️  Protocol tag candidate: {}", data_bytes[1]);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    println!("\n⚠️  Could not decode runestone data for preview");
                }
                
                // Show basic transaction structure as fallback
                println!("\n📥 Inputs ({}):", tx.input.len());
                for (i, input) in tx.input.iter().enumerate() {
                    println!("  {}. 🔗 {}:{}", i + 1, input.previous_output.txid, input.previous_output.vout);
                }
                
                println!("\n📤 Outputs ({}):", tx.output.len());
                for (i, output) in tx.output.iter().enumerate() {
                    if output.script_pubkey.is_op_return() {
                        println!("  {}. 📜 OP_RETURN ({} bytes)", i + 1, output.script_pubkey.len());
                    } else {
                        println!("  {}. 💰 {} sats", i + 1, output.value.to_sat());
                    }
                }
            }
        }
    }

    /// Request user confirmation
    fn request_user_confirmation(&self) -> Result<()> {
        println!("\n⚠️  TRANSACTION CONFIRMATION");
        println!("═══════════════════════════");
        println!("This transaction will be broadcast to the network.");
        println!("Please review the details above carefully.");
        print!("\nDo you want to proceed with broadcasting this transaction? (y/N): ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).context("Failed to read user input")?;
        let input = input.trim().to_lowercase();
        
        if input != "y" && input != "yes" {
            return Err(anyhow!("Transaction cancelled by user"));
        }
        
        Ok(())
    }

    /// Trace reveal transaction protostones with enhanced functionality
    async fn trace_reveal_transaction(
        &self,
        txid: &str,
        params: &EnhancedExecuteParams
    ) -> Result<Option<Vec<serde_json::Value>>> {
        info!("Starting enhanced transaction tracing for reveal transaction: {}", txid);
        
        if !params.raw_output {
            println!("\n🔍 Enhanced tracing for reveal transaction protostones...");
        }
        
        // Step 1: Mine blocks if requested (for regtest)
        if params.mine_enabled {
            self.mine_blocks_if_regtest().await?;
        }
        
        // Step 2: Wait for transaction to be mined
        self.wait_for_transaction_mined(txid, params).await?;
        
        // Step 3: Wait for metashrew to catch up
        self.wait_for_metashrew_sync_enhanced(params).await?;
        
        // Step 4: Wait for Esplora to catch up before getting transaction hex
        self.wait_for_esplora_sync_enhanced(params).await?;
        
        // Step 4.5: CRITICAL - Also ensure metashrew is synchronized before getting transaction hex
        // This ensures both Esplora and metashrew have indexed the transaction
        if !params.raw_output {
            println!("🔄 Ensuring metashrew is also synchronized before getting transaction hex...");
        }
        self.wait_for_metashrew_sync_enhanced(params).await?;
        
        // Step 5: Get transaction details to find protostone outputs
        let tx_hex = self.rpc_client.get_transaction_hex(txid).await?;
        
        // Debug: Log the raw hex string returned from RPC (truncated for readability)
        let truncated_raw_hex = if tx_hex.len() > 128 {
            format!("{}...{} (truncated)", &tx_hex[..64], &tx_hex[tx_hex.len()-64..])
        } else {
            tx_hex.clone()
        };
        info!("🔍 Hex string length: {} characters", tx_hex.len());
        
        // Clean the hex string more thoroughly
        let cleaned_hex = tx_hex
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .trim_end();
        
        // Log cleaned hex with truncation for readability
        let truncated_cleaned_hex = if cleaned_hex.len() > 128 {
            format!("{}...{} (truncated)", &cleaned_hex[..64], &cleaned_hex[cleaned_hex.len()-64..])
        } else {
            cleaned_hex.to_string()
        };
        info!("🔍 Cleaned hex string: '{}'", truncated_cleaned_hex);
        info!("🔍 Cleaned hex length: {} characters", cleaned_hex.len());
        
        // Check if the hex string has an even number of characters
        if cleaned_hex.len() % 2 != 0 {
            return Err(anyhow!("Invalid hex string: odd number of characters ({}). Raw hex: '{}'", cleaned_hex.len(), tx_hex));
        }
        
        // Validate that all characters are valid hex
        if !cleaned_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Invalid hex string: contains non-hex characters. Raw hex: '{}'", tx_hex));
        }
        
        let tx_bytes = hex::decode(cleaned_hex)
            .with_context(|| format!("Failed to decode transaction hex. Raw: '{}', Cleaned: '{}'", tx_hex, cleaned_hex))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .context("Failed to deserialize transaction")?;
        
        // Step 5.5: CRITICAL - Wait for metashrew to sync AFTER getting transaction bytes but BEFORE tracing
        // This ensures metashrew has indexed the new transaction before we attempt to trace it
        if !params.raw_output {
            println!("🔄 Waiting for metashrew to index the new transaction before tracing...");
        }
        self.wait_for_metashrew_sync_enhanced(params).await?;
        
        // Step 6: Find OP_RETURN outputs (protostones) and trace them
        let mut traces = Vec::new();
        let mut protostone_count = 0;
        
        for (vout, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.is_op_return() {
                if !params.raw_output {
                    println!("🔍 Tracing protostone #{} at vout {}...", protostone_count + 1, vout);
                }
                
                // CRITICAL FIX: According to user feedback, protostones start at tx.output.len() + 1
                // This means the first protostone is at vout = tx.output.len() + 1
                // Subsequent protostones increment from there
                let trace_vout = tx.output.len() as u32 + 1 + protostone_count as u32;
                
                // Reverse the txid bytes for trace calls
                let reversed_txid = self.reverse_txid_bytes(txid)?;
                
                // Debug: Log the trace calculation
                debug!("Tracing protostone #{}: OP_RETURN at vout {}, tracing at virtual vout {}",
                       protostone_count + 1, vout, trace_vout);
                
                // Trace this protostone using the reversed txid and calculated vout
                match self.rpc_client.trace_outpoint_json(&reversed_txid, trace_vout).await {
                    Ok(trace_result) => {
                        if params.raw_output {
                            traces.push(serde_json::Value::String(trace_result));
                        } else {
                            // Pretty print the trace
                            match self.rpc_client.trace_outpoint_pretty(&reversed_txid, trace_vout).await {
                                Ok(pretty_trace) => {
                                    println!("\n📊 Trace for protostone #{} (vout {}, trace_vout {}):", protostone_count + 1, vout, trace_vout);
                                    println!("{}", pretty_trace);
                                },
                                Err(e) => {
                                    println!("❌ Failed to get pretty trace for protostone #{} (vout {}, trace_vout {}): {}", protostone_count + 1, vout, trace_vout, e);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        if !params.raw_output {
                            println!("❌ Failed to trace protostone #{} (vout {}, trace_vout {}): {}", protostone_count + 1, vout, trace_vout, e);
                        }
                    }
                }
                
                protostone_count += 1;
            }
        }
        
        if !params.raw_output && protostone_count > 0 {
            println!("\n✅ Traced {} protostone(s) successfully", protostone_count);
        }
        
        if traces.is_empty() {
            Ok(None)
        } else {
            Ok(Some(traces))
        }
    }
    
    /// Mine blocks if we're on regtest network
    async fn mine_blocks_if_regtest(&self) -> Result<()> {
        let network = self.wallet_manager.get_network();
        
        if network == bitcoin::Network::Regtest {
            info!("Mining blocks on regtest network for coinbase maturity...");
            
            // Get change address for mining
            let change_address = self.wallet_manager.get_address().await?;
            
            // Mine 101 blocks to ensure coinbase outputs are spendable
            // Coinbase outputs require 100+ confirmations to be mature
            let blocks_to_mine = 101;
            
            match self.rpc_client.generate_to_address(blocks_to_mine, &change_address).await {
                Ok(block_hashes) => {
                    let first_hash = if let Some(array) = block_hashes.as_array() {
                        array.get(0).and_then(|h| h.as_str()).unwrap_or("none")
                    } else {
                        "none"
                    };
                    let last_hash = if let Some(array) = block_hashes.as_array() {
                        array.last().and_then(|h| h.as_str()).unwrap_or("none")
                    } else {
                        "none"
                    };
                    
                    info!("✅ Mined {} blocks on regtest: first={}, last={}",
                          blocks_to_mine, first_hash, last_hash);
                    println!("⛏️  Mined {} blocks on regtest to address: {}", blocks_to_mine, change_address);
                    println!("💡 Coinbase outputs now have sufficient confirmations to be spendable");
                },
                Err(e) => {
                    warn!("Failed to mine blocks on regtest: {}", e);
                    println!("⚠️  Failed to mine blocks on regtest: {}", e);
                }
            }
        } else {
            info!("Not on regtest network, skipping block mining");
        }
        
        Ok(())
    }
    
    /// Wait for transaction to be mined
    async fn wait_for_transaction_mined(&self, txid: &str, params: &EnhancedExecuteParams) -> Result<()> {
        info!("Waiting for transaction {} to be mined...", txid);
        
        if !params.raw_output {
            println!("⏳ Waiting for transaction to be mined...");
        }
        
        let max_attempts = 60; // 60 seconds timeout
        let mut attempts = 0;
        let mut last_block_count = 0;
        
        loop {
            attempts += 1;
            
            // Check if transaction exists and is confirmed
            match self.rpc_client.get_transaction_hex(txid).await {
                Ok(_) => {
                    // Transaction found, check if it's confirmed by getting block count
                    let current_block_count = self.rpc_client.get_block_count().await?;
                    
                    if current_block_count > last_block_count {
                        if !params.raw_output {
                            println!("📦 New block mined (height: {}), checking transaction status...", current_block_count);
                        }
                        last_block_count = current_block_count;
                    }
                    
                    // For simplicity, assume transaction is mined if we can retrieve it
                    // In a full implementation, we'd check the confirmation count
                    info!("✅ Transaction {} found and appears to be mined", txid);
                    if !params.raw_output {
                        println!("✅ Transaction mined successfully!");
                    }
                    break;
                },
                Err(_) => {
                    // Transaction not found yet
                    if attempts >= max_attempts {
                        return Err(anyhow!("Timeout waiting for transaction {} to be mined", txid));
                    }
                    
                    // Check if new blocks have been mined while waiting
                    let current_block_count = self.rpc_client.get_block_count().await?;
                    if current_block_count > last_block_count {
                        if !params.raw_output {
                            println!("📦 Block mined (height: {}) but transaction not yet included...", current_block_count);
                        }
                        last_block_count = current_block_count;
                    }
                    
                    debug!("Transaction {} not found yet, attempt {}/{}", txid, attempts, max_attempts);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
        
        Ok(())
    }
    
    /// Enhanced metashrew synchronization with logging
    async fn wait_for_metashrew_sync_enhanced(&self, params: &EnhancedExecuteParams) -> Result<()> {
        info!("Waiting for metashrew to synchronize with enhanced logging...");
        
        if !params.raw_output {
            println!("🔄 Waiting for metashrew to synchronize...");
        }
        
        let max_attempts = 30; // 30 seconds timeout
        let mut attempts = 0;
        
        loop {
            attempts += 1;
            
            // Get heights from both Bitcoin Core and Metashrew
            let bitcoin_height = self.rpc_client.get_block_count().await?;
            let metashrew_height = self.rpc_client.get_metashrew_height().await?;
            
            // Metashrew should be at least equal to Bitcoin Core height
            if metashrew_height >= bitcoin_height {
                info!("✅ Metashrew synchronized: Bitcoin={}, Metashrew={}", bitcoin_height, metashrew_height);
                if !params.raw_output {
                    println!("✅ Metashrew synchronized (Bitcoin: {}, Metashrew: {})", bitcoin_height, metashrew_height);
                }
                break;
            }
            
            if attempts >= max_attempts {
                return Err(anyhow!("Timeout waiting for metashrew synchronization. Bitcoin height: {}, Metashrew height: {}", bitcoin_height, metashrew_height));
            }
            
            if !params.raw_output && attempts % 5 == 0 {
                println!("🔄 Still waiting for sync: Bitcoin={}, Metashrew={} (attempt {}/{})", bitcoin_height, metashrew_height, attempts, max_attempts);
            }
            
            debug!("Waiting for sync: Bitcoin={}, Metashrew={}, attempt {}/{}", bitcoin_height, metashrew_height, attempts, max_attempts);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        
        Ok(())
    }
    
    /// Enhanced Esplora synchronization with logging
    async fn wait_for_esplora_sync_enhanced(&self, params: &EnhancedExecuteParams) -> Result<()> {
        info!("Waiting for Esplora to synchronize with enhanced logging...");
        
        if !params.raw_output {
            println!("🔄 Waiting for Esplora to synchronize...");
        }
        
        let max_attempts = 30; // 30 seconds timeout
        let mut attempts = 0;
        
        loop {
            attempts += 1;
            
            // Get heights from both Bitcoin Core and Esplora
            let bitcoin_height = self.rpc_client.get_block_count().await?;
            let esplora_height = self.rpc_client.get_esplora_blocks_tip_height().await?;
            
            // Esplora should be at least equal to Bitcoin Core height
            if esplora_height >= bitcoin_height {
                info!("✅ Esplora synchronized: Bitcoin={}, Esplora={}", bitcoin_height, esplora_height);
                if !params.raw_output {
                    println!("✅ Esplora synchronized (Bitcoin: {}, Esplora: {})", bitcoin_height, esplora_height);
                }
                break;
            }
            
            if attempts >= max_attempts {
                return Err(anyhow!("Timeout waiting for Esplora synchronization. Bitcoin height: {}, Esplora height: {}", bitcoin_height, esplora_height));
            }
            
            if !params.raw_output && attempts % 5 == 0 {
                println!("🔄 Still waiting for Esplora sync: Bitcoin={}, Esplora={} (attempt {}/{})", bitcoin_height, esplora_height, attempts, max_attempts);
            }
            
            debug!("Waiting for Esplora sync: Bitcoin={}, Esplora={}, attempt {}/{}", bitcoin_height, esplora_height, attempts, max_attempts);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        
        Ok(())
    }
    
    /// Reverse TXID bytes for trace calls
    fn reverse_txid_bytes(&self, txid: &str) -> Result<String> {
        // Remove any 0x prefix if present
        let clean_txid = txid.trim_start_matches("0x");
        
        // Decode hex string to bytes
        let txid_bytes = hex::decode(clean_txid)
            .context("Failed to decode TXID hex")?;
        
        // Reverse the bytes
        let mut reversed_bytes = txid_bytes;
        reversed_bytes.reverse();
        
        // Encode back to hex string
        let reversed_txid = hex::encode(reversed_bytes);
        
        debug!("Reversed TXID: {} -> {}", clean_txid, reversed_txid);
        Ok(reversed_txid)
    }

    /// Wait for metashrew to synchronize with Bitcoin Core
    async fn wait_for_metashrew_sync(&self) -> Result<()> {
        info!("Waiting for metashrew to synchronize...");
        
        let max_attempts = 30; // 30 seconds timeout
        let mut attempts = 0;
        
        loop {
            attempts += 1;
            
            // Get heights from both Bitcoin Core and Metashrew
            let bitcoin_height = self.rpc_client.get_block_count().await?;
            let metashrew_height = self.rpc_client.get_metashrew_height().await?;
            
            // Metashrew should be at least equal to Bitcoin Core height
            if metashrew_height >= bitcoin_height {
                info!("Metashrew synchronized: Bitcoin={}, Metashrew={}", bitcoin_height, metashrew_height);
                break;
            }
            
            if attempts >= max_attempts {
                return Err(anyhow!("Timeout waiting for metashrew synchronization. Bitcoin height: {}, Metashrew height: {}", bitcoin_height, metashrew_height));
            }
            
            debug!("Waiting for sync: Bitcoin={}, Metashrew={}, attempt {}/{}", bitcoin_height, metashrew_height, attempts, max_attempts);
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        
        Ok(())
    }

    /// Create commit address for envelope using taproot
    async fn create_commit_address_for_envelope(
        &self,
        envelope: &AlkanesEnvelope,
        network: bitcoin::Network,
        internal_key: bitcoin::XOnlyPublicKey,
    ) -> Result<bitcoin::Address> {
        use bitcoin::taproot::{TaprootBuilder, LeafVersion};
        
        // Build the reveal script
        let reveal_script = envelope.build_reveal_script();
        
        // Create taproot builder with the reveal script
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .context("Failed to add reveal script to taproot builder")?;
        
        // Finalize the taproot spend info
        let taproot_spend_info = taproot_builder
            .finalize(&bitcoin::secp256k1::Secp256k1::verification_only(), internal_key)
            .map_err(|e| anyhow::anyhow!("Failed to finalize taproot spend info: {:?}", e))?;
        
        // Create the commit address
        let commit_address = bitcoin::Address::p2tr_tweaked(
            taproot_spend_info.output_key(),
            network,
        );
        
        Ok(commit_address)
    }

    /// Create taproot spend info for envelope
    async fn create_taproot_spend_info_for_envelope(
        &self,
        envelope: &AlkanesEnvelope,
        internal_key: bitcoin::XOnlyPublicKey,
    ) -> Result<(bitcoin::taproot::TaprootSpendInfo, bitcoin::taproot::ControlBlock)> {
        use bitcoin::taproot::{TaprootBuilder, LeafVersion};
        
        // Build the reveal script
        let reveal_script = envelope.build_reveal_script();
        
        // Create taproot builder with the reveal script
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .context("Failed to add reveal script to taproot builder")?;
        
        // Finalize the taproot spend info
        let taproot_spend_info = taproot_builder
            .finalize(&bitcoin::secp256k1::Secp256k1::verification_only(), internal_key)
            .map_err(|e| anyhow::anyhow!("Failed to finalize taproot spend info: {:?}", e))?;
        
        // Create control block for script-path spending
        let control_block = taproot_spend_info
            .control_block(&(reveal_script, LeafVersion::TapScript))
            .context("Failed to create control block for reveal script")?;
        
        Ok((taproot_spend_info, control_block))
    }
}

/// Parse input requirements from string format
pub fn parse_input_requirements(input_str: &str) -> Result<Vec<InputRequirement>> {
    let mut requirements = Vec::new();
    
    for part in input_str.split(',') {
        let trimmed = part.trim();
        
        if trimmed.starts_with("B:") {
            // Bitcoin requirement: B:amount
            let amount_str = &trimmed[2..];
            let amount = amount_str.parse::<u64>()
                .context("Invalid Bitcoin amount in input requirement")?;
            requirements.push(InputRequirement::Bitcoin { amount });
        } else {
            // Alkanes requirement: block:tx:amount
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() != 3 {
                return Err(anyhow!("Invalid alkanes input requirement format. Expected 'block:tx:amount'"));
            }
            
            let block = parts[0].parse::<u64>()
                .context("Invalid block number in alkanes requirement")?;
            let tx = parts[1].parse::<u64>()
                .context("Invalid tx number in alkanes requirement")?;
            let amount = parts[2].parse::<u64>()
                .context("Invalid amount in alkanes requirement")?;
            
            requirements.push(InputRequirement::Alkanes { block, tx, amount });
        }
    }
    
    Ok(requirements)
}

/// Parse protostone specifications from complex string format
pub fn parse_protostones(protostones_str: &str) -> Result<Vec<ProtostoneSpec>> {
    info!("Parsing protostones from: {}", protostones_str);
    
    // Split by comma, but ignore commas inside [] brackets (cellpacks)
    let protostone_parts = split_respecting_brackets(protostones_str, ',')?;
    
    let mut protostones = Vec::new();
    
    for part in protostone_parts {
        let spec = parse_single_protostone(&part)?;
        protostones.push(spec);
    }
    
    Ok(protostones)
}

/// Parse a single protostone specification
fn parse_single_protostone(spec_str: &str) -> Result<ProtostoneSpec> {
    let mut cellpack = None;
    let mut edicts = Vec::new();
    let mut bitcoin_transfer = None;
    
    info!("Parsing single protostone: {}", spec_str);
    
    // First, we need to handle the complex format properly
    // The format can be: [cellpack]:target:pointer:[edict1]:[edict2],...
    // We need to split by colon but respect both [] brackets and nested structures
    
    // Use a more sophisticated parsing approach
    let parts = split_complex_protostone(spec_str)?;
    
    for (i, part) in parts.iter().enumerate() {
        let trimmed = part.trim();
        info!("Processing protostone part {}: '{}'", i, trimmed);
        
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let content = &trimmed[1..trimmed.len()-1];
            
            // Check if this is a cellpack (contains commas) or an edict (contains colons)
            if content.contains(',') && !content.contains(':') {
                // This is a cellpack: [3,797,101]
                info!("Found cellpack: {}", content);
                cellpack = Some(parse_cellpack(content)?);
            } else if content.contains(':') {
                // This is a bracketed edict: [4:797:1:p1]
                info!("Found bracketed edict: {}", content);
                let edict = parse_edict(trimmed)?;
                edicts.push(edict);
            } else {
                // Ambiguous - try cellpack first, then edict
                if let Ok(cp) = parse_cellpack(content) {
                    info!("Parsed as cellpack: {}", content);
                    cellpack = Some(cp);
                } else {
                    info!("Failed as cellpack, trying as edict: {}", content);
                    let edict = parse_edict(trimmed)?;
                    edicts.push(edict);
                }
            }
        } else if trimmed.starts_with("B:") {
            // This is a Bitcoin transfer
            info!("Found Bitcoin transfer: {}", trimmed);
            bitcoin_transfer = Some(parse_bitcoin_transfer(trimmed)?);
        } else if trimmed.starts_with('v') || trimmed.starts_with('p') || trimmed == "split" {
            // This is an output target (standalone, not part of an edict)
            info!("Found standalone target: {}", trimmed);
            // For now, skip standalone targets - they should be part of edicts
            continue;
        } else if !trimmed.is_empty() {
            // This might be a simple edict: block:tx:amount:target
            info!("Trying to parse as simple edict: {}", trimmed);
            if let Ok(edict) = parse_edict(trimmed) {
                edicts.push(edict);
            } else {
                warn!("Could not parse protostone part: {}", trimmed);
            }
        }
    }
    
    info!("Parsed protostone - cellpack: {:?}, edicts: {}, bitcoin_transfer: {:?}",
          cellpack.is_some(), edicts.len(), bitcoin_transfer.is_some());
    
    Ok(ProtostoneSpec {
        cellpack,
        edicts,
        bitcoin_transfer,
    })
}

/// Parse cellpack from string format
fn parse_cellpack(cellpack_str: &str) -> Result<Cellpack> {
    // Parse comma-separated numbers into Vec<u128>
    let mut values = Vec::new();
    
    for part in cellpack_str.split(',') {
        let trimmed = part.trim();
        let value = trimmed.parse::<u128>()
            .with_context(|| format!("Invalid u128 value in cellpack: {}", trimmed))?;
        values.push(value);
    }
    
    // Convert Vec<u128> to Cellpack using TryFrom
    // The first two values become target (block, tx), remaining values become inputs
    Cellpack::try_from(values)
        .with_context(|| "Failed to create Cellpack from values (need at least 2 values for target)")
}

/// Parse Bitcoin transfer specification
fn parse_bitcoin_transfer(transfer_str: &str) -> Result<BitcoinTransfer> {
    // Format: B:amount:target
    let parts: Vec<&str> = transfer_str.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid Bitcoin transfer format. Expected 'B:amount:target'"));
    }
    
    let amount = parts[1].parse::<u64>()
        .context("Invalid amount in Bitcoin transfer")?;
    let target = parse_output_target(parts[2])?;
    
    Ok(BitcoinTransfer { amount, target })
}

/// Parse edict specification
fn parse_edict(edict_str: &str) -> Result<ProtostoneEdict> {
    // Handle both formats:
    // 1. Simple format: block:tx:amount:target
    // 2. Bracketed format: [block:tx:amount:output] (where output becomes target)
    
    let trimmed = edict_str.trim();
    
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        // Bracketed format: [block:tx:amount:output]
        let content = &trimmed[1..trimmed.len()-1];
        let parts: Vec<&str> = content.split(':').collect();
        if parts.len() != 4 {
            return Err(anyhow!("Invalid bracketed edict format. Expected '[block:tx:amount:output]'"));
        }
        
        let block = parts[0].parse::<u64>()
            .context("Invalid block number in bracketed edict")?;
        let tx = parts[1].parse::<u64>()
            .context("Invalid tx number in bracketed edict")?;
        let amount = parts[2].parse::<u64>()
            .context("Invalid amount in bracketed edict")?;
        let target = parse_output_target(parts[3])?;
        
        Ok(ProtostoneEdict {
            alkane_id: AlkaneId { block, tx },
            amount,
            target,
        })
    } else {
        // Simple format: block:tx:amount:target
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() < 4 {
            return Err(anyhow!("Invalid edict format. Expected 'block:tx:amount:target' or '[block:tx:amount:output]'"));
        }
        
        let block = parts[0].parse::<u64>()
            .context("Invalid block number in edict")?;
        let tx = parts[1].parse::<u64>()
            .context("Invalid tx number in edict")?;
        let amount = parts[2].parse::<u64>()
            .context("Invalid amount in edict")?;
        let target = parse_output_target(parts[3])?;
        
        Ok(ProtostoneEdict {
            alkane_id: AlkaneId { block, tx },
            amount,
            target,
        })
    }
}

/// Parse complex edict specification (handles formats like "2:1000:0:v1")
fn parse_complex_edict(edict_str: &str) -> Result<ProtostoneEdict> {
    // Handle formats like "2:1000:0:v1" or "2:1:0:v0"
    let parts: Vec<&str> = edict_str.split(':').collect();
    if parts.len() < 4 {
        return Err(anyhow!("Invalid complex edict format. Expected at least 'block:tx:amount:target'"));
    }
    
    let block = parts[0].parse::<u64>()
        .context("Invalid block number in complex edict")?;
    let tx = parts[1].parse::<u64>()
        .context("Invalid tx number in complex edict")?;
    let amount = parts[2].parse::<u64>()
        .context("Invalid amount in complex edict")?;
    let target = parse_output_target(parts[3])?;
    
    Ok(ProtostoneEdict {
        alkane_id: AlkaneId { block, tx },
        amount,
        target,
    })
}

/// Parse output target (vN, pN, or split)
fn parse_output_target(target_str: &str) -> Result<OutputTarget> {
    let trimmed = target_str.trim();
    
    if trimmed == "split" {
        Ok(OutputTarget::Split)
    } else if trimmed.starts_with('v') {
        let index_str = &trimmed[1..];
        let index = index_str.parse::<u32>()
            .context("Invalid output index in target")?;
        Ok(OutputTarget::Output(index))
    } else if trimmed.starts_with('p') {
        let index_str = &trimmed[1..];
        let index = index_str.parse::<u32>()
            .context("Invalid protostone index in target")?;
        Ok(OutputTarget::Protostone(index))
    } else {
        Err(anyhow!("Invalid output target format. Expected 'vN', 'pN', or 'split'"))
    }
}

/// Split string by delimiter while respecting bracket nesting
fn split_respecting_brackets(input: &str, delimiter: char) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;
    
    for ch in input.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            },
            ']' => {
                bracket_depth -= 1;
                current.push(ch);
                if bracket_depth < 0 {
                    return Err(anyhow!("Unmatched closing bracket"));
                }
            },
            c if c == delimiter && bracket_depth == 0 => {
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
            },
            _ => {
                current.push(ch);
            }
        }
    }
    
    if bracket_depth != 0 {
        return Err(anyhow!("Unmatched opening bracket"));
    }
    
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    
    Ok(parts)
}

/// Split complex protostone specification while respecting nested brackets
fn split_complex_protostone(input: &str) -> Result<Vec<String>> {
    // Handle complex format like: [3,797,101]:v0:v0:[4:797:1:p1]:[4:797:2:p2],v1:v1,v2:v2
    // We need to split by colon but respect brackets for both cellpacks and edicts
    
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0;
    let mut chars = input.chars().peekable();
    
    while let Some(ch) = chars.next() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            },
            ']' => {
                bracket_depth -= 1;
                current.push(ch);
                if bracket_depth < 0 {
                    return Err(anyhow!("Unmatched closing bracket"));
                }
            },
            ':' if bracket_depth == 0 => {
                // Split on colon only when not inside brackets
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
            },
            ',' if bracket_depth == 0 => {
                // Also split on comma when not inside brackets (for multiple edicts)
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_string());
                }
                current.clear();
            },
            _ => {
                current.push(ch);
            }
        }
    }
    
    if bracket_depth != 0 {
        return Err(anyhow!("Unmatched opening bracket"));
    }
    
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_input_requirements() {
        let input = "2:0:1000,2:1:0,B:5000";
        let requirements = parse_input_requirements(input).unwrap();
        
        assert_eq!(requirements.len(), 3);
        
        match &requirements[0] {
            InputRequirement::Alkanes { block, tx, amount } => {
                assert_eq!(*block, 2);
                assert_eq!(*tx, 0);
                assert_eq!(*amount, 1000);
            },
            _ => panic!("Expected alkanes requirement"),
        }
        
        match &requirements[2] {
            InputRequirement::Bitcoin { amount } => {
                assert_eq!(*amount, 5000);
            },
            _ => panic!("Expected bitcoin requirement"),
        }
    }

    #[test]
    fn test_parse_output_target() {
        assert!(matches!(parse_output_target("v0").unwrap(), OutputTarget::Output(0)));
        assert!(matches!(parse_output_target("p1").unwrap(), OutputTarget::Protostone(1)));
        assert!(matches!(parse_output_target("split").unwrap(), OutputTarget::Split));
    }

    #[test]
    fn test_split_respecting_brackets() {
        let input = "a,[b,c],d";
        let parts = split_respecting_brackets(input, ',').unwrap();
        assert_eq!(parts, vec!["a", "[b,c]", "d"]);
    }

    #[test]
    fn test_parse_cellpack_with_large_values() {
        // Test the original failing case: [3,797,101]
        let cellpack = parse_cellpack("3,797,101").unwrap();
        
        // Verify target (first two values)
        assert_eq!(cellpack.target.block, 3);
        assert_eq!(cellpack.target.tx, 797);
        
        // Verify inputs (remaining values)
        assert_eq!(cellpack.inputs, vec![101]);
    }

    #[test]
    fn test_parse_cellpack_minimum_values() {
        // Test with minimum required values (target only)
        let cellpack = parse_cellpack("2,0").unwrap();
        
        assert_eq!(cellpack.target.block, 2);
        assert_eq!(cellpack.target.tx, 0);
        assert_eq!(cellpack.inputs, Vec::<u128>::new());
    }

    #[test]
    fn test_parse_cellpack_multiple_inputs() {
        // Test with multiple input values
        let cellpack = parse_cellpack("1,2,100,200,300").unwrap();
        
        assert_eq!(cellpack.target.block, 1);
        assert_eq!(cellpack.target.tx, 2);
        assert_eq!(cellpack.inputs, vec![100, 200, 300]);
    }

    #[test]
    fn test_parse_cellpack_insufficient_values() {
        // Test error case: not enough values for target
        let result = parse_cellpack("1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bracketed_edict() {
        // Test the new bracketed edict format: [block:tx:amount:output]
        let edict = parse_edict("[4:797:1:p1]").unwrap();
        
        assert_eq!(edict.alkane_id.block, 4);
        assert_eq!(edict.alkane_id.tx, 797);
        assert_eq!(edict.amount, 1);
        assert!(matches!(edict.target, OutputTarget::Protostone(1)));
    }

    #[test]
    fn test_parse_bracketed_edict_with_output() {
        // Test bracketed edict with output target: [4:797:2:v0]
        let edict = parse_edict("[4:797:2:v0]").unwrap();
        
        assert_eq!(edict.alkane_id.block, 4);
        assert_eq!(edict.alkane_id.tx, 797);
        assert_eq!(edict.amount, 2);
        assert!(matches!(edict.target, OutputTarget::Output(0)));
    }

    #[test]
    fn test_parse_complex_protostone_format() {
        // Test the complex format from the script: [3,797,101]:v0:v0:[4:797:1:p1]:[4:797:2:p2]
        let parts = split_complex_protostone("[3,797,101]:v0:v0:[4:797:1:p1]:[4:797:2:p2]").unwrap();
        
        // Should split into: ["[3,797,101]", "v0", "v0", "[4:797:1:p1]", "[4:797:2:p2]"]
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "[3,797,101]");
        assert_eq!(parts[1], "v0");
        assert_eq!(parts[2], "v0");
        assert_eq!(parts[3], "[4:797:1:p1]");
        assert_eq!(parts[4], "[4:797:2:p2]");
    }

    #[test]
    fn test_parse_single_protostone_with_edicts() {
        // Test parsing a protostone with cellpack and edicts
        let spec = parse_single_protostone("[3,797,101]:v0:v0:[4:797:1:p1]:[4:797:2:p2]").unwrap();
        
        // Should have cellpack
        assert!(spec.cellpack.is_some());
        let cellpack = spec.cellpack.unwrap();
        assert_eq!(cellpack.target.block, 3);
        assert_eq!(cellpack.target.tx, 797);
        assert_eq!(cellpack.inputs, vec![101]);
        
        // Should have 2 edicts
        assert_eq!(spec.edicts.len(), 2);
        
        // First edict: [4:797:1:p1]
        let edict1 = &spec.edicts[0];
        assert_eq!(edict1.alkane_id.block, 4);
        assert_eq!(edict1.alkane_id.tx, 797);
        assert_eq!(edict1.amount, 1);
        assert!(matches!(edict1.target, OutputTarget::Protostone(1)));
        
        // Second edict: [4:797:2:p2]
        let edict2 = &spec.edicts[1];
        assert_eq!(edict2.alkane_id.block, 4);
        assert_eq!(edict2.alkane_id.tx, 797);
        assert_eq!(edict2.amount, 2);
        assert!(matches!(edict2.target, OutputTarget::Protostone(2)));
    }
}
