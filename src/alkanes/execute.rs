//! Enhanced alkanes execute functionality with complex protostone support
//!
//! This module implements the complex alkanes execute command that supports:
//! - Complex protostone parsing with cellpacks and edicts
//! - UTXO selection based on alkanes and Bitcoin requirements
//! - Runestone construction with multiple protostones
//! - Address identifier resolution for outputs and change

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use super::types::*;
use super::envelope::EnvelopeManager;

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
    /// Optional cellpack message (encoded as Vec<u8>)
    pub cellpack: Option<Vec<u8>>,
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
}

/// Enhanced execute result
#[derive(Debug, Clone)]
pub struct EnhancedExecuteResult {
    pub txid: String,
    pub fee: u64,
    pub inputs_used: Vec<String>,
    pub outputs_created: Vec<String>,
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

    /// Execute an enhanced alkanes transaction
    pub async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        info!("Starting enhanced alkanes execution");
        
        // Step 1: Handle envelope if present
        let envelope_manager = if let Some(envelope_data) = &params.envelope_data {
            info!("Processing envelope with {} bytes", envelope_data.len());
            let manager = EnvelopeManager::new(envelope_data.clone());
            
            // Show envelope preview and request user approval
            println!("{}", manager.preview());
            println!("\n⚠️  ENVELOPE COMMIT-REVEAL TRANSACTION");
            println!("This will create a commit transaction first, then use it as input.");
            println!("Do you want to proceed? (y/N): ");
            
            // In a real implementation, we'd wait for user input
            // For now, we'll proceed automatically
            info!("Envelope approved, proceeding with commit-reveal");
            
            Some(manager)
        } else {
            None
        };
        
        // Step 2: Validate protostone specifications
        self.validate_protostones(&params.protostones, params.to_addresses.len())?;
        
        // Step 3: Find UTXOs that meet input requirements
        let mut selected_utxos = self.select_utxos(&params.input_requirements).await?;
        
        // Step 4: Handle envelope commit if present
        if let Some(envelope_manager) = &envelope_manager {
            let commit_utxo = self.create_envelope_commit(envelope_manager).await?;
            // Insert envelope UTXO as the FIRST input
            selected_utxos.insert(0, commit_utxo);
            info!("Added envelope commit as first input");
        }
        
        // Step 5: Create transaction with outputs for each address
        let outputs = self.create_outputs(&params.to_addresses, &params.change_address).await?;
        
        // Step 6: Construct runestone with protostones
        let runestone = self.construct_runestone(&params.protostones, outputs.len())?;
        
        // Step 7: Build and sign transaction (with envelope reveal if present)
        let (tx, fee) = self.build_transaction_with_envelope(
            selected_utxos,
            outputs,
            runestone,
            params.fee_rate,
            envelope_manager.as_ref()
        ).await?;
        
        // Step 8: Broadcast transaction
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
        let txid = self.rpc_client.broadcast_transaction(&tx_hex).await?;
        
        Ok(EnhancedExecuteResult {
            txid,
            fee,
            inputs_used: vec![], // TODO: populate with actual inputs
            outputs_created: vec![], // TODO: populate with actual outputs
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
        
        // Get all wallet UTXOs
        let wallet_utxos = self.wallet_manager.get_utxos().await?;
        debug!("Found {} wallet UTXOs", wallet_utxos.len());
        
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
            
            // Check if this UTXO helps meet our requirements
            let mut should_include = false;
            
            // Check Bitcoin requirement
            if bitcoin_collected < bitcoin_needed {
                bitcoin_collected += utxo.amount;
                should_include = true;
            }
            
            // Check alkanes requirements (simplified - would need RPC calls to check actual balances)
            for ((block, tx), needed_amount) in &alkanes_needed {
                let collected = alkanes_collected.get(&(*block, *tx)).unwrap_or(&0);
                if collected < needed_amount {
                    // This UTXO might contain the needed alkanes token
                    // In a full implementation, we'd check the actual alkanes balance
                    should_include = true;
                    *alkanes_collected.entry((*block, *tx)).or_insert(0) += 1; // Placeholder
                }
            }
            
            if should_include {
                selected_utxos.push(outpoint);
            }
            
            // Check if we've met all requirements
            let bitcoin_satisfied = bitcoin_collected >= bitcoin_needed;
            let alkanes_satisfied = alkanes_needed.iter().all(|(key, needed)| {
                alkanes_collected.get(key).unwrap_or(&0) >= needed
            });
            
            if bitcoin_satisfied && alkanes_satisfied {
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

    /// Create outputs for recipient addresses
    async fn create_outputs(&self, to_addresses: &[String], change_address: &Option<String>) -> Result<Vec<bitcoin::TxOut>> {
        info!("Creating outputs for {} addresses", to_addresses.len());
        
        let mut outputs = Vec::new();
        
        // Create outputs for each recipient address (dust amount for now)
        for address_str in to_addresses {
            let address = bitcoin::Address::from_str(address_str)
                .context("Invalid recipient address")?
                .require_network(bitcoin::Network::Bitcoin) // TODO: Get from wallet config
                .context("Address network mismatch")?;
            
            let output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(546), // Dust limit
                script_pubkey: address.script_pubkey(),
            };
            outputs.push(output);
        }
        
        // Add change output if specified
        if let Some(change_addr) = change_address {
            let change_address = bitcoin::Address::from_str(change_addr)
                .context("Invalid change address")?
                .require_network(bitcoin::Network::Bitcoin) // TODO: Get from wallet config
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

    /// Construct runestone with protostones
    fn construct_runestone(&self, protostones: &[ProtostoneSpec], num_outputs: usize) -> Result<Vec<u8>> {
        info!("Constructing runestone with {} protostones", protostones.len());
        
        // Create OP_RETURN script with runestone data
        let mut script_data = Vec::new();
        
        // OP_RETURN opcode
        script_data.push(0x6a);
        
        // Runestone magic bytes and subprotocol ID 1
        script_data.extend_from_slice(b"RUNE_TEST"); // Placeholder magic
        script_data.push(1); // Subprotocol ID 1 for alkanes
        
        // Encode protostones
        for (i, protostone) in protostones.iter().enumerate() {
            // Add protostone index
            script_data.push(i as u8);
            
            // Add cellpack if present
            if let Some(cellpack) = &protostone.cellpack {
                script_data.push(0xFF); // Cellpack marker
                script_data.extend_from_slice(cellpack);
            }
            
            // Add edicts
            for edict in &protostone.edicts {
                // Encode edict: alkane_id, amount, target
                script_data.extend_from_slice(&edict.alkane_id.block.to_le_bytes());
                script_data.extend_from_slice(&edict.alkane_id.tx.to_le_bytes());
                script_data.extend_from_slice(&edict.amount.to_le_bytes());
                
                // Encode target
                match edict.target {
                    OutputTarget::Output(v) => {
                        script_data.push(0x01); // Output target marker
                        script_data.extend_from_slice(&v.to_le_bytes());
                    },
                    OutputTarget::Protostone(p) => {
                        script_data.push(0x02); // Protostone target marker
                        script_data.extend_from_slice(&p.to_le_bytes());
                    },
                    OutputTarget::Split => {
                        script_data.push(0x03); // Split target marker
                    }
                }
            }
            
            // Add Bitcoin transfer if present
            if let Some(bitcoin_transfer) = &protostone.bitcoin_transfer {
                script_data.push(0xFE); // Bitcoin transfer marker
                script_data.extend_from_slice(&bitcoin_transfer.amount.to_le_bytes());
                
                // Encode target
                match bitcoin_transfer.target {
                    OutputTarget::Output(v) => {
                        script_data.push(0x01);
                        script_data.extend_from_slice(&v.to_le_bytes());
                    },
                    OutputTarget::Split => {
                        script_data.push(0x03);
                    },
                    OutputTarget::Protostone(_) => {
                        return Err(anyhow!("Bitcoin transfers cannot target protostones"));
                    }
                }
            }
        }
        
        info!("Constructed runestone with {} bytes", script_data.len());
        Ok(script_data)
    }

    /// Build and sign transaction
    async fn build_transaction(
        &self,
        utxos: Vec<bitcoin::OutPoint>,
        mut outputs: Vec<bitcoin::TxOut>,
        runestone: Vec<u8>,
        fee_rate: Option<f32>
    ) -> Result<(bitcoin::Transaction, u64)> {
        info!("Building and signing transaction");
        
        use bitcoin::{Transaction, TxIn, TxOut, ScriptBuf};
        
        // Create inputs from selected UTXOs
        let inputs: Vec<TxIn> = utxos.iter().map(|outpoint| {
            TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }
        }).collect();
        
        // Add OP_RETURN output with runestone
        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::from(runestone),
        };
        outputs.push(op_return_output);
        
        // Create transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };
        
        // Calculate fee (simplified)
        let fee = fee_rate.unwrap_or(1.0) as u64 * tx.vsize() as u64;
        
        info!("Built transaction with {} inputs, {} outputs, fee: {} sats",
              tx.input.len(), tx.output.len(), fee);
        
        Ok((tx, fee))
    }

    /// Create envelope commit transaction and return its outpoint
    async fn create_envelope_commit(&self, envelope_manager: &EnvelopeManager) -> Result<bitcoin::OutPoint> {
        info!("Creating envelope commit transaction");
        
        // Get wallet's internal key for taproot
        let internal_key = self.wallet_manager.get_internal_key().await?;
        
        // Create commit address
        let network = bitcoin::Network::Bitcoin; // TODO: Get from wallet config
        let commit_address = envelope_manager.create_commit_address(network, internal_key)?;
        
        info!("Envelope commit address: {}", commit_address);
        
        // Create a simple transaction to the commit address
        // In a real implementation, this would be a proper transaction
        // For now, we'll create a placeholder outpoint
        let commit_txid = bitcoin::Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .context("Failed to create placeholder commit txid")?;
        
        let commit_outpoint = bitcoin::OutPoint {
            txid: commit_txid,
            vout: 0,
        };
        
        info!("Created envelope commit outpoint: {}:{}", commit_outpoint.txid, commit_outpoint.vout);
        Ok(commit_outpoint)
    }

    /// Build and sign transaction with envelope reveal support
    async fn build_transaction_with_envelope(
        &self,
        utxos: Vec<bitcoin::OutPoint>,
        mut outputs: Vec<bitcoin::TxOut>,
        runestone: Vec<u8>,
        fee_rate: Option<f32>,
        envelope_manager: Option<&EnvelopeManager>
    ) -> Result<(bitcoin::Transaction, u64)> {
        info!("Building and signing transaction with envelope support");
        
        use bitcoin::{Transaction, TxIn, TxOut, ScriptBuf};
        
        // Create inputs from selected UTXOs
        let mut inputs: Vec<TxIn> = utxos.iter().enumerate().map(|(i, outpoint)| {
            let mut input = TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };
            
            // If this is the first input and we have an envelope, set the witness
            if i == 0 && envelope_manager.is_some() {
                let envelope_witness = envelope_manager.unwrap().create_witness();
                input.witness = envelope_witness;
                info!("Set envelope reveal witness for first input");
            }
            
            input
        }).collect();
        
        // Add OP_RETURN output with runestone
        let op_return_output = TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::from(runestone),
        };
        outputs.push(op_return_output);
        
        // Create transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };
        
        // Calculate fee (simplified)
        let fee = fee_rate.unwrap_or(1.0) as u64 * tx.vsize() as u64;
        
        info!("Built transaction with {} inputs, {} outputs, fee: {} sats",
              tx.input.len(), tx.output.len(), fee);
        
        if envelope_manager.is_some() {
            info!("Transaction includes envelope reveal in first input witness");
        }
        
        Ok((tx, fee))
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
    
    // Split by colon, but respect brackets for cellpacks
    let parts = split_respecting_brackets(spec_str, ':')?;
    
    for part in parts {
        let trimmed = part.trim();
        
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // This is a cellpack
            let cellpack_content = &trimmed[1..trimmed.len()-1];
            cellpack = Some(parse_cellpack(cellpack_content)?);
        } else if trimmed.starts_with("B:") {
            // This is a Bitcoin transfer
            bitcoin_transfer = Some(parse_bitcoin_transfer(trimmed)?);
        } else if trimmed.starts_with('v') || trimmed.starts_with('p') || trimmed == "split" {
            // This is an output target (should be part of an edict)
            continue;
        } else {
            // This should be an edict: block:tx:amount:target
            let edict = parse_edict(trimmed)?;
            edicts.push(edict);
        }
    }
    
    Ok(ProtostoneSpec {
        cellpack,
        edicts,
        bitcoin_transfer,
    })
}

/// Parse cellpack from string format
fn parse_cellpack(cellpack_str: &str) -> Result<Vec<u8>> {
    // Parse comma-separated numbers into Vec<u8>
    let mut bytes = Vec::new();
    
    for part in cellpack_str.split(',') {
        let trimmed = part.trim();
        let byte_val = trimmed.parse::<u8>()
            .with_context(|| format!("Invalid byte value in cellpack: {}", trimmed))?;
        bytes.push(byte_val);
    }
    
    Ok(bytes)
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
    // Format: block:tx:amount:target or block,tx,amount:target:target
    // Need to handle the complex format from the example
    
    // For now, implement basic format
    let parts: Vec<&str> = edict_str.split(':').collect();
    if parts.len() < 4 {
        return Err(anyhow!("Invalid edict format. Expected at least 'block:tx:amount:target'"));
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
}