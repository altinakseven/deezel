//! Alkanes protocol support
//!
//! This module provides functionality for:
//! - Alkanes contract deployment
//! - Token minting and transfer
//! - Contract interaction
//! - Balance tracking

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Network, OutPoint, Script, Transaction, TxOut, Address, Amount};
use bdk::bitcoin::psbt::Psbt;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use crate::account::Account;
use crate::rpc::RpcClient;
use crate::signer::Signer;
use crate::utils::{GatheredUtxos, UtxoInfo, DUST_OUTPUT_VALUE};

/// Alkanes contract information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesContract {
    /// Contract ID (block:tx)
    pub id: ContractId,
    /// Contract name
    pub name: String,
    /// Contract symbol
    pub symbol: String,
    /// Total supply
    pub total_supply: u64,
    /// Cap
    pub cap: u64,
    /// Minted amount
    pub minted: u64,
    /// Mint amount per transaction
    pub mint_amount: u64,
    /// Is minting active
    pub mint_active: bool,
    /// Percentage minted
    pub percentage_minted: u64,
}

/// Contract ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ContractId {
    /// Block height
    pub block: String,
    /// Transaction index
    pub tx: String,
}

/// Alkanes token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesToken {
    /// Token ID
    pub id: ContractId,
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Token balance
    pub balance: String,
    /// Token divisibility
    pub divisibility: u8,
    /// Token spacers
    pub spacers: u8,
}

/// Alkanes outpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesOutpoint {
    /// Tokens at this outpoint
    pub tokens: Vec<AlkanesToken>,
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Output value
    pub value: u64,
    /// Output script
    pub script: String,
    /// Transaction index
    pub tx_index: u32,
    /// Block height
    pub height: u32,
}

/// Alkanes payload for contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesPayload {
    /// Contract name
    pub name: String,
    /// Contract symbol
    pub symbol: String,
    /// Total supply
    pub total_supply: u64,
    /// Cap
    pub cap: u64,
    /// Mint amount per transaction
    pub mint_amount: u64,
    /// Contract body (WASM)
    pub body: Vec<u8>,
}

/// Alkanes manager for contract interaction
pub struct AlkanesManager {
    /// RPC client
    rpc_client: RpcClient,
    /// Network
    network: Network,
}

impl AlkanesManager {
    /// Create a new Alkanes manager
    pub fn new(rpc_client: RpcClient, network: Network) -> Self {
        Self {
            rpc_client,
            network,
        }
    }
    
    /// Get Alkanes tokens by address
    pub async fn get_tokens_by_address(
        &self,
        address: &str,
        protocol_tag: &str,
    ) -> Result<Vec<AlkanesOutpoint>> {
        // Call alkanes_protorunesbyaddress RPC method
        let result = self.rpc_client._call(
            "alkanes_protorunesbyaddress",
            serde_json::json!([{
                "address": address,
                "protocolTag": protocol_tag,
            }]),
        ).await?;
        
        // Parse response
        let outpoints = result.get("outpoints")
            .ok_or_else(|| anyhow!("Invalid response: missing outpoints"))?;
        
        // Convert to AlkanesOutpoint objects
        let mut alkanes_outpoints = Vec::new();
        
        for outpoint in outpoints.as_array().unwrap_or(&Vec::new()) {
            // Parse outpoint
            let txid = outpoint.get("outpoint").and_then(|o| o.get("txid"))
                .and_then(|t| t.as_str())
                .ok_or_else(|| anyhow!("Invalid outpoint: missing txid"))?;
            
            // Reverse txid bytes (from little-endian to big-endian)
            let txid_bytes = hex::decode(txid)?;
            let txid = hex::encode(txid_bytes.iter().rev().cloned().collect::<Vec<u8>>());
            
            let vout = outpoint.get("outpoint").and_then(|o| o.get("vout"))
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("Invalid outpoint: missing vout"))? as u32;
            
            let value = outpoint.get("output").and_then(|o| o.get("value"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid output: missing value"))?;
            let value = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                .context("Invalid output value")?;
            
            let script = outpoint.get("output").and_then(|o| o.get("script"))
                .and_then(|s| s.as_str())
                .ok_or_else(|| anyhow!("Invalid output: missing script"))?;
            
            let tx_index = outpoint.get("txindex")
                .and_then(|t| t.as_u64())
                .ok_or_else(|| anyhow!("Invalid outpoint: missing txindex"))? as u32;
            
            let height = outpoint.get("height")
                .and_then(|h| h.as_u64())
                .ok_or_else(|| anyhow!("Invalid outpoint: missing height"))? as u32;
            
            // Parse tokens
            let mut tokens = Vec::new();
            
            for rune in outpoint.get("runes").and_then(|r| r.as_array()).unwrap_or(&Vec::new()) {
                let balance = rune.get("balance")
                    .and_then(|b| b.as_str())
                    .ok_or_else(|| anyhow!("Invalid rune: missing balance"))?;
                let balance = u64::from_str_radix(balance.trim_start_matches("0x"), 16)
                    .context("Invalid rune balance")?;
                
                let rune_obj = rune.get("rune")
                    .ok_or_else(|| anyhow!("Invalid rune: missing rune object"))?;
                
                let id_block = rune_obj.get("id").and_then(|i| i.get("block"))
                    .and_then(|b| b.as_str())
                    .ok_or_else(|| anyhow!("Invalid rune: missing id.block"))?;
                let id_block = u64::from_str_radix(id_block.trim_start_matches("0x"), 16)
                    .context("Invalid rune id.block")?;
                
                let id_tx = rune_obj.get("id").and_then(|i| i.get("tx"))
                    .and_then(|t| t.as_str())
                    .ok_or_else(|| anyhow!("Invalid rune: missing id.tx"))?;
                let id_tx = u64::from_str_radix(id_tx.trim_start_matches("0x"), 16)
                    .context("Invalid rune id.tx")?;
                
                let name = rune_obj.get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                
                let symbol = rune_obj.get("symbol")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                
                let divisibility = rune_obj.get("divisibility")
                    .and_then(|d| d.as_u64())
                    .unwrap_or(0) as u8;
                
                let spacers = rune_obj.get("spacers")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0) as u8;
                
                tokens.push(AlkanesToken {
                    id: ContractId {
                        block: id_block.to_string(),
                        tx: id_tx.to_string(),
                    },
                    name: name.to_string(),
                    symbol: symbol.to_string(),
                    balance: balance.to_string(),
                    divisibility,
                    spacers,
                });
            }
            
            alkanes_outpoints.push(AlkanesOutpoint {
                tokens,
                txid,
                vout,
                value,
                script: script.to_string(),
                tx_index,
                height,
            });
        }
        
        Ok(alkanes_outpoints)
    }
    
    /// Get Alkanes contract by ID
    pub async fn get_contract_by_id(&self, contract_id: &ContractId) -> Result<AlkanesContract> {
        // Define opcodes for contract properties
        let opcodes = [
            "99",  // name
            "100", // symbol
            "101", // totalSupply
            "102", // cap
            "103", // minted
            "104", // mintAmount
        ];
        
        // Initialize contract data
        let mut contract = AlkanesContract {
            id: contract_id.clone(),
            name: String::new(),
            symbol: String::new(),
            total_supply: 0,
            cap: 0,
            minted: 0,
            mint_amount: 0,
            mint_active: false,
            percentage_minted: 0,
        };
        
        // Query each property
        for (i, opcode) in opcodes.iter().enumerate() {
            let result = self.rpc_client._call(
                "alkanes_simulate",
                serde_json::json!([{
                    "target": {
                        "block": contract_id.block,
                        "tx": contract_id.tx,
                    },
                    "alkanes": [],
                    "transaction": "0x",
                    "block": "0x",
                    "height": "20000",
                    "txindex": 0,
                    "inputs": [opcode],
                    "pointer": 0,
                    "refundPointer": 0,
                    "vout": 0,
                }]),
            ).await?;
            
            // Check status
            let status = result.get("status")
                .and_then(|s| s.as_u64())
                .unwrap_or(1);
            
            if status == 0 {
                // Parse result based on opcode
                match i {
                    0 => { // name
                        contract.name = result.get("execution")
                            .and_then(|e| e.get("data"))
                            .and_then(|d| d.as_str())
                            .map(|s| {
                                let hex_str = s.trim_start_matches("0x");
                                if let Ok(bytes) = hex::decode(hex_str) {
                                    String::from_utf8_lossy(&bytes).to_string()
                                } else {
                                    String::new()
                                }
                            })
                            .unwrap_or_default();
                    },
                    1 => { // symbol
                        contract.symbol = result.get("execution")
                            .and_then(|e| e.get("data"))
                            .and_then(|d| d.as_str())
                            .map(|s| {
                                let hex_str = s.trim_start_matches("0x");
                                if let Ok(bytes) = hex::decode(hex_str) {
                                    String::from_utf8_lossy(&bytes).to_string()
                                } else {
                                    String::new()
                                }
                            })
                            .unwrap_or_default();
                    },
                    2 => { // totalSupply
                        contract.total_supply = result.get("execution")
                            .and_then(|e| e.get("data"))
                            .and_then(|d| d.as_str())
                            .map(|s| {
                                let hex_str = s.trim_start_matches("0x");
                                u64::from_str_radix(hex_str, 16).unwrap_or(0)
                            })
                            .unwrap_or(0);
                    },
                    3 => { // cap
                        contract.cap = result.get("execution")
                            .and_then(|e| e.get("data"))
                            .and_then(|d| d.as_str())
                            .map(|s| {
                                let hex_str = s.trim_start_matches("0x");
                                u64::from_str_radix(hex_str, 16).unwrap_or(0)
                            })
                            .unwrap_or(0);
                    },
                    4 => { // minted
                        contract.minted = result.get("execution")
                            .and_then(|e| e.get("data"))
                            .and_then(|d| d.as_str())
                            .map(|s| {
                                let hex_str = s.trim_start_matches("0x");
                                u64::from_str_radix(hex_str, 16).unwrap_or(0)
                            })
                            .unwrap_or(0);
                    },
                    5 => { // mintAmount
                        contract.mint_amount = result.get("execution")
                            .and_then(|e| e.get("data"))
                            .and_then(|d| d.as_str())
                            .map(|s| {
                                let hex_str = s.trim_start_matches("0x");
                                u64::from_str_radix(hex_str, 16).unwrap_or(0)
                            })
                            .unwrap_or(0);
                    },
                    _ => {}
                }
            }
        }
        
        // Calculate derived properties
        contract.mint_active = contract.minted < contract.cap;
        if contract.cap > 0 {
            contract.percentage_minted = (contract.minted * 100) / contract.cap;
        }
        
        Ok(contract)
    }
    
    /// Find Alkanes tokens by ID
    pub async fn find_tokens_by_id(
        &self,
        address: &str,
        contract_id: &ContractId,
        target_amount: u64,
        greatest_to_least: bool,
    ) -> Result<(Vec<AlkanesOutpoint>, u64)> {
        // Get all tokens for the address
        let outpoints = self.get_tokens_by_address(address, "1").await?;
        
        // Filter tokens by contract ID
        let mut matching_outpoints = Vec::new();
        let mut total_balance = 0;
        
        for outpoint in outpoints {
            for token in &outpoint.tokens {
                if token.id.block == contract_id.block && token.id.tx == contract_id.tx {
                    let balance = token.balance.parse::<u64>().unwrap_or(0);
                    matching_outpoints.push((outpoint.clone(), balance));
                    break;
                }
            }
        }
        
        // Sort by balance
        if greatest_to_least {
            matching_outpoints.sort_by(|a, b| b.1.cmp(&a.1));
        } else {
            matching_outpoints.sort_by(|a, b| a.1.cmp(&b.1));
        }
        
        // Select outpoints up to target amount
        let mut selected_outpoints = Vec::new();
        let mut total_selected = 0;
        
        for (outpoint, balance) in matching_outpoints {
            selected_outpoints.push(outpoint);
            total_selected += balance;
            
            if total_selected >= target_amount {
                break;
            }
        }
        
        Ok((selected_outpoints, total_selected))
    }
    
    /// Create a PSBT for executing an Alkanes contract
    pub async fn create_execute_psbt(
        &self,
        alkane_outpoints: Option<&[AlkanesOutpoint]>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        protostone: &[u8],
        fee_rate: f64,
        fee: Option<u64>,
    ) -> Result<Psbt> {
        // Calculate minimum fee if not provided
        let fee = if let Some(fee) = fee {
            fee
        } else {
            let params = crate::utils::FeeCalculationParams {
                taproot_input_count: 2, // Assuming 2 taproot inputs
                non_taproot_input_count: 0,
                output_count: 2, // Dust output + OP_RETURN output
            };
            crate::utils::calculate_minimum_fee(params, fee_rate)
        };
        
        // Create PSBT
        let mut psbt = Psbt::from_unsigned_tx(Transaction {
            version: 2,
            lock_time: bitcoin::locktime::PackedLockTime(0),
            input: vec![],
            output: vec![],
        })?;
        
        // Add Alkanes inputs if provided
        let mut alkane_total = 0;
        if let Some(outpoints) = alkane_outpoints {
            for outpoint in outpoints {
                // Add input
                let txid = bdk::bitcoin::Txid::from_str(&outpoint.txid)?;
                let vout = outpoint.vout;
                
                // Create input
                let input = bdk::bitcoin::TxIn {
                    previous_output: OutPoint {
                        txid,
                        vout,
                    },
                    script_sig: Script::new(),
                    sequence: bitcoin::Sequence(0xFFFFFFFF),
                    witness: bitcoin::Witness::new(),
                };
                
                // Add input to transaction
                psbt.unsigned_tx.input.push(input);
                
                // Set witness UTXO
                let last_input_index = psbt.unsigned_tx.input.len() - 1;
                psbt.inputs.push(bdk::bitcoin::psbt::Input {
                    witness_utxo: Some(TxOut {
                        value: outpoint.value,
                        script_pubkey: Script::from_str(&outpoint.script)?,
                    }),
                    ..Default::default()
                });
                
                // Add to total
                alkane_total += outpoint.value;
            }
        }
        
        // Add regular inputs
        for utxo in &gathered_utxos.utxos {
            // Add input
            let txid = bdk::bitcoin::Txid::from_str(&utxo.txid)?;
            let vout = utxo.vout;
            
            // Create input
            let input = bdk::bitcoin::TxIn {
                previous_output: OutPoint {
                    txid,
                    vout,
                },
                script_sig: Script::new(),
                sequence: bitcoin::Sequence(0xFFFFFFFF),
                witness: bitcoin::Witness::new(),
            };
            
            // Add input to transaction
            psbt.unsigned_tx.input.push(input);
            
            // Set witness UTXO
            let last_input_index = psbt.unsigned_tx.input.len() - 1;
            psbt.inputs.push(bdk::bitcoin::psbt::Input {
                witness_utxo: Some(TxOut {
                    value: utxo.amount,
                    script_pubkey: Script::from_str(&utxo.script_pubkey)?,
                }),
                ..Default::default()
            });
        }
        
        // Add dust output
        let dust_address = Address::from_str(&account.get_address(account.spend_strategy.change_address))?;
        let dust_output = TxOut {
            value: DUST_OUTPUT_VALUE,
            script_pubkey: dust_address.script_pubkey(),
        };
        psbt.unsigned_tx.output.push(dust_output);
        psbt.outputs.push(Default::default());
        
        // Add OP_RETURN output with protostone
        let op_return_output = TxOut {
            value: 0,
            script_pubkey: Script::from(protostone.to_vec()),
        };
        psbt.unsigned_tx.output.push(op_return_output);
        psbt.outputs.push(Default::default());
        
        // Add change output if needed
        let change_amount = gathered_utxos.total_amount + alkane_total - fee - DUST_OUTPUT_VALUE;
        if change_amount > DUST_OUTPUT_VALUE {
            let change_address = Address::from_str(&account.get_address(account.spend_strategy.change_address))?;
            let change_output = TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            };
            psbt.unsigned_tx.output.push(change_output);
            psbt.outputs.push(Default::default());
        }
        
        Ok(psbt)
    }
    
    /// Create a PSBT for deploying an Alkanes contract
    pub async fn create_deploy_commit_psbt(
        &self,
        payload: &AlkanesPayload,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        fee_rate: f64,
        fee: Option<u64>,
    ) -> Result<(Psbt, Script)> {
        // TODO: Implement contract deployment
        // This is a placeholder implementation
        
        Err(anyhow!("Contract deployment not yet implemented"))
    }
    
    /// Create a PSBT for revealing an Alkanes contract
    pub async fn create_deploy_reveal_psbt(
        &self,
        protostone: &[u8],
        commit_txid: &str,
        script: &Script,
        fee_rate: f64,
        fee: Option<u64>,
    ) -> Result<Psbt> {
        // TODO: Implement contract reveal
        // This is a placeholder implementation
        
        Err(anyhow!("Contract reveal not yet implemented"))
    }
    
    /// Execute an Alkanes contract
    pub async fn execute(
        &self,
        alkane_outpoints: Option<&[AlkanesOutpoint]>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        protostone: &[u8],
        fee_rate: f64,
    ) -> Result<String> {
        // Calculate actual fee
        let fee = self.calculate_execute_fee(
            alkane_outpoints,
            gathered_utxos,
            account,
            signer,
            protostone,
            fee_rate,
        ).await?;
        
        // Create PSBT
        let mut psbt = self.create_execute_psbt(
            alkane_outpoints,
            gathered_utxos,
            account,
            protostone,
            fee_rate,
            Some(fee),
        ).await?;
        
        // Sign PSBT
        signer.sign_psbt(&mut psbt)?;
        
        // Extract transaction
        let tx = psbt.extract_tx();
        
        // Broadcast transaction
        let tx_hex = hex::encode(bdk::bitcoin::consensus::serialize(&tx));
        let result = self.rpc_client._call(
            "btc_sendrawtransaction",
            serde_json::json!([tx_hex]),
        ).await?;
        
        // Get transaction ID
        let txid = tx.txid().to_string();
        
        Ok(txid)
    }
    
    /// Calculate fee for executing an Alkanes contract
    pub async fn calculate_execute_fee(
        &self,
        alkane_outpoints: Option<&[AlkanesOutpoint]>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        protostone: &[u8],
        fee_rate: f64,
    ) -> Result<u64> {
        // Create initial PSBT
        let mut psbt = self.create_execute_psbt(
            alkane_outpoints,
            gathered_utxos,
            account,
            protostone,
            fee_rate,
            None,
        ).await?;
        
        // Sign PSBT
        signer.sign_psbt(&mut psbt)?;
        
        // Extract transaction
        let tx = psbt.extract_tx();
        
        // Calculate vsize
        let vsize = tx.vsize();
        
        // Calculate fee
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
        
        // Ensure minimum fee
        if fee < 250 {
            Ok(250)
        } else {
            Ok(fee)
        }
    }
    
    /// Deploy an Alkanes contract
    pub async fn deploy_contract(
        &self,
        payload: &AlkanesPayload,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        fee_rate: f64,
    ) -> Result<(String, String)> {
        // TODO: Implement contract deployment
        // This is a placeholder implementation
        
        Err(anyhow!("Contract deployment not yet implemented"))
    }
    
    /// Create a protostone for an Alkanes contract
    pub fn create_protostone(protocol_tag: u8, message: &[u8]) -> Result<Vec<u8>> {
        // Create OP_RETURN script with protocol tag and message
        let mut script_data = Vec::new();
        
        // Add OP_RETURN opcode
        script_data.push(0x6a); // OP_RETURN
        
        // Add protocol tag
        script_data.push(0x01); // Push 1 byte
        script_data.push(protocol_tag);
        
        // Add message
        if !message.is_empty() {
            // If message is longer than 75 bytes, use OP_PUSHDATA1
            if message.len() <= 75 {
                script_data.push(message.len() as u8); // Push N bytes
            } else {
                script_data.push(0x4c); // OP_PUSHDATA1
                script_data.push(message.len() as u8);
            }
            
            // Add message data
            script_data.extend_from_slice(message);
        }
        
        Ok(script_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // TODO: Add tests for Alkanes functionality
}
