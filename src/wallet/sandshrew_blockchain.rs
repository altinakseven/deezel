//! Sandshrew blockchain backend for BDK
//!
//! This module implements a BDK blockchain backend that uses Sandshrew RPC
//! to sync wallet state and discover UTXOs.

use anyhow::{Context, Result};
use async_trait::async_trait;
use bdk::bitcoin::{Address, Network, OutPoint, Transaction, Txid};
use bdk::blockchain::{WalletSync, GetHeight, GetTx, GetBlockHash, Capability};
use bdk::database::BatchDatabase;
use bdk::{Error as BdkError, FeeRate, LocalUtxo, TransactionDetails, ConfirmationTime};
use log::{debug, info, warn};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use crate::rpc::RpcClient;

/// Sandshrew blockchain backend for BDK
#[derive(Clone)]
pub struct SandshrewBlockchain {
    /// RPC client for Sandshrew API
    rpc_client: Arc<RpcClient>,
    /// Bitcoin network
    network: Network,
}

impl SandshrewBlockchain {
    /// Create a new Sandshrew blockchain backend
    pub fn new(rpc_client: Arc<RpcClient>, network: Network) -> Self {
        info!("Creating Sandshrew blockchain backend for network: {:?}", network);
        Self {
            rpc_client,
            network,
        }
    }
}

#[async_trait]
impl GetHeight for SandshrewBlockchain {
    async fn get_height(&self) -> Result<u32, BdkError> {
        debug!("Getting blockchain height from Sandshrew");
        
        match self.rpc_client.get_metashrew_height().await {
            Ok(height) => {
                debug!("Current blockchain height: {}", height);
                Ok(height as u32)
            },
            Err(e) => {
                warn!("Failed to get height from Sandshrew: {}", e);
                Err(BdkError::Generic(format!("Failed to get height: {}", e)))
            }
        }
    }
}

#[async_trait]
impl GetBlockHash for SandshrewBlockchain {
    async fn get_block_hash(&self, height: u64) -> Result<bdk::bitcoin::BlockHash, BdkError> {
        debug!("Getting block hash for height: {}", height);
        
        match self.rpc_client.get_block_hash(height).await {
            Ok(hash_str) => {
                match hash_str.parse() {
                    Ok(hash) => {
                        debug!("Block hash for height {}: {}", height, hash_str);
                        Ok(hash)
                    },
                    Err(e) => {
                        warn!("Failed to parse block hash: {}", e);
                        Err(BdkError::Generic(format!("Invalid block hash: {}", e)))
                    }
                }
            },
            Err(e) => {
                warn!("Failed to get block hash from Sandshrew: {}", e);
                Err(BdkError::Generic(format!("Failed to get block hash: {}", e)))
            }
        }
    }
}

#[async_trait]
impl GetTx for SandshrewBlockchain {
    async fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, BdkError> {
        debug!("Getting transaction: {}", txid);
        
        match self.rpc_client.get_transaction_hex(&txid.to_string()).await {
            Ok(tx_hex) => {
                match hex::decode(&tx_hex) {
                    Ok(tx_bytes) => {
                        match bdk::bitcoin::consensus::deserialize::<Transaction>(&tx_bytes) {
                            Ok(tx) => {
                                debug!("Successfully retrieved transaction: {}", txid);
                                Ok(Some(tx))
                            },
                            Err(e) => {
                                warn!("Failed to deserialize transaction {}: {}", txid, e);
                                Ok(None)
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Failed to decode transaction hex for {}: {}", txid, e);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                warn!("Failed to get transaction {} from Sandshrew: {}", txid, e);
                Ok(None)
            }
        }
    }
}

#[async_trait]
impl WalletSync for SandshrewBlockchain {
    async fn wallet_sync<D: BatchDatabase>(
        &self,
        database: &mut D,
        progress_update: Box<dyn Fn(f32, Option<String>) + Send>,
    ) -> Result<(), BdkError> {
        info!("Syncing wallet with Sandshrew blockchain");
        
        // Report sync start
        progress_update(0.0, Some("Starting sync".to_string()));
        
        // Get all script pubkeys from the database
        let script_pubkeys = database.iter_script_pubkeys(None)?;
        let total_scripts = script_pubkeys.len();
        
        info!("Syncing {} script pubkeys", total_scripts);
        
        for (i, script) in script_pubkeys.iter().enumerate() {
            // Convert script to address
            if let Ok(address) = Address::from_script(script, self.network) {
                let address_str = address.to_string();
                debug!("Syncing address: {}", address_str);
                
                // Get UTXOs for this address from Sandshrew
                match self.rpc_client.get_address_utxos(&address_str).await {
                    Ok(utxos_response) => {
                        debug!("UTXOs response for {}: {:?}", address_str, utxos_response);
                        
                        // Parse UTXOs and add them to the database
                        if let Some(utxos_array) = utxos_response.as_array() {
                            for utxo in utxos_array {
                                if let Some(utxo_obj) = utxo.as_object() {
                                    // Extract UTXO information
                                    if let (Some(txid_str), Some(vout), Some(value)) = (
                                        utxo_obj.get("txid").and_then(|v| v.as_str()),
                                        utxo_obj.get("vout").and_then(|v| v.as_u64()),
                                        utxo_obj.get("value").and_then(|v| v.as_u64())
                                    ) {
                                        // Parse txid
                                        if let Ok(txid) = Txid::from_str(txid_str) {
                                            let outpoint = OutPoint {
                                                txid,
                                                vout: vout as u32,
                                            };
                                            
                                            // Create a LocalUtxo for this UTXO
                                            let local_utxo = LocalUtxo {
                                                outpoint,
                                                txout: bdk::bitcoin::TxOut {
                                                    value,
                                                    script_pubkey: script.clone(),
                                                },
                                                keychain: bdk::KeychainKind::External,
                                                is_spent: false,
                                            };
                                            
                                            // Check if confirmed
                                            let is_confirmed = utxo_obj.get("status")
                                                .and_then(|s| s.get("confirmed"))
                                                .and_then(|c| c.as_bool())
                                                .unwrap_or(false);
                                            
                                            let block_height = if is_confirmed {
                                                utxo_obj.get("status")
                                                    .and_then(|s| s.get("block_height"))
                                                    .and_then(|h| h.as_u64())
                                                    .map(|h| h as u32)
                                            } else {
                                                None
                                            };
                                            
                                            // Add UTXO to database
                                            database.set_utxo(&local_utxo)?;
                                            
                                            // Set confirmation status
                                            if let Some(height) = block_height {
                                                database.set_tx(&TransactionDetails {
                                                    transaction: None, // We don't have the full transaction
                                                    txid: outpoint.txid,
                                                    received: value,
                                                    sent: 0,
                                                    fee: None,
                                                    confirmation_time: Some(ConfirmationTime::Confirmed {
                                                        height,
                                                        time: 0, // We don't have timestamp
                                                    }),
                                                })?;
                                            }
                                            
                                            debug!("Added UTXO to database: {}:{} - {} sats", txid, vout, value);
                                        } else {
                                            warn!("Invalid txid format: {}", txid_str);
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Failed to get UTXOs for address {}: {}", address_str, e);
                    }
                }
            }
            
            // Report progress
            let progress = (i + 1) as f32 / total_scripts as f32;
            progress_update(progress * 100.0, Some(format!("Syncing address {} of {}", i + 1, total_scripts)));
        }
        
        // Report sync completion
        progress_update(100.0, Some("Sync completed".to_string()));
        info!("Wallet sync completed successfully");
        
        Ok(())
    }
}