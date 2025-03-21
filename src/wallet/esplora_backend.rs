//! Custom Esplora backend implementation using Sandshrew RPC
//!
//! This module provides utility functions for interacting with the Sandshrew RPC API
//! for blockchain data.

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Transaction, Txid};
use log::{debug, info};
use std::sync::Arc;

use crate::rpc::RpcClient;

/// Custom Esplora backend using Sandshrew RPC
#[derive(Clone)]
pub struct SandshrewEsploraBackend {
    /// RPC client for Sandshrew API
    pub rpc_client: Arc<RpcClient>,
}

impl SandshrewEsploraBackend {
    /// Create a new Sandshrew Esplora backend
    pub fn new(rpc_client: Arc<RpcClient>) -> Self {
        info!("Creating Sandshrew Esplora backend");
        Self {
            rpc_client,
        }
    }
    
    /// Get transaction details from Sandshrew RPC
    pub async fn get_transaction_details(&self, txid: &Txid) -> Result<Transaction> {
        debug!("Getting transaction details for {}", txid);
        
        // Use the esplora_tx method from Sandshrew RPC
        let tx_hex = self.rpc_client._call("esplora_tx::hex", serde_json::json!([txid.to_string()])).await?;
        let tx_hex = tx_hex.as_str()
            .ok_or_else(|| anyhow!("Transaction hex not found in response"))?;
        
        let tx = hex::decode(tx_hex)
            .context("Failed to decode transaction hex")?;
        
        let transaction = bdk::bitcoin::consensus::deserialize(&tx)
            .context("Failed to deserialize transaction")?;
        
        Ok(transaction)
    }
    
    /// Get UTXOs for an address
    pub async fn get_address_utxos(&self, address: &str) -> Result<serde_json::Value> {
        debug!("Getting UTXOs for address {}", address);
        
        // Use the esplora_address::utxo method from Sandshrew RPC
        let utxos = self.rpc_client._call("esplora_address::utxo", serde_json::json!([address])).await?;
        
        Ok(utxos)
    }
    
    /// Get transaction history for an address
    pub async fn get_address_transactions(&self, address: &str) -> Result<serde_json::Value> {
        debug!("Getting transaction history for address {}", address);
        
        // Use the esplora_address::txs method from Sandshrew RPC
        let txs = self.rpc_client._call("esplora_address::txs", serde_json::json!([address])).await?;
        
        Ok(txs)
    }
    
    /// Get mempool transactions for an address
    pub async fn get_address_mempool_transactions(&self, address: &str) -> Result<serde_json::Value> {
        debug!("Getting mempool transactions for address {}", address);
        
        // Use the esplora_address::txs:mempool method from Sandshrew RPC
        let txs = self.rpc_client._call("esplora_address::txs:mempool", serde_json::json!([address])).await?;
        
        Ok(txs)
    }
    
    /// Broadcast a transaction
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<serde_json::Value> {
        debug!("Broadcasting transaction");
        
        // Use the esplora_broadcast method from Sandshrew RPC
        let result = self.rpc_client._call("esplora_broadcast", serde_json::json!([tx_hex])).await?;
        
        Ok(result)
    }
}