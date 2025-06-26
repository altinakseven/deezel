//! Generic RPC management

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Address, Transaction, Txid};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::traits::RpcClientLike;

/// RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub bitcoin_rpc_url: String,
    pub ord_rpc_url: Option<String>,
    pub esplora_url: Option<String>,
    pub metashrew_url: Option<String>,
    pub timeout_ms: u64,
    pub max_retries: u32,
}

/// RPC management errors
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Request timeout")]
    Timeout,
    
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    
    #[error("RPC error: {0}")]
    RpcError(String),
}

/// Generic RPC manager
pub struct RpcManager<RC>
where
    RC: RpcClientLike,
{
    client: RC,
    config: RpcConfig,
}

impl<RC> RpcManager<RC>
where
    RC: RpcClientLike,
{
    pub fn new(client: RC, config: RpcConfig) -> Self {
        Self { client, config }
    }
    
    pub async fn get_block_height(&self) -> Result<u64, RpcError> {
        self.client.get_block_height().await
            .map_err(|e| RpcError::RpcError(format!("{:?}", e)))
    }
    
    pub async fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, RpcError> {
        self.client.get_transaction(txid).await
            .map_err(|e| RpcError::RpcError(format!("{:?}", e)))
    }
    
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
        self.client.broadcast_transaction(tx).await
            .map_err(|e| RpcError::RpcError(format!("{:?}", e)))
    }
    
    pub async fn get_address_balance(&self, address: &Address) -> Result<u64, RpcError> {
        self.client.get_address_balance(address).await
            .map_err(|e| RpcError::RpcError(format!("{:?}", e)))
    }
    
    pub async fn get_address_utxos(&self, address: &Address) -> Result<Vec<serde_json::Value>, RpcError> {
        self.client.get_address_utxos(address).await
            .map_err(|e| RpcError::RpcError(format!("{:?}", e)))
    }
}