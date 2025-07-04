//! Alkanes smart contract functionality
//!
//! This module provides comprehensive alkanes smart contract interaction capabilities,
//! including contract deployment, token operations, AMM/DEX functionality, and simulation.

pub mod contract;
pub mod token;
pub mod amm;
pub mod simulation;
pub mod inspector;
pub mod types;
pub mod execute;
pub mod envelope;

use anyhow::{Context, Result};
use log::{debug, info};
use std::sync::Arc;

use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use self::types::*;
use self::contract::ContractManager;
use self::token::TokenManager;
use self::amm::AmmManager;
use self::simulation::SimulationManager;

/// Alkanes manager for handling all alkanes operations
pub struct AlkanesManager {
    /// RPC client for blockchain interaction
    rpc_client: Arc<RpcClient>,
    /// Wallet manager for transaction signing
    wallet_manager: Arc<WalletManager>,
    /// Contract operations manager
    pub contract: ContractManager,
    /// Token operations manager
    pub token: TokenManager,
    /// AMM operations manager
    pub amm: AmmManager,
    /// Simulation manager
    pub simulation: SimulationManager,
}

impl AlkanesManager {
    /// Create a new alkanes manager
    pub fn new(rpc_client: Arc<RpcClient>, wallet_manager: Arc<WalletManager>) -> Self {
        let contract = ContractManager::new(Arc::clone(&rpc_client), Arc::clone(&wallet_manager));
        let token = TokenManager::new(Arc::clone(&rpc_client), Arc::clone(&wallet_manager));
        let amm = AmmManager::new(Arc::clone(&rpc_client), Arc::clone(&wallet_manager));
        let simulation = SimulationManager::new(Arc::clone(&rpc_client), Arc::clone(&wallet_manager));
        
        Self {
            rpc_client,
            wallet_manager,
            contract,
            token,
            amm,
            simulation,
        }
    }

    /// Get alkanes balance for an address
    pub async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkaneBalance>> {
        let addr = match address {
            Some(a) => a.to_string(),
            None => self.wallet_manager.get_address().await?,
        };

        info!("Getting alkanes balance for address: {}", addr);
        
        let result = self.rpc_client.get_protorunes_by_address(&addr).await?;
        
        let mut balances = Vec::new();
        
        if let Some(runes_array) = result.as_array() {
            for rune in runes_array {
                if let Some(rune_obj) = rune.as_object() {
                    let name = rune_obj.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    
                    let symbol = rune_obj.get("symbol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    let balance = rune_obj.get("balance")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0);
                    
                    let alkane_id = rune_obj.get("id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| parse_alkane_id(s).ok())
                        .unwrap_or(AlkaneId { block: 0, tx: 0 });
                    
                    balances.push(AlkaneBalance {
                        alkane_id,
                        name,
                        symbol,
                        balance,
                    });
                }
            }
        }
        
        Ok(balances)
    }

    /// Get token information
    pub async fn get_token_info(&self, alkane_id: &AlkaneId) -> Result<TokenInfo> {
        self.token.get_token_info(alkane_id).await
    }

    /// Trace an alkanes transaction
    pub async fn trace_transaction(&self, txid: &str, vout: u32) -> Result<serde_json::Value> {
        info!("Tracing alkanes transaction: {}:{}", txid, vout);
        self.rpc_client.trace_transaction(txid, vout as usize).await
    }

    /// Get the RPC client
    pub fn get_rpc_client(&self) -> Arc<RpcClient> {
        Arc::clone(&self.rpc_client)
    }

    /// Get the wallet manager
    pub fn get_wallet_manager(&self) -> Arc<WalletManager> {
        Arc::clone(&self.wallet_manager)
    }
}

/// Parse alkane ID from string format "block:tx"
pub fn parse_alkane_id(s: &str) -> Result<AlkaneId> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid alkane ID format. Expected 'block:tx'"));
    }
    
    let block = parts[0].parse::<u64>()
        .context("Invalid block number")?;
    let tx = parts[1].parse::<u64>()
        .context("Invalid transaction number")?;
    
    Ok(AlkaneId { block, tx })
}

/// Format alkane ID to string
pub fn format_alkane_id(alkane_id: &AlkaneId) -> String {
    format!("{}:{}", alkane_id.block, alkane_id.tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alkane_id() {
        let id = parse_alkane_id("123:456").unwrap();
        assert_eq!(id.block, 123);
        assert_eq!(id.tx, 456);
    }

    #[test]
    fn test_format_alkane_id() {
        let id = AlkaneId { block: 123, tx: 456 };
        assert_eq!(format_alkane_id(&id), "123:456");
    }

    #[test]
    fn test_parse_invalid_alkane_id() {
        assert!(parse_alkane_id("invalid").is_err());
        assert!(parse_alkane_id("123").is_err());
        assert!(parse_alkane_id("123:456:789").is_err());
    }
}