//! BRC20 protocol support
//!
//! This module provides functionality for:
//! - BRC20 token deployment
//! - Token minting and transfer
//! - Balance tracking
//! - Transaction construction

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Address, Network, OutPoint, Script, Transaction, TxOut};
use bdk::bitcoin::psbt::Psbt;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use crate::account::Account;
use crate::rpc::RpcClient;
use crate::signer::Signer;
use crate::utils::{GatheredUtxos, UtxoInfo, DUST_OUTPUT_VALUE};

/// BRC20 token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Brc20Token {
    /// Token ticker
    pub ticker: String,
    /// Token name
    pub name: Option<String>,
    /// Token description
    pub description: Option<String>,
    /// Token supply
    pub supply: String,
    /// Token limit per mint
    pub limit_per_mint: Option<String>,
    /// Token decimals
    pub decimals: u8,
    /// Token minted amount
    pub minted: String,
    /// Token mint progress
    pub mint_progress: f64,
    /// Token deployment transaction ID
    pub deploy_txid: Option<String>,
    /// Token deployment block height
    pub deploy_height: Option<u32>,
}

/// BRC20 balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Brc20Balance {
    /// Token ticker
    pub ticker: String,
    /// Overall balance
    pub overall_balance: String,
    /// Available balance
    pub available_balance: String,
    /// Transferable balance
    pub transferable_balance: String,
}

/// BRC20 inscription content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Brc20InscriptionContent {
    /// Protocol
    pub p: String,
    /// Operation
    pub op: String,
    /// Ticker
    pub tick: String,
    /// Maximum supply
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
    /// Limit per mint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lim: Option<String>,
    /// Decimals
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dec: Option<u8>,
    /// Amount
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amt: Option<String>,
}

/// BRC20 operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Brc20Operation {
    /// Deploy a new token
    Deploy,
    /// Mint tokens
    Mint,
    /// Transfer tokens
    Transfer,
}

impl ToString for Brc20Operation {
    fn to_string(&self) -> String {
        match self {
            Brc20Operation::Deploy => "deploy".to_string(),
            Brc20Operation::Mint => "mint".to_string(),
            Brc20Operation::Transfer => "transfer".to_string(),
        }
    }
}

/// BRC20 manager for token operations
pub struct Brc20Manager {
    /// RPC client
    rpc_client: RpcClient,
    /// Network
    network: Network,
}

impl Brc20Manager {
    /// Create a new BRC20 manager
    pub fn new(rpc_client: RpcClient, network: Network) -> Self {
        Self {
            rpc_client,
            network,
        }
    }
    
    /// Get BRC20 token information
    pub async fn get_token_info(&self, ticker: &str) -> Result<Brc20Token> {
        // Call ord_brc20_token RPC method
        let result = self.rpc_client._call(
            "ord_brc20_token",
            serde_json::json!([ticker]),
        ).await?;
        
        // Parse response
        let ticker = result.get("ticker")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing ticker"))?
            .to_string();
        
        let name = result.get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());
        
        let description = result.get("description")
            .and_then(|d| d.as_str())
            .map(|s| s.to_string());
        
        let supply = result.get("supply")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing supply"))?
            .to_string();
        
        let limit_per_mint = result.get("limit_per_mint")
            .and_then(|l| l.as_str())
            .map(|s| s.to_string());
        
        let decimals = result.get("decimals")
            .and_then(|d| d.as_u64())
            .ok_or_else(|| anyhow!("Invalid response: missing decimals"))? as u8;
        
        let minted = result.get("minted")
            .and_then(|m| m.as_str())
            .ok_or_else(|| anyhow!("Invalid response: missing minted"))?
            .to_string();
        
        let mint_progress = result.get("mint_progress")
            .and_then(|p| p.as_f64())
            .unwrap_or(0.0);
        
        let deploy_txid = result.get("deploy_txid")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        
        let deploy_height = result.get("deploy_height")
            .and_then(|h| h.as_u64())
            .map(|h| h as u32);
        
        Ok(Brc20Token {
            ticker,
            name,
            description,
            supply,
            limit_per_mint,
            decimals,
            minted,
            mint_progress,
            deploy_txid,
            deploy_height,
        })
    }
    
    /// Get BRC20 balances for an address
    pub async fn get_balances(&self, address: &str) -> Result<Vec<Brc20Balance>> {
        // Call ord_brc20_balances RPC method
        let result = self.rpc_client._call(
            "ord_brc20_balances",
            serde_json::json!([address]),
        ).await?;
        
        // Parse response
        let balances = result.as_array()
            .ok_or_else(|| anyhow!("Invalid response: expected array"))?;
        
        let mut brc20_balances = Vec::new();
        
        for balance in balances {
            let ticker = balance.get("ticker")
                .and_then(|t| t.as_str())
                .ok_or_else(|| anyhow!("Invalid balance: missing ticker"))?
                .to_string();
            
            let overall_balance = balance.get("overall_balance")
                .and_then(|b| b.as_str())
                .ok_or_else(|| anyhow!("Invalid balance: missing overall_balance"))?
                .to_string();
            
            let available_balance = balance.get("available_balance")
                .and_then(|b| b.as_str())
                .ok_or_else(|| anyhow!("Invalid balance: missing available_balance"))?
                .to_string();
            
            let transferable_balance = balance.get("transferable_balance")
                .and_then(|b| b.as_str())
                .ok_or_else(|| anyhow!("Invalid balance: missing transferable_balance"))?
                .to_string();
            
            brc20_balances.push(Brc20Balance {
                ticker,
                overall_balance,
                available_balance,
                transferable_balance,
            });
        }
        
        Ok(brc20_balances)
    }
    
    /// Create BRC20 inscription content
    pub fn create_inscription_content(
        operation: Brc20Operation,
        ticker: &str,
        amount: Option<&str>,
        max_supply: Option<&str>,
        limit_per_mint: Option<&str>,
        decimals: Option<u8>,
    ) -> Result<String> {
        let mut content = Brc20InscriptionContent {
            p: "brc-20".to_string(),
            op: operation.to_string(),
            tick: ticker.to_string(),
            max: None,
            lim: None,
            dec: None,
            amt: None,
        };
        
        match operation {
            Brc20Operation::Deploy => {
                content.max = max_supply.map(|s| s.to_string());
                content.lim = limit_per_mint.map(|l| l.to_string());
                content.dec = decimals;
            },
            Brc20Operation::Mint | Brc20Operation::Transfer => {
                content.amt = amount.map(|a| a.to_string());
            },
        }
        
        // Serialize to JSON
        let json = serde_json::to_string(&content)
            .context("Failed to serialize BRC20 inscription content")?;
        
        Ok(json)
    }
    
    /// Create a PSBT for a BRC20 operation
    pub async fn create_operation_psbt(
        &self,
        operation: Brc20Operation,
        ticker: &str,
        amount: Option<&str>,
        max_supply: Option<&str>,
        limit_per_mint: Option<&str>,
        decimals: Option<u8>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        fee_rate: f64,
    ) -> Result<Psbt> {
        // Create inscription content
        let content = Self::create_inscription_content(
            operation,
            ticker,
            amount,
            max_supply,
            limit_per_mint,
            decimals,
        )?;
        
        // TODO: Implement inscription creation
        // This is a placeholder implementation
        
        Err(anyhow!("BRC20 operation not yet implemented"))
    }
    
    /// Deploy a new BRC20 token
    pub async fn deploy(
        &self,
        ticker: &str,
        max_supply: &str,
        limit_per_mint: Option<&str>,
        decimals: Option<u8>,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        fee_rate: f64,
    ) -> Result<String> {
        // Create PSBT
        let mut psbt = self.create_operation_psbt(
            Brc20Operation::Deploy,
            ticker,
            None,
            Some(max_supply),
            limit_per_mint,
            decimals,
            gathered_utxos,
            account,
            fee_rate,
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
    
    /// Mint BRC20 tokens
    pub async fn mint(
        &self,
        ticker: &str,
        amount: &str,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        fee_rate: f64,
    ) -> Result<String> {
        // Create PSBT
        let mut psbt = self.create_operation_psbt(
            Brc20Operation::Mint,
            ticker,
            Some(amount),
            None,
            None,
            None,
            gathered_utxos,
            account,
            fee_rate,
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
    
    /// Transfer BRC20 tokens
    pub async fn transfer(
        &self,
        ticker: &str,
        amount: &str,
        gathered_utxos: &GatheredUtxos,
        account: &Account,
        signer: &Signer,
        fee_rate: f64,
    ) -> Result<String> {
        // Create PSBT
        let mut psbt = self.create_operation_psbt(
            Brc20Operation::Transfer,
            ticker,
            Some(amount),
            None,
            None,
            None,
            gathered_utxos,
            account,
            fee_rate,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_inscription_content() {
        // Test deploy operation
        let content = Brc20Manager::create_inscription_content(
            Brc20Operation::Deploy,
            "TEST",
            None,
            Some("1000"),
            Some("10"),
            Some(8),
        ).unwrap();
        
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["p"], "brc-20");
        assert_eq!(json["op"], "deploy");
        assert_eq!(json["tick"], "TEST");
        assert_eq!(json["max"], "1000");
        assert_eq!(json["lim"], "10");
        assert_eq!(json["dec"], 8);
        
        // Test mint operation
        let content = Brc20Manager::create_inscription_content(
            Brc20Operation::Mint,
            "TEST",
            Some("10"),
            None,
            None,
            None,
        ).unwrap();
        
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["p"], "brc-20");
        assert_eq!(json["op"], "mint");
        assert_eq!(json["tick"], "TEST");
        assert_eq!(json["amt"], "10");
        
        // Test transfer operation
        let content = Brc20Manager::create_inscription_content(
            Brc20Operation::Transfer,
            "TEST",
            Some("5"),
            None,
            None,
            None,
        ).unwrap();
        
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["p"], "brc-20");
        assert_eq!(json["op"], "transfer");
        assert_eq!(json["tick"], "TEST");
        assert_eq!(json["amt"], "5");
    }
}
