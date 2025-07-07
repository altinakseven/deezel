//! Token operations functionality

use anyhow::{Context, Result};
use log::{debug, info};
use std::sync::Arc;

use crate::rpc::RpcClient;
use crate::wallet::WalletManager;
use super::types::*;

/// Token operations manager
pub struct TokenManager {
    rpc_client: Arc<RpcClient>,
    _wallet_manager: Arc<WalletManager>,
}

impl TokenManager {
    /// Create a new token manager
    pub fn new(rpc_client: Arc<RpcClient>, wallet_manager: Arc<WalletManager>) -> Self {
        Self {
            rpc_client,
            _wallet_manager: wallet_manager,
        }
    }

    /// Deploy a new alkanes token
    pub async fn deploy_token(&self, params: TokenDeployParams) -> Result<TokenDeployResult> {
        info!("Deploying token: {} ({})", params.name, params.symbol);
        debug!("Token parameters: cap={}, amount_per_mint={}, reserve_number={}", 
               params.cap, params.amount_per_mint, params.reserve_number);
        
        // For now, return a placeholder result
        // In a real implementation, this would:
        // 1. Create a transaction that deploys the token contract
        // 2. Include token metadata in the transaction
        // 3. Handle premine if specified
        // 4. Sign and broadcast the transaction
        
        let token_id = AlkaneId { block: 0, tx: 0 };
        let txid = "placeholder_token_deploy_txid".to_string();
        let fee = 2000; // Placeholder fee
        
        Ok(TokenDeployResult {
            token_id,
            txid,
            fee,
        })
    }

    /// Send alkanes tokens
    pub async fn send_token(&self, params: TokenSendParams) -> Result<TransactionResult> {
        info!("Sending {} units of token {}:{} to {}", 
              params.amount, params.token.block, params.token.tx, params.to);
        
        // Validate recipient address
        if params.to.is_empty() {
            return Err(anyhow::anyhow!("Recipient address cannot be empty"));
        }
        
        // For now, return a placeholder result
        // In a real implementation, this would:
        // 1. Check token balance
        // 2. Create a transaction with protostone edicts
        // 3. Sign and broadcast the transaction
        
        let txid = "placeholder_token_send_txid".to_string();
        let fee = 1000; // Placeholder fee
        
        Ok(TransactionResult { txid, fee })
    }

    /// Get token information
    pub async fn get_token_info(&self, token_id: &AlkaneId) -> Result<TokenInfo> {
        info!("Getting token info for: {}:{}", token_id.block, token_id.tx);
        
        // Use the trace method to get token information
        let trace_result = self.rpc_client.trace_transaction(
            &format!("{}:{}", token_id.block, token_id.tx), 
            0
        ).await?;
        
        debug!("Trace result: {}", serde_json::to_string_pretty(&trace_result)?);
        
        // Parse the trace result to extract token information
        // This is a simplified implementation - in practice, you'd need to decode the actual contract state
        Ok(TokenInfo {
            alkane_id: token_id.clone(),
            name: "Unknown Token".to_string(),
            symbol: "UNK".to_string(),
            total_supply: 0,
            cap: 0,
            amount_per_mint: 0,
            minted: 0,
        })
    }

    /// Get token balance for an address
    pub async fn get_token_balance(&self, token_id: &AlkaneId, address: &str) -> Result<u64> {
        info!("Getting balance for token {}:{} at address {}", 
              token_id.block, token_id.tx, address);
        
        let result = self.rpc_client.get_protorunes_by_address(address).await?;
        
        if let Some(runes_array) = result.as_array() {
            for rune in runes_array {
                if let Some(rune_obj) = rune.as_object() {
                    // Check if this is the token we're looking for
                    if let Some(id_str) = rune_obj.get("id").and_then(|v| v.as_str()) {
                        if let Ok(alkane_id) = super::parse_alkane_id(id_str) {
                            if alkane_id.block == token_id.block && alkane_id.tx == token_id.tx {
                                return Ok(rune_obj.get("balance")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(0));
                            }
                        }
                    }
                }
            }
        }
        
        Ok(0) // Token not found or no balance
    }
}

/// Parse token amounts from string format "block:tx:amount,block:tx:amount,..."
pub fn parse_token_amounts(tokens_str: &str) -> Result<Vec<TokenAmount>> {
    let mut token_amounts = Vec::new();
    
    for token_part in tokens_str.split(',') {
        let parts: Vec<&str> = token_part.trim().split(':').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid token amount format. Expected 'block:tx:amount'"));
        }
        
        let block = parts[0].parse::<u64>()
            .context("Invalid block number in token amount")?;
        let tx = parts[1].parse::<u64>()
            .context("Invalid transaction number in token amount")?;
        let amount = parts[2].parse::<u64>()
            .context("Invalid amount in token amount")?;
        
        token_amounts.push(TokenAmount {
            alkane_id: AlkaneId { block, tx },
            amount,
        });
    }
    
    Ok(token_amounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_token_amounts() {
        let amounts = parse_token_amounts("123:456:1000,789:012:2000").unwrap();
        assert_eq!(amounts.len(), 2);
        
        assert_eq!(amounts[0].alkane_id.block, 123);
        assert_eq!(amounts[0].alkane_id.tx, 456);
        assert_eq!(amounts[0].amount, 1000);
        
        assert_eq!(amounts[1].alkane_id.block, 789);
        assert_eq!(amounts[1].alkane_id.tx, 12);
        assert_eq!(amounts[1].amount, 2000);
    }

    #[test]
    fn test_parse_invalid_token_amounts() {
        assert!(parse_token_amounts("invalid").is_err());
        assert!(parse_token_amounts("123:456").is_err());
        assert!(parse_token_amounts("123:456:1000:extra").is_err());
    }

    #[test]
    fn test_parse_empty_token_amounts() {
        let amounts = parse_token_amounts("").unwrap();
        assert_eq!(amounts.len(), 0);
    }
}