//! HTTP RPC adapter implementations for CLI environment

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{Address, Block, Transaction, Txid};
use deezel_core::traits::{RpcClientLike, BlockchainClientLike};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

/// HTTP RPC client adapter
pub struct HttpRpcClient {
    client: reqwest::Client,
    base_url: String,
    timeout: std::time::Duration,
}

impl HttpRpcClient {
    pub fn new(base_url: String, timeout_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            client,
            base_url,
            timeout: std::time::Duration::from_millis(timeout_ms),
        }
    }
}

#[async_trait]
impl RpcClientLike for HttpRpcClient {
    type Error = Error;

    async fn call_rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Self::Error> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self.client
            .post(&self.base_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        if let Some(error) = json.get("error") {
            return Err(Error::new(ErrorKind::Other, format!("RPC error: {}", error)));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "No result in RPC response"))
    }

    async fn get_block_height(&self) -> Result<u64, Self::Error> {
        let result = self.call_rpc("getblockcount", serde_json::Value::Array(vec![])).await?;
        result.as_u64()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid block height"))
    }

    async fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, Self::Error> {
        let params = serde_json::json!([txid.to_string(), true]);
        match self.call_rpc("getrawtransaction", params).await {
            Ok(result) => {
                let hex = result.get("hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::new(ErrorKind::InvalidData, "No hex in transaction"))?;
                
                let tx_bytes = hex::decode(hex)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                
                let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                
                Ok(Some(tx))
            }
            Err(_) => Ok(None), // Transaction not found
        }
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid, Self::Error> {
        let tx_hex = hex::encode(bitcoin::consensus::serialize(tx));
        let params = serde_json::json!([tx_hex]);
        let result = self.call_rpc("sendrawtransaction", params).await?;
        
        let txid_str = result.as_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid txid response"))?;
        
        txid_str.parse()
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
    }

    async fn get_address_balance(&self, address: &Address) -> Result<u64, Self::Error> {
        // This would typically use an esplora endpoint or similar
        // For now, return a placeholder
        Ok(0)
    }

    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<serde_json::Value>, Self::Error> {
        // This would typically use an esplora endpoint or similar
        // For now, return empty
        Ok(vec![])
    }
}

/// HTTP blockchain client adapter
pub struct HttpBlockchainClient {
    client: reqwest::Client,
    base_url: String,
}

impl HttpBlockchainClient {
    pub fn new(base_url: String, timeout_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            client,
            base_url,
        }
    }

    async fn call_rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Error> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self.client
            .post(&self.base_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        if let Some(error) = json.get("error") {
            return Err(Error::new(ErrorKind::Other, format!("RPC error: {}", error)));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "No result in RPC response"))
    }
}

#[async_trait]
impl BlockchainClientLike for HttpBlockchainClient {
    type Error = Error;

    async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Self::Error> {
        // Get block hash first
        let params = serde_json::json!([height]);
        let hash_result = self.call_rpc("getblockhash", params).await?;
        let block_hash = hash_result.as_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid block hash"))?;

        self.get_block_by_hash(block_hash).await
    }

    async fn get_block_by_hash(&self, hash: &str) -> Result<Option<Block>, Self::Error> {
        let params = serde_json::json!([hash, 0]); // 0 = raw block data
        match self.call_rpc("getblock", params).await {
            Ok(result) => {
                let hex = result.as_str()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid block hex"))?;
                
                let block_bytes = hex::decode(hex)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                
                let block: Block = bitcoin::consensus::deserialize(&block_bytes)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
                
                Ok(Some(block))
            }
            Err(_) => Ok(None), // Block not found
        }
    }

    async fn get_tip_height(&self) -> Result<u64, Self::Error> {
        let result = self.call_rpc("getblockcount", serde_json::Value::Array(vec![])).await?;
        result.as_u64()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid block height"))
    }

    async fn get_fee_estimates(&self) -> Result<HashMap<String, f64>, Self::Error> {
        let result = self.call_rpc("estimatesmartfee", serde_json::json!([6])).await?;
        let mut estimates = HashMap::new();
        
        if let Some(feerate) = result.get("feerate").and_then(|v| v.as_f64()) {
            estimates.insert("6".to_string(), feerate);
        }
        
        Ok(estimates)
    }
}