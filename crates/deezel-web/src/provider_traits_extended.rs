//! Esplora, Runestone, Alkanes, and Monitor provider implementations for WebProvider
//
// This module contains the remaining trait implementations for WebProvider
// that couldn't fit in the main provider.rs file due to size constraints.

use async_trait::async_trait;
use deezel_common::*;
use serde_json::Value as JsonValue;

#[cfg(target_arch = "wasm32")]
use alloc::{
    vec::Vec,
    boxed::Box,
    string::{String, ToString},
};

#[cfg(not(target_arch = "wasm32"))]
use std::{
    vec::Vec,
    boxed::Box,
    string::String,
};

use crate::provider::WebProvider;

// EsploraProvider implementation
#[async_trait(?Send)]
impl EsploraProvider for WebProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_blocks:tip:hash", serde_json::json!([]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_blocks_tip_height(&self) -> Result<u64> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_blocks:tip:height", serde_json::json!([]), 1).await?;
        Ok(result.as_u64().unwrap_or_default())
    }

    async fn get_block_by_height(&self, height: u64) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_block:height", serde_json::json!([height]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }
    
    async fn get_address_utxo(&self, address: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_address::utxo", serde_json::json!([address]), 1).await
    }

    async fn get_address_txs(&self, address: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_address::txs", serde_json::json!([address]), 1).await
    }

    async fn get_tx(&self, txid: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_tx", serde_json::json!([txid]), 1).await
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_broadcast", serde_json::json!([tx_hex]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_fee_estimates(&self) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_fee:estimates", serde_json::json!([]), 1).await
    }

    async fn get_address(&self, address: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_address", serde_json::json!([address]), 1).await
    }

    async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_tx::hex", serde_json::json!([txid]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_block(&self, hash: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_block", serde_json::json!([hash]), 1).await
    }

    async fn get_block_status(&self, hash: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_block::status", serde_json::json!([hash]), 1).await
    }

    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<JsonValue> {
        let params = if let Some(start) = start_index {
            serde_json::json!([hash, start])
        } else {
            serde_json::json!([hash])
        };
        self.call(self.sandshrew_rpc_url(), "esplora_block::txs", params, 1).await
    }
    async fn get_block_txids(&self, hash: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_block::txids", serde_json::json!([hash]), 1).await
    }


    async fn get_tx_status(&self, txid: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_tx::status", serde_json::json!([txid]), 1).await
    }

    async fn get_blocks(&self, start_height: Option<u64>) -> Result<JsonValue> {
        let params = if let Some(height) = start_height {
            serde_json::json!([height])
        } else {
            serde_json::json!([])
        };
        self.call(self.sandshrew_rpc_url(), "esplora_blocks", params, 1).await
    }

    async fn get_block_header(&self, hash: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_block::header", serde_json::json!([hash]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_block_raw(&self, hash: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_block::raw", serde_json::json!([hash]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_block::txid", serde_json::json!([hash, index]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<JsonValue> {
        let params = if let Some(txid) = last_seen_txid {
            serde_json::json!([address, txid])
        } else {
            serde_json::json!([address])
        };
        self.call(self.sandshrew_rpc_url(), "esplora_address::txs:chain", params, 1).await
    }

    async fn get_address_txs_mempool(&self, address: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_address::txs:mempool", serde_json::json!([address]), 1).await
    }

    async fn get_address_prefix(&self, prefix: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_address:prefix", serde_json::json!([prefix]), 1).await
    }

    async fn get_tx_raw(&self, txid: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_tx::raw", serde_json::json!([txid]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_tx::merkle:proof", serde_json::json!([txid]), 1).await
    }

    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "esplora_tx::merkleblock:proof", serde_json::json!([txid]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_tx::outspend", serde_json::json!([txid, index]), 1).await
    }

    async fn get_tx_outspends(&self, txid: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_tx::outspends", serde_json::json!([txid]), 1).await
    }

    async fn get_mempool(&self) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_mempool", serde_json::json!([]), 1).await
    }

    async fn get_mempool_txids(&self) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_mempool::txids", serde_json::json!([]), 1).await
    }

    async fn get_mempool_recent(&self) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "esplora_mempool::recent", serde_json::json!([]), 1).await
    }
}
// RunestoneProvider implementation
#[async_trait(?Send)]
impl RunestoneProvider for WebProvider {
    async fn decode_runestone(&self, tx: &bitcoin::Transaction) -> Result<JsonValue> {
        let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
        self.call(self.sandshrew_rpc_url(), "runestone_decode", serde_json::json!([tx_hex]), 1).await
    }

    async fn format_runestone_with_decoded_messages(&self, tx: &bitcoin::Transaction) -> Result<JsonValue> {
        let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
        self.call(self.sandshrew_rpc_url(), "runestone_format", serde_json::json!([tx_hex]), 1).await
    }

    async fn analyze_runestone(&self, txid: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "runestone_analyze", serde_json::json!([txid]), 1).await
    }
}
// AlkanesProvider implementation
#[async_trait(?Send)]
impl AlkanesProvider for WebProvider {
    async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_execute", serde_json::to_value(params)?, 1).await?;
        serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        let params = if let Some(addr) = address {
            serde_json::json!([addr])
        } else {
            serde_json::json!([])
        };
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_balance", params, 1).await?;
        serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_token_info(&self, alkane_id: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "alkanes_token_info", serde_json::json!([alkane_id]), 1).await
    }

    async fn get_alkanes_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
       let params = if let Some(addr) = address {
           serde_json::json!([addr])
       } else {
           serde_json::json!([])
       };
       let result = self.call(self.sandshrew_rpc_url(), "alkanes_balance", params, 1).await?;
       serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

    async fn trace(&self, outpoint: &str) -> Result<JsonValue> {
        self.call(self.sandshrew_rpc_url(), "alkanes_trace", serde_json::json!([outpoint]), 1).await
    }

    async fn inspect(&self, target: &str, config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_inspect", serde_json::json!([target, config]), 1).await?;
        serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_bytecode(&self, alkane_id: &str) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_bytecode", serde_json::json!([alkane_id]), 1).await?;
        Ok(result.as_str().unwrap_or_default().to_string())
    }

    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue> {
        let p = if let Some(p_str) = params {
            serde_json::json!([contract_id, p_str])
        } else {
            serde_json::json!([contract_id])
        };
        self.call(self.sandshrew_rpc_url(), "alkanes_simulate", p, 1).await
    }
}
// MonitorProvider implementation
#[async_trait(?Send)]
impl MonitorProvider for WebProvider {
    async fn monitor_blocks(&self, start: Option<u64>) -> Result<()> {
        let params = if let Some(s) = start {
            serde_json::json!([s])
        } else {
            serde_json::json!([])
        };
        self.call(self.sandshrew_rpc_url(), "monitor_blocks", params, 1).await?;
        Ok(())
    }

    async fn get_block_events(&self, height: u64) -> Result<Vec<BlockEvent>> {
        let result = self.call(self.sandshrew_rpc_url(), "monitor_events", serde_json::json!([height]), 1).await?;
        serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }
}
// DeezelProvider implementation
#[async_trait(?Send)]
impl DeezelProvider for WebProvider {
    fn provider_name(&self) -> &str {
        "WebProvider"
    }

    async fn initialize(&self) -> Result<()> {
        // No-op for web provider
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        // No-op for web provider
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn DeezelProvider> {
        Box::new(self.clone())
    }
}