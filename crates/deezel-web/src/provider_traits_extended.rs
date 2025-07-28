//! Esplora, Runestone, Alkanes, and Monitor provider implementations for WebProvider
//
// This module contains the remaining trait implementations for WebProvider
// that couldn't fit in the main provider.rs file due to size constraints.

use async_trait::async_trait;
use bitcoin::{
    secp256k1::{schnorr::Signature, All, Secp256k1, Message},
    OutPoint, TxOut,
};
use deezel_common::{*, alkanes::{AlkanesInspectConfig, AlkanesInspectResult, AlkaneBalance}};
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

// EsploraProvider implementation is now in provider.rs
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
    async fn execute(&mut self, params: deezel_common::alkanes::types::EnhancedExecuteParams) -> Result<deezel_common::alkanes::types::ExecutionState> {
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_execute", serde_json::to_value(params)?, 1).await?;
        serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn resume_execution(
        &mut self,
        _state: deezel_common::alkanes::types::ReadyToSignTx,
        _params: &deezel_common::alkanes::types::EnhancedExecuteParams,
    ) -> Result<deezel_common::alkanes::types::EnhancedExecuteResult> {
        unimplemented!("resume_execution is not implemented for WebProvider")
    }

    async fn resume_commit_execution(
        &mut self,
        _state: deezel_common::alkanes::types::ReadyToSignCommitTx,
    ) -> Result<deezel_common::alkanes::types::ExecutionState> {
        unimplemented!("resume_commit_execution is not implemented for WebProvider")
    }

    async fn resume_reveal_execution(
        &mut self,
        _state: deezel_common::alkanes::types::ReadyToSignRevealTx,
    ) -> Result<deezel_common::alkanes::types::EnhancedExecuteResult> {
        unimplemented!("resume_reveal_execution is not implemented for WebProvider")
    }

    async fn protorunes_by_address(&self, _address: &str, _block_tag: Option<String>, _protocol_tag: u128) -> Result<deezel_common::alkanes::protorunes::ProtoruneWalletResponse> {
        unimplemented!()
    }

    async fn protorunes_by_outpoint(&self, _txid: &str, _vout: u32, _block_tag: Option<String>, _protocol_tag: u128) -> Result<deezel_common::alkanes::protorunes::ProtoruneOutpointResponse> {
        unimplemented!()
    }

    async fn simulate(&self, _contract_id: &str, _params: Option<&str>) -> Result<JsonValue> {
        unimplemented!()
    }

    async fn trace(&self, _outpoint: &str) -> Result<alkanes_support::proto::alkanes::Trace> {
        unimplemented!()
    }

    async fn get_block(&self, _height: u64) -> Result<alkanes_support::proto::alkanes::BlockResponse> {
        unimplemented!()
    }

    async fn sequence(&self, _txid: &str, _vout: u32) -> Result<JsonValue> {
        unimplemented!()
    }

    async fn spendables_by_address(&self, _address: &str) -> Result<JsonValue> {
        unimplemented!()
    }

    async fn trace_block(&self, _height: u64) -> Result<alkanes_support::proto::alkanes::Trace> {
        unimplemented!()
    }

    async fn get_bytecode(&self, _alkane_id: &str) -> Result<String> {
        unimplemented!()
    }

    async fn inspect(&self, _target: &str, _config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        unimplemented!()
    }

    async fn get_balance(&self, _address: Option<&str>) -> Result<Vec<AlkaneBalance>> {
        unimplemented!()
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
// OrdProvider implementation
#[async_trait(?Send)]
impl OrdProvider for WebProvider {
    async fn get_inscription(&self, inscription_id: &str) -> Result<ord::Inscription> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_getInscription", serde_json::json!([inscription_id]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_inscriptions_in_block(&self, block_hash: &str) -> Result<ord::Inscriptions> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_getInscriptionsInBlock", serde_json::json!([block_hash]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_ord_address_info(&self, address: &str) -> Result<ord::AddressInfo> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_address", serde_json::json!([address]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_block_info(&self, query: &str) -> Result<ord::Block> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_block", serde_json::json!([query]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_ord_block_count(&self) -> Result<u64> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_blockCount", serde_json::json!([]), 1).await?;
        json.as_u64().ok_or_else(|| DeezelError::RpcError("Invalid block count response".to_string()))
    }

    async fn get_ord_blocks(&self) -> Result<ord::Blocks> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_blocks", serde_json::json!([]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_children(&self, inscription_id: &str, page: Option<u32>) -> Result<ord::Children> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_children", serde_json::json!([inscription_id, page]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_content(&self, inscription_id: &str) -> Result<Vec<u8>> {
        let result = self.call(self.sandshrew_rpc_url(), "ord_content", serde_json::json!([inscription_id]), 1).await?;
        let hex_str = result.as_str().ok_or_else(|| DeezelError::RpcError("Invalid content response".to_string()))?;
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_inscriptions(&self, page: Option<u32>) -> Result<ord::Inscriptions> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_inscriptions", serde_json::json!([page]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_output(&self, output: &str) -> Result<ord::Output> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_output", serde_json::json!([output]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_parents(&self, inscription_id: &str, page: Option<u32>) -> Result<ord::ParentInscriptions> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_parents", serde_json::json!([inscription_id, page]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_rune(&self, rune: &str) -> Result<ord::RuneInfo> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_rune", serde_json::json!([rune]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_runes(&self, page: Option<u32>) -> Result<ord::Runes> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_runes", serde_json::json!([page]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_sat(&self, sat: u64) -> Result<ord::SatResponse> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_sat", serde_json::json!([sat]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_tx_info(&self, txid: &str) -> Result<ord::TxInfo> {
        let json = self.call(self.sandshrew_rpc_url(), "ord_tx", serde_json::json!([txid]), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }
}

#[async_trait(?Send)]
impl MetashrewProvider for WebProvider {
    async fn get_height(&self) -> Result<u64> {
        Err(DeezelError::NotImplemented("Metashrew operations not implemented for web provider".to_string()))
    }
    async fn get_block_hash(&self, _height: u64) -> Result<String> {
        Err(DeezelError::NotImplemented("Metashrew operations not implemented for web provider".to_string()))
    }
    async fn get_state_root(&self, _height: JsonValue) -> Result<String> {
        Err(DeezelError::NotImplemented("Metashrew operations not implemented for web provider".to_string()))
    }
}

// DeezelProvider implementation
#[async_trait(?Send)]
impl KeystoreProvider for WebProvider {
    async fn derive_addresses(&self, _master_public_key: &str, _network: Network, _script_types: &[&str], _start_index: u32, _count: u32) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for web provider".to_string()))
    }
    
    async fn get_default_addresses(&self, _master_public_key: &str, _network: Network) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for web provider".to_string()))
    }
    
    fn parse_address_range(&self, _range_spec: &str) -> Result<(String, u32, u32)> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for web provider".to_string()))
    }
    
    async fn get_keystore_info(&self, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for web provider".to_string()))
    }
    async fn get_address(&self, _address_type: &str, _index: u32) -> Result<String> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for web provider".to_string()))
    }
}

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

    fn secp(&self) -> &Secp256k1<All> {
        todo!()
    }

    async fn get_utxo(&self, _outpoint: &OutPoint) -> Result<Option<TxOut>> {
        todo!()
    }

    async fn sign_taproot_script_spend(&self, _msg: Message) -> Result<Signature> {
        todo!()
    }
    fn get_bitcoin_rpc_url(&self) -> Option<String> {
        Some(self.sandshrew_rpc_url().to_string())
    }
    fn get_esplora_api_url(&self) -> Option<String> {
        self.esplora_rpc_url().map(|s| s.to_string())
    }
    fn get_ord_server_url(&self) -> Option<String> {
        Some(self.sandshrew_rpc_url().to_string())
    }
}