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

    async fn trace_outpoint_json(&self, txid: &str, vout: u32) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_trace", serde_json::json!([format!("{}:{}", txid, vout)]), 1).await?;
        serde_json::to_string(&result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn trace_outpoint_pretty(&self, txid: &str, vout: u32) -> Result<String> {
        let result = self.call(self.sandshrew_rpc_url(), "alkanes_trace", serde_json::json!([format!("{}:{}", txid, vout)]), 1).await?;
        serde_json::to_string_pretty(&result).map_err(|e| DeezelError::Serialization(e.to_string()))
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
    
    async fn get_keystore_info(&self, _master_public_key: &str, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for web provider".to_string()))
    }
}

#[async_trait(?Send)]
impl PgpProvider for WebProvider {
    async fn generate_keypair(&self, _user_id: &str, _passphrase: Option<&str>) -> Result<PgpKeyPair> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn import_key(&self, _armored_key: &str) -> Result<PgpKey> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn export_key(&self, _key: &PgpKey, _include_private: bool) -> Result<String> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn encrypt(&self, _data: &[u8], _recipient_keys: &[PgpKey], _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn decrypt(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn sign(&self, _data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn verify(&self, _data: &[u8], _signature: &[u8], _public_key: &PgpKey) -> Result<bool> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn encrypt_and_sign(&self, _data: &[u8], _recipient_keys: &[PgpKey], _signing_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn decrypt_and_verify(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _sender_public_key: &PgpKey, _passphrase: Option<&str>) -> Result<PgpDecryptResult> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn get_key(&self, _identifier: &str) -> Result<Option<PgpKey>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn delete_key(&self, _identifier: &str) -> Result<()> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
    }
    
    async fn change_passphrase(&self, _key: &PgpKey, _old_passphrase: Option<&str>, _new_passphrase: Option<&str>) -> Result<PgpKey> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for web provider".to_string()))
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
}