//! The ConcreteProvider implementation for deezel.
//!
//! This module provides a concrete implementation of all provider traits
//! using deezel-rpgp for PGP operations and other concrete implementations.

use crate::traits::*;
use crate::{
    alkanes::types::{ExecutionState, ReadyToSignCommitTx, ReadyToSignRevealTx, ReadyToSignTx},
    DeezelError, JsonValue, Result,
};
use crate::ord;
use crate::alkanes::execute::EnhancedAlkanesExecutor;
#[cfg(feature = "wasm-inspection")]
use crate::alkanes::inspector::{AlkaneInspector, InspectionConfig};
use crate::alkanes::types::{
	EnhancedExecuteParams, EnhancedExecuteResult, AlkanesInspectConfig, AlkanesInspectResult,
	AlkaneBalance, AlkaneId,
};
use alkanes_support::proto::alkanes as alkanes_pb;
use protorune_support::proto::protorune as protorune_pb;
use protobuf::Message;
use std::collections::BTreeMap;
use async_trait::async_trait;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
use core::str::FromStr;
use crate::keystore::Keystore;

// Import deezel-rpgp types for PGP functionality

#[cfg(not(target_arch = "wasm32"))]
use rand::thread_rng;
#[cfg(target_arch = "wasm32")]
use rand::rngs::OsRng;

// Import Bitcoin and BIP39 for wallet functionality
use bitcoin::Network;
use bip39::{Mnemonic, MnemonicType, Seed};

// Additional imports for wallet functionality
use hex::{self, FromHex};
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
    key::{TapTweak, UntweakedKeypair},
    secp256k1::{All, Secp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};
use bitcoin_hashes::Hash;
use ordinals::{Runestone, Artifact};


/// Represents the state of the wallet within the provider
#[derive(Clone)]
pub enum WalletState {
    /// No wallet is loaded
    None,
    /// Keystore is loaded but locked (only public information is available)
    Locked(Keystore),
    /// Wallet is unlocked, with access to the decrypted mnemonic
    Unlocked {
        keystore: Keystore,
        mnemonic: String,
    },
}

#[derive(Clone)]
pub struct ConcreteProvider {
    rpc_url: String,
    metashrew_rpc_url: String,
    esplora_url: Option<String>,
    provider: String,
    #[cfg(not(target_arch = "wasm32"))]
    wallet_path: Option<PathBuf>,
    #[cfg(target_arch = "wasm32")]
    wallet_path: Option<String>,
    passphrase: Option<String>,
    wallet_state: WalletState,
    #[cfg(feature = "native-deps")]
    http_client: reqwest::Client,
    secp: Secp256k1<All>,
}

impl ConcreteProvider {
    pub async fn new(
        bitcoin_rpc_url: Option<String>,
        metashrew_rpc_url: String,
        sandshrew_rpc_url: Option<String>,
        esplora_url: Option<String>,
        provider: String,
        #[cfg(not(target_arch = "wasm32"))]
        wallet_path: Option<PathBuf>,
        #[cfg(target_arch = "wasm32")]
        wallet_path: Option<String>,
    ) -> Result<Self> {
        let rpc_url = bitcoin_rpc_url
            .or(sandshrew_rpc_url)
            .unwrap_or_else(|| {
                match provider.as_str() {
                    "mainnet" => "https://mainnet.sandshrew.io/v2/lasereyes".to_string(),
                    "testnet" => "https://testnet.sandshrew.io/v2/lasereyes".to_string(),
                    "signet" => "https://signet.sandshrew.io/v2/lasereyes".to_string(),
                    _ => "http://localhost:18888".to_string(),
                }
            });

       let mut new_self = Self {
           rpc_url,
           metashrew_rpc_url,
           esplora_url,
           provider,
           wallet_path: wallet_path.clone(),
           passphrase: None,
           wallet_state: WalletState::None,
           #[cfg(feature = "native-deps")]
           http_client: reqwest::Client::new(),
           secp: Secp256k1::new(),
       };

       // Try to load the keystore metadata if a path is provided
       #[cfg(not(target_arch = "wasm32"))]
       if let Some(path) = &wallet_path {
           if path.exists() {
               match Keystore::from_file(path) {
                   Ok(keystore) => new_self.wallet_state = WalletState::Locked(keystore),
                   Err(e) => log::warn!("Failed to load keystore metadata: {e}"),
               }
           }
       }

       Ok(new_self)
   }

   /// Unlock the wallet by decrypting the seed
   pub async fn unlock_wallet(&mut self, passphrase: &str) -> Result<()> {
       if let WalletState::Locked(keystore) = &self.wallet_state {
           let mnemonic = keystore.decrypt_mnemonic(passphrase)?;
           self.wallet_state = WalletState::Unlocked {
               keystore: keystore.clone(),
               mnemonic,
           };
           self.passphrase = Some(passphrase.to_string());
           Ok(())
       } else if let WalletState::Unlocked { .. } = &self.wallet_state {
           // Already unlocked, do nothing.
           Ok(())
       } else {
           Err(DeezelError::Wallet("Wallet is not in a locked state".to_string()))
       }
   }

    /// Get the wallet path
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_wallet_path(&self) -> Option<&PathBuf> {
        self.wallet_path.as_ref()
    }
    #[cfg(target_arch = "wasm32")]
    pub fn get_wallet_path(&self) -> Option<&String> {
        self.wallet_path.as_ref()
    }

    /// Get the current wallet state
    pub fn get_wallet_state(&self) -> &WalletState {
        &self.wallet_state
    }

    /// Get the loaded keystore, if any
    pub fn get_keystore(&self) -> Option<&Keystore> {
        match &self.wallet_state {
            WalletState::Locked(keystore) | WalletState::Unlocked { keystore, .. } => Some(keystore),
            WalletState::None => None,
        }
    }


    fn select_coins(&self, mut utxos: Vec<UtxoInfo>, target_amount: Amount) -> Result<(Vec<UtxoInfo>, Amount)> {
        utxos.sort_by(|a, b| b.amount.cmp(&a.amount)); // Largest-first

        let mut selected_utxos = Vec::new();
        let mut total_input_amount = Amount::ZERO;

        for utxo in utxos {
            if total_input_amount >= target_amount {
                break;
            }
            total_input_amount += Amount::from_sat(utxo.amount);
            selected_utxos.push(utxo);
        }

        if total_input_amount < target_amount {
            return Err(DeezelError::Wallet("Insufficient funds".to_string()));
        }

        Ok((selected_utxos, total_input_amount))
    }

    fn estimate_tx_vsize(&self, tx: &Transaction, num_inputs: usize) -> u64 {
        // This is a rough estimation for P2TR inputs and P2TR outputs.
        // A more accurate estimation would require knowing the exact script types.
        let base_vsize = 10;
        let input_vsize = 58; // P2TR input
        let output_vsize = 43; // P2TR output

        base_vsize + (input_vsize * num_inputs) as u64 + (output_vsize * tx.output.len() as u64)
    }

}

impl ConcreteProvider {
    fn find_address_info(
        keystore: &Keystore,
        address: &Address,
        network: Network,
    ) -> Result<crate::keystore::AddressInfo> {
        // Since we removed the address cache, we derive on-the-fly.
        // This is necessary for signing transactions for addresses that haven't been explicitly
        // listed or used before. We search a reasonable gap limit.
        let secp = Secp256k1::<All>::new();
        let account_xpub = Xpub::from_str(&keystore.account_xpub)
            .map_err(|e| DeezelError::Wallet(format!("Invalid account xpub in keystore: {e}")))?;

        // Standard gap limit is 20, but we'll search a bit more to be safe.
        // We need to check both the receive (0) and change (1) branches.
        for branch in 0..=1 {
            for i in 0..101 { // Gap limit of 100
                let address_path_str = format!("{branch}/{i}");
                let address_path = DerivationPath::from_str(&address_path_str)?;
                let derived_xpub = account_xpub.derive_pub(&secp, &address_path)?;
                let (internal_key, _) = derived_xpub.public_key.x_only_public_key();
                let derived_address = Address::p2tr(&secp, internal_key, None, network);

                if derived_address == *address {
                    // We found the address!
                    let base_path = keystore.hd_paths.get("p2tr").map(|s| s.as_str()).unwrap_or("m/86'/0'/0'");
                    let full_path = format!("{}/{}", base_path.strip_suffix('/').unwrap_or(base_path), address_path_str.strip_prefix("m/").unwrap_or(&address_path_str));
                    return Ok(crate::keystore::AddressInfo {
                        path: full_path,
                        address: address.to_string(),
                        address_type: "p2tr".to_string(),
                    });
                }
            }
        }

        Err(DeezelError::Wallet(format!(
            "Address {address} not found in keystore and could not be derived within the gap limit"
        )))
    }

    async fn metashrew_view_call(
        &self,
        method: &str,
        hex_input: &str,
        block_tag: &str,
    ) -> Result<Vec<u8>> {
        let result = self
            .call(
                &self.metashrew_rpc_url,
                "metashrew_view",
                serde_json::json!([method, hex_input, block_tag]),
                1, // Using a static ID for simplicity, can be made dynamic if needed
            )
            .await?;

        let hex_response = result.as_str().ok_or_else(|| {
            DeezelError::RpcError("metashrew_view response was not a string".to_string())
        })?;

        let bytes = hex::decode(hex_response.strip_prefix("0x").unwrap_or(hex_response))?;
        Ok(bytes)
    }
}

#[async_trait(?Send)]
impl JsonRpcProvider for ConcreteProvider {
    async fn call(
        &self,
        url: &str,
        method: &str,
        params: serde_json::Value,
        id: u64,
    ) -> Result<serde_json::Value> {
        // Debug logging for JsonRpcProvider call - logs all RPC payloads sent
        log::debug!(
            "JsonRpcProvider::call - URL: {}, Method: {}, Params: {}, ID: {}",
            url,
            method,
            serde_json::to_string(&params).unwrap_or_else(|_| "INVALID_JSON".to_string()),
            id
        );
        
        #[cfg(feature = "native-deps")]
        {
            use crate::rpc::RpcRequest;
            let request = RpcRequest::new(method, params, id);
            let response = self.http_client
                .post(url)
                .json(&request)
                .send()
                .await
                .map_err(|e| DeezelError::Network(e.to_string()))?;
            let response_text = response.text().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            
            log::debug!("Raw RPC response: {response_text}");
            // First, try to parse as a standard RpcResponse
            // A more robust parsing logic that handles different RPC response structures.
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&response_text) {
                // Check for a standard JSON-RPC error object.
                if let Some(error_obj) = json_value.get("error") {
                    if !error_obj.is_null() {
                        if let Ok(rpc_error) = serde_json::from_value::<crate::rpc::RpcError>(error_obj.clone()) {
                            return Err(DeezelError::RpcError(format!("Code {}: {}", rpc_error.code, rpc_error.message)));
                        } else {
                            return Err(DeezelError::RpcError(format!("Non-standard error object received: {error_obj}")));
                        }
                    }
                }

                // Check for a standard JSON-RPC result.
                if let Some(result) = json_value.get("result") {
                    return Ok(result.clone());
                }
                
                // Fallback for non-standard responses that are just the result value.
                return Ok(json_value);
            }

            // If that fails, try to parse as a raw JsonValue (for non-compliant servers)
            if let Ok(mut raw_result) = serde_json::from_str::<serde_json::Value>(&response_text) {
                // Handle cases where the actual result is nested inside a "result" field
                if let Some(obj) = raw_result.as_object_mut() {
                    if obj.contains_key("result") {
                        if let Some(val) = obj.remove("result") {
                            return Ok(val);
                        }
                    }
                }
                return Ok(raw_result);
            }

            // If that also fails, check if the response is just a plain string
            // This is needed for some Esplora endpoints that return plain text
            if !response_text.starts_with('{') && !response_text.starts_with('[') {
                // It's likely a plain string, wrap it in a JsonValue
                return Ok(serde_json::Value::String(response_text));
            }

            // If all attempts fail, return a generic error
            Err(DeezelError::Network(format!("Failed to decode RPC response: {response_text}")))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            let _ = (url, method, params, id); // Suppress unused parameter warnings
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }
    
    async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String> {
        let block = block.parse::<u64>()?;
        let tx = tx.parse::<u64>()?;

        let mut alkane_id_pb = alkanes_pb::AlkaneId::new();
        let mut block_uint128 = alkanes_pb::Uint128::new();
        block_uint128.lo = block;
        let mut tx_uint128 = alkanes_pb::Uint128::new();
        tx_uint128.lo = tx;
        alkane_id_pb.block = ::protobuf::MessageField::some(block_uint128);
        alkane_id_pb.tx = ::protobuf::MessageField::some(tx_uint128);

        let mut request = alkanes_pb::BytecodeRequest::new();
        request.id = ::protobuf::MessageField::some(alkane_id_pb);

        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self
            .metashrew_view_call("getbytecode", &hex_input, "latest")
            .await?;

        Ok(format!("0x{}", hex::encode(response_bytes)))
    }
}

#[async_trait(?Send)]
impl StorageProvider for ConcreteProvider {
    async fn read(&self, _key: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn write(&self, _key: &str, _data: &[u8]) -> Result<()> {
        unimplemented!()
    }
    
    async fn exists(&self, _key: &str) -> Result<bool> {
        unimplemented!()
    }
    
    async fn delete(&self, _key: &str) -> Result<()> {
        unimplemented!()
    }
    
    async fn list_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        unimplemented!()
    }
    
    fn storage_type(&self) -> &'static str {
        "placeholder"
    }
}

#[async_trait(?Send)]
impl NetworkProvider for ConcreteProvider {
    async fn get(&self, _url: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn post(&self, _url: &str, _body: &[u8], _content_type: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn is_reachable(&self, _url: &str) -> bool {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl CryptoProvider for ConcreteProvider {
    fn random_bytes(&self, _len: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    fn sha256(&self, _data: &[u8]) -> Result<[u8; 32]> {
        unimplemented!()
    }
    
    fn sha3_256(&self, _data: &[u8]) -> Result<[u8; 32]> {
        unimplemented!()
    }
    
    async fn encrypt_aes_gcm(&self, _data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn decrypt_aes_gcm(&self, _data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
    
    async fn pbkdf2_derive(&self, _password: &[u8], _salt: &[u8], _iterations: u32, _key_len: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
}



#[async_trait(?Send)]
impl TimeProvider for ConcreteProvider {
    fn now_secs(&self) -> u64 {
        unimplemented!()
    }
    
    fn now_millis(&self) -> u64 {
        unimplemented!()
    }
    
    #[cfg(feature = "native-deps")]
    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(core::time::Duration::from_millis(ms)).await;
    }

    #[cfg(not(feature = "native-deps"))]
    async fn sleep_ms(&self, ms: u64) {
        #[cfg(target_arch = "wasm32")]
        {
            gloo_timers::future::sleep(core::time::Duration::from_millis(ms)).await;
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = ms;
            unimplemented!("sleep_ms is not implemented for non-wasm targets without native-deps feature")
        }
    }
}

impl LogProvider for ConcreteProvider {
    fn debug(&self, _message: &str) {
        unimplemented!()
    }
    
    fn info(&self, _message: &str) {
        unimplemented!()
    }
    
    fn warn(&self, _message: &str) {
        unimplemented!()
    }
    
    fn error(&self, _message: &str) {
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl WalletProvider for ConcreteProvider {
    async fn create_wallet(&mut self, config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<WalletInfo> {
        let mnemonic = if let Some(m) = mnemonic {
            Mnemonic::from_phrase(&m, bip39::Language::English).map_err(|e| DeezelError::Wallet(format!("Invalid mnemonic: {e}")))?
        } else {
            Mnemonic::new(MnemonicType::Words24, bip39::Language::English)
        };

        let pass = passphrase.clone().unwrap_or_default();
        let keystore = Keystore::new(&mnemonic, config.network, &pass, None)?;

        #[cfg(feature = "native-deps")]
        if let Some(path) = &self.wallet_path {
            keystore.save_to_file(path)?;
        }

        let addresses = keystore.get_addresses(config.network, "p2tr", 0, 0, 1)?;
        let address = addresses.first().map(|a| a.address.clone()).unwrap_or_default();
        
        self.wallet_state = WalletState::Unlocked {
            keystore,
            mnemonic: mnemonic.to_string(),
        };
        self.passphrase = passphrase;

        Ok(WalletInfo {
            address,
            network: config.network,
            mnemonic: Some(mnemonic.to_string()),
        })
    }
    
    async fn load_wallet(&mut self, config: WalletConfig, passphrase: Option<String>) -> Result<WalletInfo> {
        #[cfg(feature = "native-deps")]
        {
            let path = PathBuf::from(config.wallet_path);
            let keystore = Keystore::from_file(&path)?;
            let pass = passphrase.as_deref().ok_or_else(|| DeezelError::Wallet("Passphrase required to load wallet".to_string()))?;
            let mnemonic = keystore.decrypt_mnemonic(pass)?;
            let addresses = keystore.get_addresses(config.network, "p2tr", 0, 0, 1)?;
            let address = addresses.first().map(|a| a.address.clone()).unwrap_or_default();

            self.wallet_state = WalletState::Unlocked {
                keystore,
                mnemonic: mnemonic.clone(),
            };
            self.passphrase = passphrase;

            Ok(WalletInfo {
                address,
                network: config.network,
                mnemonic: Some(mnemonic),
            })
        }
        #[cfg(not(feature = "native-deps"))]
        {
            let _ = (config, passphrase);
            Err(DeezelError::NotImplemented("File system not available in wasm".to_string()))
        }
    }
    
    async fn get_balance(&self, addresses: Option<Vec<String>>) -> Result<WalletBalance> {
        let addrs_to_check = if let Some(provided_addresses) = addresses {
            provided_addresses
        } else {
            // If no addresses are provided, derive the first 20 from the public key.
            let derived_infos = self.get_addresses(20).await?;
            derived_infos.into_iter().map(|info| info.address).collect()
        };

        if addrs_to_check.is_empty() {
            return Ok(WalletBalance { confirmed: 0, pending: 0 });
        }

        let mut total_confirmed_balance = 0_u64;
        let mut total_pending_balance = 0_i64;

        for address in addrs_to_check {
            let info = self.get_address_info(&address).await?;

            // Confirmed balance
            if let Some(chain_stats) = info.get("chain_stats") {
                let funded = chain_stats.get("funded_txo_sum").and_then(|v| v.as_u64()).unwrap_or(0);
                let spent = chain_stats.get("spent_txo_sum").and_then(|v| v.as_u64()).unwrap_or(0);
                total_confirmed_balance += funded.saturating_sub(spent);
            }

            // Pending balance (can be negative)
            if let Some(mempool_stats) = info.get("mempool_stats") {
                let funded = mempool_stats.get("funded_txo_sum").and_then(|v| v.as_i64()).unwrap_or(0);
                let spent = mempool_stats.get("spent_txo_sum").and_then(|v| v.as_i64()).unwrap_or(0);
                total_pending_balance += funded - spent;
            }
        }

        Ok(WalletBalance {
            confirmed: total_confirmed_balance,
            pending: total_pending_balance,
        })
    }
    
    async fn get_address(&self) -> Result<String> {
        let addresses = self.get_addresses(1).await?;
        if let Some(address_info) = addresses.first() {
            Ok(address_info.address.clone())
        } else {
            Err(DeezelError::Wallet("No addresses found in wallet".to_string()))
        }
    }
    
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>> {
        let keystore = self.get_keystore().ok_or_else(|| DeezelError::Wallet("Keystore not loaded".to_string()))?;
        let addresses = keystore.get_addresses(self.get_network(), "p2tr", 0, 0, count)?;
        Ok(addresses)
    }
    
    async fn send(&mut self, params: SendParams) -> Result<String> {
        // 1. Create the transaction
        let tx_hex = self.create_transaction(params).await?;

        // 2. Sign the transaction
        let signed_tx_hex = self.sign_transaction(tx_hex).await?;

        // 3. Broadcast the transaction
        self.broadcast_transaction(signed_tx_hex).await
    }
    
    async fn get_utxos(&self, _include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<(OutPoint, UtxoInfo)>> {
        let addrs_to_check = if let Some(provided_addresses) = addresses {
            provided_addresses
        } else {
            // If no addresses are provided, derive the first 20 from the public key.
            let derived_infos = self.get_addresses(20).await?;
            derived_infos.into_iter().map(|info| info.address).collect()
        };

        if addrs_to_check.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_utxos = Vec::new();

        for address in addrs_to_check {
            log::info!("Fetching UTXOs for address: {address}");
            let utxos_json = self.get_address_utxo(&address).await?;
            
            if let Some(utxos_array) = utxos_json.as_array() {
                for utxo_json in utxos_array {
                    let txid_str = utxo_json.get("txid").and_then(|t| t.as_str()).ok_or_else(|| DeezelError::Other("Missing txid in UTXO".to_string()))?;
                    let vout = utxo_json.get("vout").and_then(|v| v.as_u64()).ok_or_else(|| DeezelError::Other("Missing vout in UTXO".to_string()))? as u32;
                    let value = utxo_json.get("value").and_then(|v| v.as_u64()).ok_or_else(|| DeezelError::Other("Missing value in UTXO".to_string()))?;
                    
                    let status = utxo_json.get("status");
                    let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
                    let block_height = status.and_then(|s| s.get("block_height")).and_then(|h| h.as_u64());

                    let confirmations = if confirmed {
                        if let Some(bh) = block_height {
                            let current_height = self.get_block_count().await.unwrap_or(bh);
                            current_height.saturating_sub(bh) as u32 + 1
                        } else { 1 }
                    } else { 0 };

                    let outpoint = OutPoint::from_str(&format!("{}:{}", txid_str, vout))?;
                    let utxo_info = UtxoInfo {
                        txid: txid_str.to_string(),
                        vout,
                        amount: value,
                        address: address.clone(),
                        script_pubkey: Some(Address::from_str(&address)?.require_network(self.get_network())?.script_pubkey()),
                        confirmations,
                        frozen: false, // TODO: Implement frozen UTXO logic
                        freeze_reason: None,
                        block_height,
                        has_inscriptions: false, // Placeholder
                        has_runes: false, // Placeholder
                        has_alkanes: false, // Placeholder
                        is_coinbase: false, // Placeholder, would need to check vin
                    };
                    all_utxos.push((outpoint, utxo_info));
                }
            }
        }

        Ok(all_utxos)
    }
    
    async fn get_history(&self, count: u32, address: Option<String>) -> Result<Vec<TransactionInfo>> {
        let addr = address.ok_or_else(|| DeezelError::Wallet("get_history requires an address".to_string()))?;
        let txs_json = self.get_address_txs(&addr).await?;
        let mut transactions = Vec::new();

        if let Some(txs_array) = txs_json.as_array() {
            for tx in txs_array.iter().take(count as usize) {
                if let Some(txid) = tx.get("txid").and_then(|t| t.as_str()) {
                    let status = tx.get("status");
                    let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
                    let block_height = status.and_then(|s| s.get("block_height")).and_then(|h| h.as_u64());
                    let block_time = status.and_then(|s| s.get("block_time")).and_then(|t| t.as_u64());
                    let fee = tx.get("fee").and_then(|f| f.as_u64());

                    transactions.push(TransactionInfo {
                        txid: txid.to_string(),
                        block_height,
                        block_time,
                        confirmed,
                        fee,
                        inputs: vec![], // Requires parsing vin
                        outputs: vec![], // Requires parsing vout
                    });
                }
            }
        }
        Ok(transactions)
    }
    
    async fn freeze_utxo(&self, _utxo: String, _reason: Option<String>) -> Result<()> {
        unimplemented!()
    }
    
    async fn unfreeze_utxo(&self, _utxo: String) -> Result<()> {
        unimplemented!()
    }
    
    async fn create_transaction(&self, params: SendParams) -> Result<String> {
        // 1. Determine which addresses to use for sourcing UTXOs
        let (address_strings, all_addresses) = if let Some(from_addresses) = &params.from {
            (from_addresses.clone(), from_addresses.iter().map(|s| AddressInfo {
                address: s.clone(),
                index: 0, // Not relevant here
                derivation_path: "".to_string(), // Not relevant here
                script_type: "".to_string(), // Not relevant here
                used: false, // Not relevant here
            }).collect())
        } else {
            // Fallback to discovering addresses if --from is not provided
            let discovered_addresses = self.get_addresses(100).await?; // A reasonable number for a simple wallet
            (discovered_addresses.iter().map(|a| a.address.clone()).collect(), discovered_addresses)
        };

        // 2. Get UTXOs for the specified addresses
        let utxos = self.get_utxos(false, Some(address_strings.clone())).await?;

        // 3. Perform coin selection
        let target_amount = Amount::from_sat(params.amount);
        let fee_rate = params.fee_rate.unwrap_or(1.0); // Default to 1 sat/vbyte

        let utxo_infos: Vec<UtxoInfo> = utxos.into_iter().map(|(_, info)| info).collect();
        let (selected_utxos, total_input_amount) = self.select_coins(utxo_infos, target_amount)?;

        // 4. Build the transaction skeleton
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };

        // Add inputs from selected UTXOs
        for utxo in &selected_utxos {
            tx.input.push(TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_str(&utxo.txid)?,
                    vout: utxo.vout,
                },
                script_sig: ScriptBuf::new(), // Empty for SegWit
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // Empty for now, will be added during signing
            });
        }

        // Add the recipient's output
        let network = self.get_network();
        let recipient_address = Address::from_str(&params.address)?.require_network(network)?;
        tx.output.push(TxOut {
            value: target_amount,
            script_pubkey: recipient_address.script_pubkey(),
        });

        // 5. Calculate fee and add change output if necessary
        // Start with an initial fee estimate. We add a placeholder change output to get a more
        // accurate size, then calculate the fee, then the actual change.
        let change_address = Address::from_str(&all_addresses[0].address)?.require_network(network)?;
        let change_script = change_address.script_pubkey();
        let placeholder_change = TxOut { value: Amount::ZERO, script_pubkey: change_script.clone() };
        tx.output.push(placeholder_change);

        let estimated_vsize = self.estimate_tx_vsize(&tx, selected_utxos.len());
        let fee = Amount::from_sat((estimated_vsize as f32 * fee_rate).ceil() as u64);

        // Now that we have a good fee estimate, remove the placeholder and calculate the real change.
        tx.output.pop();
        let change_amount = total_input_amount.checked_sub(target_amount).and_then(|a| a.checked_sub(fee));

        if let Some(change) = change_amount {
            if change > bitcoin::Amount::from_sat(546) { // Dust limit
                tx.output.push(TxOut {
                    value: change,
                    script_pubkey: change_script,
                });
            }
            // If change is dust, it's not added, effectively becoming part of the fee.
        }

        // 6. Serialize the unsigned transaction to hex
        Ok(bitcoin::consensus::encode::serialize_hex(&tx))
    }

    async fn sign_transaction(&mut self, tx_hex: String) -> Result<String> {
        // 1. Deserialize the transaction
        let hex_bytes = hex::decode(tx_hex)?;
        let mut tx: Transaction = bitcoin::consensus::deserialize(&hex_bytes)?;

        // 2. Setup for signing - gather immutable info first to avoid borrow checker issues.
        let network = self.get_network();
        let secp: Secp256k1<All> = Secp256k1::new();

        // 3. Fetch the previous transaction outputs (prevouts) for signing.
        let mut prevouts = Vec::new();
        for input in &tx.input {
            let tx_info = self.get_tx(&input.previous_output.txid.to_string()).await?;
            let vout_info = tx_info["vout"].get(input.previous_output.vout as usize)
                .ok_or_else(|| DeezelError::Wallet(format!("Vout {} not found for tx {}", input.previous_output.vout, input.previous_output.txid)))?;
            
            let amount = vout_info["value"].as_u64()
                .ok_or_else(|| DeezelError::Wallet("UTXO value not found".to_string()))?;
            let script_pubkey_hex = vout_info["scriptpubkey"].as_str()
                .ok_or_else(|| DeezelError::Wallet("UTXO script pubkey not found".to_string()))?;
            
            let script_pubkey = ScriptBuf::from(Vec::from_hex(script_pubkey_hex)?);
            prevouts.push(TxOut { value: Amount::from_sat(amount), script_pubkey });
        }

        // 4. Get mutable access to the wallet state *after* all immutable borrows are done.
        let (keystore, mnemonic) = match &mut self.wallet_state {
            WalletState::Unlocked { keystore, mnemonic } => (keystore, mnemonic),
            _ => return Err(DeezelError::Wallet("Wallet must be unlocked to sign transactions".to_string())),
        };

        // 5. Sign each input
        let mut sighash_cache = SighashCache::new(&mut tx);
        for i in 0..prevouts.len() {
            let prev_txout = &prevouts[i];
            
            // Find the address and its derivation path from our keystore
            let address = Address::from_script(&prev_txout.script_pubkey, network)
                .map_err(|e| DeezelError::Wallet(format!("Failed to parse address from script: {e}")))?;
            
            // This call now takes a mutable keystore and may cache the derived address info.
            let addr_info = Self::find_address_info(keystore, &address, network)?;
            let path = DerivationPath::from_str(&addr_info.path)?;

            // Derive the private key for this input
            let mnemonic_obj = Mnemonic::from_phrase(mnemonic, bip39::Language::English)?;
            let seed = Seed::new(&mnemonic_obj, "");
            let root_key = Xpriv::new_master(network, seed.as_bytes())?;
            let derived_xpriv = root_key.derive_priv(&secp, &path)?;
            let keypair = derived_xpriv.to_keypair(&secp);
            let untweaked_keypair = UntweakedKeypair::from(keypair);
            let tweaked_keypair = untweaked_keypair.tap_tweak(&secp, None);

            // Create the sighash
            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )?;

            // Sign the sighash
            let msg = bitcoin::secp256k1::Message::from(sighash);
            #[cfg(not(target_arch = "wasm32"))]
            let signature = secp.sign_schnorr_with_rng(&msg, &tweaked_keypair.to_keypair(), &mut thread_rng());
            #[cfg(target_arch = "wasm32")]
            let signature = secp.sign_schnorr_with_rng(&msg, &tweaked_keypair.to_keypair(), &mut OsRng);
            
            let taproot_signature = taproot::Signature {
                signature,
                sighash_type: TapSighashType::Default,
            };

            // Add the signature to the witness
            sighash_cache.witness_mut(i).unwrap().clone_from(&Witness::p2tr_key_spend(&taproot_signature));
        }

        // 6. Serialize the signed transaction
        let signed_tx = sighash_cache.into_transaction();
        Ok(bitcoin::consensus::encode::serialize_hex(&signed_tx))
    }
    
    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String> {
        self.send_raw_transaction(&tx_hex).await
    }
    
    async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate> {
        let fee_estimates = self.get_fee_estimates().await?;
        let fee_rate = fee_estimates
            .get(target.to_string())
            .and_then(|v| v.as_f64().map(|f| f as f32))
            .unwrap_or(1.0);

        Ok(FeeEstimate {
            fee_rate,
            target_blocks: target,
        })
    }
    
    async fn get_fee_rates(&self) -> Result<FeeRates> {
        let fee_estimates = self.get_fee_estimates().await?;
        
        let fast = fee_estimates.get("1").and_then(|v| v.as_f64()).unwrap_or(10.0) as f32;
        let medium = fee_estimates.get("6").and_then(|v| v.as_f64()).unwrap_or(5.0) as f32;
        let slow = fee_estimates.get("144").and_then(|v| v.as_f64()).unwrap_or(1.0) as f32;

        Ok(FeeRates {
            fast,
            medium,
            slow,
        })
    }
    
    async fn sync(&self) -> Result<()> {
        log::info!("Starting backend synchronization...");
        let max_retries = 60; // ~2 minutes timeout
        for i in 0..max_retries {
            // 1. Get bitcoind height (source of truth)
            let bitcoind_height = match self.get_block_count().await {
                Ok(h) => h,
                Err(e) => {
                    log::warn!("Attempt {}: Failed to get bitcoind height: {}. Retrying...", i + 1, e);
                    self.sleep_ms(2000).await;
                    continue;
                }
            };

            // 2. Get other service heights
            let metashrew_height_res = self.get_metashrew_height().await;
            let esplora_height_res = self.get_blocks_tip_height().await;
            let ord_height_res = self.get_ord_block_count().await;

            // 3. Check if services are synced
            // All services should be at least at the same height as bitcoind.
            let metashrew_synced = metashrew_height_res.as_ref().is_ok_and(|&h| h >= bitcoind_height);
            let esplora_synced = esplora_height_res.as_ref().is_ok_and(|&h| h >= bitcoind_height);
            let ord_synced = ord_height_res.as_ref().is_ok_and(|&h| h >= bitcoind_height);

            log::info!(
                "Sync attempt {}/{}: bitcoind: {}, metashrew: {} (synced: {}), esplora: {} (synced: {}), ord: {} (synced: {})",
                i + 1,
                max_retries,
                bitcoind_height,
                metashrew_height_res.map_or_else(|e| format!("err ({e})"), |h| h.to_string()),
                metashrew_synced,
                esplora_height_res.map_or_else(|e| format!("err ({e})"), |h| h.to_string()),
                esplora_synced,
                ord_height_res.map_or_else(|e| format!("err ({e})"), |h| h.to_string()),
                ord_synced
            );

            if metashrew_synced && esplora_synced && ord_synced {
                log::info!("✅ All backends synchronized successfully!");
                return Ok(());
            }

            self.sleep_ms(2000).await;
        }

        Err(DeezelError::Other(format!("Timeout waiting for backends to sync after {max_retries} attempts")))
    }
    
    async fn backup(&self) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_mnemonic(&self) -> Result<Option<String>> {
        match &self.wallet_state {
            WalletState::Unlocked { mnemonic, .. } => Ok(Some(mnemonic.clone())),
            _ => Ok(None),
        }
    }
    
    fn get_network(&self) -> bitcoin::Network {
        // Parse the provider string to determine network
        match self.provider.as_str() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" | _ => Network::Regtest, // Default to regtest
        }
    }
    
    async fn get_internal_key(&self) -> Result<(bitcoin::XOnlyPublicKey, (Fingerprint, DerivationPath))> {
        let (keystore, mnemonic) = match &self.wallet_state {
            WalletState::Unlocked { keystore, mnemonic } => (keystore, mnemonic),
            _ => return Err(DeezelError::Wallet("Wallet must be unlocked to get internal key".to_string())),
        };

        let mnemonic = bip39::Mnemonic::from_phrase(mnemonic, bip39::Language::English)?;
        let seed = bip39::Seed::new(&mnemonic, "");
        let network = self.get_network();
        let root_key = Xpriv::new_master(network, seed.as_bytes())?;
        
        // Standard path for Taproot internal key. This should be configurable in a real wallet.
        let path = DerivationPath::from_str("m/86'/1'/0'")?;
        
        let derived_xpriv = root_key.derive_priv(&self.secp, &path)?;
        let keypair = derived_xpriv.to_keypair(&self.secp);
        let (internal_key, _) = keypair.x_only_public_key();

        let master_fingerprint = Fingerprint::from_str(&keystore.master_fingerprint)?;

        Ok((internal_key, (master_fingerprint, path)))
    }
    
    async fn sign_psbt(&mut self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt> {
        let mut psbt = psbt.clone();
        let mut tx = psbt.clone().extract_tx().map_err(|e| DeezelError::Other(e.to_string()))?;
        let network = self.get_network();
        let secp = Secp256k1::<All>::new();

        let mut prevouts = Vec::new();
        for input in &tx.input {
            let utxo = self.get_utxo(&input.previous_output).await?
                .ok_or_else(|| DeezelError::Wallet(format!("UTXO not found: {}", input.previous_output)))?;
            prevouts.push(utxo);
        }

        let (keystore, mnemonic) = match &mut self.wallet_state {
            WalletState::Unlocked { keystore, mnemonic } => (keystore, mnemonic),
            _ => return Err(DeezelError::Wallet("Wallet must be unlocked to sign transactions".to_string())),
        };

        let mut sighash_cache = SighashCache::new(&mut tx);
        for (i, psbt_input) in psbt.inputs.iter_mut().enumerate() {
            let prev_txout = &prevouts[i];

            if !psbt_input.tap_scripts.is_empty() {
                // Script-path spend
                let (control_block, (script, leaf_version)) = psbt_input.tap_scripts.iter().next().unwrap();
                let leaf_hash = taproot::TapLeafHash::from_script(script, *leaf_version);
                let sighash = sighash_cache.taproot_script_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )?;
                
                // Find the keypair corresponding to the internal public key from the PSBT's tap_key_origins.
                // There should be exactly one entry for a script path spend.
                let (internal_pk, (_leaf_hashes, (master_fingerprint, derivation_path))) = psbt_input.tap_key_origins.iter().next()
                    .ok_or_else(|| DeezelError::Wallet("tap_key_origins is empty for script spend".to_string()))?;

                if *master_fingerprint != Fingerprint::from_str(&keystore.master_fingerprint)? {
                    return Err(DeezelError::Wallet(
                        "Master fingerprint mismatch in tap_key_origins".to_string(),
                    ));
                }

                // Derive the private key for this input
                let mnemonic_obj = Mnemonic::from_phrase(mnemonic, bip39::Language::English)?;
                let seed = Seed::new(&mnemonic_obj, "");
                let root_key = Xpriv::new_master(network, seed.as_bytes())?;
                let derived_xpriv = root_key.derive_priv(&secp, derivation_path)?;
                let keypair = derived_xpriv.to_keypair(&secp);

                // Verify that the derived key matches the public key from the PSBT
                if keypair.public_key().x_only_public_key().0 != *internal_pk {
                    return Err(DeezelError::Wallet("Derived key does not match internal public key in PSBT".to_string()));
                }

                let msg = bitcoin::secp256k1::Message::from(sighash);
                
                #[cfg(not(target_arch = "wasm32"))]
                let signature = self.secp.sign_schnorr_with_rng(&msg, &keypair, &mut rand::thread_rng());
                #[cfg(target_arch = "wasm32")]
                let signature = self.secp.sign_schnorr_with_rng(&msg, &keypair, &mut OsRng);

                let taproot_signature = taproot::Signature { signature, sighash_type: TapSighashType::Default };
                
                let mut final_witness = Witness::new();
                final_witness.push(taproot_signature.to_vec());
                final_witness.push(script.as_bytes());
                final_witness.push(control_block.serialize());
                psbt_input.final_script_witness = Some(final_witness);

            } else {
                // Key-path spend
                let address = Address::from_script(&prev_txout.script_pubkey, network)
                    .map_err(|e| DeezelError::Wallet(format!("Failed to parse address from script: {e}")))?;
                
                let addr_info = Self::find_address_info(keystore, &address, network)?;
                let path = DerivationPath::from_str(&addr_info.path)?;

                let mnemonic_obj = Mnemonic::from_phrase(mnemonic, bip39::Language::English)?;
                let seed = Seed::new(&mnemonic_obj, "");
                let root_key = Xpriv::new_master(network, seed.as_bytes())?;
                let derived_xpriv = root_key.derive_priv(&secp, &path)?;
                let keypair = derived_xpriv.to_keypair(&secp);
                let untweaked_keypair = UntweakedKeypair::from(keypair);
                let tweaked_keypair = untweaked_keypair.tap_tweak(&secp, None);

                let sighash = sighash_cache.taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )?;

                let msg = bitcoin::secp256k1::Message::from(sighash);
                #[cfg(not(target_arch = "wasm32"))]
                let signature = secp.sign_schnorr_with_rng(&msg, &tweaked_keypair.to_keypair(), &mut thread_rng());
                #[cfg(target_arch = "wasm32")]
                let signature = secp.sign_schnorr_with_rng(&msg, &tweaked_keypair.to_keypair(), &mut OsRng);
                
                let taproot_signature = taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                };

                psbt_input.tap_key_sig = Some(taproot_signature);
            }
        }

        Ok(psbt)
    }
    
    async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
        let mnemonic = self.get_mnemonic().await?
            .ok_or_else(|| DeezelError::Wallet("Wallet must be unlocked to get keypair".to_string()))?;
        let mnemonic = bip39::Mnemonic::from_phrase(&mnemonic, bip39::Language::English)?;
        let seed = bip39::Seed::new(&mnemonic, "");
        let network = self.get_network();
        let xpriv = bitcoin::bip32::Xpriv::new_master(network, seed.as_bytes())?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        Ok(xpriv.to_keypair(&secp))
    }

    fn set_passphrase(&mut self, _passphrase: Option<String>) {
    }

    async fn get_last_used_address_index(&self) -> Result<u32> {
        let keystore = self.get_keystore().ok_or_else(|| DeezelError::Wallet("Keystore not loaded".to_string()))?;
        let network = self.get_network();
        let mut last_used_index = 0;
        let gap_limit = 20; // Standard gap limit

        // We check both receive (0) and change (1) chains
        for chain in 0..=1 {
            let mut consecutive_unused = 0;
            for index in 0.. {
                // Derive one address at a time
                let addresses = keystore.get_addresses(network, "p2tr", chain, index, 1)?;
                if let Some(address_info) = addresses.first() {
                    let txs = self.get_address_txs(&address_info.address).await?;
                    if txs.as_array().is_none_or(|a| a.is_empty()) {
                        consecutive_unused += 1;
                    } else {
                        last_used_index = core::cmp::max(last_used_index, index);
                        consecutive_unused = 0;
                    }
                } else {
                    // Should not happen if get_addresses works correctly
                    break;
                }

                if consecutive_unused >= gap_limit {
                    break;
                }
            }
        }
        Ok(last_used_index)
    }
}


#[async_trait(?Send)]
impl BitcoinRpcProvider for ConcreteProvider {
    async fn get_block_count(&self) -> Result<u64> {
        let result = self.call(&self.rpc_url, "getblockcount", serde_json::Value::Null, 1).await?;
        if let Some(count) = result.as_u64() {
            return Ok(count);
        }
        if let Some(count_str) = result.as_str() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(count_str) {
                if let Some(count) = json.get("result").and_then(|v| v.as_u64()) {
                    return Ok(count);
                }
            }
            return count_str.parse::<u64>().map_err(|_| DeezelError::RpcError("Invalid block count string response".to_string()));
        }
        if let Some(obj) = result.as_object() {
            if let Some(count) = obj.get("result").and_then(|v| v.as_u64()) {
                return Ok(count);
            }
        }
        Err(DeezelError::RpcError("Invalid block count response: not a u64, string, or object with a result field".to_string()))
    }
    
    async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([nblocks, address]);
        self.call(&self.rpc_url, "generatetoaddress", params, 1).await
    }

    async fn get_new_address(&self) -> Result<JsonValue> {
        self.call(&self.rpc_url, "getnewaddress", serde_json::Value::Null, 1).await
    }
    
    async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        let params = serde_json::json!([txid]);
        let result = self.call(&self.rpc_url, "getrawtransaction", params, 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid transaction hex response".to_string()))
    }
    
    async fn get_block(&self, hash: &str, raw: bool) -> Result<serde_json::Value> {
        let verbosity = if raw { 0 } else { 2 };
        let params = serde_json::json!([hash, verbosity]);
        self.call(&self.rpc_url, "getblock", params, 1).await
    }
    
    async fn get_block_hash(&self, height: u64) -> Result<String> {
        let params = serde_json::json!([height]);
        let result = self.call(&self.rpc_url, "getblockhash", params, 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block hash response".to_string()))
    }
    
    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String> {
        log::info!("Attempting to broadcast transaction hex: {}", tx_hex);
        // The second parameter is maxfeerate. Setting it to 0 disables the fee check.
        let params = serde_json::json!([tx_hex, 0]);
        let result = self.call(&self.rpc_url, "sendrawtransaction", params, 1).await;
        
        log::info!("sendrawtransaction result: {:?}", result);

        match result {
            Ok(value) => {
                if let Some(txid) = value.as_str() {
                    Ok(txid.to_string())
                } else {
                    Err(DeezelError::RpcError(format!("Invalid txid response from sendrawtransaction: response was not a string: {value:?}")))
                }
            }
            Err(e) => {
                log::error!("sendrawtransaction RPC call failed: {e}");
                Err(e)
            }
        }
    }
    
    async fn get_mempool_info(&self) -> Result<serde_json::Value> {
        self.call(&self.rpc_url, "getmempoolinfo", serde_json::Value::Null, 1).await
    }
    
    async fn estimate_smart_fee(&self, target: u32) -> Result<serde_json::Value> {
        let params = serde_json::json!([target]);
        self.call(&self.rpc_url, "estimatesmartfee", params, 1).await
    }
    
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64> {
        unimplemented!("This method belongs to the EsploraProvider")
    }
    
    async fn trace_transaction(&self, txid: &str, vout: u32, _block: Option<&str>, _tx: Option<&str>) -> Result<serde_json::Value> {
        <Self as MetashrewRpcProvider>::trace_outpoint(self, txid, vout).await
    }
}

#[async_trait(?Send)]
impl MetashrewRpcProvider for ConcreteProvider {
    async fn get_metashrew_height(&self) -> Result<u64> {
        let json = self.call(&self.metashrew_rpc_url, "metashrew_height", serde_json::Value::Null, 1).await?;
        log::debug!("get_metashrew_height response: {:?}", json);
        if let Some(count) = json.as_u64() {
            return Ok(count);
        }
        if let Some(count_str) = json.as_str() {
            return count_str.parse::<u64>().map_err(|_| DeezelError::RpcError("Invalid metashrew height string response".to_string()));
        }
        Err(DeezelError::RpcError("Invalid metashrew height response: not a u64 or string".to_string()))
    }
    
    async fn get_contract_meta(&self, block: &str, tx: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([block, tx]);
        self.call(&self.metashrew_rpc_url, "metashrew_view", params, 1).await
    }
    
    async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue> {
        let txid_parsed = bitcoin::Txid::from_str(txid)?;
        let mut outpoint_pb = alkanes_pb::Outpoint::new();
        // The metashrew_view `trace` method expects the raw txid bytes (little-endian),
        // which is how the `bitcoin::Txid` type stores them internally.
        // We do not need to reverse them.
        outpoint_pb.txid = txid_parsed.to_raw_hash().to_byte_array().to_vec();
        outpoint_pb.vout = vout;

        let hex_input = format!("0x{}", hex::encode(outpoint_pb.write_to_bytes()?));
        let response_bytes = self
            .metashrew_view_call("trace", &hex_input, "latest")
            .await?;
        if response_bytes.is_empty() {
            return Ok(JsonValue::Null);
        }
        // The response from `trace` is already JSON, so we parse it directly.
        let trace_json: JsonValue = serde_json::from_slice(&response_bytes)?;
        Ok(trace_json)
    }
    
    async fn get_spendables_by_address(&self, address: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([address]);
        self.call(&self.metashrew_rpc_url, "spendablesbyaddress", params, 1).await
    }
    
    async fn get_protorunes_by_address(
        &self,
        address: &str,
        block_tag: Option<String>,
        protocol_tag: u128,
    ) -> Result<crate::alkanes::protorunes::ProtoruneWalletResponse> {
        let mut request = protorune_pb::ProtorunesWalletRequest::new();
        request.wallet = address.as_bytes().to_vec();
        request.protocol_tag = ::protobuf::MessageField::some(crate::utils::to_uint128(protocol_tag));
        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self
            .metashrew_view_call(
                "protorunesbyaddress",
                &hex_input,
                block_tag.as_deref().unwrap_or("latest"),
            )
            .await?;
        if response_bytes.is_empty() {
            return Ok(crate::alkanes::protorunes::ProtoruneWalletResponse {
                balances: vec![],
            });
        }
        let wallet_response = protorune_pb::WalletResponse::parse_from_bytes(&response_bytes)?;
        let mut balances = vec![];
        for item in wallet_response.outpoints.into_iter() {
            let outpoint = item.outpoint.into_option().ok_or_else(|| {
                DeezelError::Other("missing outpoint in wallet response".to_string())
            })?;
            let output = item.output.into_option().ok_or_else(|| {
                DeezelError::Other("missing output in wallet response".to_string())
            })?;
            let balance_sheet_pb = item.balances.into_option().ok_or_else(|| {
                DeezelError::Other("missing balance sheet in wallet response".to_string())
            })?;
            let txid_bytes: [u8; 32] = outpoint.txid.try_into().map_err(|_| {
                DeezelError::Other("invalid txid length in wallet response".to_string())
            })?;
            balances.push(crate::alkanes::protorunes::ProtoruneOutpointResponse {
                output: TxOut {
                    value: Amount::from_sat(output.value),
                    script_pubkey: ScriptBuf::from_bytes(output.script),
                },
                outpoint: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(txid_bytes),
                    vout: outpoint.vout,
                },
                balance_sheet: {
                    let mut balances_map = BTreeMap::new();
                    for entry in balance_sheet_pb.entries {
                        if let Some(rune) = entry.rune.into_option() {
                            if let Some(rune_id) = rune.runeId.into_option() {
                                if let (Some(height), Some(txindex), Some(balance)) = (
                                    rune_id.height.into_option(),
                                    rune_id.txindex.into_option(),
                                    entry.balance.into_option(),
                                ) {
                                    let protorune_id =
                                        protorune_support::balance_sheet::ProtoruneRuneId {
                                            block: height.lo as u128,
                                            tx: txindex.lo as u128,
                                        };
                                    balances_map.insert(protorune_id, balance.lo as u128);
                                }
                            }
                        }
                    }
                    protorune_support::balance_sheet::BalanceSheet {
                        cached: protorune_support::balance_sheet::CachedBalanceSheet {
                            balances: balances_map,
                        },
                        load_ptrs: vec![],
                    }
                },
            });
        }
        Ok(crate::alkanes::protorunes::ProtoruneWalletResponse { balances })
    }

    async fn get_protorunes_by_outpoint(
        &self,
        txid: &str,
        vout: u32,
        block_tag: Option<String>,
        protocol_tag: u128,
    ) -> Result<crate::alkanes::protorunes::ProtoruneOutpointResponse> {
        let txid = bitcoin::Txid::from_str(txid)?;
        let outpoint = bitcoin::OutPoint { txid, vout };
        let mut request = protorune_pb::OutpointWithProtocol::new();
        let mut txid_bytes = txid.to_byte_array().to_vec();
        txid_bytes.reverse();
        request.txid = txid_bytes;
        request.vout = outpoint.vout;
        request.protocol = ::protobuf::MessageField::some(crate::utils::to_uint128(protocol_tag));
        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self
            .metashrew_view_call(
                "protorunesbyoutpoint",
                &hex_input,
                block_tag.as_deref().unwrap_or("latest"),
            )
            .await?;
        if response_bytes.is_empty() {
            return Err(DeezelError::Other(
                "empty response from protorunesbyoutpoint".to_string(),
            ));
        }
        let proto_response = protorune_pb::OutpointResponse::parse_from_bytes(&response_bytes)?;
        let output = proto_response
            .output
            .into_option()
            .ok_or_else(|| DeezelError::Other("missing output in outpoint response".to_string()))?;
        let balance_sheet_pb = proto_response
            .balances
            .into_option()
            .ok_or_else(|| {
                DeezelError::Other("missing balance sheet in outpoint response".to_string())
            })?;
        Ok(crate::alkanes::protorunes::ProtoruneOutpointResponse {
            output: TxOut {
                value: Amount::from_sat(output.value),
                script_pubkey: ScriptBuf::from_bytes(output.script),
            },
            outpoint,
            balance_sheet: {
                let mut balances_map = BTreeMap::new();
                for entry in balance_sheet_pb.entries {
                    if let Some(rune) = entry.rune.into_option() {
                        if let Some(rune_id) = rune.runeId.into_option() {
                            if let (Some(height), Some(txindex), Some(balance)) = (
                                rune_id.height.into_option(),
                                rune_id.txindex.into_option(),
                                entry.balance.into_option(),
                            ) {
                                let protorune_id =
                                    protorune_support::balance_sheet::ProtoruneRuneId {
                                        block: height.lo as u128,
                                        tx: txindex.lo as u128,
                                    };
                                balances_map.insert(protorune_id, balance.lo as u128);
                            }
                        }
                    }
                }
                protorune_support::balance_sheet::BalanceSheet {
                    cached: protorune_support::balance_sheet::CachedBalanceSheet {
                        balances: balances_map,
                    },
                    load_ptrs: vec![],
                }
            },
        })
    }
}

#[async_trait(?Send)]
impl EsploraProvider for ConcreteProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/blocks/tip/hash");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }

        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCKS_TIP_HASH, crate::esplora::params::empty(), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid tip hash response".to_string()))
    }

    async fn get_blocks_tip_height(&self) -> Result<u64> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/blocks/tip/height");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let text = response.text().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return text.parse::<u64>().map_err(|e| DeezelError::RpcError(format!("Invalid tip height response from REST API: {e}")));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCKS_TIP_HEIGHT, crate::esplora::params::empty(), 1).await?;
        result.as_u64().ok_or_else(|| DeezelError::RpcError("Invalid tip height response".to_string()))
    }

    async fn get_blocks(&self, start_height: Option<u64>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = if let Some(height) = start_height {
                format!("{esplora_url}/blocks/{height}")
            } else {
                format!("{esplora_url}/blocks")
            };
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCKS, crate::esplora::params::optional_single(start_height), 1).await
    }

    async fn get_block_by_height(&self, height: u64) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block-height/{height}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_HEIGHT, crate::esplora::params::single(height), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block hash response".to_string()))
    }

    async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block/{hash}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK, crate::esplora::params::single(hash), 1).await
    }

    async fn get_block_status(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block/{hash}/status");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_STATUS, crate::esplora::params::single(hash), 1).await
    }

    async fn get_block_txids(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block/{hash}/txids");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_TXIDS, crate::esplora::params::single(hash), 1).await
    }

    async fn get_block_header(&self, hash: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block/{hash}/header");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_HEADER, crate::esplora::params::single(hash), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block header response".to_string()))
    }

    async fn get_block_raw(&self, hash: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block/{hash}/raw");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let bytes = response.bytes().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return Ok(hex::encode(bytes));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_RAW, crate::esplora::params::single(hash), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid raw block response".to_string()))
    }

    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/block/{hash}/txid/{index}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_TXID, crate::esplora::params::dual(hash, index), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid txid response".to_string()))
    }

    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = if let Some(index) = start_index {
                format!("{esplora_url}/block/{hash}/txs/{index}")
            } else {
                format!("{esplora_url}/block/{hash}/txs")
            };
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_TXS, crate::esplora::params::optional_dual(hash, start_index), 1).await
    }

    async fn get_address(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/address/{address}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_info(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/address/{address}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_txs(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/address/{address}/txs");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_TXS, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = if let Some(txid) = last_seen_txid {
                format!("{esplora_url}/address/{address}/txs/chain/{txid}")
            } else {
                format!("{esplora_url}/address/{address}/txs/chain")
            };
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_TXS_CHAIN, crate::esplora::params::optional_dual(address, last_seen_txid), 1).await
    }

    async fn get_address_txs_mempool(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/address/{address}/txs/mempool");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_TXS_MEMPOOL, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_utxo(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/address/{address}/utxo");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_UTXO, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_prefix(&self, prefix: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/address-prefix/{prefix}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_PREFIX, crate::esplora::params::single(prefix), 1).await
    }

    async fn get_tx(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX, crate::esplora::params::single(txid), 1).await
    }

    async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/hex");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_HEX, crate::esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid tx hex response".to_string()))
    }

    async fn get_tx_raw(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/raw");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let bytes = response.bytes().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return Ok(hex::encode(bytes));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_RAW, crate::esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid raw tx response".to_string()))
    }

    async fn get_tx_status(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/status");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_STATUS, crate::esplora::params::single(txid), 1).await
    }

    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/merkle-proof");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_MERKLE_PROOF, crate::esplora::params::single(txid), 1).await
    }

    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/merkleblock-proof");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_MERKLEBLOCK_PROOF, crate::esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid merkleblock proof response".to_string()))
    }

    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/outspend/{index}");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_OUTSPEND, crate::esplora::params::dual(txid, index), 1).await
    }

    async fn get_tx_outspends(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx/{txid}/outspends");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_OUTSPENDS, crate::esplora::params::single(txid), 1).await
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/tx");
            let response = self.http_client.post(&url).body(tx_hex.to_string()).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::BROADCAST, crate::esplora::params::single(tx_hex), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid broadcast response".to_string()))
    }

    async fn get_mempool(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/mempool");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::MEMPOOL, crate::esplora::params::empty(), 1).await
    }

    async fn get_mempool_txids(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/mempool/txids");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::MEMPOOL_TXIDS, crate::esplora::params::empty(), 1).await
    }

    async fn get_mempool_recent(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/mempool/recent");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::MEMPOOL_RECENT, crate::esplora::params::empty(), 1).await
    }

    async fn get_fee_estimates(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{esplora_url}/fee-estimates");
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.rpc_url, crate::esplora::EsploraJsonRpcMethods::FEE_ESTIMATES, crate::esplora::params::empty(), 1).await
    }
}

#[async_trait(?Send)]
impl RunestoneProvider for ConcreteProvider {
    async fn decode_runestone(&self, tx: &Transaction) -> Result<serde_json::Value> {
        if let Some(artifact) = Runestone::decipher(tx) {
            match artifact {
                Artifact::Runestone(runestone) => Ok(serde_json::to_value(runestone)?),
                Artifact::Cenotaph(cenotaph) => Err(DeezelError::Runestone(format!("Cenotaph found: {cenotaph:?}"))),
            }
        } else {
            Err(DeezelError::Runestone("No runestone found in transaction".to_string()))
        }
    }

    async fn format_runestone_with_decoded_messages(&self, tx: &Transaction) -> Result<serde_json::Value> {
        if let Some(artifact) = Runestone::decipher(tx) {
            match artifact {
                Artifact::Runestone(runestone) => {
                    Ok(serde_json::json!({
                        "runestone": runestone,
                        "decoded_messages": format!("{:?}", runestone)
                    }))
                },
                Artifact::Cenotaph(cenotaph) => Err(DeezelError::Runestone(format!("Cenotaph found: {cenotaph:?}"))),
            }
        } else {
            Err(DeezelError::Runestone("No runestone found in transaction".to_string()))
        }
    }

    async fn analyze_runestone(&self, txid: &str) -> Result<serde_json::Value> {
        let tx_hex = self.get_tx_hex(txid).await?;
        let tx_bytes = hex::decode(&tx_hex)?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)?;
        self.decode_runestone(&tx).await
    }
}

#[async_trait(?Send)]
impl AlkanesProvider for ConcreteProvider {
    async fn execute(&mut self, params: EnhancedExecuteParams) -> Result<ExecutionState> {
        let mut executor = EnhancedAlkanesExecutor::new(self);
        executor.execute(params).await
    }

    async fn resume_execution(
        &mut self,
        state: ReadyToSignTx,
        params: &EnhancedExecuteParams,
    ) -> Result<EnhancedExecuteResult> {
        let mut executor = EnhancedAlkanesExecutor::new(self);
        executor.resume_execution(state, params).await
    }

    async fn resume_commit_execution(
        &mut self,
        state: ReadyToSignCommitTx,
    ) -> Result<ExecutionState> {
        let mut executor = EnhancedAlkanesExecutor::new(self);
        executor.resume_commit_execution(state).await
    }

    async fn resume_reveal_execution(
        &mut self,
        state: ReadyToSignRevealTx,
    ) -> Result<EnhancedExecuteResult> {
        let mut executor = EnhancedAlkanesExecutor::new(self);
        executor.resume_reveal_execution(state).await
    }

    async fn protorunes_by_address(
        &self,
        address: &str,
        block_tag: Option<String>,
        protocol_tag: u128,
    ) -> Result<crate::alkanes::protorunes::ProtoruneWalletResponse> {
        <Self as MetashrewRpcProvider>::get_protorunes_by_address(self, address, block_tag, protocol_tag).await
    }

    async fn protorunes_by_outpoint(
        &self,
        txid: &str,
        vout: u32,
        block_tag: Option<String>,
        protocol_tag: u128,
    ) -> Result<crate::alkanes::protorunes::ProtoruneOutpointResponse> {
        <Self as MetashrewRpcProvider>::get_protorunes_by_outpoint(self, txid, vout, block_tag, protocol_tag).await
    }

    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue> {
        let parts: Vec<&str> = contract_id.split(':').collect();
        if parts.len() != 2 {
            return Err(DeezelError::InvalidParameters("Invalid contract_id format. Expected 'block:tx'".to_string()));
        }
        let block = parts[0].parse::<u64>()?;
        let tx = parts[1].parse::<u64>()?;

        let mut alkane_id = alkanes_pb::AlkaneId::new();
        let mut block_uint128 = alkanes_pb::Uint128::new();
        block_uint128.lo = block;
        let mut tx_uint128 = alkanes_pb::Uint128::new();
        tx_uint128.lo = tx;
        alkane_id.block = ::protobuf::MessageField::some(block_uint128);
        alkane_id.tx = ::protobuf::MessageField::some(tx_uint128);

        let mut request = alkanes_pb::BytecodeRequest::new();
        request.id = ::protobuf::MessageField::some(alkane_id);
        
        let contract_id_hex = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let params_hex = params.map(|p| format!("0x{}", hex::encode(p.as_bytes()))).unwrap_or_else(|| "0x".to_string());

        let rpc_params = serde_json::json!([contract_id_hex, params_hex]);

        self.call(&self.metashrew_rpc_url, "alkanes_simulate", rpc_params, 1).await
    }

    async fn trace(&self, outpoint: &str) -> Result<alkanes_pb::Trace> {
        let parts: Vec<&str> = outpoint.split(':').collect();
        if parts.len() != 2 {
            return Err(DeezelError::InvalidParameters("Invalid outpoint format. Expected 'txid:vout'".to_string()));
        }
        let txid = bitcoin::Txid::from_str(parts[0])?;
        let vout = parts[1].parse::<u32>()?;

        let mut out_point_pb = alkanes_pb::Outpoint::new();
        out_point_pb.txid = txid.to_raw_hash().as_byte_array().to_vec();
        out_point_pb.vout = vout;

        let hex_input = format!("0x{}", hex::encode(out_point_pb.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("trace", &hex_input, "latest").await?;
        
        let trace = alkanes_pb::Trace::parse_from_bytes(&response_bytes)?;
        Ok(trace)
    }

    async fn get_block(&self, height: u64) -> Result<alkanes_pb::BlockResponse> {
        let mut block_request = alkanes_pb::BlockRequest::new();
        block_request.height = height as u32;
        
        let hex_input = format!("0x{}", hex::encode(block_request.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("getblock", &hex_input, "latest").await?;

        let block_response = alkanes_pb::BlockResponse::parse_from_bytes(&response_bytes)?;
        Ok(block_response)
    }

    async fn sequence(&self, txid: &str, vout: u32) -> Result<JsonValue> {
        let params = serde_json::json!([txid, vout]);
        self.call(&self.metashrew_rpc_url, "alkanes_sequence", params, 1).await
    }

    async fn spendables_by_address(&self, address: &str) -> Result<JsonValue> {
        let mut request = protorune_pb::WalletRequest::new();
        request.wallet = address.as_bytes().to_vec();
        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self
            .metashrew_view_call("spendablesbyaddress", &hex_input, "latest")
            .await?;
        if response_bytes.is_empty() {
            return Ok(serde_json::json!([]));
        }
        let wallet_response = protorune_pb::WalletResponse::parse_from_bytes(&response_bytes)?;
        let entries: Vec<serde_json::Value> = wallet_response.outpoints.into_iter().map(|item| {
            serde_json::json!({
                "outpoint": {
                    "txid": hex::encode(item.outpoint.as_ref().map_or(vec![], |o| o.txid.clone())),
                    "vout": item.outpoint.as_ref().map_or(0, |o| o.vout),
                },
                "amount": item.output.as_ref().map_or(0, |o| o.value),
                "script": hex::encode(item.output.as_ref().map_or(vec![], |o| o.script.clone())),
                "runes": item.balances.iter().flat_map(|balance| {
                    balance.entries.iter().map(|entry| {
                        serde_json::json!({
                            "runeId": {
                                "height": entry.rune.as_ref().and_then(|r| r.runeId.as_ref()).map_or(0, |id| id.height.as_ref().map_or(0, |h| h.lo)),
                                "txindex": entry.rune.as_ref().and_then(|r| r.runeId.as_ref()).map_or(0, |id| id.txindex.as_ref().map_or(0, |t| t.lo)),
                            },
                            "amount": entry.balance.as_ref().map_or(0, |a| a.lo),
                        })
                    }).collect::<Vec<_>>()
                }).collect::<Vec<_>>(),
            })
        }).collect();
        Ok(serde_json::json!(entries))
    }

    async fn trace_block(&self, height: u64) -> Result<alkanes_pb::Trace> {
        let mut block_request = alkanes_pb::BlockRequest::new();
        block_request.height = height as u32;
        
        let hex_input = format!("0x{}", hex::encode(block_request.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("traceblock", &hex_input, "latest").await?;

        let trace = alkanes_pb::Trace::parse_from_bytes(&response_bytes)?;
        Ok(trace)
    }

    async fn get_bytecode(&self, alkane_id: &str) -> Result<String> {
        let parts: Vec<&str> = alkane_id.split(':').collect();
        if parts.len() != 2 {
            return Err(DeezelError::InvalidParameters("Invalid alkane_id format. Expected 'block:tx'".to_string()));
        }
        let block = parts[0].parse::<u64>()?;
        let tx = parts[1].parse::<u64>()?;

        let mut alkane_id_pb = alkanes_pb::AlkaneId::new();
        let mut block_uint128 = alkanes_pb::Uint128::new();
        block_uint128.lo = block;
        let mut tx_uint128 = alkanes_pb::Uint128::new();
        tx_uint128.lo = tx;
        alkane_id_pb.block = ::protobuf::MessageField::some(block_uint128);
        alkane_id_pb.tx = ::protobuf::MessageField::some(tx_uint128);

        let mut request = alkanes_pb::BytecodeRequest::new();
        request.id = ::protobuf::MessageField::some(alkane_id_pb);

        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("getbytecode", &hex_input, "latest").await?;

        Ok(format!("0x{}", hex::encode(response_bytes)))
    }

    #[cfg(feature = "wasm-inspection")]
    async fn inspect(
  &self,
  target: &str,
  config: AlkanesInspectConfig,
 ) -> Result<AlkanesInspectResult> {
  let inspector = AlkaneInspector::new(self.clone());
  let parts: Vec<&str> = target.split(':').collect();
  if parts.len() != 2 {
   return Err(DeezelError::InvalidParameters(
    "Invalid target format. Expected 'block:tx'".to_string(),
   ));
  }
  let block = parts[0].parse::<u64>()?;
  let tx = parts[1].parse::<u64>()?;
  let alkane_id = AlkaneId { block, tx };
  let inspection_config = InspectionConfig {
   disasm: config.disasm,
   fuzz: config.fuzz,
   fuzz_ranges: config.fuzz_ranges,
   meta: config.meta,
   codehash: config.codehash,
   raw: config.raw,
  };
  let result = inspector.inspect_alkane(&alkane_id, &inspection_config).await.map_err(|e| DeezelError::Other(e.to_string()))?;
  Ok(serde_json::from_value(serde_json::to_value(result)?)?)
 }

    #[cfg(not(feature = "wasm-inspection"))]
    async fn inspect(
        &self,
        _target: &str,
        _config: AlkanesInspectConfig,
    ) -> Result<AlkanesInspectResult> {
        Err(DeezelError::NotImplemented(
            "Alkanes inspection is not available without the 'wasm-inspection' feature".to_string(),
        ))
    }

    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkaneBalance>> {
        let addr_str = match address {
            Some(a) => a.to_string(),
            None => WalletProvider::get_address(self).await?,
        };
        let mut request = protorune_pb::WalletRequest::new();
        request.wallet = addr_str.as_bytes().to_vec();
        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self
            .metashrew_view_call("balancesbyaddress", &hex_input, "latest")
            .await?;
        if response_bytes.is_empty() {
            return Ok(vec![]);
        }
        let proto_sheet = protorune_pb::BalanceSheet::parse_from_bytes(&response_bytes)?;

        let result: Vec<AlkaneBalance> = proto_sheet
            .entries
            .into_iter()
            .map(|item| {
                let (alkane_id, name, symbol) = item.rune.as_ref().map_or(
                    (AlkaneId { block: 0, tx: 0 }, String::new(), String::new()),
                    |r| {
                        let id = r.runeId.as_ref().map_or(AlkaneId { block: 0, tx: 0 }, |rid| AlkaneId {
                            block: rid.height.as_ref().map_or(0, |b| b.lo),
                            tx: rid.txindex.as_ref().map_or(0, |t| t.lo),
                        });
                        (id, r.name.clone(), r.symbol.clone())
                    },
                );

                let balance = item.balance.as_ref().map_or(0, |b| b.lo);

                AlkaneBalance { alkane_id, name, symbol, balance }
            })
            .collect();

        Ok(result)
    }
}

// Implement DeezelProvider trait for ConcreteProvider
#[async_trait(?Send)]
impl AddressResolver for ConcreteProvider {
    async fn resolve_all_identifiers(&self, input: &str) -> Result<String> {
        let mut resolver = crate::address_resolver::AddressResolver::new(self.clone());
        resolver.resolve_all_identifiers(input).await
    }

    fn contains_identifiers(&self, input: &str) -> bool {
        let resolver = crate::address_resolver::AddressResolver::new(self.clone());
        resolver.contains_identifiers(input)
    }

    async fn get_address(&self, address_type: &str, index: u32) -> Result<String> {
        if address_type != "p2tr" {
            return Err(DeezelError::Wallet("Only p2tr addresses are supported".to_string()));
        }
        let addresses = WalletProvider::get_addresses(self, index + 1).await?;
        addresses.get(index as usize)
            .map(|a| a.address.clone())
            .ok_or_else(|| DeezelError::Wallet(format!("Address with index {index} not found")))
    }

    async fn list_identifiers(&self) -> Result<Vec<String>> {
        // This is a placeholder. A real implementation would inspect the wallet.
        Ok(vec!["[self:p2tr:0]".to_string(), "[self:p2tr:1]".to_string()])
    }
}

#[async_trait(?Send)]
impl DeezelProvider for ConcreteProvider {
    fn provider_name(&self) -> &str {
        "ConcreteProvider"
    }

    fn clone_box(&self) -> Box<dyn DeezelProvider> {
        Box::new(self.clone())
    }

    async fn initialize(&self) -> Result<()> {
        // Initialize the provider - for now this is a no-op
        // In a full implementation, this might:
        // - Verify RPC connections
        // - Load configuration
        // - Initialize caches
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        // Shutdown the provider - for now this is a no-op
        // In a full implementation, this might:
        // - Close connections
        // - Save state
        // - Clean up resources
        Ok(())
    }

    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>> {
        let tx_info = self.get_tx(&outpoint.txid.to_string()).await?;
        let vout_info = tx_info["vout"].get(outpoint.vout as usize)
            .ok_or_else(|| DeezelError::Wallet(format!("Vout {} not found for tx {}", outpoint.vout, outpoint.txid)))?;
        
        let amount = vout_info["value"].as_u64()
            .ok_or_else(|| DeezelError::Wallet("UTXO value not found".to_string()))?;
        let script_pubkey_hex = vout_info["scriptpubkey"].as_str()
            .ok_or_else(|| DeezelError::Wallet("UTXO script pubkey not found".to_string()))?;
        
        let script_pubkey = ScriptBuf::from(Vec::from_hex(script_pubkey_hex)?);
        Ok(Some(TxOut { value: Amount::from_sat(amount), script_pubkey }))
    }

    async fn sign_taproot_script_spend(&self, sighash: bitcoin::secp256k1::Message) -> Result<bitcoin::secp256k1::schnorr::Signature> {
        let keypair = self.get_keypair().await?;
        let untweaked_keypair = UntweakedKeypair::from(keypair);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        #[cfg(not(target_arch = "wasm32"))]
        let signature = secp.sign_schnorr_with_rng(&sighash, &untweaked_keypair, &mut thread_rng());
        #[cfg(target_arch = "wasm32")]
        let signature = secp.sign_schnorr_with_rng(&sighash, &untweaked_keypair, &mut OsRng);
        Ok(signature)
    }

    fn get_bitcoin_rpc_url(&self) -> Option<String> {
        Some(self.rpc_url.clone())
    }

    fn get_esplora_api_url(&self) -> Option<String> {
        self.esplora_url.clone()
    }

    fn get_ord_server_url(&self) -> Option<String> {
        // Assuming ord server url is the same as rpc_url for now
        Some(self.rpc_url.clone())
    }
}

#[async_trait(?Send)]
impl MetashrewProvider for ConcreteProvider {
    async fn get_height(&self) -> Result<u64> {
        <Self as MetashrewRpcProvider>::get_metashrew_height(self).await
    }

    async fn get_block_hash(&self, height: u64) -> Result<String> {
        <Self as BitcoinRpcProvider>::get_block_hash(self, height).await
    }

    async fn get_state_root(&self, _height: JsonValue) -> Result<String> {
        // Placeholder implementation.
        // In a real scenario, this would call a specific RPC method like `getstateroot`.
        Err(DeezelError::NotImplemented("get_state_root is not implemented for ConcreteProvider".to_string()))
    }
}

#[async_trait(?Send)]
impl UtxoProvider for ConcreteProvider {
    async fn get_utxos_by_spec(&self, spec: &[String]) -> Result<Vec<Utxo>> {
        let utxos = self.get_utxos(false, Some(spec.to_vec())).await?;
        let result = utxos
            .into_iter()
            .map(|(_outpoint, utxo_info)| Utxo {
                txid: utxo_info.txid,
                vout: utxo_info.vout,
                amount: utxo_info.amount,
                address: utxo_info.address,
            })
            .collect();
        Ok(result)
    }
}

// Implement KeystoreProvider trait for ConcreteProvider
#[async_trait(?Send)]
impl KeystoreProvider for ConcreteProvider {
    async fn get_address(&self, address_type: &str, index: u32) -> Result<String> {
        <Self as AddressResolver>::get_address(self, address_type, index).await
    }
    async fn derive_addresses(&self, _master_public_key: &str, _network: Network, _script_types: &[&str], _start_index: u32, _count: u32) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("KeystoreProvider derive_addresses not yet implemented".to_string()))
    }

    async fn get_default_addresses(&self, _master_public_key: &str, _network: Network) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("KeystoreProvider get_default_addresses not yet implemented".to_string()))
    }

    fn parse_address_range(&self, _range_spec: &str) -> Result<(String, u32, u32)> {
        Err(DeezelError::NotImplemented("KeystoreProvider parse_address_range not yet implemented".to_string()))
    }

    async fn get_keystore_info(&self, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> {
        Err(DeezelError::NotImplemented("KeystoreProvider get_keystore_info not yet implemented".to_string()))
    }
}

// Implement MonitorProvider trait for ConcreteProvider
#[async_trait(?Send)]
impl MonitorProvider for ConcreteProvider {
    async fn monitor_blocks(&self, _start: Option<u64>) -> Result<()> {
        Err(DeezelError::NotImplemented("MonitorProvider monitor_blocks not yet implemented".to_string()))
    }

    async fn get_block_events(&self, _height: u64) -> Result<Vec<BlockEvent>> {
        Err(DeezelError::NotImplemented("MonitorProvider get_block_events not yet implemented".to_string()))
    }
}

#[cfg(all(test, feature = "native-deps"))]
mod esplora_provider_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use serde_json::json;

    async fn setup() -> (MockServer, ConcreteProvider) {
        let server = MockServer::start().await;
        let provider = ConcreteProvider::new(
            Some(server.uri()), // bitcoin rpc
            server.uri(), // metashrew rpc
            Some(server.uri()), // sandshrew rpc
            Some(server.uri()), // esplora url
            "regtest".to_string(),
            None,
        ).await.unwrap();
        (server, provider)
    }

    #[tokio::test]
    async fn test_get_blocks_tip_hash() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_hash = "0000000000000000000abcde".to_string();
        
        Mock::given(method("GET"))
            .and(path("/blocks/tip/hash"))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_hash.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_blocks_tip_hash().await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_hash);
    }

    #[tokio::test]
    async fn test_get_blocks_tip_height() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_height = 800000;

        Mock::given(method("GET"))
            .and(path("/blocks/tip/height"))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_height.to_string()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_blocks_tip_height().await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_height);
    }

    #[tokio::test]
    async fn test_get_block_by_height() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_height = 800000;
        let mock_hash = "0000000000000000000abcde".to_string();

        Mock::given(method("GET"))
            .and(path(format!("/block-height/{mock_height}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_hash.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_block_by_height(mock_height).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_hash);
    }

    #[tokio::test]
    async fn test_get_block() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_hash = "00000000000000000001c7b8332e01ab8802397082a1f29f2e7e07e4f8a2a4b7";
        let mock_block = json!({
            "id": mock_hash,
            "height": 700000,
            "version": 536870912,
            "timestamp": 1629886679,
            "tx_count": 2500,
            "size": 1369315,
            "weight": 3992260,
            "merkle_root": "f35e359ac01426b654b33389d739dfe4288634029348a84a169e210d862289c9",
            "previousblockhash": "00000000000000000003a3b2b3b4b5b6b7b8b9bacbdcedfefe010203",
            "nonce": 1234567890,
            "bits": 402793003,
            "difficulty": 17899999999999.99
        });

        Mock::given(method("GET"))
            .and(path(format!("/block/{mock_hash}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_block.clone()))
            .mount(&server)
            .await;

        // Act
        let result = EsploraProvider::get_block(&provider, mock_hash).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_block);
    }

    #[tokio::test]
    async fn test_get_block_status() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_hash = "00000000000000000001c7b8332e01ab8802397082a1f29f2e7e07e4f8a2a4b7";
        let mock_status = json!({
            "in_best_chain": true,
            "height": 700000,
            "next_best": "00000000000000000002a3b2b3b4b5b6b7b8b9bacbdcedfefe010203"
        });

        Mock::given(method("GET"))
            .and(path(format!("/block/{mock_hash}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_status.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_block_status(mock_hash).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_status);
    }

    #[tokio::test]
    async fn test_get_block_txids() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_hash = "00000000000000000001c7b8332e01ab8802397082a1f29f2e7e07e4f8a2a4b7";
        let mock_txids = json!([
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/block/{mock_hash}/txids")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_txids.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_block_txids(mock_hash).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txids);
    }

    #[tokio::test]
    async fn test_get_block_txid() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_hash = "00000000000000000001c7b8332e01ab8802397082a1f29f2e7e07e4f8a2a4b7";
        let mock_index = 5;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        Mock::given(method("GET"))
            .and(path(format!("/block/{mock_hash}/txid/{mock_index}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_txid))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_block_txid(mock_hash, mock_index).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txid);
    }

    #[tokio::test]
    async fn test_get_tx() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_tx = json!({
            "txid": mock_txid,
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [],
            "size": 100,
            "weight": 400,
            "fee": 1000,
            "status": {
                "confirmed": true,
                "block_height": 700000,
                "block_hash": "00000000000000000001c7b8332e01ab8802397082a1f29f2e7e07e4f8a2a4b7",
                "block_time": 1629886679
            }
        });

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_tx.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx(mock_txid).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_tx);
    }

    #[tokio::test]
    async fn test_get_tx_status() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_status = json!({
            "confirmed": true,
            "block_height": 700000,
            "block_hash": "00000000000000000001c7b8332e01ab8802397082a1f29f2e7e07e4f8a2a4b7",
            "block_time": 1629886679
        });

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_status.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx_status(mock_txid).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_status);
    }

    #[tokio::test]
    async fn test_get_tx_hex() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_hex = "02000000000101...";

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}/hex")))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_hex))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx_hex(mock_txid).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_hex);
    }

    #[tokio::test]
    async fn test_get_tx_raw() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_raw = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01];

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}/raw")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(mock_raw.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx_raw(mock_txid).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), hex::encode(mock_raw));
    }

    #[tokio::test]
    async fn test_get_tx_merkle_proof() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_proof = json!({
            "block_height": 700000,
            "merkle": [
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            ],
            "pos": 123
        });

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}/merkle-proof")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_proof.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx_merkle_proof(mock_txid).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_proof);
    }

    #[tokio::test]
    async fn test_get_tx_outspend() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_index = 0;
        let mock_outspend = json!({
            "spent": true,
            "txid": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
            "vin": 0,
            "status": {
                "confirmed": true,
                "block_height": 700001,
                "block_hash": "00000000000000000002a3b2b3b4b5b6b7b8b9bacbdcedfefe010203",
                "block_time": 1629886779
            }
        });

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}/outspend/{mock_index}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_outspend.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx_outspend(mock_txid, mock_index).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_outspend);
    }

    #[tokio::test]
    async fn test_get_tx_outspends() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let mock_outspends = json!([
            {
                "spent": true,
                "txid": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
                "vin": 0,
                "status": {
                    "confirmed": true,
                    "block_height": 700001,
                    "block_hash": "00000000000000000002a3b2b3b4b5b6b7b8b9bacbdcedfefe010203",
                    "block_time": 1629886779
                }
            },
            {
                "spent": false
            }
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/tx/{mock_txid}/outspends")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_outspends.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_tx_outspends(mock_txid).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_outspends);
    }

    #[tokio::test]
    async fn test_get_address() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_address = "bc1q...";
        let mock_address_info = json!({
            "address": mock_address,
            "chain_stats": { "funded_txo_count": 1, "funded_txo_sum": 100000, "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 1 },
            "mempool_stats": { "funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 0 }
        });

        Mock::given(method("GET"))
            .and(path(format!("/address/{mock_address}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_address_info.clone()))
            .mount(&server)
            .await;

        // Act
        let result = EsploraProvider::get_address(&provider, mock_address).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_address_info);
    }

    #[tokio::test]
    async fn test_get_address_txs() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_address = "bc1q...";
        let mock_txs = json!([
            { "txid": "a1b2c3d4...", "status": { "confirmed": true } }
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/address/{mock_address}/txs")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_txs.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_address_txs(mock_address).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txs);
    }

    #[tokio::test]
    async fn test_get_address_txs_chain() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_address = "bc1q...";
        let mock_last_txid = "a1b2c3d4...";
        let mock_txs = json!([
            { "txid": "e5f6g7h8...", "status": { "confirmed": true } }
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/address/{mock_address}/txs/chain/{mock_last_txid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_txs.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_address_txs_chain(mock_address, Some(mock_last_txid)).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txs);
    }

    #[tokio::test]
    async fn test_get_address_txs_mempool() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_address = "bc1q...";
        let mock_txs = json!([
            { "txid": "mempooltx...", "status": { "confirmed": false } }
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/address/{mock_address}/txs/mempool")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_txs.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_address_txs_mempool(mock_address).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txs);
    }

    #[tokio::test]
    async fn test_get_address_utxo() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_address = "bc1q...";
        let mock_utxos = json!([
            { "txid": "utxotx...", "vout": 0, "value": 12345, "status": { "confirmed": true } }
        ]);

        Mock::given(method("GET"))
            .and(path(format!("/address/{mock_address}/utxo")))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_utxos.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_address_utxo(mock_address).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_utxos);
    }

    #[tokio::test]
    async fn test_get_mempool() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_mempool_info = json!({
            "count": 10,
            "vsize": 12345,
            "total_fee": 54321,
            "fee_histogram": [[1.0, 12345]]
        });

        Mock::given(method("GET"))
            .and(path("/mempool"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_mempool_info.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_mempool().await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_mempool_info);
    }

    #[tokio::test]
    async fn test_get_mempool_txids() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_txids = json!([
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        ]);

        Mock::given(method("GET"))
            .and(path("/mempool/txids"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_txids.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_mempool_txids().await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txids);
    }

    #[tokio::test]
    async fn test_get_mempool_recent() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_recent = json!([
            { "txid": "a1b2c3d4...", "fee": 1000, "vsize": 200, "value": 12345 }
        ]);

        Mock::given(method("GET"))
            .and(path("/mempool/recent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_recent.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_mempool_recent().await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_recent);
    }

    #[tokio::test]
    async fn test_get_fee_estimates() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_fees = json!({ "1": 10.0, "6": 5.0, "144": 1.0 });

        Mock::given(method("GET"))
            .and(path("/fee-estimates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(mock_fees.clone()))
            .mount(&server)
            .await;

        // Act
        let result = provider.get_fee_estimates().await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_fees);
    }

    #[tokio::test]
    async fn test_broadcast() {
        // Arrange
        let (server, provider) = setup().await;
        let mock_tx_hex = "0100000001...";
        let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_txid))
            .mount(&server)
            .await;

        // Act
        let result = provider.broadcast(mock_tx_hex).await;

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mock_txid);
    }
}

#[async_trait(?Send)]
impl OrdProvider for ConcreteProvider {
    async fn get_inscription(&self, inscription_id: &str) -> Result<ord::Inscription> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::INSCRIPTION, crate::esplora::params::single(inscription_id), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_inscriptions_in_block(&self, block_hash: &str) -> Result<ord::Inscriptions> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::INSCRIPTIONS_IN_BLOCK, crate::esplora::params::single(block_hash), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

   async fn get_ord_address_info(&self, address: &str) -> Result<ord::AddressInfo> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::ADDRESS, crate::esplora::params::single(address), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_block_info(&self, query: &str) -> Result<ord::Block> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::BLOCK, crate::esplora::params::single(query), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_ord_block_count(&self) -> Result<u64> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::BLOCK_COUNT, crate::esplora::params::empty(), 1).await?;
        log::debug!("get_ord_block_count response: {:?}", json);
        if let Some(count) = json.as_u64() {
            return Ok(count);
        }
        if let Some(count_str) = json.as_str() {
            return count_str.parse::<u64>().map_err(|_| DeezelError::RpcError("Invalid block count string response".to_string()));
        }
        Err(DeezelError::RpcError("Invalid block count response: not a u64 or string".to_string()))
   }

   async fn get_ord_blocks(&self) -> Result<ord::Blocks> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::BLOCKS, crate::esplora::params::empty(), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_children(&self, inscription_id: &str, page: Option<u32>) -> Result<ord::Children> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::CHILDREN, crate::esplora::params::optional_dual(inscription_id, page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_content(&self, inscription_id: &str) -> Result<Vec<u8>> {
        let result = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::CONTENT, crate::esplora::params::single(inscription_id), 1).await?;
        let hex_str = result.as_str().ok_or_else(|| DeezelError::RpcError("Invalid content response".to_string()))?;
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_inscriptions(&self, page: Option<u32>) -> Result<ord::Inscriptions> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::INSCRIPTIONS, crate::esplora::params::optional_single(page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_output(&self, output: &str) -> Result<ord::Output> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::OUTPUT, crate::esplora::params::single(output), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_parents(&self, inscription_id: &str, page: Option<u32>) -> Result<ord::ParentInscriptions> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::PARENTS, crate::esplora::params::optional_dual(inscription_id, page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_rune(&self, rune: &str) -> Result<ord::RuneInfo> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::RUNE, crate::esplora::params::single(rune), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_runes(&self, page: Option<u32>) -> Result<ord::Runes> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::RUNES, crate::esplora::params::optional_single(page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_sat(&self, sat: u64) -> Result<ord::SatResponse> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::SAT, crate::esplora::params::single(sat), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_tx_info(&self, txid: &str) -> Result<ord::TxInfo> {
        let json = self.call(&self.rpc_url, crate::ord::OrdJsonRpcMethods::TX, crate::esplora::params::single(txid), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }
}
