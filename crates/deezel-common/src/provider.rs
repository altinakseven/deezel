//! The ConcreteProvider implementation for deezel.
//!
//! This module provides a concrete implementation of all provider traits
//! using deezel-rpgp for PGP operations and other concrete implementations.

use crate::traits::*;
use crate::{Result, DeezelError, JsonValue};
use crate::ord;
use crate::alkanes::execute::EnhancedAlkanesExecutor;
#[cfg(feature = "wasm-inspection")]
use crate::alkanes::inspector::{AlkaneInspector, InspectionConfig};
use crate::alkanes::types::{
	EnhancedExecuteParams, EnhancedExecuteResult, AlkanesInspectConfig, AlkanesInspectResult,
	AlkaneBalance, AlkaneId,
};
use crate::utils::hex::reverse_txid_bytes;
use alkanes_support::proto::alkanes as alkanes_pb;
use protorune_support::proto::protorune as protorune_pb;
use protobuf::Message;
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
use deezel_rpgp::composed::{
    SecretKeyParamsBuilder, KeyType, SignedSecretKey, SignedPublicKey,
    ArmorOptions
};
use deezel_rpgp::types::{Password, KeyDetails, PublicKeyTrait};
use deezel_rpgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use deezel_rpgp::types::CompressionAlgorithm;
use smallvec::smallvec;

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
    secp256k1::{Secp256k1, All},
    sighash::{SighashCache, Prevouts, TapSighashType},
    bip32::{DerivationPath, Xpriv, Xpub},
};
use bitcoin_hashes::Hash;
use ordinals::{Runestone, Artifact};

#[cfg(feature = "native-deps")]
use std::fs;

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
    bitcoin_rpc_url: String,
    metashrew_rpc_url: String,
    sandshrew_rpc_url: String,
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
}

impl ConcreteProvider {
    pub async fn new(
        bitcoin_rpc_url: String,
        metashrew_rpc_url: String,
        sandshrew_rpc_url: String,
        esplora_url: Option<String>,
        provider: String,
        #[cfg(not(target_arch = "wasm32"))]
        wallet_path: Option<PathBuf>,
        #[cfg(target_arch = "wasm32")]
        wallet_path: Option<String>,
    ) -> Result<Self> {
       let mut new_self = Self {
           bitcoin_rpc_url,
           metashrew_rpc_url,
           sandshrew_rpc_url,
           esplora_url,
           provider,
           wallet_path: wallet_path.clone(),
           passphrase: None,
           wallet_state: WalletState::None,
           #[cfg(feature = "native-deps")]
           http_client: reqwest::Client::new(),
       };

       // Try to load the keystore metadata if a path is provided
       #[cfg(not(target_arch = "wasm32"))]
       if let Some(path) = &wallet_path {
           if path.exists() {
               match Keystore::from_file(path) {
                   Ok(keystore) => new_self.wallet_state = WalletState::Locked(keystore),
                   Err(e) => log::warn!("Failed to load keystore metadata: {}", e),
               }
           }
       }

       Ok(new_self)
   }

   /// Unlock the wallet by decrypting the seed
   pub async fn unlock_wallet(&mut self, passphrase: &str) -> Result<()> {
       if let WalletState::Locked(keystore) = &self.wallet_state {
           let mnemonic = keystore.decrypt_seed(passphrase)?;
           self.wallet_state = WalletState::Unlocked {
               keystore: keystore.clone(),
               mnemonic,
           };
           self.passphrase = Some(passphrase.to_string());
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

    /// Convert a SignedSecretKey to our PgpKey format
    fn convert_signed_secret_key_to_pgp_key(key: &SignedSecretKey) -> Result<PgpKey> {
        // Serialize the key to armored format
        let armored_data = key.to_armored_string(ArmorOptions::default())
            .map_err(|e| DeezelError::Pgp(format!("Failed to armor secret key: {:?}", e)))?
            .into_bytes();

        // Extract key information
        let fingerprint = hex::encode(key.fingerprint().as_bytes());
        let key_id = hex::encode(key.key_id().as_ref());
        let user_ids = key.details.users.iter()
            .map(|user| String::from_utf8_lossy(user.id.id()).to_string())
            .collect();
        let creation_time = key.created_at().timestamp() as u64;

        let algorithm = PgpAlgorithm {
            public_key_algorithm: format!("{:?}", key.algorithm()),
            symmetric_algorithm: Some("AES256".to_string()),
            hash_algorithm: Some("SHA256".to_string()),
            compression_algorithm: Some("ZLIB".to_string()),
        };

        Ok(PgpKey {
            key_data: armored_data,
            is_private: true,
            fingerprint,
            key_id,
            user_ids,
            creation_time,
            expiration_time: key.expires_at().map(|t| t.timestamp() as u64),
            algorithm,
        })
    }

    /// Convert a SignedPublicKey to our PgpKey format
    fn convert_signed_public_key_to_pgp_key(key: &SignedPublicKey) -> Result<PgpKey> {
        // Serialize the key to armored format
        let armored_data = key.to_armored_string(ArmorOptions::default())
            .map_err(|e| DeezelError::Pgp(format!("Failed to armor public key: {:?}", e)))?
            .into_bytes();

        // Extract key information
        let fingerprint = hex::encode(key.fingerprint().as_bytes());
        let key_id = hex::encode(key.key_id().as_ref());
        let user_ids = key.details.users.iter()
            .map(|user| String::from_utf8_lossy(user.id.id()).to_string())
            .collect();
        let creation_time = key.created_at().timestamp() as u64;

        let algorithm = PgpAlgorithm {
            public_key_algorithm: format!("{:?}", key.algorithm()),
            symmetric_algorithm: Some("AES256".to_string()),
            hash_algorithm: Some("SHA256".to_string()),
            compression_algorithm: Some("ZLIB".to_string()),
        };

        Ok(PgpKey {
            key_data: armored_data,
            is_private: false,
            fingerprint,
            key_id,
            user_ids,
            creation_time,
            expiration_time: key.expires_at().map(|t| t.timestamp() as u64),
            algorithm,
        })
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
    fn find_address_info<'a>(
        keystore: &'a mut Keystore,
        address: &Address,
        network: Network,
    ) -> Result<crate::keystore::AddressInfo> {
        // First, check the existing cache.
        if let Some(info) = keystore
            .addresses
            .get(&network.to_string())
            .and_then(|addrs| addrs.iter().find(|a| a.address == address.to_string()))
        {
            return Ok(info.clone());
        }

        // If not found, attempt to derive it on-the-fly.
        // This is necessary for signing transactions for addresses that haven't been explicitly
        // listed or used before. We search a reasonable gap limit.
        let secp = Secp256k1::<All>::new();
        let account_xpub = Xpub::from_str(&keystore.account_xpub)
            .map_err(|e| DeezelError::Wallet(format!("Invalid account xpub in keystore: {}", e)))?;

        // Standard gap limit is 20, but we'll search a bit more to be safe.
        for i in 0..101 {
            let address_path_str = format!("0/{}", i);
            let address_path = DerivationPath::from_str(&address_path_str)?;
            let derived_xpub = account_xpub.derive_pub(&secp, &address_path)?;
            let (internal_key, _) = derived_xpub.public_key.x_only_public_key();
            let derived_address = Address::p2tr(&secp, internal_key, None, network);

            if derived_address == *address {
                // We found the address! Now we can construct its info and cache it.
                let full_path = format!("m/86'/1'/0'/{}", address_path_str);
                let new_info = crate::keystore::AddressInfo {
                    path: full_path,
                    address: address.to_string(),
                    address_type: "p2tr".to_string(),
                };

                // Add to cache for future lookups.
                keystore
                    .addresses
                    .entry(network.to_string())
                    .or_default()
                    .push(new_info.clone());

                return Ok(new_info);
            }
        }

        Err(DeezelError::Wallet(format!(
            "Address {} not found in keystore and could not be derived within the gap limit",
            address
        )))
    }

    async fn metashrew_view_call(&self, method: &str, hex_input: &str) -> Result<Vec<u8>> {
        let result = self.call(
            &self.metashrew_rpc_url,
            "metashrew_view",
            serde_json::json!([method, hex_input, "latest"]),
            1, // Using a static ID for simplicity, can be made dynamic if needed
        ).await?;

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
            use crate::rpc::{RpcRequest, RpcResponse};
            let request = RpcRequest::new(method, params, id);
            let response = self.http_client
                .post(url)
                .json(&request)
                .send()
                .await
                .map_err(|e| DeezelError::Network(e.to_string()))?;
            let response_text = response.text().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            
            // First, try to parse as a standard RpcResponse
            if let Ok(rpc_response) = serde_json::from_str::<RpcResponse>(&response_text) {
                if let Some(error) = rpc_response.error {
                    return Err(DeezelError::RpcError(format!("{}: {}", error.code, error.message)));
                }
                return rpc_response.result.ok_or_else(|| DeezelError::RpcError("No result in RPC response".to_string()));
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
            Err(DeezelError::Network(format!("Failed to decode RPC response: {}", response_text)))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            let _ = (url, method, params, id); // Suppress unused parameter warnings
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }
    
    async fn get_bytecode(&self, _block: &str, _tx: &str) -> Result<String> {
        Err(DeezelError::NotImplemented(
            "get_bytecode is part of AlkanesProvider, not JsonRpcProvider".to_string(),
        ))
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
impl PgpProvider for ConcreteProvider {
    async fn generate_keypair(&self, user_id: &str, passphrase: Option<&str>) -> Result<PgpKeyPair> {
        // Create key generation parameters
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Rsa(2048))
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(true)
            .primary_user_id(user_id.into())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB]);

        let secret_key_params = key_params
            .build()
            .map_err(|e| DeezelError::Pgp(format!("Failed to build key params: {:?}", e)))?;

        // Generate the secret key
        #[cfg(not(target_arch = "wasm32"))]
        let secret_key = secret_key_params
            .generate(thread_rng())
            .map_err(|e| DeezelError::Pgp(format!("Failed to generate secret key: {:?}", e)))?;

        #[cfg(target_arch = "wasm32")]
        let secret_key = secret_key_params
            .generate(OsRng)
            .map_err(|e| DeezelError::Pgp(format!("Failed to generate secret key: {:?}", e)))?;

        // Create password function
        let password_fn = if let Some(pass) = passphrase {
            Password::from(pass.to_string())
        } else {
            Password::empty()
        };

        // Sign the secret key
        #[cfg(not(target_arch = "wasm32"))]
        let signed_secret_key = secret_key
            .sign(&mut thread_rng(), &password_fn)
            .map_err(|e| DeezelError::Pgp(format!("Failed to sign secret key: {:?}", e)))?;

        #[cfg(target_arch = "wasm32")]
        let signed_secret_key = secret_key
            .sign(&mut OsRng, &password_fn)
            .map_err(|e| DeezelError::Pgp(format!("Failed to sign secret key: {:?}", e)))?;

        // Get the public key
        let public_key = signed_secret_key.signed_public_key();

        // Convert to our PgpKey format
        let private_pgp_key = Self::convert_signed_secret_key_to_pgp_key(&signed_secret_key)?;
        let public_pgp_key = Self::convert_signed_public_key_to_pgp_key(&public_key)?;

        Ok(PgpKeyPair {
            public_key: public_pgp_key,
            private_key: private_pgp_key.clone(),
            fingerprint: private_pgp_key.fingerprint.clone(),
            key_id: private_pgp_key.key_id.clone(),
        })
    }
    
    async fn import_key(&self, _armored_key: &str) -> Result<PgpKey> {
        Err(DeezelError::NotImplemented("PGP import_key not yet implemented".to_string()))
    }
    
    async fn export_key(&self, _key: &PgpKey, _include_private: bool) -> Result<String> {
        Err(DeezelError::NotImplemented("PGP export_key not yet implemented".to_string()))
    }
    
    async fn encrypt(&self, _data: &[u8], _recipient_keys: &[PgpKey], _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP encrypt not yet implemented".to_string()))
    }
    
    async fn decrypt(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP decrypt not yet implemented".to_string()))
    }
    
    async fn sign(&self, _data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP sign not yet implemented".to_string()))
    }
    
    async fn verify(&self, _data: &[u8], _signature: &[u8], _public_key: &PgpKey) -> Result<bool> {
        Err(DeezelError::NotImplemented("PGP verify not yet implemented".to_string()))
    }
    
    async fn encrypt_and_sign(&self, _data: &[u8], _recipient_keys: &[PgpKey], _signing_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP encrypt_and_sign not yet implemented".to_string()))
    }
    
    async fn decrypt_and_verify(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _sender_public_key: &PgpKey, _passphrase: Option<&str>) -> Result<PgpDecryptResult> {
        Err(DeezelError::NotImplemented("PGP decrypt_and_verify not yet implemented".to_string()))
    }
    
    async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>> {
        Ok(Vec::new())
    }
    
    async fn get_key(&self, _identifier: &str) -> Result<Option<PgpKey>> {
        Ok(None)
    }
    
    async fn delete_key(&self, _identifier: &str) -> Result<()> {
        Ok(())
    }
    
    async fn change_passphrase(&self, _key: &PgpKey, _old_passphrase: Option<&str>, _new_passphrase: Option<&str>) -> Result<PgpKey> {
        Err(DeezelError::NotImplemented("PGP change_passphrase not yet implemented".to_string()))
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
    async fn create_wallet(&self, config: WalletConfig, mnemonic: Option<String>, _passphrase: Option<String>) -> Result<WalletInfo> {
        // Generate or use provided mnemonic
        let mnemonic_obj = if let Some(mnemonic_str) = mnemonic {
            Mnemonic::from_phrase(&mnemonic_str, bip39::Language::English)
                .map_err(|e| DeezelError::Wallet(format!("Invalid mnemonic provided: {:?}", e)))?
        } else {
            Mnemonic::new(MnemonicType::Words24, bip39::Language::English)
        };

        let mnemonic_str = mnemonic_obj.to_string();

        // Generate seed from mnemonic
        let _seed = Seed::new(&mnemonic_obj, "");
        
        // For now, generate a placeholder address
        // In a real implementation, you would derive actual addresses from the seed
        let address = "bc1qplaceholder0000000000000000000000000000000".to_string();

        // Create wallet info with correct field structure
        let wallet_info = WalletInfo {
            address,
            network: config.network,
            mnemonic: Some(mnemonic_str),
        };

        Ok(wallet_info)
    }
    
    async fn load_wallet(&self, config: WalletConfig, _passphrase: Option<String>) -> Result<WalletInfo> {
        #[cfg(feature = "native-deps")]
        {
            let keystore_path = PathBuf::from(config.wallet_path);
            let keystore_data = fs::read(keystore_path)
                .map_err(|e| DeezelError::Wallet(format!("Failed to read keystore: {}", e)))?;
        
            let keystore: Keystore = serde_json::from_slice(&keystore_data)
                .map_err(|e| DeezelError::Wallet(format!("Failed to deserialize keystore: {}", e)))?;

            // Decryption would happen here. For now, we assume it's not encrypted.
            let mnemonic = keystore.encrypted_seed;

            // For now, we'll just return placeholder info.
            // A full implementation would derive the address from the mnemonic.
            let address = "bc1qloadedplaceholder0000000000000000000000000".to_string();

            Ok(WalletInfo {
                address,
                network: config.network,
                mnemonic: Some(mnemonic),
            })
        }
        #[cfg(not(feature = "native-deps"))]
        {
            let _ = config; // Suppress unused parameter warning
            Err(DeezelError::NotImplemented("File system operations not supported in WASM environment".to_string()))
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
        #[cfg(feature = "native-deps")]
        {
            match &self.wallet_state {
                WalletState::Unlocked { mnemonic, .. } => {
                    let path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
                    let network = self.get_network();
                    let address = crate::keystore::derive_address(mnemonic, &path, network)?;
                    Ok(address.to_string())
                },
                WalletState::Locked(_) => Err(DeezelError::Wallet("Wallet is locked. Cannot get address without unlocking.".to_string())),
                WalletState::None => Err(DeezelError::Wallet("No wallet loaded".to_string())),
            }
        }
        #[cfg(not(feature = "native-deps"))]
        {
            let _ = self; // Suppress unused parameter warning
            Err(DeezelError::NotImplemented("File system operations not supported in WASM environment".to_string()))
        }
    }
    
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>> {
        let keystore = match &self.wallet_state {
            WalletState::Unlocked { keystore, .. } => keystore,
            WalletState::Locked(keystore) => keystore,
            WalletState::None => return Err(DeezelError::Wallet("No wallet loaded".to_string())),
        };

        if keystore.account_xpub.is_empty() {
            return Err(DeezelError::Wallet(
                "Keystore is missing the account_xpub. Please recreate the wallet.".to_string(),
            ));
        }

        let network = self.get_network();
        let mut addresses = Vec::new();
        let secp = Secp256k1::<All>::new();

        let account_xpub = Xpub::from_str(&keystore.account_xpub)?;

        for i in 0..count {
            // The derivation path here is non-hardened, so it can be derived from the public key.
            let address_path_str = format!("0/{}", i);
            let address_path = DerivationPath::from_str(&address_path_str)?;
            let derived_xpub = account_xpub.derive_pub(&secp, &address_path)?;
            let (internal_key, _) = derived_xpub.public_key.x_only_public_key();
            let address = Address::p2tr(&secp, internal_key, None, network);

            addresses.push(AddressInfo {
                address: address.to_string(),
                index: i,
                // The full path includes the hardened part used to derive the account_xpub
                derivation_path: format!("m/86'/1'/0'/{}", address_path_str),
                script_type: "p2tr".to_string(),
                used: false,
            });
        }

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
            // If no addresses are provided, derive the first 101 from the public key to find the coinbase UTXO.
            let derived_infos = self.get_addresses(101).await?;
            derived_infos.into_iter().map(|info| info.address).collect()
        };

        if addrs_to_check.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_utxos = Vec::new();
        for address in addrs_to_check {
            log::info!("Checking UTXOs for address: {}", address);
            let utxos_json = self.get_address_utxo(&address).await;
            
            if let Err(e) = utxos_json {
                log::warn!("Failed to get UTXOs for address {}: {}", address, e);
                continue;
            }
            let utxos_json = utxos_json.unwrap();

            if let Some(utxos_array) = utxos_json.as_array() {
                log::info!("Found {} UTXOs for address {}", utxos_array.len(), address);
                for utxo in utxos_array {
                    if let (Some(txid_str), Some(vout), Some(value)) = (
                        utxo.get("txid").and_then(|t| t.as_str()),
                        utxo.get("vout").and_then(|v| v.as_u64()),
                        utxo.get("value").and_then(|v| v.as_u64()),
                    ) {
                        let status = utxo.get("status");
                        let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
                        let block_height = status.and_then(|s| s.get("block_height")).and_then(|h| h.as_u64());
                        
                        let outpoint = OutPoint::from_str(&format!("{}:{}", txid_str, vout))?;
                        let addr = Address::from_str(&address)?.require_network(self.get_network())?;
                        let utxo_info = UtxoInfo {
                            txid: txid_str.to_string(),
                            vout: vout as u32,
                            amount: value,
                            address: address.clone(),
                            script_pubkey: Some(addr.script_pubkey()),
                            confirmations: if confirmed {
                                if let Some(bh) = block_height {
                                    let current_height = self.get_block_count().await.unwrap_or(bh);
                                    current_height.saturating_sub(bh) as u32 + 1
                                } else {
                                    1
                                }
                            } else { 0 },
                            frozen: false,
                            freeze_reason: None,
                            block_height,
                            has_inscriptions: false,
                            has_runes: false,
                            has_alkanes: false,
                            is_coinbase: false,
                        };
                        log::info!("Found UTXO: {}:{} - {} sats", utxo_info.txid, utxo_info.vout, utxo_info.amount);
                        all_utxos.push((outpoint, utxo_info));
                    }
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
        let estimated_vsize = self.estimate_tx_vsize(&tx, selected_utxos.len());
        let fee = Amount::from_sat((estimated_vsize as f32 * fee_rate).ceil() as u64);

        let change_amount = total_input_amount.checked_sub(target_amount).and_then(|a| a.checked_sub(fee));

        if let Some(change) = change_amount {
            if change > bitcoin::Amount::from_sat(546) { // Dust limit
                // Use the first address as the change address for simplicity
                let change_address = Address::from_str(&all_addresses[0].address)?.require_network(network)?;
                tx.output.push(TxOut {
                    value: change,
                    script_pubkey: change_address.script_pubkey(),
                });
            }
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
                .map_err(|e| DeezelError::Wallet(format!("Failed to parse address from script: {}", e)))?;
            
            // This call now takes a mutable keystore and may cache the derived address info.
            let addr_info = Self::find_address_info(keystore, &address, network)?;
            let path = DerivationPath::from_str(&addr_info.path)?;

            // Derive the private key for this input
            let root_key = Xpriv::new_master(network, mnemonic.as_bytes())?;
            let derived_xpriv = root_key.derive_priv(&secp, &path)?;
            let keypair = derived_xpriv.to_keypair(&secp);

            // Create the sighash
            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )?;

            // Sign the sighash
            let msg = bitcoin::secp256k1::Message::from(sighash);
            let signature = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rand::thread_rng());

            // Add the signature to the witness
            let mut witness = Witness::new();
            witness.push(signature.as_ref());
            sighash_cache.witness_mut(i).unwrap().clone_from(&witness);
        }

        // 6. Serialize the signed transaction
        let signed_tx = sighash_cache.into_transaction();
        Ok(bitcoin::consensus::encode::serialize_hex(&signed_tx))
    }
    
    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String> {
        self.broadcast(&tx_hex).await
    }
    
    async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate> {
        let fee_estimates = self.get_fee_estimates().await?;
        let fee_rate = fee_estimates
            .get(&target.to_string())
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
            let metashrew_synced = metashrew_height_res.as_ref().map_or(false, |&h| h >= bitcoind_height);
            let esplora_synced = esplora_height_res.as_ref().map_or(false, |&h| h >= bitcoind_height);
            let ord_synced = ord_height_res.as_ref().map_or(false, |&h| h >= bitcoind_height);

            log::info!(
                "Sync attempt {}/{}: bitcoind: {}, metashrew: {} (synced: {}), esplora: {} (synced: {}), ord: {} (synced: {})",
                i + 1,
                max_retries,
                bitcoind_height,
                metashrew_height_res.map_or_else(|e| format!("err ({})", e), |h| h.to_string()),
                metashrew_synced,
                esplora_height_res.map_or_else(|e| format!("err ({})", e), |h| h.to_string()),
                esplora_synced,
                ord_height_res.map_or_else(|e| format!("err ({})", e), |h| h.to_string()),
                ord_synced
            );

            if metashrew_synced && esplora_synced && ord_synced {
                log::info!("✅ All backends synchronized successfully!");
                return Ok(());
            }

            self.sleep_ms(2000).await;
        }

        Err(DeezelError::Other(format!("Timeout waiting for backends to sync after {} attempts", max_retries)))
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
    
    async fn get_internal_key(&self) -> Result<bitcoin::XOnlyPublicKey> {
        unimplemented!()
    }
    
    async fn sign_psbt(&self, _psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt> {
        unimplemented!()
    }
    
    async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
        unimplemented!()
    }

    fn set_passphrase(&mut self, passphrase: Option<String>) {
        self.passphrase = passphrase;
    }
}


#[async_trait(?Send)]
impl BitcoinRpcProvider for ConcreteProvider {
    async fn get_block_count(&self) -> Result<u64> {
        let result = self.call(&self.bitcoin_rpc_url, "getblockcount", serde_json::Value::Null, 1).await?;
        result.as_u64().ok_or_else(|| DeezelError::RpcError("Invalid block count response".to_string()))
    }
    
    async fn generate_to_address(&self, nblocks: u32, address: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([nblocks, address]);
        self.call(&self.bitcoin_rpc_url, "generatetoaddress", params, 1).await
    }

    async fn get_new_address(&self) -> Result<JsonValue> {
        self.call(&self.bitcoin_rpc_url, "getnewaddress", serde_json::Value::Null, 1).await
    }
    
    async fn get_transaction_hex(&self, txid: &str) -> Result<String> {
        let params = serde_json::json!([txid]);
        let result = self.call(&self.bitcoin_rpc_url, "getrawtransaction", params, 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid transaction hex response".to_string()))
    }
    
    async fn get_block(&self, hash: &str, raw: bool) -> Result<serde_json::Value> {
        let verbosity = if raw { 0 } else { 2 };
        let params = serde_json::json!([hash, verbosity]);
        self.call(&self.bitcoin_rpc_url, "getblock", params, 1).await
    }
    
    async fn get_block_hash(&self, height: u64) -> Result<String> {
        let params = serde_json::json!([height]);
        let result = self.call(&self.bitcoin_rpc_url, "getblockhash", params, 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block hash response".to_string()))
    }
    
    async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String> {
        let params = serde_json::json!([tx_hex]);
        let result = self.call(&self.bitcoin_rpc_url, "sendrawtransaction", params, 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid txid response from sendrawtransaction".to_string()))
    }
    
    async fn get_mempool_info(&self) -> Result<serde_json::Value> {
        self.call(&self.bitcoin_rpc_url, "getmempoolinfo", serde_json::Value::Null, 1).await
    }
    
    async fn estimate_smart_fee(&self, target: u32) -> Result<serde_json::Value> {
        let params = serde_json::json!([target]);
        self.call(&self.bitcoin_rpc_url, "estimatesmartfee", params, 1).await
    }
    
    async fn get_esplora_blocks_tip_height(&self) -> Result<u64> {
        unimplemented!("This method belongs to the EsploraProvider")
    }
    
    async fn trace_transaction(&self, _txid: &str, _vout: u32, _block: Option<&str>, _tx: Option<&str>) -> Result<serde_json::Value> {
        unimplemented!("This method belongs to the MetashrewRpcProvider")
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
    
    async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<serde_json::Value> {
        let params = serde_json::json!([format!("{}:{}", txid, vout)]);
        self.call(&self.metashrew_rpc_url, "metashrew_view", params, 1).await
    }
    
    async fn get_spendables_by_address(&self, address: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([address]);
        self.call(&self.metashrew_rpc_url, "spendablesbyaddress", params, 1).await
    }
    
    async fn get_protorunes_by_address(&self, address: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([address]);
        self.call(&self.metashrew_rpc_url, "protorunesbyaddress", params, 1).await
    }
    
    async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<serde_json::Value> {
        let params = serde_json::json!([format!("{}:{}", txid, vout)]);
        self.call(&self.metashrew_rpc_url, "protorunesbyoutpoint", params, 1).await
    }
}

#[async_trait(?Send)]
impl EsploraProvider for ConcreteProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/blocks/tip/hash", esplora_url);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }

        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCKS_TIP_HASH, crate::esplora::params::empty(), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid tip hash response".to_string()))
    }

    async fn get_blocks_tip_height(&self) -> Result<u64> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/blocks/tip/height", esplora_url);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let text = response.text().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return text.parse::<u64>().map_err(|e| DeezelError::RpcError(format!("Invalid tip height response from REST API: {}", e)));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCKS_TIP_HEIGHT, crate::esplora::params::empty(), 1).await?;
        result.as_u64().ok_or_else(|| DeezelError::RpcError("Invalid tip height response".to_string()))
    }

    async fn get_blocks(&self, start_height: Option<u64>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = if let Some(height) = start_height {
                format!("{}/blocks/{}", esplora_url, height)
            } else {
                format!("{}/blocks", esplora_url)
            };
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCKS, crate::esplora::params::optional_single(start_height), 1).await
    }

    async fn get_block_by_height(&self, height: u64) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block-height/{}", esplora_url, height);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_HEIGHT, crate::esplora::params::single(height), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block hash response".to_string()))
    }

    async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block/{}", esplora_url, hash);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK, crate::esplora::params::single(hash), 1).await
    }

    async fn get_block_status(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block/{}/status", esplora_url, hash);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_STATUS, crate::esplora::params::single(hash), 1).await
    }

    async fn get_block_txids(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block/{}/txids", esplora_url, hash);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_TXIDS, crate::esplora::params::single(hash), 1).await
    }

    async fn get_block_header(&self, hash: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block/{}/header", esplora_url, hash);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_HEADER, crate::esplora::params::single(hash), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid block header response".to_string()))
    }

    async fn get_block_raw(&self, hash: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block/{}/raw", esplora_url, hash);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let bytes = response.bytes().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return Ok(hex::encode(bytes));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_RAW, crate::esplora::params::single(hash), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid raw block response".to_string()))
    }

    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/block/{}/txid/{}", esplora_url, hash, index);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_TXID, crate::esplora::params::dual(hash, index), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid txid response".to_string()))
    }

    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = if let Some(index) = start_index {
                format!("{}/block/{}/txs/{}", esplora_url, hash, index)
            } else {
                format!("{}/block/{}/txs", esplora_url, hash)
            };
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BLOCK_TXS, crate::esplora::params::optional_dual(hash, start_index), 1).await
    }

    async fn get_address(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/address/{}", esplora_url, address);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_info(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/address/{}", esplora_url, address);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_txs(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/address/{}/txs", esplora_url, address);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_TXS, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = if let Some(txid) = last_seen_txid {
                format!("{}/address/{}/txs/chain/{}", esplora_url, address, txid)
            } else {
                format!("{}/address/{}/txs/chain", esplora_url, address)
            };
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_TXS_CHAIN, crate::esplora::params::optional_dual(address, last_seen_txid), 1).await
    }

    async fn get_address_txs_mempool(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/address/{}/txs/mempool", esplora_url, address);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_TXS_MEMPOOL, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_utxo(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/address/{}/utxo", esplora_url, address);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_UTXO, crate::esplora::params::single(address), 1).await
    }

    async fn get_address_prefix(&self, prefix: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/address-prefix/{}", esplora_url, prefix);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::ADDRESS_PREFIX, crate::esplora::params::single(prefix), 1).await
    }

    async fn get_tx(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX, crate::esplora::params::single(txid), 1).await
    }

    async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/hex", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_HEX, crate::esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid tx hex response".to_string()))
    }

    async fn get_tx_raw(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/raw", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let bytes = response.bytes().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return Ok(hex::encode(bytes));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_RAW, crate::esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid raw tx response".to_string()))
    }

    async fn get_tx_status(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/status", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_STATUS, crate::esplora::params::single(txid), 1).await
    }

    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/merkle-proof", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_MERKLE_PROOF, crate::esplora::params::single(txid), 1).await
    }

    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/merkleblock-proof", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_MERKLEBLOCK_PROOF, crate::esplora::params::single(txid), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid merkleblock proof response".to_string()))
    }

    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/outspend/{}", esplora_url, txid, index);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_OUTSPEND, crate::esplora::params::dual(txid, index), 1).await
    }

    async fn get_tx_outspends(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx/{}/outspends", esplora_url, txid);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::TX_OUTSPENDS, crate::esplora::params::single(txid), 1).await
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/tx", esplora_url);
            let response = self.http_client.post(&url).body(tx_hex.to_string()).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.text().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        let result = self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::BROADCAST, crate::esplora::params::single(tx_hex), 1).await?;
        result.as_str().map(|s| s.to_string()).ok_or_else(|| DeezelError::RpcError("Invalid broadcast response".to_string()))
    }

    async fn get_mempool(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/mempool", esplora_url);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::MEMPOOL, crate::esplora::params::empty(), 1).await
    }

    async fn get_mempool_txids(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/mempool/txids", esplora_url);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::MEMPOOL_TXIDS, crate::esplora::params::empty(), 1).await
    }

    async fn get_mempool_recent(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/mempool/recent", esplora_url);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::MEMPOOL_RECENT, crate::esplora::params::empty(), 1).await
    }

    async fn get_fee_estimates(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        if let Some(esplora_url) = &self.esplora_url {
            let url = format!("{}/fee-estimates", esplora_url);
            let response = self.http_client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            return response.json().await.map_err(|e| DeezelError::Network(e.to_string()));
        }
        
        self.call(&self.sandshrew_rpc_url, crate::esplora::EsploraJsonRpcMethods::FEE_ESTIMATES, crate::esplora::params::empty(), 1).await
    }
}

#[async_trait(?Send)]
impl RunestoneProvider for ConcreteProvider {
    async fn decode_runestone(&self, tx: &Transaction) -> Result<serde_json::Value> {
        if let Some(artifact) = Runestone::decipher(tx) {
            match artifact {
                Artifact::Runestone(runestone) => Ok(serde_json::to_value(runestone)?),
                Artifact::Cenotaph(cenotaph) => Err(DeezelError::Runestone(format!("Cenotaph found: {:?}", cenotaph))),
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
                Artifact::Cenotaph(cenotaph) => Err(DeezelError::Runestone(format!("Cenotaph found: {:?}", cenotaph))),
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
    async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        let executor = EnhancedAlkanesExecutor::new(self);
        executor.execute(params).await
    }

    async fn protorunes_by_address(&self, address: &str) -> Result<JsonValue> {
        let mut request = protorune_pb::WalletRequest::new();
        request.wallet = address.as_bytes().to_vec();
        let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("protorunesbyaddress", &hex_input).await?;
        if response_bytes.is_empty() {
            return Ok(serde_json::Value::Array(vec![]));
        }
        let proto_sheet = protorune_pb::BalanceSheet::parse_from_bytes(&response_bytes)?;

        let entries: Vec<serde_json::Value> = proto_sheet.entries.into_iter().map(|item| {
            let rune = item.rune.as_ref();
            let rune_id = rune.and_then(|r| r.runeId.as_ref());
            serde_json::json!({
                "rune": {
                    "runeId": {
                        "height": rune_id.and_then(|id| id.height.as_ref()).map_or(0, |h| h.lo),
                        "txindex": rune_id.and_then(|id| id.txindex.as_ref()).map_or(0, |t| t.lo)
                    },
                    "name": rune.map_or("".to_string(), |r| r.name.clone()),
                    "divisibility": rune.map_or(0, |r| r.divisibility),
                    "spacers": rune.map_or(0, |r| r.spacers),
                    "symbol": rune.map_or("".to_string(), |r| r.symbol.clone()),
                },
                "balance": item.balance.as_ref().map_or(0, |b| b.lo)
            })
        }).collect();

        Ok(serde_json::json!({ "entries": entries }))
    }

    async fn protorunes_by_outpoint(
  &self,
  txid: &str,
  vout: u32,
 ) -> Result<protorune_pb::OutpointResponse> {
  let mut request = protorune_pb::Outpoint::new();
  let reversed_txid_hex = reverse_txid_bytes(txid)?;
  request.txid = hex::decode(reversed_txid_hex)?;
  request.vout = vout;
  let hex_input = format!("0x{}", hex::encode(request.write_to_bytes()?));
  let response_bytes = self.metashrew_view_call("protorunesbyoutpoint", &hex_input).await?;
  if response_bytes.is_empty() {
   return Ok(protorune_pb::OutpointResponse::new());
  }
  let proto_response = protorune_pb::OutpointResponse::parse_from_bytes(&response_bytes)?;
  Ok(proto_response)
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
        let response_bytes = self.metashrew_view_call("trace", &hex_input).await?;
        
        let trace = alkanes_pb::Trace::parse_from_bytes(&response_bytes)?;
        Ok(trace)
    }

    async fn get_block(&self, height: u64) -> Result<alkanes_pb::BlockResponse> {
        let mut block_request = alkanes_pb::BlockRequest::new();
        block_request.height = height as u32;
        
        let hex_input = format!("0x{}", hex::encode(block_request.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("getblock", &hex_input).await?;

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
        let response_bytes = self.metashrew_view_call("spendablesbyaddress", &hex_input).await?;
        if response_bytes.is_empty() {
            return Ok(serde_json::json!([]));
        }
        let wallet_response = protorune_pb::WalletResponse::parse_from_bytes(&response_bytes)?;
        let entries: Vec<serde_json::Value> = wallet_response.outpoints.into_iter().map(|item| {
            serde_json::json!({
                "outpoint": {
                    "txid": hex::encode(&item.outpoint.as_ref().map_or(vec![], |o| o.txid.clone())),
                    "vout": item.outpoint.as_ref().map_or(0, |o| o.vout),
                },
                "amount": item.output.as_ref().map_or(0, |o| o.value),
                "script": hex::encode(&item.output.as_ref().map_or(vec![], |o| o.script.clone())),
                "runes": item.balances.iter().map(|balance| {
                    balance.entries.iter().map(|entry| {
                        serde_json::json!({
                            "runeId": {
                                "height": entry.rune.as_ref().and_then(|r| r.runeId.as_ref()).map_or(0, |id| id.height.as_ref().map_or(0, |h| h.lo)),
                                "txindex": entry.rune.as_ref().and_then(|r| r.runeId.as_ref()).map_or(0, |id| id.txindex.as_ref().map_or(0, |t| t.lo)),
                            },
                            "amount": entry.balance.as_ref().map_or(0, |a| a.lo),
                        })
                    }).collect::<Vec<_>>()
                }).flatten().collect::<Vec<_>>(),
            })
        }).collect();
        Ok(serde_json::json!(entries))
    }

    async fn trace_block(&self, height: u64) -> Result<alkanes_pb::Trace> {
        let mut block_request = alkanes_pb::BlockRequest::new();
        block_request.height = height as u32;
        
        let hex_input = format!("0x{}", hex::encode(block_request.write_to_bytes()?));
        let response_bytes = self.metashrew_view_call("traceblock", &hex_input).await?;

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
        let response_bytes = self.metashrew_view_call("getbytecode", &hex_input).await?;

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
        let response_bytes = self.metashrew_view_call("balancesbyaddress", &hex_input).await?;
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
            .ok_or_else(|| DeezelError::Wallet(format!("Address with index {} not found", index)))
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
        // This is a temporary solution. A proper implementation would have a shared secp context.
        unimplemented!()
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

    async fn sign_taproot_script_spend(&self, _sighash: bitcoin::secp256k1::Message) -> Result<bitcoin::secp256k1::schnorr::Signature> {
        Err(DeezelError::NotImplemented("sign_taproot_script_spend not implemented for ConcreteProvider".to_string()))
    }

}

// Implement KeystoreProvider trait for ConcreteProvider
#[async_trait(?Send)]
impl KeystoreProvider for ConcreteProvider {
    async fn derive_addresses(&self, _master_public_key: &str, _network: Network, _script_types: &[&str], _start_index: u32, _count: u32) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("KeystoreProvider derive_addresses not yet implemented".to_string()))
    }

    async fn get_default_addresses(&self, _master_public_key: &str, _network: Network) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("KeystoreProvider get_default_addresses not yet implemented".to_string()))
    }

    fn parse_address_range(&self, _range_spec: &str) -> Result<(String, u32, u32)> {
        Err(DeezelError::NotImplemented("KeystoreProvider parse_address_range not yet implemented".to_string()))
    }

    async fn get_keystore_info(&self, _master_public_key: &str, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> {
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
            server.uri(), // bitcoin rpc
            server.uri(), // metashrew rpc
            server.uri(), // sandshrew rpc
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
            .and(path(format!("/block-height/{}", mock_height)))
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
            .and(path(format!("/block/{}", mock_hash)))
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
            .and(path(format!("/block/{}/status", mock_hash)))
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
            .and(path(format!("/block/{}/txids", mock_hash)))
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
            .and(path(format!("/block/{}/txid/{}", mock_hash, mock_index)))
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
            .and(path(format!("/tx/{}", mock_txid)))
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
            .and(path(format!("/tx/{}/status", mock_txid)))
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
            .and(path(format!("/tx/{}/hex", mock_txid)))
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
            .and(path(format!("/tx/{}/raw", mock_txid)))
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
            .and(path(format!("/tx/{}/merkle-proof", mock_txid)))
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
            .and(path(format!("/tx/{}/outspend/{}", mock_txid, mock_index)))
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
            .and(path(format!("/tx/{}/outspends", mock_txid)))
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
            .and(path(format!("/address/{}", mock_address)))
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
            .and(path(format!("/address/{}/txs", mock_address)))
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
            .and(path(format!("/address/{}/txs/chain/{}", mock_address, mock_last_txid)))
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
            .and(path(format!("/address/{}/txs/mempool", mock_address)))
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
            .and(path(format!("/address/{}/utxo", mock_address)))
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
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::INSCRIPTION, crate::esplora::params::single(inscription_id), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_inscriptions_in_block(&self, block_hash: &str) -> Result<ord::Inscriptions> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::INSCRIPTIONS_IN_BLOCK, crate::esplora::params::single(block_hash), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

   async fn get_ord_address_info(&self, address: &str) -> Result<ord::AddressInfo> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::ADDRESS, crate::esplora::params::single(address), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_block_info(&self, query: &str) -> Result<ord::Block> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::BLOCK, crate::esplora::params::single(query), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_ord_block_count(&self) -> Result<u64> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::BLOCK_COUNT, crate::esplora::params::empty(), 1).await?;
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
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::BLOCKS, crate::esplora::params::empty(), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_children(&self, inscription_id: &str, page: Option<u32>) -> Result<ord::Children> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::CHILDREN, crate::esplora::params::optional_dual(inscription_id, page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_content(&self, inscription_id: &str) -> Result<Vec<u8>> {
        let result = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::CONTENT, crate::esplora::params::single(inscription_id), 1).await?;
        let hex_str = result.as_str().ok_or_else(|| DeezelError::RpcError("Invalid content response".to_string()))?;
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_inscriptions(&self, page: Option<u32>) -> Result<ord::Inscriptions> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::INSCRIPTIONS, crate::esplora::params::optional_single(page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_output(&self, output: &str) -> Result<ord::Output> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::OUTPUT, crate::esplora::params::single(output), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_parents(&self, inscription_id: &str, page: Option<u32>) -> Result<ord::ParentInscriptions> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::PARENTS, crate::esplora::params::optional_dual(inscription_id, page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_rune(&self, rune: &str) -> Result<ord::RuneInfo> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::RUNE, crate::esplora::params::single(rune), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_runes(&self, page: Option<u32>) -> Result<ord::Runes> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::RUNES, crate::esplora::params::optional_single(page), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_sat(&self, sat: u64) -> Result<ord::SatResponse> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::SAT, crate::esplora::params::single(sat), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }

   async fn get_tx_info(&self, txid: &str) -> Result<ord::TxInfo> {
        let json = self.call(&self.sandshrew_rpc_url, crate::ord::OrdJsonRpcMethods::TX, crate::esplora::params::single(txid), 1).await?;
        serde_json::from_value(json).map_err(|e| DeezelError::Serialization(e.to_string()))
   }
}