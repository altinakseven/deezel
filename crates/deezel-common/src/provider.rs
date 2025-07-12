//! The ConcreteProvider implementation for deezel.
//!
//! This module provides a concrete implementation of all provider traits
//! using deezel-rpgp for PGP operations and other concrete implementations.

use crate::traits::*;
use crate::{Result, DeezelError, JsonValue};
use async_trait::async_trait;
use std::path::PathBuf;
use std::fs;
use std::str::FromStr;
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
    sighash::{self, SighashCache, Prevouts},
    bip32::{DerivationPath, Xpriv},
};
use ordinals::{Runestone, Artifact};

#[derive(Clone)]
pub struct ConcreteProvider {
    bitcoin_rpc_url: String,
    metashrew_rpc_url: String,
    provider: String,
    wallet_path: Option<PathBuf>,
    passphrase: Option<String>,
}

impl ConcreteProvider {
    pub async fn new(
        bitcoin_rpc_url: String,
        metashrew_rpc_url: String,
        provider: String,
        wallet_path: Option<PathBuf>,
    ) -> Result<Self> {
        Ok(Self {
            bitcoin_rpc_url,
            metashrew_rpc_url,
            provider,
            wallet_path,
            passphrase: None,
        })
    }

    /// Get the wallet path
    pub fn get_wallet_path(&self) -> Option<&PathBuf> {
        self.wallet_path.as_ref()
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
    fn find_address_info<'a>(&self, keystore: &'a Keystore, address: &Address, network: Network) -> Result<&'a crate::keystore::AddressInfo> {
        keystore
            .addresses
            .get(&network.to_string())
            .and_then(|addrs| addrs.iter().find(|a| a.address == address.to_string()))
            .ok_or_else(|| DeezelError::Wallet(format!("Address {} not found in keystore", address)))
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
        #[cfg(feature = "native-deps")]
        {
            use crate::rpc::{RpcRequest, RpcResponse};
            let request = RpcRequest::new(method, params, id);
            let client = reqwest::Client::new();
            let response = client
                .post(url)
                .json(&request)
                .send()
                .await
                .map_err(|e| DeezelError::Network(e.to_string()))?;
            let rpc_response: RpcResponse = response
                .json()
                .await
                .map_err(|e| DeezelError::Network(e.to_string()))?;
            if let Some(error) = rpc_response.error {
                return Err(DeezelError::RpcError(format!("{}: {}", error.code, error.message)));
            }
            rpc_response.result.ok_or_else(|| DeezelError::RpcError("No result in RPC response".to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }
    
    async fn get_bytecode(&self, block: &str, tx: &str) -> Result<String> {
        use crate::rpc::{StandaloneRpcClient, RpcConfig};
        use alkanes_support::proto::alkanes::{BytecodeRequest, AlkaneId, Uint128};
        use protobuf::Message;

        let rpc_config = RpcConfig {
            bitcoin_rpc_url: self.bitcoin_rpc_url.clone(),
            metashrew_rpc_url: self.metashrew_rpc_url.clone(),
            sandshrew_rpc_url: self.metashrew_rpc_url.clone(), // sandshrew_rpc_url is the same as metashrew
            timeout_seconds: 600,
        };

        let rpc_client = StandaloneRpcClient::new(rpc_config);
        
        let mut bytecode_request = BytecodeRequest::new();
        let mut alkane_id = AlkaneId::new();

        let block_u128 = block.parse::<u128>().map_err(|e| DeezelError::Other(e.to_string()))?;
        let tx_u128 = tx.parse::<u128>().map_err(|e| DeezelError::Other(e.to_string()))?;

        let mut block_uint128 = Uint128::new();
        block_uint128.lo = (block_u128 & 0xFFFFFFFFFFFFFFFF) as u64;
        block_uint128.hi = (block_u128 >> 64) as u64;

        let mut tx_uint128 = Uint128::new();
        tx_uint128.lo = (tx_u128 & 0xFFFFFFFFFFFFFFFF) as u64;
        tx_uint128.hi = (tx_u128 >> 64) as u64;

        alkane_id.block = protobuf::MessageField::some(block_uint128);
        alkane_id.tx = protobuf::MessageField::some(tx_uint128);

        bytecode_request.id = protobuf::MessageField::some(alkane_id);

        let encoded_bytes = bytecode_request.write_to_bytes().map_err(|e| DeezelError::Other(e.to_string()))?;
        let hex_input = format!("0x{}", hex::encode(encoded_bytes));

        let result = rpc_client.http_call(
            &self.metashrew_rpc_url,
            "metashrew_view",
            serde_json::json!(["getbytecode", hex_input, "latest"])
        ).await?;

        result.as_str()
            .ok_or_else(|| DeezelError::RpcError("Invalid bytecode response".to_string()))
            .map(|s| s.to_string())
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

impl TimeProvider for ConcreteProvider {
    fn now_secs(&self) -> u64 {
        unimplemented!()
    }
    
    fn now_millis(&self) -> u64 {
        unimplemented!()
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    fn sleep_ms(&self, _ms: u64) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(std::time::Duration::from_millis(_ms)))
    }

    #[cfg(target_arch = "wasm32")]
    fn sleep_ms(&self, _ms: u64) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()>>> {
        Box::pin(gloo_timers::future::sleep(std::time::Duration::from_millis(_ms)))
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
            Err(DeezelError::NotImplemented("File system operations not supported in WASM environment".to_string()))
        }
    }
    
    async fn get_balance(&self) -> Result<WalletBalance> {
        // This is a simplified implementation. A real wallet would manage multiple addresses.
        // For now, we assume the wallet has a single address we can query.
        // A full implementation would need to load the keystore and iterate through addresses.
        Err(DeezelError::NotImplemented("get_balance requires a loaded wallet, which is not yet implemented".to_string()))
    }
    
    async fn get_address(&self) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let wallet_path = self.get_wallet_path().ok_or_else(|| DeezelError::Wallet("Wallet path not set".to_string()))?;
            let keystore_data = fs::read(wallet_path)
                .map_err(|e| DeezelError::Wallet(format!("Failed to read keystore: {}", e)))?;
            let keystore: Keystore = serde_json::from_slice(&keystore_data)
                .map_err(|e| DeezelError::Wallet(format!("Failed to deserialize keystore: {}", e)))?;

            let passphrase = self.passphrase.as_deref().ok_or_else(|| DeezelError::Wallet("Passphrase not set".to_string()))?;
            let seed = crate::keystore::decrypt_seed(&keystore, passphrase)?;
            let path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
            let network = self.get_network();
            let address = crate::keystore::derive_address(&seed, &path, network)?;
            
            Ok(address.to_string())
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("File system operations not supported in WASM environment".to_string()))
        }
    }
    
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>> {
        #[cfg(feature = "native-deps")]
        {
            let wallet_path = self.get_wallet_path().ok_or_else(|| DeezelError::Wallet("Wallet path not set".to_string()))?;
            let keystore_data = fs::read(wallet_path)
                .map_err(|e| DeezelError::Wallet(format!("Failed to read keystore: {}", e)))?;
            let keystore: Keystore = serde_json::from_slice(&keystore_data)
                .map_err(|e| DeezelError::Wallet(format!("Failed to deserialize keystore: {}", e)))?;

            let passphrase = self.passphrase.as_deref().ok_or_else(|| DeezelError::Wallet("Passphrase not set".to_string()))?;
            let seed = crate::keystore::decrypt_seed(&keystore, passphrase)?;
            let network = self.get_network();
            let mut addresses = Vec::new();

            for i in 0..count {
                let path_str = format!("m/86'/0'/0'/0/{}", i);
                let path = bitcoin::bip32::DerivationPath::from_str(&path_str).unwrap();
                let address = crate::keystore::derive_address(&seed, &path, network)?;
                
                addresses.push(AddressInfo {
                    address: address.to_string(),
                    index: i,
                    derivation_path: path_str,
                    script_type: "p2tr".to_string(),
                    used: false, // Assuming not used for now
                });
            }
            
            Ok(addresses)
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("File system operations not supported in WASM environment".to_string()))
        }
    }
    
    async fn send(&self, params: SendParams) -> Result<String> {
        // 1. Create the transaction
        let tx_hex = self.create_transaction(params).await?;

        // 2. Sign the transaction
        let signed_tx_hex = self.sign_transaction(tx_hex).await?;

        // 3. Broadcast the transaction
        self.broadcast_transaction(signed_tx_hex).await
    }
    
    async fn get_utxos(&self, _include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>> {
        let addrs = addresses.ok_or_else(|| DeezelError::Wallet("get_utxos requires at least one address".to_string()))?;
        let mut all_utxos = Vec::new();

        for address in addrs {
            let utxos_json = self.get_address_utxo(&address).await?;
            if let Some(utxos_array) = utxos_json.as_array() {
                for utxo in utxos_array {
                    if let (Some(txid), Some(vout), Some(value)) = (
                        utxo.get("txid").and_then(|t| t.as_str()),
                        utxo.get("vout").and_then(|v| v.as_u64()),
                        utxo.get("value").and_then(|v| v.as_u64()),
                    ) {
                        let status = utxo.get("status");
                        let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
                        let block_height = status.and_then(|s| s.get("block_height")).and_then(|h| h.as_u64());

                        all_utxos.push(UtxoInfo {
                            txid: txid.to_string(),
                            vout: vout as u32,
                            amount: value,
                            address: address.clone(),
                            script_pubkey: None, // Esplora doesn't provide this directly
                            confirmations: if confirmed { 1 } else { 0 }, // Simplified
                            frozen: false, // Not supported yet
                            freeze_reason: None,
                            block_height,
                            has_inscriptions: false, // Not supported yet
                            has_runes: false, // Not supported yet
                            has_alkanes: false, // Not supported yet
                            is_coinbase: false, // Not easily determined from Esplora
                        });
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
        // 1. Get all addresses from the keystore to find UTXOs
        let all_addresses = self.get_addresses(100).await?; // A reasonable number for a simple wallet
        let address_strings: Vec<String> = all_addresses.iter().map(|a| a.address.clone()).collect();

        // 2. Get UTXOs for all our addresses
        let utxos = self.get_utxos(false, Some(address_strings)).await?;

        // 3. Perform coin selection
        let target_amount = Amount::from_sat(params.amount);
        let fee_rate = params.fee_rate.unwrap_or(1.0); // Default to 1 sat/vbyte

        let (selected_utxos, total_input_amount) = self.select_coins(utxos, target_amount)?;

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

    async fn sign_transaction(&self, tx_hex: String) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            // 1. Deserialize the transaction
            let hex_bytes = hex::decode(tx_hex)?;
            let mut tx: Transaction = bitcoin::consensus::deserialize(&hex_bytes)?;

            // 2. Get the seed and keystore
            let wallet_path = self.get_wallet_path().ok_or_else(|| DeezelError::Wallet("Wallet path not set".to_string()))?;
            let keystore_data = fs::read(wallet_path)?;
        let keystore: Keystore = serde_json::from_slice(&keystore_data)?;
        let passphrase = self.passphrase.as_deref().ok_or_else(|| DeezelError::Wallet("Passphrase not set for signing".to_string()))?;
        let seed = crate::keystore::decrypt_seed(&keystore, passphrase)?;
        let network = self.get_network();
        let secp: Secp256k1<All> = Secp256k1::new();

        // 3. Fetch the previous transaction outputs (prevouts) for signing
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

        // 4. Sign each input
        let mut sighash_cache = SighashCache::new(&mut tx);
        for i in 0..prevouts.len() {
            let prev_txout = &prevouts[i];
            
            // Find the address and its derivation path from our keystore
            let address = Address::from_script(&prev_txout.script_pubkey, network)
                .map_err(|e| DeezelError::Wallet(format!("Failed to parse address from script: {}", e)))?;
            let addr_info = self.find_address_info(&keystore, &address, network)?;
            let path = DerivationPath::from_str(&addr_info.path)?;

            // Derive the private key for this input
            let root_key = Xpriv::new_master(network, seed.as_bytes())?;
            let derived_xpriv = root_key.derive_priv(&secp, &path)?;
            let keypair = derived_xpriv.to_keypair(&secp);

            // Create the sighash
            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                sighash::TapSighashType::Default,
            )?;

            // Sign the sighash
            let msg = bitcoin::secp256k1::Message::from(sighash);
            let signature = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rand::thread_rng());

            // Add the signature to the witness
            let mut witness = Witness::new();
            witness.push(signature.as_ref());
            sighash_cache.witness_mut(i).unwrap().clone_from(&witness);
        }

        // 5. Serialize the signed transaction
        let signed_tx = sighash_cache.into_transaction();
        Ok(bitcoin::consensus::encode::serialize_hex(&signed_tx))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("File system operations not supported in WASM environment".to_string()))
        }
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
        unimplemented!()
    }
    
    async fn backup(&self) -> Result<String> {
        unimplemented!()
    }
    
    async fn get_mnemonic(&self) -> Result<Option<String>> {
        unimplemented!()
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
impl AddressResolver for ConcreteProvider {
    async fn resolve_all_identifiers(&self, _input: &str) -> Result<String> {
        unimplemented!()
    }
    
    fn contains_identifiers(&self, _input: &str) -> bool {
        unimplemented!()
    }
    
    async fn get_address(&self, _address_type: &str, _index: u32) -> Result<String> {
        unimplemented!()
    }
    
    async fn list_identifiers(&self) -> Result<Vec<String>> {
        unimplemented!()
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
    
    async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([hash, 2]); // Verbosity 2 for JSON object
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
        let result = self.call(&self.metashrew_rpc_url, "metashrew_height", serde_json::Value::Null, 1).await?;
        result.as_u64().ok_or_else(|| DeezelError::RpcError("Invalid metashrew height response".to_string()))
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
        {
            let url = format!("{}/blocks/tip/hash", self.bitcoin_rpc_url);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.text().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_blocks_tip_height(&self) -> Result<u64> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/blocks/tip/height", self.bitcoin_rpc_url);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let text = response.text().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            text.parse::<u64>().map_err(|e| DeezelError::RpcError(format!("Invalid height response: {}", e)))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_blocks(&self, start_height: Option<u64>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = if let Some(height) = start_height {
                format!("{}/blocks/{}", self.bitcoin_rpc_url, height)
            } else {
                format!("{}/blocks", self.bitcoin_rpc_url)
            };
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_by_height(&self, height: u64) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block-height/{}", self.bitcoin_rpc_url, height);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.text().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block/{}", self.bitcoin_rpc_url, hash);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_status(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block/{}/status", self.bitcoin_rpc_url, hash);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_txids(&self, hash: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block/{}/txids", self.bitcoin_rpc_url, hash);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_header(&self, hash: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block/{}/header", self.bitcoin_rpc_url, hash);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.text().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_raw(&self, hash: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block/{}/raw", self.bitcoin_rpc_url, hash);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let bytes = response.bytes().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            Ok(hex::encode(bytes))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/block/{}/txid/{}", self.bitcoin_rpc_url, hash, index);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.text().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = if let Some(index) = start_index {
                format!("{}/block/{}/txs/{}", self.bitcoin_rpc_url, hash, index)
            } else {
                format!("{}/block/{}/txs", self.bitcoin_rpc_url, hash)
            };
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_address(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/address/{}", self.bitcoin_rpc_url, address);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_address_txs(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/address/{}/txs", self.bitcoin_rpc_url, address);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = if let Some(txid) = last_seen_txid {
                format!("{}/address/{}/txs/chain/{}", self.bitcoin_rpc_url, address, txid)
            } else {
                format!("{}/address/{}/txs/chain", self.bitcoin_rpc_url, address)
            };
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_address_txs_mempool(&self, address: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/address/{}/txs/mempool", self.bitcoin_rpc_url, address);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_address_utxo(&self, address: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([address]);
        self.call(&self.bitcoin_rpc_url, "esplora_address::utxo", params, 1).await
    }

    async fn get_address_prefix(&self, prefix: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/address/prefix/{}", self.bitcoin_rpc_url, prefix);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx(&self, txid: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!([txid]);
        self.call(&self.bitcoin_rpc_url, "esplora_tx", params, 1).await
    }

    async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/hex", self.bitcoin_rpc_url, txid);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.text().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx_raw(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/raw", self.bitcoin_rpc_url, txid);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            let bytes = response.bytes().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            Ok(hex::encode(bytes))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx_status(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/status", self.bitcoin_rpc_url, txid);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/merkle-proof", self.bitcoin_rpc_url, txid);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/merkleblock-proof", self.bitcoin_rpc_url, txid);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.text().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/outspend/{}", self.bitcoin_rpc_url, txid, index);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_tx_outspends(&self, txid: &str) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/tx/{}/outspends", self.bitcoin_rpc_url, txid);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        // Broadcasting is a standard bitcoind RPC call, not an Esplora-specific one.
        // Delegate to the BitcoinRpcProvider implementation.
        self.send_raw_transaction(tx_hex).await
    }

    async fn get_mempool(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/mempool", self.bitcoin_rpc_url);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_mempool_txids(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/mempool/txids", self.bitcoin_rpc_url);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_mempool_recent(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/mempool/recent", self.bitcoin_rpc_url);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
    }

    async fn get_fee_estimates(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "native-deps")]
        {
            let url = format!("{}/fee-estimates", self.bitcoin_rpc_url);
            let client = reqwest::Client::new();
            let response = client.get(&url).send().await.map_err(|e| DeezelError::Network(e.to_string()))?;
            response.json().await.map_err(|e| DeezelError::Network(e.to_string()))
        }
        #[cfg(not(feature = "native-deps"))]
        {
            Err(DeezelError::NotImplemented("HTTP requests not available in WASM environment".to_string()))
        }
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
    async fn execute(&self, _params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        unimplemented!()
    }
    
    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        let addr = address.ok_or_else(|| DeezelError::Wallet("get_balance requires an address".to_string()))?;
        let result = self.get_protorunes_by_address(addr).await?;
        serde_json::from_value(result).map_err(|e| DeezelError::Serialization(e.to_string()))
    }

    async fn get_alkanes_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        <Self as AlkanesProvider>::get_balance(self, address).await
    }
    
    async fn get_token_info(&self, alkane_id: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!(["gettokeninfo", alkane_id, "latest"]);
        self.call(&self.metashrew_rpc_url, "metashrew_view", params, 1).await
    }
    
    async fn trace(&self, outpoint: &str) -> Result<serde_json::Value> {
        let params = serde_json::json!(["trace", outpoint, "latest"]);
        self.call(&self.metashrew_rpc_url, "metashrew_view", params, 1).await
    }
    
    async fn inspect(&self, _target: &str, _config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        unimplemented!()
    }

    async fn get_bytecode(&self, _alkane_id: &str) -> Result<String> {
        unimplemented!()
    }

    async fn simulate(&self, _contract_id: &str, _params: Option<&str>) -> Result<JsonValue> {
        unimplemented!()
    }
}

// Implement DeezelProvider trait for ConcreteProvider
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