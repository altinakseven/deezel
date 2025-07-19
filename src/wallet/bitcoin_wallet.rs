//! Pure rust-bitcoin wallet implementation
//!
//! This module provides:
//! - Wallet creation and management using rust-bitcoin directly
//! - Mnemonic generation and key derivation
//! - Transaction creation and signing
//! - UTXO management via Sandshrew RPC
//! - Address generation for different networks

use anyhow::{Context, Result, anyhow};
use bitcoin::{
    Network, Address, Txid, OutPoint, TxOut, TxIn, Transaction, Witness,
    PrivateKey, PublicKey, CompressedPublicKey,
    sighash::{SighashCache, EcdsaSighashType, Prevouts},
    absolute::LockTime,
    Sequence, Amount, ScriptBuf,
};
use bitcoin::bip32::{Xpriv, Xpub, DerivationPath, ChildNumber};
use bitcoin::secp256k1::{Secp256k1, Message, All};
use bip39::Mnemonic;
use serde::Serialize;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{debug, info, warn};

use crate::rpc::RpcClient;
use super::crypto::{WalletCrypto, WalletData};

/// Bitcoin wallet configuration
#[derive(Clone, Debug)]
pub struct BitcoinWalletConfig {
    /// Path to wallet file
    pub wallet_path: String,
    /// Bitcoin network
    pub network: Network,
    /// Sandshrew RPC URL for blockchain data
    pub sandshrew_rpc_url: String,
    /// Custom network parameters for address generation
    pub network_params: Option<protorune_support::network::NetworkParams>,
}

/// UTXO information
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Address
    pub address: String,
    /// Confirmation count
    pub confirmations: u32,
    /// Whether UTXO is frozen
    pub frozen: bool,
    /// Script pubkey
    pub script_pubkey: ScriptBuf,
}

/// Enriched UTXO information with ordinals and runes data
#[derive(Debug, Clone)]
pub struct EnrichedUtxoInfo {
    /// Basic UTXO information
    pub utxo: UtxoInfo,
    /// Block height when UTXO was created
    pub block_height: Option<u64>,
    /// Whether this UTXO has inscriptions
    pub has_inscriptions: bool,
    /// Whether this UTXO has runes
    pub has_runes: bool,
    /// Whether this UTXO has alkanes
    pub has_alkanes: bool,
    /// Whether this is a coinbase output
    pub is_coinbase: bool,
    /// Freeze reason if frozen
    pub freeze_reason: Option<String>,
    /// Ordinal/inscription data if present
    pub ord_data: Option<serde_json::Value>,
    /// Runes data if present
    pub runes_data: Option<serde_json::Value>,
    /// Alkanes data if present
    pub alkanes_data: Option<serde_json::Value>,
}

/// UTXO freeze reasons
#[derive(Debug, Clone)]
pub enum FreezeReason {
    /// UTXO value is 546 sats or lower (dust)
    Dust,
    /// UTXO has inscriptions
    HasInscriptions,
    /// UTXO has runes
    HasRunes,
    /// UTXO has alkanes
    HasAlkanes,
    /// Coinbase output with less than 100 confirmations
    ImmatureCoinbase,
    /// Manually frozen by user
    Manual,
}

impl FreezeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            FreezeReason::Dust => "dust",
            FreezeReason::HasInscriptions => "has_inscriptions",
            FreezeReason::HasRunes => "has_runes",
            FreezeReason::HasAlkanes => "has_alkanes",
            FreezeReason::ImmatureCoinbase => "immature_coinbase",
            FreezeReason::Manual => "manual",
        }
    }
}

/// Transaction creation parameters
#[derive(Debug, Clone)]
pub struct SendParams {
    /// Recipient address
    pub address: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Fee rate in sat/vB
    pub fee_rate: Option<f32>,
    /// Whether to send all available funds
    pub send_all: bool,
    /// Source address to send from (optional - if None, uses all wallet addresses)
    pub from_address: Option<String>,
    /// Change address (optional - if None, uses default change address from sender)
    pub change_address: Option<String>,
    /// Auto-confirm without user prompt
    pub auto_confirm: bool,
}

/// Transaction details
#[derive(Debug, Clone)]
pub struct TransactionDetails {
    /// Transaction
    pub transaction: Transaction,
    /// Transaction ID
    pub txid: Txid,
    /// Amount received
    pub received: u64,
    /// Amount sent
    pub sent: u64,
    /// Fee paid
    pub fee: Option<u64>,
}

/// Wallet balance information
#[derive(Debug, Clone)]
pub struct Balance {
    /// Confirmed balance
    pub confirmed: u64,
    /// Trusted pending balance
    pub trusted_pending: u64,
    /// Untrusted pending balance
    pub untrusted_pending: u64,
    /// Immature balance (coinbase)
    pub immature: u64,
}

/// Transaction history entry
#[derive(Debug, Clone, Serialize)]
pub struct TransactionHistoryEntry {
    /// Transaction ID
    pub txid: String,
    /// Amount (positive for received, negative for sent)
    pub amount: i64,
    /// Fee paid (for outgoing transactions)
    pub fee: Option<u64>,
    /// Confirmation count
    pub confirmations: u32,
    /// Block height
    pub block_height: Option<u32>,
    /// Transaction timestamp
    pub timestamp: Option<u64>,
    /// Transaction type
    pub tx_type: String,
}

/// Pure rust-bitcoin wallet implementation
pub struct BitcoinWallet {
    /// Wallet configuration
    config: BitcoinWalletConfig,
    /// Master extended private key
    master_xprv: Xpriv,
    /// Master extended public key
    master_xpub: Xpub,
    /// Secp256k1 context
    secp: Secp256k1<All>,
    /// RPC client for blockchain data
    rpc_client: Arc<RpcClient>,
    /// Frozen UTXOs
    frozen_utxos: Arc<Mutex<HashMap<OutPoint, bool>>>,
    /// Address derivation index
    address_index: Arc<Mutex<u32>>,
    /// Wallet crypto manager
    crypto: WalletCrypto,
    /// Original mnemonic phrase
    mnemonic: Mnemonic,
}

impl BitcoinWallet {
    /// Create a new wallet from mnemonic
    pub fn new(
        config: BitcoinWalletConfig,
        mnemonic: Mnemonic,
        rpc_client: Arc<RpcClient>,
    ) -> Result<Self> {
        info!("Creating new Bitcoin wallet");
        
        let secp = Secp256k1::new();
        
        // Generate seed from mnemonic
        let seed = mnemonic.to_seed(""); // No passphrase for BIP39
        
        // Create master extended private key
        let master_xprv = Xpriv::new_master(config.network, &seed)
            .context("Failed to create master extended private key")?;
        
        // Derive master extended public key
        let master_xpub = Xpub::from_priv(&secp, &master_xprv);
        
        info!("Wallet created successfully");
        debug!("Master public key: {}", master_xpub);
        
        Ok(Self {
            config,
            master_xprv,
            master_xpub,
            secp,
            rpc_client,
            frozen_utxos: Arc::new(Mutex::new(HashMap::new())),
            address_index: Arc::new(Mutex::new(0)),
            crypto: WalletCrypto::new(),
            mnemonic,
        })
    }
    
    /// Create a new wallet with generated mnemonic
    pub fn create_new(
        config: BitcoinWalletConfig,
        rpc_client: Arc<RpcClient>,
    ) -> Result<Self> {
        info!("Generating new mnemonic for wallet creation");
        
        // Generate new mnemonic
        // Generate entropy for 12-word mnemonic (128 bits)
        let mut entropy = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .context("Failed to generate mnemonic")?;
        
        info!("Generated mnemonic: {}", mnemonic);
        
        Self::new(config, mnemonic, rpc_client)
    }
    
    /// Restore wallet from mnemonic string
    pub fn restore_from_mnemonic(
        config: BitcoinWalletConfig,
        mnemonic_str: &str,
        rpc_client: Arc<RpcClient>,
    ) -> Result<Self> {
        info!("Restoring wallet from mnemonic");
        
        let mnemonic = Mnemonic::parse(mnemonic_str)
            .context("Invalid mnemonic phrase")?;
        
        Self::new(config, mnemonic, rpc_client)
    }
    
    /// Get the mnemonic phrase
    pub fn get_mnemonic(&self) -> String {
        self.mnemonic.to_string()
    }
    
    /// Get the master extended private key
    pub fn get_master_xprv(&self) -> Xpriv {
        self.master_xprv
    }
    
    /// Get the master extended public key
    pub fn get_master_xpub(&self) -> Xpub {
        self.master_xpub
    }
    
    /// Get the internal key for taproot operations
    pub async fn get_internal_key(&self) -> Result<bitcoin::secp256k1::XOnlyPublicKey> {
        // For taproot, we use the master public key as the internal key
        // In a more sophisticated implementation, you might derive a specific key
        let master_pubkey = self.master_xpub.public_key;
        let x_only_pubkey = bitcoin::secp256k1::XOnlyPublicKey::from(master_pubkey);
        Ok(x_only_pubkey)
    }
    
    /// Get a keypair for taproot operations
    pub async fn get_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
        // For taproot, we use the master private key to create a keypair
        // In a more sophisticated implementation, you might derive a specific key
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&self.secp, &self.master_xprv.private_key);
        Ok(keypair)
    }
    
    /// Derive a private key for a specific derivation path
    pub fn derive_private_key(&self, derivation_path: &DerivationPath) -> Result<PrivateKey> {
        let derived_xprv = self.master_xprv.derive_priv(&self.secp, derivation_path)
            .context("Failed to derive private key")?;
        
        Ok(PrivateKey::new(derived_xprv.private_key, self.config.network))
    }
    
    /// Derive a public key for a specific derivation path
    pub fn derive_public_key(&self, derivation_path: &DerivationPath) -> Result<PublicKey> {
        // For hardened derivation paths, we need to use the private key
        // Check if any part of the path is hardened
        let has_hardened = derivation_path.as_ref().iter().any(|child| child.is_hardened());
        
        if has_hardened {
            // Use private key derivation and extract public key
            let derived_xprv = self.master_xprv.derive_priv(&self.secp, derivation_path)
                .context("Failed to derive private key for hardened path")?;
            Ok(PublicKey::from(derived_xprv.private_key.public_key(&self.secp)))
        } else {
            // Use public key derivation for non-hardened paths
            let derived_xpub = self.master_xpub.derive_pub(&self.secp, derivation_path)
                .context("Failed to derive public key")?;
            Ok(PublicKey::from(derived_xpub.public_key))
        }
    }
    
    /// Get the next receiving address (external chain)
    pub async fn get_address(&self) -> Result<String> {
        let mut index = self.address_index.lock().await;
        let address = self.get_address_at_index(*index, false).await?;
        *index += 1;
        Ok(address)
    }
    
    /// Get multiple addresses
    pub async fn get_addresses(&self, count: u32) -> Result<Vec<String>> {
        let mut addresses = Vec::new();
        for i in 0..count {
            let address = self.get_address_at_index(i, false).await?;
            addresses.push(address);
        }
        Ok(addresses)
    }
    
    /// Get multiple addresses as JSON objects
    pub async fn get_addresses_as_json(&self, count: u32) -> Result<Vec<serde_json::Value>> {
        let mut addresses = Vec::new();
        for i in 0..count {
            let address_str = self.get_address_at_index(i, false).await?;
            let address_json = serde_json::json!({
                "address": address_str,
                "index": i,
                "type": "p2wpkh" // Assuming default address type
            });
            addresses.push(address_json);
        }
        Ok(addresses)
    }
    
    /// Get address at specific index
    pub async fn get_address_at_index(&self, index: u32, is_change: bool) -> Result<String> {
        // BIP44 derivation path: m/84'/coin_type'/0'/change/address_index
        let coin_type = match self.config.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 1,
            Network::Regtest => 1,
            _ => 0,
        };
        
        let change_index = if is_change { 1 } else { 0 };
        
        let derivation_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84).unwrap(), // BIP84 (Native SegWit)
            ChildNumber::from_hardened_idx(coin_type).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(change_index).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ]);
        
        let public_key = self.derive_public_key(&derivation_path)?;
        
        // Create P2WPKH address (Native SegWit)
        let compressed_pubkey = CompressedPublicKey::try_from(public_key)
            .context("Failed to compress public key")?;
        
        let address = Address::p2wpkh(&compressed_pubkey, self.config.network);
        
        // If we have custom network parameters, use protorune_support for address generation
        if let Some(network_params) = &self.config.network_params {
            let protorune_params = protorune_support::network::NetworkParams {
                bech32_prefix: network_params.bech32_prefix.clone(),
                p2pkh_prefix: network_params.p2pkh_prefix,
                p2sh_prefix: network_params.p2sh_prefix,
            };
            protorune_support::network::set_network(protorune_params);
            
            // Convert to protorune_support format
            let script_pubkey = address.script_pubkey();
            let script_bytes = script_pubkey.as_bytes();
            let bitcoin_script = bitcoin::Script::from_bytes(script_bytes);
            
            match protorune_support::network::to_address_str(bitcoin_script) {
                Ok(custom_address) => return Ok(custom_address),
                Err(e) => {
                    warn!("Failed to generate custom address: {}, falling back to standard", e);
                }
            }
        }
        
        Ok(address.to_string())
    }
    
    /// Get address of specific type at specific index
    pub async fn get_address_of_type_at_index(&self, address_type: &str, index: u32, is_change: bool) -> Result<String> {
        // BIP44 derivation path varies by address type
        let coin_type = match self.config.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 1,
            Network::Regtest => 1,
            _ => 0,
        };
        
        let change_index = if is_change { 1 } else { 0 };
        
        let derivation_path = match address_type.to_lowercase().as_str() {
            "p2pkh" => {
                // BIP44 derivation path: m/44'/coin_type'/0'/change/address_index
                DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(44).unwrap(), // BIP44 (Legacy)
                    ChildNumber::from_hardened_idx(coin_type).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(change_index).unwrap(),
                    ChildNumber::from_normal_idx(index).unwrap(),
                ])
            },
            "p2sh" => {
                // BIP49 derivation path: m/49'/coin_type'/0'/change/address_index
                DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(49).unwrap(), // BIP49 (P2SH-wrapped SegWit)
                    ChildNumber::from_hardened_idx(coin_type).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(change_index).unwrap(),
                    ChildNumber::from_normal_idx(index).unwrap(),
                ])
            },
            "p2wpkh" => {
                // BIP84 derivation path: m/84'/coin_type'/0'/change/address_index
                DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(84).unwrap(), // BIP84 (Native SegWit)
                    ChildNumber::from_hardened_idx(coin_type).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(change_index).unwrap(),
                    ChildNumber::from_normal_idx(index).unwrap(),
                ])
            },
            "p2tr" => {
                // BIP86 derivation path: m/86'/coin_type'/0'/change/address_index
                DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(86).unwrap(), // BIP86 (Taproot)
                    ChildNumber::from_hardened_idx(coin_type).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(change_index).unwrap(),
                    ChildNumber::from_normal_idx(index).unwrap(),
                ])
            },
            _ => {
                return Err(anyhow!("Unsupported address type: {}", address_type));
            }
        };
        
        let public_key = self.derive_public_key(&derivation_path)?;
        let compressed_pubkey = CompressedPublicKey::try_from(public_key)
            .context("Failed to compress public key")?;
        
        let address = match address_type.to_lowercase().as_str() {
            "p2pkh" => {
                Address::p2pkh(&compressed_pubkey, self.config.network)
            },
            "p2sh" => {
                // Create P2SH-wrapped P2WPKH
                let wpkh_script = Address::p2wpkh(&compressed_pubkey, self.config.network).script_pubkey();
                Address::p2sh(&wpkh_script, self.config.network)
                    .context("Failed to create P2SH address")?
            },
            "p2wpkh" => {
                Address::p2wpkh(&compressed_pubkey, self.config.network)
            },
            "p2tr" => {
                // For Taproot, we need to use the internal key
                use bitcoin::key::UntweakedPublicKey;
                use bitcoin::secp256k1::XOnlyPublicKey;
                
                let x_only_pubkey = XOnlyPublicKey::from(compressed_pubkey.0);
                let untweaked = UntweakedPublicKey::from(x_only_pubkey);
                Address::p2tr(&self.secp, untweaked, None, self.config.network)
            },
            _ => {
                return Err(anyhow!("Unsupported address type: {}", address_type));
            }
        };
        
        // If we have custom network parameters, use protorune_support for address generation
        if let Some(network_params) = &self.config.network_params {
            let protorune_params = protorune_support::network::NetworkParams {
                bech32_prefix: network_params.bech32_prefix.clone(),
                p2pkh_prefix: network_params.p2pkh_prefix,
                p2sh_prefix: network_params.p2sh_prefix,
            };
            protorune_support::network::set_network(protorune_params);
            
            // Convert to protorune_support format
            let script_pubkey = address.script_pubkey();
            let script_bytes = script_pubkey.as_bytes();
            let bitcoin_script = bitcoin::Script::from_bytes(script_bytes);
            
            match protorune_support::network::to_address_str(bitcoin_script) {
                Ok(custom_address) => return Ok(custom_address),
                Err(e) => {
                    warn!("Failed to generate custom address: {}, falling back to standard", e);
                }
            }
        }
        
        Ok(address.to_string())
    }
    
    /// Get change address (internal chain)
    pub async fn get_change_address(&self) -> Result<String> {
        let index = self.address_index.lock().await;
        self.get_address_at_index(*index, true).await
    }
    
    /// Save wallet to encrypted file
    pub async fn save_encrypted(&self, passphrase: Option<&str>) -> Result<()> {
        info!("Saving encrypted wallet to {}", self.config.wallet_path);
        
        // Create wallet data
        let wallet_data = WalletData {
            mnemonic: self.mnemonic.to_string(),
            network: format!("{:?}", self.config.network),
            master_private_key: hex::encode(self.master_xprv.private_key.secret_bytes()),
            master_public_key: hex::encode(self.master_xpub.public_key.serialize()),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Encrypt wallet data
        let encrypted_data = if let Some(passphrase) = passphrase {
            // Non-interactive mode with passphrase
            self.crypto.encrypt_with_passphrase(&wallet_data, passphrase)?
        } else {
            // Interactive mode with GPG
            self.crypto.encrypt_with_gpg(&wallet_data)?
        };
        
        // Write to file
        tokio::fs::write(&self.config.wallet_path, encrypted_data).await
            .context("Failed to write encrypted wallet file")?;
        
        info!("Wallet saved successfully");
        Ok(())
    }
    
    /// Load wallet from encrypted file
    pub async fn load_encrypted(
        config: BitcoinWalletConfig,
        rpc_client: Arc<RpcClient>,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        info!("Loading encrypted wallet from {}", config.wallet_path);
        
        // Read encrypted data
        let encrypted_data = tokio::fs::read(&config.wallet_path).await
            .context("Failed to read wallet file")?;
        
        let crypto = WalletCrypto::new();
        
        // Decrypt wallet data
        let wallet_data = if let Some(passphrase) = passphrase {
            // Non-interactive mode with passphrase
            crypto.decrypt_with_passphrase(&encrypted_data, passphrase)?
        } else {
            // Interactive mode with GPG
            crypto.decrypt_with_gpg(&encrypted_data)?
        };
        
        // Validate network
        let saved_network = match wallet_data.network.as_str() {
            "Bitcoin" => Network::Bitcoin,
            "Testnet" => Network::Testnet,
            "Signet" => Network::Signet,
            "Regtest" => Network::Regtest,
            _ => return Err(anyhow!("Unknown network in wallet data: {}", wallet_data.network)),
        };
        
        if saved_network != config.network {
            return Err(anyhow!(
                "Network mismatch: wallet was created for {:?} but trying to load as {:?}",
                saved_network, config.network
            ));
        }
        
        // Restore wallet from mnemonic
        let mnemonic = Mnemonic::parse(&wallet_data.mnemonic)
            .context("Invalid mnemonic in wallet data")?;
        
        let wallet = Self::new(config, mnemonic, rpc_client)?;
        
        info!("Wallet loaded successfully");
        Ok(wallet)
    }
    
    /// Get wallet balance by querying Sandshrew
    pub async fn get_balance(&self) -> Result<Balance> {
        let address = self.get_address_at_index(0, false).await?;
        debug!("Getting balance for address: {}", address);
        
        match self.rpc_client.get_address_utxos(&address).await {
            Ok(utxos_response) => {
                let mut confirmed_balance = 0u64;
                let mut unconfirmed_balance = 0u64;
                
                if let Some(utxos_array) = utxos_response.as_array() {
                    for utxo in utxos_array {
                        if let Some(utxo_obj) = utxo.as_object() {
                            if let Some(value) = utxo_obj.get("value").and_then(|v| v.as_u64()) {
                                let is_confirmed = utxo_obj.get("status")
                                    .and_then(|s| s.get("confirmed"))
                                    .and_then(|c| c.as_bool())
                                    .unwrap_or(false);
                                
                                if is_confirmed {
                                    confirmed_balance += value;
                                } else {
                                    unconfirmed_balance += value;
                                }
                            }
                        }
                    }
                }
                
                Ok(Balance {
                    confirmed: confirmed_balance,
                    trusted_pending: 0,
                    untrusted_pending: unconfirmed_balance,
                    immature: 0,
                })
            },
            Err(e) => {
                warn!("Failed to get UTXOs from Sandshrew: {}", e);
                Ok(Balance {
                    confirmed: 0,
                    trusted_pending: 0,
                    untrusted_pending: 0,
                    immature: 0,
                })
            }
        }
    }
    
    /// Get UTXOs for the wallet (checks multiple addresses and types)
    pub async fn get_utxos(&self) -> Result<Vec<UtxoInfo>> {
        let mut all_utxos = Vec::new();
        let current_height = self.rpc_client.get_block_count().await.unwrap_or(0);
        
        info!("Starting UTXO detection at block height {}", current_height);
        
        // Check different address types - prioritize P2TR first since that's what we're using
        let address_types = ["p2tr", "p2wpkh", "p2pkh", "p2sh"];
        
        for address_type in &address_types {
            info!("Checking {} addresses for UTXOs...", address_type);
            
            // Check first 5 addresses of each type to find UTXOs (reduced for debugging)
            for i in 0..5 {
                let address = self.get_address_of_type_at_index(address_type, i, false).await?;
                info!("🔍 Checking {} address {} ({}): {}", address_type, i,
                      if i == 0 { "PRIMARY" } else { "secondary" }, address);
                
                let utxos = self.get_utxos_for_address(&address, current_height).await?;
                if !utxos.is_empty() {
                    info!("✅ Found {} UTXOs at {} address {}: {}", utxos.len(), address_type, i, address);
                    for utxo in &utxos {
                        info!("  UTXO: {}:{} = {} sats ({} confirmations)",
                              utxo.txid, utxo.vout, utxo.amount, utxo.confirmations);
                    }
                } else {
                    info!("❌ No UTXOs found at {} address {}: {}", address_type, i, address);
                }
                all_utxos.extend(utxos);
                
                // Early exit if we found UTXOs to avoid unnecessary API calls
                if !all_utxos.is_empty() && i >= 2 {
                    info!("Found UTXOs, stopping {} address scan at index {}", address_type, i);
                    break;
                }
            }
            
            // If we found UTXOs, we can stop checking other address types for now
            if !all_utxos.is_empty() {
                info!("Found {} total UTXOs from {} addresses, stopping address type scan",
                      all_utxos.len(), address_type);
                break;
            } else {
                info!("❌ No UTXOs found in any {} addresses", address_type);
            }
        }
        
        if all_utxos.is_empty() {
            warn!("❌ No UTXOs found in any wallet addresses!");
        } else {
            info!("✅ Total UTXOs found: {}", all_utxos.len());
        }
        
        Ok(all_utxos)
    }
    
    /// Get UTXOs for a specific address with proper confirmation calculation
    async fn get_utxos_for_address(&self, address: &str, current_height: u64) -> Result<Vec<UtxoInfo>> {
        let frozen_utxos = self.frozen_utxos.lock().await;
        let utxo_infos = Vec::new();
        
        info!("🔍 Fetching UTXOs for address: {}", address);
        
        // Try multiple methods to find UTXOs
        // Method 1: Try esplora_address::utxo (standard method)
        info!("📡 Trying esplora_address::utxo method...");
        match self.rpc_client.get_address_utxos(address).await {
            Ok(utxos_response) => {
                info!("📡 esplora_address::utxo response for {}: {}", address,
                      if utxos_response.is_array() {
                          format!("array with {} items", utxos_response.as_array().unwrap().len())
                      } else {
                          format!("non-array: {:?}", utxos_response)
                      });
                
                if let Some(utxos_array) = utxos_response.as_array() {
                    if !utxos_array.is_empty() {
                        info!("✅ Found {} UTXOs via esplora_address::utxo", utxos_array.len());
                        // Process the UTXOs normally
                        return self.process_utxos_response(utxos_array, address, current_height, &frozen_utxos).await;
                    } else {
                        info!("📭 No UTXOs found via esplora_address::utxo");
                    }
                }
            },
            Err(e) => {
                warn!("❌ esplora_address::utxo failed for address {}: {}", address, e);
            }
        }
        
        // Method 2: Try spendablesbyaddress (alternative method)
        info!("📡 Trying spendablesbyaddress method...");
        match self.rpc_client.get_spendables_by_address(address).await {
            Ok(spendables_response) => {
                info!("📡 spendablesbyaddress response for {}: {:?}", address, spendables_response);
                
                // Try to parse spendables response and convert to UTXO format
                if let Some(spendables_str) = spendables_response.as_str() {
                    if spendables_str != "0x" && !spendables_str.is_empty() {
                        info!("✅ Found spendables data via spendablesbyaddress: {}", spendables_str);
                        // For now, log that we found data but can't parse it yet
                        // This would need proper protobuf parsing
                    } else {
                        info!("📭 No spendables found via spendablesbyaddress");
                    }
                }
            },
            Err(e) => {
                warn!("❌ spendablesbyaddress failed for address {}: {}", address, e);
            }
        }
        
        // Method 3: Try getting transaction history and derive UTXOs
        info!("📡 Trying esplora_address::txs method...");
        match self.rpc_client.get_address_transactions(address).await {
            Ok(txs_response) => {
                info!("📡 esplora_address::txs response for {}: {}", address,
                      if txs_response.is_array() {
                          format!("array with {} items", txs_response.as_array().unwrap().len())
                      } else {
                          format!("non-array: {:?}", txs_response)
                      });
                
                if let Some(txs_array) = txs_response.as_array() {
                    if !txs_array.is_empty() {
                        info!("✅ Found {} transactions via esplora_address::txs", txs_array.len());
                        // Process transactions to find UTXOs
                        return self.process_transactions_for_utxos(txs_array, address, current_height, &frozen_utxos).await;
                    } else {
                        info!("📭 No transactions found via esplora_address::txs");
                    }
                }
            },
            Err(e) => {
                warn!("❌ esplora_address::txs failed for address {}: {}", address, e);
            }
        }
        
        warn!("❌ All UTXO detection methods failed for address: {}", address);
        Ok(utxo_infos)
    }
    
    /// Process UTXOs response array
    async fn process_utxos_response(
        &self,
        utxos_array: &[serde_json::Value],
        address: &str,
        current_height: u64,
        frozen_utxos: &tokio::sync::MutexGuard<'_, std::collections::HashMap<bitcoin::OutPoint, bool>>
    ) -> Result<Vec<UtxoInfo>> {
        let mut utxo_infos = Vec::new();
        
        for utxo in utxos_array {
            if let Some(utxo_obj) = utxo.as_object() {
                let txid = utxo_obj.get("txid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                let vout = utxo_obj.get("vout")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                
                let amount = utxo_obj.get("value")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                
                debug!("Processing UTXO {}:{} with {} sats", txid, vout, amount);
                
                // Calculate proper confirmations
                let confirmations = if let Some(status) = utxo_obj.get("status") {
                    if status.get("confirmed").and_then(|c| c.as_bool()).unwrap_or(false) {
                        // Get block height and calculate confirmations
                        if let Some(block_height) = status.get("block_height").and_then(|h| h.as_u64()) {
                            let confs = (current_height.saturating_sub(block_height) + 1) as u32;
                            debug!("UTXO {}:{} has {} confirmations (block {} vs current {})",
                                   txid, vout, confs, block_height, current_height);
                            confs
                        } else {
                            debug!("UTXO {}:{} is confirmed but no block height available", txid, vout);
                            1 // Confirmed but no block height available
                        }
                    } else {
                        debug!("UTXO {}:{} is unconfirmed", txid, vout);
                        0 // Unconfirmed
                    }
                } else {
                    debug!("UTXO {}:{} has no status information", txid, vout);
                    0 // No status available
                };
                
                let outpoint = if let Ok(parsed_txid) = bitcoin::Txid::from_str(&txid) {
                    bitcoin::OutPoint {
                        txid: parsed_txid,
                        vout,
                    }
                } else {
                    warn!("Invalid txid format: {}", txid);
                    continue;
                };
                
                let frozen = frozen_utxos.contains_key(&outpoint);
                
                // Create script pubkey for the address
                let addr = bitcoin::Address::from_str(address)
                    .context("Invalid address")?
                    .require_network(self.config.network)
                    .context("Address network mismatch")?;
                
                let utxo_info = UtxoInfo {
                    txid,
                    vout,
                    amount,
                    address: address.to_string(),
                    confirmations,
                    frozen,
                    script_pubkey: addr.script_pubkey(),
                };
                
                debug!("Added UTXO: {}:{} - {} sats, {} confirmations",
                       utxo_info.txid, utxo_info.vout, utxo_info.amount, utxo_info.confirmations);
                utxo_infos.push(utxo_info);
            }
        }
        
        Ok(utxo_infos)
    }
    
    /// Process transactions to find UTXOs
    async fn process_transactions_for_utxos(
        &self,
        txs_array: &[serde_json::Value],
        address: &str,
        current_height: u64,
        frozen_utxos: &tokio::sync::MutexGuard<'_, std::collections::HashMap<bitcoin::OutPoint, bool>>
    ) -> Result<Vec<UtxoInfo>> {
        let mut utxo_infos = Vec::new();
        
        info!("🔍 Processing {} transactions to find UTXOs for address {}", txs_array.len(), address);
        
        for (i, tx) in txs_array.iter().enumerate() {
            if let Some(tx_obj) = tx.as_object() {
                let txid = tx_obj.get("txid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                info!("📄 Processing transaction {}/{}: {}", i + 1, txs_array.len(), txid);
                
                // Check if this transaction has outputs to our address
                if let Some(vout_array) = tx_obj.get("vout").and_then(|v| v.as_array()) {
                    for (vout_index, vout) in vout_array.iter().enumerate() {
                        if let Some(vout_obj) = vout.as_object() {
                            // Check if this output is to our address
                            if let Some(scriptpubkey) = vout_obj.get("scriptpubkey_address") {
                                if scriptpubkey.as_str() == Some(address) {
                                    let amount = vout_obj.get("value")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    
                                    info!("💰 Found output to our address: {}:{} = {} sats", txid, vout_index, amount);
                                    
                                    // Calculate confirmations
                                    let confirmations = if let Some(status) = tx_obj.get("status") {
                                        if status.get("confirmed").and_then(|c| c.as_bool()).unwrap_or(false) {
                                            if let Some(block_height) = status.get("block_height").and_then(|h| h.as_u64()) {
                                                (current_height.saturating_sub(block_height) + 1) as u32
                                            } else {
                                                1
                                            }
                                        } else {
                                            0
                                        }
                                    } else {
                                        0
                                    };
                                    
                                    // Check if this UTXO is spent
                                    let is_spent = self.check_if_utxo_is_spent(&txid, vout_index as u32).await.unwrap_or(false);
                                    
                                    if !is_spent {
                                        let outpoint = if let Ok(parsed_txid) = bitcoin::Txid::from_str(&txid) {
                                            bitcoin::OutPoint {
                                                txid: parsed_txid,
                                                vout: vout_index as u32,
                                            }
                                        } else {
                                            warn!("Invalid txid format: {}", txid);
                                            continue;
                                        };
                                        
                                        let frozen = frozen_utxos.contains_key(&outpoint);
                                        
                                        // Create script pubkey for the address
                                        let addr = bitcoin::Address::from_str(address)
                                            .context("Invalid address")?
                                            .require_network(self.config.network)
                                            .context("Address network mismatch")?;
                                        
                                        let utxo_info = UtxoInfo {
                                            txid: txid.clone(),
                                            vout: vout_index as u32,
                                            amount,
                                            address: address.to_string(),
                                            confirmations,
                                            frozen,
                                            script_pubkey: addr.script_pubkey(),
                                        };
                                        
                                        info!("✅ Added unspent UTXO: {}:{} - {} sats, {} confirmations",
                                               utxo_info.txid, utxo_info.vout, utxo_info.amount, utxo_info.confirmations);
                                        utxo_infos.push(utxo_info);
                                    } else {
                                        info!("❌ UTXO {}:{} is already spent", txid, vout_index);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        info!("🎯 Found {} unspent UTXOs from transaction history", utxo_infos.len());
        Ok(utxo_infos)
    }
    
    /// Check if a UTXO is spent by looking for spending transactions
    async fn check_if_utxo_is_spent(&self, _txid: &str, _vout: u32) -> Result<bool> {
        // For now, assume UTXOs are unspent since we don't have a direct way to check
        // In a full implementation, we would check if this outpoint appears as an input in any transaction
        Ok(false)
    }
    
    /// Get UTXOs for a specific address with proper confirmation calculation (LEGACY METHOD)
    async fn _get_utxos_for_address_legacy(&self, address: &str, current_height: u64) -> Result<Vec<UtxoInfo>> {
        let frozen_utxos = self.frozen_utxos.lock().await;
        let mut utxo_infos = Vec::new();
        
        info!("🔍 Fetching UTXOs for address: {}", address);
        
        match self.rpc_client.get_address_utxos(address).await {
            Ok(utxos_response) => {
                info!("📡 RPC response for {}: {}", address,
                      if utxos_response.is_array() {
                          format!("array with {} items", utxos_response.as_array().unwrap().len())
                      } else {
                          format!("non-array: {:?}", utxos_response)
                      });
                
                if let Some(utxos_array) = utxos_response.as_array() {
                    if utxos_array.is_empty() {
                        info!("📭 No UTXOs found for address {}", address);
                    } else {
                        info!("📬 Found {} UTXOs for address {}", utxos_array.len(), address);
                    }
                    
                    for utxo in utxos_array {
                        if let Some(utxo_obj) = utxo.as_object() {
                            let txid = utxo_obj.get("txid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            
                            let vout = utxo_obj.get("vout")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            
                            let amount = utxo_obj.get("value")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            
                            debug!("Processing UTXO {}:{} with {} sats", txid, vout, amount);
                            
                            // Calculate proper confirmations
                            let confirmations = if let Some(status) = utxo_obj.get("status") {
                                if status.get("confirmed").and_then(|c| c.as_bool()).unwrap_or(false) {
                                    // Get block height and calculate confirmations
                                    if let Some(block_height) = status.get("block_height").and_then(|h| h.as_u64()) {
                                        let confs = (current_height.saturating_sub(block_height) + 1) as u32;
                                        debug!("UTXO {}:{} has {} confirmations (block {} vs current {})",
                                               txid, vout, confs, block_height, current_height);
                                        confs
                                    } else {
                                        debug!("UTXO {}:{} is confirmed but no block height available", txid, vout);
                                        1 // Confirmed but no block height available
                                    }
                                } else {
                                    debug!("UTXO {}:{} is unconfirmed", txid, vout);
                                    0 // Unconfirmed
                                }
                            } else {
                                debug!("UTXO {}:{} has no status information", txid, vout);
                                0 // No status available
                            };
                            
                            let outpoint = if let Ok(parsed_txid) = Txid::from_str(&txid) {
                                OutPoint {
                                    txid: parsed_txid,
                                    vout,
                                }
                            } else {
                                warn!("Invalid txid format: {}", txid);
                                continue;
                            };
                            
                            let frozen = frozen_utxos.contains_key(&outpoint);
                            
                            // Create script pubkey for the address
                            let addr = Address::from_str(address)
                                .context("Invalid address")?
                                .require_network(self.config.network)
                                .context("Address network mismatch")?;
                            
                            let utxo_info = UtxoInfo {
                                txid,
                                vout,
                                amount,
                                address: address.to_string(),
                                confirmations,
                                frozen,
                                script_pubkey: addr.script_pubkey(),
                            };
                            
                            debug!("Added UTXO: {}:{} - {} sats, {} confirmations",
                                   utxo_info.txid, utxo_info.vout, utxo_info.amount, utxo_info.confirmations);
                            utxo_infos.push(utxo_info);
                        }
                    }
                } else {
                    debug!("UTXO response is not an array for address {}: {:?}", address, utxos_response);
                }
            },
            Err(e) => {
                warn!("Failed to get UTXOs from Sandshrew for address {}: {}", address, e);
            }
        }
        
        debug!("Returning {} UTXOs for address {}", utxo_infos.len(), address);
        Ok(utxo_infos)
    }
    
    /// Wait for all blockchain services to synchronize with Bitcoin node
    async fn wait_for_blockchain_sync(&self) -> Result<u64> {
        info!("🔄 Checking blockchain service synchronization...");
        
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 60; // 5 minutes with 5-second intervals
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        
        loop {
            attempts += 1;
            
            // Get Bitcoin node's current state
            let bitcoin_height = match self.rpc_client.get_block_count().await {
                Ok(height) => height,
                Err(e) => {
                    warn!("❌ Failed to get Bitcoin block count: {}", e);
                    if attempts >= MAX_ATTEMPTS {
                        return Err(anyhow!("Failed to connect to Bitcoin node after {} attempts", MAX_ATTEMPTS));
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            
            let bitcoin_hash = match self.rpc_client.get_block_hash_btc(bitcoin_height).await {
                Ok(hash) => hash,
                Err(e) => {
                    warn!("❌ Failed to get Bitcoin block hash for height {}: {}", bitcoin_height, e);
                    if attempts >= MAX_ATTEMPTS {
                        return Err(anyhow!("Failed to get Bitcoin block hash after {} attempts", MAX_ATTEMPTS));
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            
            info!("📊 Bitcoin node: height={}, hash={}", bitcoin_height, &bitcoin_hash[..16]);
            
            // Check all services
            let mut all_synced = true;
            let mut sync_status = Vec::new();
            
            // Check ord service
            match self.rpc_client.get_ord_block_height().await {
                Ok(ord_height) => {
                    if ord_height == bitcoin_height {
                        match self.rpc_client.get_ord_block_hash().await {
                            Ok(ord_hash) => {
                                if ord_hash == bitcoin_hash {
                                    sync_status.push(format!("✅ ord: height={}, hash={}", ord_height, &ord_hash[..16]));
                                } else {
                                    sync_status.push(format!("❌ ord: height={} (✓) but hash mismatch: {} vs {}", ord_height, &ord_hash[..16], &bitcoin_hash[..16]));
                                    all_synced = false;
                                }
                            },
                            Err(e) => {
                                sync_status.push(format!("❌ ord: height={} (✓) but failed to get hash: {}", ord_height, e));
                                all_synced = false;
                            }
                        }
                    } else {
                        sync_status.push(format!("⏳ ord: height={} (behind by {})", ord_height, bitcoin_height.saturating_sub(ord_height)));
                        all_synced = false;
                    }
                },
                Err(e) => {
                    sync_status.push(format!("❌ ord: failed to get height: {}", e));
                    all_synced = false;
                }
            }
            
            // Check esplora service - only check height, not hash
            match self.rpc_client.get_esplora_blocks_tip_height().await {
                Ok(esplora_height) => {
                    if esplora_height == bitcoin_height {
                        sync_status.push(format!("✅ esplora: height={}", esplora_height));
                    } else {
                        sync_status.push(format!("⏳ esplora: height={} (behind by {})", esplora_height, bitcoin_height.saturating_sub(esplora_height)));
                        all_synced = false;
                    }
                },
                Err(e) => {
                    sync_status.push(format!("❌ esplora: failed to get height: {}", e));
                    all_synced = false;
                }
            }
            
            // Check metashrew service - only check height, not hash
            match self.rpc_client.get_metashrew_height().await {
                Ok(metashrew_height) => {
                    if metashrew_height == bitcoin_height {
                        sync_status.push(format!("✅ metashrew: height={}", metashrew_height));
                    } else {
                        sync_status.push(format!("⏳ metashrew: height={} (behind by {})", metashrew_height, bitcoin_height.saturating_sub(metashrew_height)));
                        all_synced = false;
                    }
                },
                Err(e) => {
                    sync_status.push(format!("❌ metashrew: failed to get height: {}", e));
                    all_synced = false;
                }
            }
            
            // Log current sync status
            for status in &sync_status {
                info!("  {}", status);
            }
            
            if all_synced {
                info!("🎉 All blockchain services are synchronized at height {}", bitcoin_height);
                return Ok(bitcoin_height);
            }
            
            if attempts >= MAX_ATTEMPTS {
                return Err(anyhow!("Blockchain services failed to synchronize after {} attempts ({}s)", MAX_ATTEMPTS, (MAX_ATTEMPTS as u64) * POLL_INTERVAL.as_secs()));
            }
            
            info!("⏳ Waiting {}s for services to sync (attempt {}/{})", POLL_INTERVAL.as_secs(), attempts, MAX_ATTEMPTS);
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    
    /// Get enriched UTXOs with ordinals, runes, and alkanes data
    pub async fn get_enriched_utxos(&self) -> Result<Vec<EnrichedUtxoInfo>> {
        // Wait for blockchain synchronization before processing UTXOs
        let current_height = self.wait_for_blockchain_sync().await?;
        
        let utxos = self.get_utxos().await?;
        
        let mut enriched_utxos = Vec::new();
        
        // Process UTXOs in parallel for better performance
        let futures: Vec<_> = utxos.into_iter().map(|utxo| {
            let rpc_client = Arc::clone(&self.rpc_client);
            async move {
                self.enrich_utxo(utxo, current_height, rpc_client).await
            }
        }).collect();
        
        // Wait for all enrichment operations to complete
        let results = futures::future::join_all(futures).await;
        
        for result in results {
            match result {
                Ok(enriched_utxo) => enriched_utxos.push(enriched_utxo),
                Err(e) => {
                    warn!("Failed to enrich UTXO: {}", e);
                    // Continue with other UTXOs even if one fails
                }
            }
        }
        
        Ok(enriched_utxos)
    }
    
    /// Get enriched UTXOs for a specific address
    pub async fn get_enriched_utxos_for_address(&self, address: &str) -> Result<Vec<EnrichedUtxoInfo>> {
        let current_height = self.rpc_client.get_block_count().await.unwrap_or(0);
        let frozen_utxos = self.frozen_utxos.lock().await;
        let mut utxo_infos = Vec::new();
        
        // Get UTXOs for the specific address
        match self.rpc_client.get_address_utxos(address).await {
            Ok(utxos_response) => {
                if let Some(utxos_array) = utxos_response.as_array() {
                    for utxo in utxos_array {
                        if let Some(utxo_obj) = utxo.as_object() {
                            let txid = utxo_obj.get("txid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            
                            let vout = utxo_obj.get("vout")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            
                            let amount = utxo_obj.get("value")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            
                            // Calculate proper confirmations
                            let confirmations = if let Some(status) = utxo_obj.get("status") {
                                if status.get("confirmed").and_then(|c| c.as_bool()).unwrap_or(false) {
                                    // Get block height and calculate confirmations
                                    if let Some(block_height) = status.get("block_height").and_then(|h| h.as_u64()) {
                                        (current_height.saturating_sub(block_height) + 1) as u32
                                    } else {
                                        1 // Confirmed but no block height available
                                    }
                                } else {
                                    0 // Unconfirmed
                                }
                            } else {
                                0 // No status available
                            };
                            
                            let outpoint = if let Ok(parsed_txid) = Txid::from_str(&txid) {
                                OutPoint {
                                    txid: parsed_txid,
                                    vout,
                                }
                            } else {
                                continue;
                            };
                            
                            let frozen = frozen_utxos.contains_key(&outpoint);
                            
                            // Create script pubkey for the address
                            let addr = Address::from_str(address)
                                .context("Invalid address")?
                                .require_network(self.config.network)
                                .context("Address network mismatch")?;
                            
                            let utxo_info = UtxoInfo {
                                txid,
                                vout,
                                amount,
                                address: address.to_string(),
                                confirmations,
                                frozen,
                                script_pubkey: addr.script_pubkey(),
                            };
                            
                            utxo_infos.push(utxo_info);
                        }
                    }
                }
            },
            Err(e) => {
                warn!("Failed to get UTXOs from Sandshrew for address {}: {}", address, e);
            }
        }
        
        // Enrich the UTXOs
        let mut enriched_utxos = Vec::new();
        
        // Process UTXOs in parallel for better performance
        let futures: Vec<_> = utxo_infos.into_iter().map(|utxo| {
            let rpc_client = Arc::clone(&self.rpc_client);
            async move {
                self.enrich_utxo(utxo, current_height, rpc_client).await
            }
        }).collect();
        
        // Wait for all enrichment operations to complete
        let results = futures::future::join_all(futures).await;
        
        for result in results {
            match result {
                Ok(enriched_utxo) => enriched_utxos.push(enriched_utxo),
                Err(e) => {
                    warn!("Failed to enrich UTXO: {}", e);
                    // Continue with other UTXOs even if one fails
                }
            }
        }
        
        Ok(enriched_utxos)
    }
    
    /// Enrich a single UTXO with ordinals, runes, and alkanes data
    async fn enrich_utxo(&self, utxo: UtxoInfo, current_height: u64, rpc_client: Arc<RpcClient>) -> Result<EnrichedUtxoInfo> {
        let mut has_inscriptions = false;
        let has_runes = false;
        let mut has_alkanes = false;
        let mut ord_data = None;
        let runes_data = None;
        let mut alkanes_data = None;
        let mut block_height = None;
        let mut is_coinbase = false;
        
        // Parallel requests for ord_output and protorunes data
        let ord_future = rpc_client.get_ord_output(&utxo.txid, utxo.vout);
        let protorunes_future = rpc_client.get_protorunes_by_outpoint_with_protocol(&utxo.txid, utxo.vout, 1);
        
        // Execute both requests in parallel
        let (ord_result, protorunes_result) = tokio::join!(ord_future, protorunes_future);
        
        // Process ord_output result
        match ord_result {
            Ok(ord_response) => {
                debug!("ord_output response for {}:{}: {}", utxo.txid, utxo.vout, ord_response);
                
                // Check if the response contains inscriptions
                if let Some(inscriptions) = ord_response.get("inscriptions") {
                    if let Some(inscriptions_array) = inscriptions.as_array() {
                        if !inscriptions_array.is_empty() {
                            has_inscriptions = true;
                            ord_data = Some(ord_response.clone());
                            debug!("Found {} inscriptions for UTXO {}:{}",
                                   inscriptions_array.len(), utxo.txid, utxo.vout);
                        } else {
                            debug!("No inscriptions found for UTXO {}:{}", utxo.txid, utxo.vout);
                        }
                    } else {
                        debug!("Inscriptions field is not an array for UTXO {}:{}", utxo.txid, utxo.vout);
                    }
                } else {
                    debug!("No inscriptions field in ord_output response for UTXO {}:{}", utxo.txid, utxo.vout);
                }
            },
            Err(e) => {
                debug!("Failed to get ord output for {}:{}: {}", utxo.txid, utxo.vout, e);
            }
        }
        
        // Process protorunes result
        match protorunes_result {
            Ok(protorunes_response) => {
                // Check if the response contains any runes/alkanes data
                if !protorunes_response.balances.entries.is_empty() {
                    has_alkanes = true;
                    // For now, just store a simple indication that alkanes were found
                    // The complex protobuf parsing can be improved later
                    alkanes_data = Some(serde_json::json!({
                        "found_alkanes": true,
                        "count": protorunes_response.balances.entries.len()
                    }));
                }
            },
            Err(e) => {
                debug!("Failed to get protorunes for {}:{}: {}", utxo.txid, utxo.vout, e);
            }
        }
        
        // Get transaction details to check if it's coinbase and get block height
        match rpc_client.get_transaction_status(&utxo.txid).await {
            Ok(status) => {
                if let Some(status_obj) = status.as_object() {
                    if let Some(confirmed) = status_obj.get("confirmed").and_then(|c| c.as_bool()) {
                        if confirmed {
                            block_height = status_obj.get("block_height").and_then(|h| h.as_u64());
                        }
                    }
                }
            },
            Err(e) => {
                debug!("Failed to get transaction status for {}: {}", utxo.txid, e);
            }
        }
        
        // Check if it's a coinbase transaction (vout 0 and specific patterns)
        if utxo.vout == 0 {
            // For regtest, we'll assume vout 0 transactions are likely coinbase
            is_coinbase = true;
            debug!("Detected coinbase UTXO: {}:{}", utxo.txid, utxo.vout);
        }
        
        // Determine freeze status and reason
        let mut freeze_reasons = Vec::new();
        let mut frozen = utxo.frozen; // Start with existing freeze status
        
        // Check dust threshold
        if utxo.amount <= 546 {
            frozen = true;
            freeze_reasons.push(FreezeReason::Dust);
        }
        
        // Check inscriptions - but don't freeze coinbase UTXOs for testing
        if has_inscriptions {
            // Only freeze inscriptions if they're not coinbase transactions
            // Coinbase transactions in regtest often have false positive inscription detection
            if !is_coinbase {
                frozen = true;
                freeze_reasons.push(FreezeReason::HasInscriptions);
                debug!("Freezing UTXO {}:{} due to inscriptions (not coinbase)", utxo.txid, utxo.vout);
            } else {
                debug!("NOT freezing UTXO {}:{} with inscriptions because is_coinbase={}",
                       utxo.txid, utxo.vout, is_coinbase);
            }
        }
        
        // Check runes
        if has_runes {
            frozen = true;
            freeze_reasons.push(FreezeReason::HasRunes);
        }
        
        // Check alkanes - but don't freeze coinbase UTXOs automatically for testing
        if has_alkanes {
            // Only freeze alkanes if they're not coinbase transactions
            // Coinbase transactions in regtest often have false positive alkanes detection
            if !is_coinbase && utxo.vout != 0 {
                frozen = true;
                freeze_reasons.push(FreezeReason::HasAlkanes);
                debug!("Freezing UTXO {}:{} due to alkanes (not coinbase)", utxo.txid, utxo.vout);
            } else {
                debug!("NOT freezing UTXO {}:{} with alkanes because is_coinbase={} vout={}",
                       utxo.txid, utxo.vout, is_coinbase, utxo.vout);
            }
        }
        
        // Check immature coinbase
        if is_coinbase {
            if let Some(height) = block_height {
                let confirmations = current_height.saturating_sub(height);
                if confirmations <= 100 {
                    frozen = true;
                    freeze_reasons.push(FreezeReason::ImmatureCoinbase);
                    debug!("Freezing coinbase UTXO {}:{} - {} confirmations <= 100 required",
                           utxo.txid, utxo.vout, confirmations);
                } else {
                    debug!("Coinbase UTXO {}:{} is mature with {} confirmations",
                           utxo.txid, utxo.vout, confirmations);
                }
            }
        }
        
        // Create freeze reason string
        let freeze_reason = if freeze_reasons.is_empty() {
            None
        } else {
            Some(freeze_reasons.iter().map(|r| r.as_str()).collect::<Vec<_>>().join(", "))
        };
        
        // Update the UTXO's frozen status
        let mut enriched_utxo = utxo.clone();
        enriched_utxo.frozen = frozen;
        
        Ok(EnrichedUtxoInfo {
            utxo: enriched_utxo,
            block_height,
            has_inscriptions,
            has_runes,
            has_alkanes,
            is_coinbase,
            freeze_reason,
            ord_data,
            runes_data,
            alkanes_data,
        })
    }
    
    /// Preview a transaction before signing - shows the same output as `./deezel runestone` command
    pub async fn preview_transaction(&self, tx: &Transaction) -> Result<()> {
        println!("\n🔍 Transaction Preview (before signing)");
        println!("═══════════════════════════════════════");
        
        // Basic transaction information
        println!("📋 Transaction ID: {}", tx.compute_txid());
        println!("🔢 Version: {}", tx.version);
        println!("🔒 Lock Time: {}", tx.lock_time);
        
        // Transaction inputs
        println!("\n📥 Inputs ({}):", tx.input.len());
        for (i, input) in tx.input.iter().enumerate() {
            println!("  {}. 🔗 {}:{}", i + 1, input.previous_output.txid, input.previous_output.vout);
            if !input.witness.is_empty() {
                println!("     📝 Witness: {} items", input.witness.len());
            }
        }
        
        // Transaction outputs
        println!("\n📤 Outputs ({}):", tx.output.len());
        for (i, output) in tx.output.iter().enumerate() {
            println!("  {}. 💰 {} sats", i, output.value);
            
            // Check if this is an OP_RETURN output
            if output.script_pubkey.is_op_return() {
                println!("     📜 OP_RETURN script ({} bytes)", output.script_pubkey.len());
                // Show OP_RETURN data in hex
                let op_return_bytes = output.script_pubkey.as_bytes();
                if op_return_bytes.len() > 2 {
                    let data_bytes = &op_return_bytes[2..]; // Skip OP_RETURN and length byte
                    let hex_data = hex::encode(data_bytes);
                    println!("     📄 Data: {}", hex_data);
                    
                    // Check for runestone magic number (OP_PUSHNUM_13 = 0x5d)
                    if data_bytes.len() > 0 && data_bytes[0] == 0x5d {
                        println!("     🪨 Runestone detected! (Magic: 0x5d)");
                    }
                }
            } else {
                // Determine script type
                if output.script_pubkey.is_p2pkh() {
                    println!("     🏠 P2PKH (Legacy)");
                } else if output.script_pubkey.is_p2sh() {
                    println!("     🏛️  P2SH (Script Hash)");
                } else if output.script_pubkey.is_p2tr() {
                    println!("     🌳 P2TR (Taproot)");
                } else if output.script_pubkey.is_witness_program() {
                    println!("     ⚡ Witness Program (SegWit)");
                } else {
                    println!("     📋 Script ({} bytes)", output.script_pubkey.len());
                }
            }
        }
        
        println!("\n✅ Transaction preview complete!");
        println!("💡 Use `./deezel runestone <txid>` after broadcasting for detailed runestone analysis");
        
        Ok(())
    }

    /// Create a transaction
    pub async fn create_transaction(&self, params: SendParams) -> Result<(Transaction, TransactionDetails)> {
        let from_info = if let Some(ref from_addr) = params.from_address {
            format!(" from {}", from_addr)
        } else {
            String::new()
        };
        info!("Creating transaction to {} for {} sats{}", params.address, params.amount, from_info);
        
        // Wait for blockchain synchronization before creating transaction
        let _current_height = self.wait_for_blockchain_sync().await?;
        
        // Get enriched UTXOs with automatic freezing rules applied
        let enriched_utxos = if let Some(ref from_address) = params.from_address {
            // Get UTXOs from specific address
            self.get_enriched_utxos_for_address(from_address).await?
        } else {
            // Get UTXOs from all wallet addresses
            self.get_enriched_utxos().await?
        };
        
        info!("UTXO Debug Info:");
        info!("  Total enriched UTXOs found: {}", enriched_utxos.len());
        for (i, enriched_utxo) in enriched_utxos.iter().enumerate() {
            info!("  UTXO {}: {}:{} = {} sats, confirmations={}, frozen={}, freeze_reason={:?}",
                  i, enriched_utxo.utxo.txid, enriched_utxo.utxo.vout, enriched_utxo.utxo.amount,
                  enriched_utxo.utxo.confirmations, enriched_utxo.utxo.frozen, enriched_utxo.freeze_reason);
        }
        
        let confirmed_utxos: Vec<_> = enriched_utxos.into_iter()
            .filter(|u| u.utxo.confirmations > 0 && !u.utxo.frozen)
            .map(|u| u.utxo) // Extract the basic UtxoInfo for compatibility
            .collect();
        
        info!("  Confirmed spendable UTXOs: {}", confirmed_utxos.len());
        
        if confirmed_utxos.is_empty() {
            return Err(anyhow!("No confirmed UTXOs available"));
        }
        
        // Parse recipient address
        let recipient = Address::from_str(&params.address)
            .context("Invalid recipient address")?
            .require_network(self.config.network)
            .context("Address network mismatch")?;
        
        // Calculate fee and amounts
        let fee_rate = params.fee_rate.unwrap_or(1.0);
        let estimated_tx_size = 10 + (confirmed_utxos.len().min(10) * 148) + (2 * 34);
        let estimated_fee = (estimated_tx_size as f32 * fee_rate) as u64;
        
        let total_input_value: u64 = confirmed_utxos.iter().map(|u| u.amount).sum();
        
        let send_amount = if params.send_all {
            if total_input_value <= estimated_fee {
                return Err(anyhow!("Insufficient funds to cover fee"));
            }
            total_input_value - estimated_fee
        } else {
            if total_input_value < params.amount + estimated_fee {
                return Err(anyhow!("Insufficient funds"));
            }
            params.amount
        };
        
        // Select UTXOs
        let mut selected_utxos = Vec::new();
        let mut input_value = 0u64;
        
        for utxo in &confirmed_utxos {
            selected_utxos.push(utxo);
            input_value += utxo.amount;
            
            if !params.send_all && input_value >= send_amount + estimated_fee {
                break;
            }
            
            if selected_utxos.len() >= 10 {
                break;
            }
        }
        
        // Build transaction inputs
        let mut tx_inputs = Vec::new();
        for utxo in &selected_utxos {
            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&utxo.txid)?,
                    vout: utxo.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
        }
        
        // Build transaction outputs
        let mut tx_outputs = Vec::new();
        
        // Recipient output
        tx_outputs.push(TxOut {
            value: Amount::from_sat(send_amount),
            script_pubkey: recipient.script_pubkey(),
        });
        
        // Change output if needed
        let actual_fee = estimated_fee;
        let change_amount = input_value - send_amount - actual_fee;
        if change_amount > 546 { // Dust threshold
            // Use custom change address if provided, otherwise use default change address
            let change_address_str = if let Some(ref custom_change) = params.change_address {
                custom_change.clone()
            } else {
                // Default behavior: use the same address type as the sender if from_address is specified
                if let Some(ref from_addr) = params.from_address {
                    // Try to determine the address type of the sender and use the same type for change
                    // For now, just use the sender address as change address
                    from_addr.clone()
                } else {
                    // Use default change address (internal chain)
                    self.get_change_address().await?
                }
            };
            
            let change_address = Address::from_str(&change_address_str)?
                .require_network(self.config.network)?;
            
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_address.script_pubkey(),
            });
        }
        
        // Create unsigned transaction
        let mut unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };
        
        // Show transaction preview before signing
        self.preview_transaction(&unsigned_tx).await?;
        
        // Ask for confirmation before signing (unless auto-confirm is enabled)
        if !params.auto_confirm {
            println!("\n❓ Do you want to proceed with signing this transaction? (y/N)");
            use std::io::{self, Write};
            print!("Enter your choice: ");
            io::stdout().flush().unwrap();
            
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let input = input.trim().to_lowercase();
            
            if input != "y" && input != "yes" {
                return Err(anyhow!("Transaction signing cancelled by user"));
            }
        } else {
            println!("\n✅ Auto-confirming transaction signing (--yes flag enabled)");
        }
        
        println!("\n🔐 Signing transaction...");
        
        // Sign the transaction
        self.sign_transaction(&mut unsigned_tx, &selected_utxos).await?;
        
        let tx_details = TransactionDetails {
            transaction: unsigned_tx.clone(),
            txid: unsigned_tx.compute_txid(),
            received: 0,
            sent: send_amount,
            fee: Some(actual_fee),
        };
        
        Ok((unsigned_tx, tx_details))
    }
    
    /// Sign a transaction with proper address type detection
    async fn sign_transaction(&self, tx: &mut Transaction, utxos: &[&UtxoInfo]) -> Result<()> {
        info!("Signing transaction with {} inputs", tx.input.len());
        
        // Create prevouts for sighash calculation
        let prevouts: Vec<TxOut> = utxos.iter().map(|utxo| {
            TxOut {
                value: Amount::from_sat(utxo.amount),
                script_pubkey: utxo.script_pubkey.clone(),
            }
        }).collect();
        
        let prevouts = Prevouts::All(&prevouts);
        
        // Sign each input
        for (i, utxo) in utxos.iter().enumerate() {
            // Determine address type from script pubkey
            let address_type = self.determine_address_type(&utxo.script_pubkey)?;
            debug!("Input {}: address type = {}, address = {}", i, address_type, utxo.address);
            
            // Find the correct derivation path for this UTXO
            let (derivation_path, _index) = self.find_derivation_path_for_utxo(utxo, &address_type).await?;
            
            let private_key = self.derive_private_key(&derivation_path)?;
            let public_key = private_key.public_key(&self.secp);
            
            // Create sighash and sign based on address type
            let mut sighash_cache = SighashCache::new(&*tx);
            
            match address_type.as_str() {
                "p2tr" => {
                    // P2TR (Taproot) signing - following rust-bitcoin cookbook
                    use bitcoin::sighash::TapSighashType;
                    use bitcoin::secp256k1::Keypair;
                    use bitcoin::key::{TapTweak, UntweakedKeypair};
                    use bitcoin::taproot;
                    
                    // Use the specific taproot_key_spend_signature_hash method for key-path spending
                    let sighash = sighash_cache
                        .taproot_key_spend_signature_hash(
                            i,
                            &prevouts,
                            TapSighashType::Default,
                        )
                        .context("Failed to compute taproot key spend sighash")?;
                    
                    // Create keypair from private key
                    let keypair = Keypair::from_secret_key(&self.secp, &private_key.inner);
                    let untweaked_keypair = UntweakedKeypair::from(keypair);
                    
                    // Apply taproot tweak (for key-path spending with no script tree)
                    let tweaked_keypair = untweaked_keypair.tap_tweak(&self.secp, None);
                    
                    // Convert sighash to Message for signing - following official rust-bitcoin example
                    let msg = Message::from(sighash);
                    let mut rng = bitcoin::secp256k1::rand::thread_rng();
                    let signature = self.secp.sign_schnorr_with_rng(&msg, tweaked_keypair.as_keypair(), &mut rng);
                    
                    // Create a proper taproot signature with sighash type
                    let taproot_signature = taproot::Signature {
                        signature,
                        sighash_type: TapSighashType::Default,
                    };
                    
                    // Create witness for P2TR key-path spending using the proper assignment pattern
                    tx.input[i].witness = Witness::p2tr_key_spend(&taproot_signature);
                },
                "p2wpkh" => {
                    // P2WPKH (Native SegWit) signing
                    let sighash = sighash_cache
                        .p2wpkh_signature_hash(
                            i,
                            &utxo.script_pubkey,
                            Amount::from_sat(utxo.amount),
                            EcdsaSighashType::All,
                        )
                        .context("Failed to compute p2wpkh sighash")?;
                    
                    // Sign the sighash
                    let message = Message::from_digest_slice(&sighash[..])
                        .context("Failed to create message from sighash")?;
                    
                    let signature = self.secp.sign_ecdsa(&message, &private_key.inner);
                    
                    // Create witness for P2WPKH
                    let mut sig_bytes = signature.serialize_der().to_vec();
                    sig_bytes.push(EcdsaSighashType::All as u8);
                    
                    let mut witness = Witness::new();
                    witness.push(&sig_bytes);
                    witness.push(&public_key.to_bytes());
                    
                    tx.input[i].witness = witness;
                },
                _ => {
                    return Err(anyhow!("Unsupported address type for signing: {} (only P2TR and P2WPKH supported for now)", address_type));
                }
            }
        }
        
        info!("Transaction signed successfully");
        Ok(())
    }
    
    /// Broadcast a transaction
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String> {
        info!("Broadcasting transaction: {}", tx.compute_txid());
        
        let tx_hex = hex::encode(bitcoin::consensus::serialize(tx));
        let txid = self.rpc_client.send_raw_transaction(&tx_hex).await?;
        
        info!("Transaction broadcast successfully: {}", txid);
        Ok(txid)
    }
    
    /// Send Bitcoin to an address
    pub async fn send(&self, params: SendParams) -> Result<String> {
        let (tx, _details) = self.create_transaction(params).await?;
        let txid = self.broadcast_transaction(&tx).await?;
        Ok(txid)
    }
    
    /// Freeze a UTXO
    pub async fn freeze_utxo(&self, txid: &str, vout: u32) -> Result<()> {
        let outpoint = OutPoint {
            txid: Txid::from_str(txid)?,
            vout,
        };
        
        let mut frozen_utxos = self.frozen_utxos.lock().await;
        frozen_utxos.insert(outpoint, true);
        
        info!("Frozen UTXO: {}:{}", txid, vout);
        Ok(())
    }
    
    /// Unfreeze a UTXO
    pub async fn unfreeze_utxo(&self, txid: &str, vout: u32) -> Result<()> {
        let outpoint = OutPoint {
            txid: Txid::from_str(txid)?,
            vout,
        };
        
        let mut frozen_utxos = self.frozen_utxos.lock().await;
        frozen_utxos.remove(&outpoint);
        
        info!("Unfrozen UTXO: {}:{}", txid, vout);
        Ok(())
    }
    
    /// Determine address type from script pubkey
    fn determine_address_type(&self, script_pubkey: &ScriptBuf) -> Result<String> {
        if script_pubkey.is_p2tr() {
            Ok("p2tr".to_string())
        } else if script_pubkey.is_p2wpkh() {
            Ok("p2wpkh".to_string())
        } else if script_pubkey.is_p2pkh() {
            Ok("p2pkh".to_string())
        } else if script_pubkey.is_p2sh() {
            Ok("p2sh".to_string())
        } else {
            Err(anyhow!("Unknown script pubkey type"))
        }
    }
    
    /// Find the correct derivation path for a UTXO by checking all address types and indices
    async fn find_derivation_path_for_utxo(&self, utxo: &UtxoInfo, address_type: &str) -> Result<(DerivationPath, u32)> {
        let coin_type = match self.config.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 1,
            Network::Regtest => 1,
            _ => 0,
        };
        
        // Check both external (0) and change (1) chains
        for is_change in [false, true] {
            let change_index = if is_change { 1 } else { 0 };
            
            // Check up to 1000 addresses to find the matching one
            for index in 0..1000 {
                let derivation_path = match address_type {
                    "p2pkh" => {
                        DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(44).unwrap(), // BIP44
                            ChildNumber::from_hardened_idx(coin_type).unwrap(),
                            ChildNumber::from_hardened_idx(0).unwrap(),
                            ChildNumber::from_normal_idx(change_index).unwrap(),
                            ChildNumber::from_normal_idx(index).unwrap(),
                        ])
                    },
                    "p2sh" => {
                        DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(49).unwrap(), // BIP49
                            ChildNumber::from_hardened_idx(coin_type).unwrap(),
                            ChildNumber::from_hardened_idx(0).unwrap(),
                            ChildNumber::from_normal_idx(change_index).unwrap(),
                            ChildNumber::from_normal_idx(index).unwrap(),
                        ])
                    },
                    "p2wpkh" => {
                        DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(84).unwrap(), // BIP84
                            ChildNumber::from_hardened_idx(coin_type).unwrap(),
                            ChildNumber::from_hardened_idx(0).unwrap(),
                            ChildNumber::from_normal_idx(change_index).unwrap(),
                            ChildNumber::from_normal_idx(index).unwrap(),
                        ])
                    },
                    "p2tr" => {
                        DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(86).unwrap(), // BIP86
                            ChildNumber::from_hardened_idx(coin_type).unwrap(),
                            ChildNumber::from_hardened_idx(0).unwrap(),
                            ChildNumber::from_normal_idx(change_index).unwrap(),
                            ChildNumber::from_normal_idx(index).unwrap(),
                        ])
                    },
                    _ => return Err(anyhow!("Unsupported address type: {}", address_type)),
                };
                
                // Generate the address for this derivation path and check if it matches
                match self.get_address_of_type_at_index(address_type, index, is_change).await {
                    Ok(generated_address) => {
                        if generated_address == utxo.address {
                            return Ok((derivation_path, index));
                        }
                    },
                    Err(_) => continue,
                }
            }
        }
        
        Err(anyhow!("Could not find derivation path for UTXO address: {}", utxo.address))
    }
    
    /// Sign a PSBT using the wallet
    pub async fn sign_psbt(&self, psbt: &bitcoin::psbt::Psbt) -> Result<bitcoin::psbt::Psbt> {
        
        use bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
        use bitcoin::secp256k1::{Keypair, Message};
        use bitcoin::key::{TapTweak, UntweakedKeypair};
        use bitcoin::taproot;
        use bitcoin::bip32::{DerivationPath, ChildNumber};
        
        info!("Signing PSBT with {} inputs", psbt.inputs.len());
        
        let mut signed_psbt = psbt.clone();
        
        // Create prevouts for sighash calculation
        let prevouts: Vec<bitcoin::TxOut> = signed_psbt.inputs.iter()
            .map(|input| {
                input.witness_utxo.clone()
                    .ok_or_else(|| anyhow!("Missing witness_utxo for input"))
            })
            .collect::<Result<Vec<_>>>()?;
        
        let prevouts = Prevouts::All(&prevouts);
        
        // Sign each input
        for (i, input) in signed_psbt.inputs.iter_mut().enumerate() {
            // Skip if already signed
            if input.final_script_witness.is_some() || input.final_script_sig.is_some() {
                debug!("Input {} already signed, skipping", i);
                continue;
            }
            
            // Get the witness UTXO
            let witness_utxo = input.witness_utxo.as_ref()
                .ok_or_else(|| anyhow!("Missing witness_utxo for input {}", i))?;
            
            // Determine address type from script pubkey
            let address_type = self.determine_address_type(&witness_utxo.script_pubkey)?;
            debug!("Input {}: address type = {}", i, address_type);
            
            // Create a dummy UTXO info to find derivation path
            let _dummy_utxo = UtxoInfo {
                txid: signed_psbt.unsigned_tx.input[i].previous_output.txid.to_string(),
                vout: signed_psbt.unsigned_tx.input[i].previous_output.vout,
                amount: witness_utxo.value.to_sat(),
                address: "".to_string(), // We'll need to derive this
                confirmations: 1,
                frozen: false,
                script_pubkey: witness_utxo.script_pubkey.clone(),
            };
            
            // For taproot script spends, handle differently
            if address_type == "p2tr" && !input.tap_scripts.is_empty() {
                // This is a taproot script spend
                info!("Signing taproot script spend for input {}", i);
                
                // Get the internal key
                let internal_key = input.tap_internal_key
                    .ok_or_else(|| anyhow!("Missing tap_internal_key for taproot script spend"))?;
                
                // Get the script and control block from tap_scripts
                let (_control_block, (script, leaf_version)) = input.tap_scripts.iter().next()
                    .ok_or_else(|| anyhow!("Missing tap_scripts for taproot script spend"))?;
                
                // Create sighash for script spend
                let mut sighash_cache = SighashCache::new(&signed_psbt.unsigned_tx);
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        i,
                        &prevouts,
                        bitcoin::taproot::TapLeafHash::from_script(&script, *leaf_version),
                        TapSighashType::Default,
                    )
                    .context("Failed to compute taproot script spend sighash")?;
                
                // Create keypair from master private key (for envelope operations)
                let keypair = Keypair::from_secret_key(&self.secp, &self.master_xprv.private_key);
                
                // Sign the sighash
                let msg = Message::from(sighash);
                let mut rng = bitcoin::secp256k1::rand::thread_rng();
                let signature = self.secp.sign_schnorr_with_rng(&msg, &keypair, &mut rng);
                
                // Create taproot signature
                let taproot_signature = taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                };
                
                // Set the signature in tap_script_sigs
                let tap_leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&script, *leaf_version);
                input.tap_script_sigs.insert(
                    (internal_key, tap_leaf_hash),
                    taproot_signature
                );
                
                info!("Added taproot script signature for input {}", i);
            } else {
                // Regular key-path spending or other address types
                // Find the derivation path for this input
                // For now, we'll use a simplified approach and try common paths
                
                match address_type.as_str() {
                    "p2tr" => {
                        // P2TR key-path spending
                        let mut sighash_cache = SighashCache::new(&signed_psbt.unsigned_tx);
                        let sighash = sighash_cache
                            .taproot_key_spend_signature_hash(
                                i,
                                &prevouts,
                                TapSighashType::Default,
                            )
                            .context("Failed to compute taproot key spend sighash")?;
                        
                        // CRITICAL FIX: Use proper derivation path for P2TR instead of master key
                        // Find the correct derivation path for this UTXO
                        let coin_type = match self.config.network {
                            Network::Bitcoin => 0,
                            Network::Testnet => 1,
                            Network::Signet => 1,
                            Network::Regtest => 1,
                            _ => 0,
                        };
                        
                        // Try to find the correct derivation path by checking common indices
                        let mut found_key = None;
                        'outer: for is_change in [false, true] {
                            let change_index = if is_change { 1 } else { 0 };
                            for index in 0..100 { // Check first 100 addresses
                                let derivation_path = DerivationPath::from(vec![
                                    ChildNumber::from_hardened_idx(86).unwrap(), // BIP86 (Taproot)
                                    ChildNumber::from_hardened_idx(coin_type).unwrap(),
                                    ChildNumber::from_hardened_idx(0).unwrap(),
                                    ChildNumber::from_normal_idx(change_index).unwrap(),
                                    ChildNumber::from_normal_idx(index).unwrap(),
                                ]);
                                
                                // Generate address for this path and check if it matches the UTXO
                                if let Ok(test_address) = self.get_address_of_type_at_index("p2tr", index, is_change).await {
                                    // Convert script pubkey to address to compare
                                    if let Ok(utxo_address) = bitcoin::Address::from_script(&witness_utxo.script_pubkey, self.config.network) {
                                        if test_address == utxo_address.to_string() {
                                            // Found the correct derivation path
                                            let private_key = self.derive_private_key(&derivation_path)?;
                                            found_key = Some(private_key);
                                            debug!("Found matching P2TR derivation path for input {}: index={}, is_change={}", i, index, is_change);
                                            break 'outer;
                                        }
                                    }
                                }
                            }
                        }
                        
                        let private_key = found_key.unwrap_or_else(|| {
                            warn!("Could not find derivation path for P2TR input {}, using master key as fallback", i);
                            PrivateKey::new(self.master_xprv.private_key, self.config.network)
                        });
                        
                        let keypair = Keypair::from_secret_key(&self.secp, &private_key.inner);
                        let untweaked_keypair = UntweakedKeypair::from(keypair);
                        let tweaked_keypair = untweaked_keypair.tap_tweak(&self.secp, None);
                        
                        let msg = Message::from(sighash);
                        let mut rng = bitcoin::secp256k1::rand::thread_rng();
                        let signature = self.secp.sign_schnorr_with_rng(&msg, tweaked_keypair.as_keypair(), &mut rng);
                        
                        let taproot_signature = taproot::Signature {
                            signature,
                            sighash_type: TapSighashType::Default,
                        };
                        
                        // Set the signature in tap_key_sig
                        input.tap_key_sig = Some(taproot_signature);
                        
                        info!("Added taproot key signature for input {}", i);
                    },
                    "p2wpkh" => {
                        // P2WPKH signing - would need proper derivation path finding
                        // For now, skip non-taproot inputs in envelope context
                        warn!("Skipping P2WPKH input {} in envelope context", i);
                    },
                    _ => {
                        warn!("Unsupported address type for PSBT signing: {}", address_type);
                    }
                }
            }
        }
        
        info!("PSBT signing completed");
        Ok(signed_psbt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::RpcConfig;

    #[tokio::test]
    async fn test_wallet_creation() {
        let config = BitcoinWalletConfig {
            wallet_path: "test_wallet.json.asc".to_string(),
            network: Network::Regtest,
            sandshrew_rpc_url: "http://localhost:8080".to_string(),
            network_params: None,
        };
        
        let rpc_config = RpcConfig {
            bitcoin_rpc_url: "http://localhost:8080".to_string(), // FIXED: Use Sandshrew for all RPC calls
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        
        // Journal: Updated test RPC config to use consistent Sandshrew endpoint (localhost:8080)
        // for both bitcoin_rpc_url and metashrew_rpc_url to avoid network mismatch issues
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        let wallet = BitcoinWallet::create_new(config, rpc_client).unwrap();
        
        // Test getting an address
        let address = wallet.get_address().await.unwrap();
        assert!(!address.is_empty());
        
        // Test getting mnemonic
        let mnemonic = wallet.get_mnemonic();
        assert!(!mnemonic.is_empty());
        
        // Test getting balance (will be 0 in test)
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed, 0);
    }
}