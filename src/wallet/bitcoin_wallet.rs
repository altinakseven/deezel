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
    script::{PushBytesBuf, Builder},
    opcodes::all::{OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG},
    sighash::{SighashCache, EcdsaSighashType, Prevouts},
    absolute::LockTime,
    Sequence, Amount, ScriptBuf,
};
use bitcoin::bip32::{ExtendedPrivKey, ExtendedPubKey, DerivationPath, ChildNumber};
use bitcoin::secp256k1::{Secp256k1, Message, SecretKey, All};
use bip39::{Mnemonic, Language};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{debug, info, warn};

use crate::rpc::RpcClient;
use super::crypto::{WalletCrypto, WalletData, EncryptedWalletData};

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
    master_xprv: ExtendedPrivKey,
    /// Master extended public key
    master_xpub: ExtendedPubKey,
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
        let master_xprv = ExtendedPrivKey::new_master(config.network, &seed)
            .context("Failed to create master extended private key")?;
        
        // Derive master extended public key
        let master_xpub = ExtendedPubKey::from_priv(&secp, &master_xprv);
        
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
    pub fn get_master_xprv(&self) -> ExtendedPrivKey {
        self.master_xprv
    }
    
    /// Get the master extended public key
    pub fn get_master_xpub(&self) -> ExtendedPubKey {
        self.master_xpub
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
    
    /// Get UTXOs for the wallet
    pub async fn get_utxos(&self) -> Result<Vec<UtxoInfo>> {
        let address = self.get_address_at_index(0, false).await?;
        debug!("Getting UTXOs for address: {}", address);
        
        let frozen_utxos = self.frozen_utxos.lock().await;
        let mut utxo_infos = Vec::new();
        
        match self.rpc_client.get_address_utxos(&address).await {
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
                            
                            let confirmations = if let Some(status) = utxo_obj.get("status") {
                                if status.get("confirmed").and_then(|c| c.as_bool()).unwrap_or(false) {
                                    1 // Simplified confirmation count
                                } else {
                                    0
                                }
                            } else {
                                0
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
                            let addr = Address::from_str(&address)
                                .context("Invalid address")?
                                .require_network(self.config.network)
                                .context("Address network mismatch")?;
                            
                            let utxo_info = UtxoInfo {
                                txid,
                                vout,
                                amount,
                                address: address.clone(),
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
                warn!("Failed to get UTXOs from Sandshrew: {}", e);
            }
        }
        
        Ok(utxo_infos)
    }
    
    /// Create a transaction
    pub async fn create_transaction(&self, params: SendParams) -> Result<(Transaction, TransactionDetails)> {
        info!("Creating transaction to {} for {} sats", params.address, params.amount);
        
        // Get available UTXOs
        let utxos = self.get_utxos().await?;
        let confirmed_utxos: Vec<_> = utxos.into_iter()
            .filter(|u| u.confirmations > 0 && !u.frozen)
            .collect();
        
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
            let change_address_str = self.get_change_address().await?;
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
    
    /// Sign a transaction
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
            // Derive the private key for this UTXO
            let derivation_path = DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(match self.config.network {
                    Network::Bitcoin => 0,
                    _ => 1,
                }).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(0).unwrap(),
                ChildNumber::from_normal_idx(0).unwrap(),
            ]);
            
            let private_key = self.derive_private_key(&derivation_path)?;
            let public_key = private_key.public_key(&self.secp);
            
            // Create sighash
            let mut sighash_cache = SighashCache::new(&*tx);
            let sighash = sighash_cache
                .p2wpkh_signature_hash(
                    i,
                    &utxo.script_pubkey,
                    Amount::from_sat(utxo.amount),
                    EcdsaSighashType::All,
                )
                .context("Failed to compute sighash")?;
            
            // Sign the sighash
            let message = Message::from_digest_slice(&sighash[..])
                .context("Failed to create message from sighash")?;
            
            let signature = self.secp.sign_ecdsa(&message, &private_key.inner);
            
            // Create witness for P2WPKH
            let mut sig_bytes = signature.serialize_der().to_vec();
            sig_bytes.push(EcdsaSighashType::All as u8);
            
            let mut witness = Witness::new();
            witness.push(sig_bytes);
            witness.push(public_key.to_bytes());
            
            tx.input[i].witness = witness;
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
            bitcoin_rpc_url: "http://localhost:8332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
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