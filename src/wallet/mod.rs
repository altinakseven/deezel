//! Bitcoin wallet functionality using BDK
//!
//! This module handles:
//! - Wallet creation and management
//! - Mnemonic generation and restoration
//! - UTXO tracking and selection
//! - Transaction creation, signing, and broadcasting
//! - Persistent wallet state
//! - Fee estimation and coin selection

mod esplora_backend;

use anyhow::{Context, Result, anyhow};
use bdk::bitcoin::{Network, Address, Amount, Txid, OutPoint, TxOut};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::database::MemoryDatabase;
use bdk::wallet::{AddressIndex, coin_selection::DefaultCoinSelectionAlgorithm};
use bdk::{Wallet, SyncOptions, FeeRate, SignOptions, TransactionDetails};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey};
use bdk::keys::bip39::{Mnemonic, Language, WordCount};
use bdk::miniscript::Tap;
use log::{debug, info, warn, error};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs;

use crate::rpc::RpcClient;
use self::esplora_backend::SandshrewEsploraBackend;
use protorune_support::network::NetworkParams as CustomNetworkParams;

/// Wallet configuration
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// Path to wallet file
    pub wallet_path: String,
    /// Bitcoin network (mainnet, testnet, regtest)
    pub network: Network,
    /// Bitcoin RPC URL
    pub bitcoin_rpc_url: String,
    /// Metashrew RPC URL
    pub metashrew_rpc_url: String,
    /// Custom network parameters for address generation
    pub network_params: Option<CustomNetworkParams>,
}

/// Wallet data for persistence
#[derive(Serialize, Deserialize, Debug)]
pub struct WalletData {
    /// Mnemonic phrase (encrypted in real implementation)
    pub mnemonic: String,
    /// Network
    pub network: String,
    /// External descriptor
    pub external_descriptor: String,
    /// Internal descriptor (change addresses)
    pub internal_descriptor: String,
    /// Creation timestamp
    pub created_at: u64,
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

/// UTXO information
#[derive(Debug, Clone, Serialize)]
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

/// Bitcoin wallet manager
pub struct WalletManager {
    /// BDK wallet instance
    wallet: Arc<Mutex<Wallet<MemoryDatabase>>>,
    /// Wallet configuration
    config: WalletConfig,
    /// Custom Esplora backend
    backend: SandshrewEsploraBackend,
    /// RPC client
    rpc_client: Arc<RpcClient>,
    /// Frozen UTXOs
    frozen_utxos: Arc<Mutex<HashMap<OutPoint, bool>>>,
    /// Wallet data for persistence
    wallet_data: Arc<Mutex<Option<WalletData>>>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub async fn new(config: WalletConfig) -> Result<Self> {
        info!("Initializing wallet manager");
        debug!("Wallet path: {}", config.wallet_path);
        debug!("Network: {:?}", config.network);
        
        // Create RPC client
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.bitcoin_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        
        // Create custom Esplora backend
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        // Check if wallet file exists
        let wallet_path = Path::new(&config.wallet_path);
        let (wallet, wallet_data) = if wallet_path.exists() {
            info!("Loading wallet from {}", config.wallet_path);
            let data = Self::load_wallet_data(&config.wallet_path).await?;
            let wallet = Self::create_wallet_from_data(&data, config.network, &config)?;
            (wallet, Some(data))
        } else {
            return Err(anyhow!("Wallet file not found at {}. Please create a wallet first using 'deezel wallet create'", config.wallet_path));
        };
        
        info!("Wallet initialized successfully");
        
        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            config,
            backend,
            rpc_client,
            frozen_utxos: Arc::new(Mutex::new(HashMap::new())),
            wallet_data: Arc::new(Mutex::new(wallet_data)),
        })
    }
    
    /// Create a new wallet with mnemonic
    pub async fn create_wallet(config: WalletConfig, mnemonic: Option<String>, passphrase: Option<String>) -> Result<Self> {
        info!("Creating new wallet with mnemonic");
        
        // Generate or use provided mnemonic
        let mnemonic = if let Some(m) = mnemonic {
            Mnemonic::from_str(&m).context("Invalid mnemonic")?
        } else {
            // Generate a new mnemonic using entropy
            use bdk::bitcoin::secp256k1::rand::{thread_rng, RngCore};
            let mut entropy = [0u8; 16]; // 128 bits for 12 words
            thread_rng().fill_bytes(&mut entropy);
            Mnemonic::from_entropy(&entropy).context("Failed to generate mnemonic from entropy")?
        };
        
        info!("Generated mnemonic: {}", mnemonic);
        
        // Create extended key from mnemonic
        let secp = Secp256k1::new();
        let xkey: ExtendedKey = mnemonic.clone()
            .into_extended_key()
            .context("Failed to create extended key")?;
        
        let xprv = xkey.into_xprv(config.network)
            .context("Failed to create xprv")?;
        
        // Create descriptors for Native SegWit (bech32)
        // For custom networks that use Network::Bitcoin as fallback, use mainnet derivation
        let coin_type = match config.network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 1,
            Network::Regtest => 1,
            _ => 0, // Use mainnet derivation for custom networks
        };
        
        let external_descriptor = format!("wpkh({}/84'/{}'/{}/0/*)", xprv, coin_type, 0);
        let internal_descriptor = format!("wpkh({}/84'/{}'/{}/1/*)", xprv, coin_type, 0);
        
        // Create wallet
        let wallet = Wallet::new(
            &external_descriptor,
            Some(&internal_descriptor),
            config.network,
            MemoryDatabase::default(),
        )?;
        
        // Create wallet data for persistence
        let wallet_data = WalletData {
            mnemonic: mnemonic.to_string(),
            network: format!("{:?}", config.network),
            external_descriptor: external_descriptor.clone(),
            internal_descriptor: internal_descriptor.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Create RPC client and backend
        let rpc_config = crate::rpc::RpcConfig {
            bitcoin_rpc_url: config.bitcoin_rpc_url.clone(),
            metashrew_rpc_url: config.metashrew_rpc_url.clone(),
        };
        let rpc_client = Arc::new(RpcClient::new(rpc_config));
        let backend = SandshrewEsploraBackend::new(Arc::clone(&rpc_client));
        
        let manager = Self {
            wallet: Arc::new(Mutex::new(wallet)),
            config,
            backend,
            rpc_client,
            frozen_utxos: Arc::new(Mutex::new(HashMap::new())),
            wallet_data: Arc::new(Mutex::new(Some(wallet_data))),
        };
        
        // Save wallet data
        manager.save().await?;
        
        info!("Wallet created successfully");
        Ok(manager)
    }
    
    /// Restore wallet from mnemonic
    pub async fn restore_wallet(config: WalletConfig, mnemonic: String, passphrase: Option<String>) -> Result<Self> {
        info!("Restoring wallet from mnemonic");
        Self::create_wallet(config, Some(mnemonic), passphrase).await
    }
    
    /// Load wallet data from file
    async fn load_wallet_data(wallet_path: &str) -> Result<WalletData> {
        let data = fs::read_to_string(wallet_path).await
            .context("Failed to read wallet file")?;
        
        let wallet_data: WalletData = serde_json::from_str(&data)
            .context("Failed to parse wallet data")?;
        
        Ok(wallet_data)
    }
    
    /// Create wallet from saved data
    fn create_wallet_from_data(data: &WalletData, network: Network, config: &WalletConfig) -> Result<Wallet<MemoryDatabase>> {
        // Validate that the saved network matches the requested network
        let saved_network = match data.network.as_str() {
            "Bitcoin" => Network::Bitcoin,
            "Testnet" => Network::Testnet,
            "Signet" => Network::Signet,
            "Regtest" => Network::Regtest,
            _ => return Err(anyhow!("Unknown network in wallet data: {}", data.network)),
        };
        
        if saved_network != network {
            return Err(anyhow!(
                "Network mismatch: wallet was created for {:?} but trying to load as {:?}. Use --wallet-path to specify a different wallet file.",
                saved_network, network
            ));
        }
        
        // Recreate wallet from mnemonic to avoid descriptor parsing issues
        let mnemonic = Mnemonic::from_str(&data.mnemonic)
            .context("Invalid mnemonic in wallet data")?;
        
        // Create extended key from mnemonic
        let xkey: ExtendedKey = mnemonic.clone()
            .into_extended_key()
            .context("Failed to create extended key")?;
        
        let xprv = xkey.into_xprv(network)
            .context("Failed to create xprv")?;
        
        // Create descriptors for Native SegWit (bech32)
        let coin_type = match network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 1,
            Network::Regtest => 1,
            _ => 0, // Use mainnet derivation for custom networks
        };
        
        let external_descriptor = format!("wpkh({}/84'/{}'/{}/0/*)", xprv, coin_type, 0);
        let internal_descriptor = format!("wpkh({}/84'/{}'/{}/1/*)", xprv, coin_type, 0);
        
        let wallet = Wallet::new(
            &external_descriptor,
            Some(&internal_descriptor),
            network,
            MemoryDatabase::default(),
        )?;
        
        Ok(wallet)
    }
    
    /// Get a new address from the wallet
    pub async fn get_address(&self) -> Result<String> {
        let wallet = self.wallet.lock().await;
        let address_info = wallet.get_address(AddressIndex::New)?;
        
        // If we have custom network parameters, use protorune_support for address generation
        if let Some(network_params) = &self.config.network_params {
            // Set the network parameters for protorune_support
            let protorune_params = protorune_support::network::NetworkParams {
                bech32_prefix: network_params.bech32_prefix.clone(),
                p2pkh_prefix: network_params.p2pkh_prefix,
                p2sh_prefix: network_params.p2sh_prefix,
            };
            protorune_support::network::set_network(protorune_params);
            
            // Use protorune_support to generate the address with custom network parameters
            // Convert between different bitcoin crate versions by using raw bytes
            let script_pubkey = address_info.address.script_pubkey();
            let script_bytes = script_pubkey.as_bytes();
            let bitcoin_script = bitcoin::Script::from_bytes(script_bytes);
            match protorune_support::network::to_address_str(bitcoin_script) {
                Ok(custom_address) => return Ok(custom_address),
                Err(e) => {
                    warn!("Failed to generate custom address: {}, falling back to BDK", e);
                }
            }
        }
        
        // Fall back to BDK's address generation
        Ok(address_info.to_string())
    }
    
    /// Get multiple addresses from the wallet
    pub async fn get_addresses(&self, count: u32) -> Result<Vec<String>> {
        let wallet = self.wallet.lock().await;
        let mut addresses = Vec::new();
        
        // Set up custom network parameters if available
        if let Some(network_params) = &self.config.network_params {
            let protorune_params = protorune_support::network::NetworkParams {
                bech32_prefix: network_params.bech32_prefix.clone(),
                p2pkh_prefix: network_params.p2pkh_prefix,
                p2sh_prefix: network_params.p2sh_prefix,
            };
            protorune_support::network::set_network(protorune_params);
        }
        
        for _ in 0..count {
            let address_info = wallet.get_address(AddressIndex::New)?;
            
            // Use custom address generation if network parameters are available
            let address_str = if let Some(_) = &self.config.network_params {
                // Convert between different bitcoin crate versions by using raw bytes
                let script_pubkey = address_info.address.script_pubkey();
                let script_bytes = script_pubkey.as_bytes();
                let bitcoin_script = bitcoin::Script::from_bytes(script_bytes);
                match protorune_support::network::to_address_str(bitcoin_script) {
                    Ok(custom_address) => custom_address,
                    Err(e) => {
                        warn!("Failed to generate custom address: {}, falling back to BDK", e);
                        address_info.to_string()
                    }
                }
            } else {
                address_info.to_string()
            };
            
            addresses.push(address_str);
        }
        
        Ok(addresses)
    }
    
    /// Get the mnemonic phrase (if available)
    pub async fn get_mnemonic(&self) -> Result<Option<String>> {
        let wallet_data = self.wallet_data.lock().await;
        Ok(wallet_data.as_ref().map(|data| data.mnemonic.clone()))
    }
    
    /// Sync the wallet with the blockchain using Sandshrew esplora interface
    pub async fn sync(&self) -> Result<()> {
        info!("Syncing wallet with blockchain");
        
        // First verify that Metashrew height is Bitcoin height + 1
        let bitcoin_height = self.rpc_client.get_block_count().await?;
        let metashrew_height = self.rpc_client.get_metashrew_height().await?;
        
        if metashrew_height != bitcoin_height + 1 {
            warn!(
                "Metashrew height ({}) is not Bitcoin height ({}) + 1",
                metashrew_height, bitcoin_height
            );
        }
        
        // Get all addresses from the wallet
        let wallet = self.wallet.lock().await;
        let addresses = wallet.list_unspent()?;
        drop(wallet);
        
        // Sync each address using esplora interface
        for utxo in addresses {
            let address = Address::from_script(&utxo.txout.script_pubkey, self.config.network)
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            debug!("Syncing address: {}", address);
            
            // Get UTXOs for this address
            match self.rpc_client.get_address_utxos(&address).await {
                Ok(utxos) => {
                    debug!("Found UTXOs for address {}: {:?}", address, utxos);
                    // TODO: Update wallet state with UTXOs
                },
                Err(e) => {
                    warn!("Failed to get UTXOs for address {}: {}", address, e);
                }
            }
        }
        
        info!("Wallet sync completed");
        
        // Get and log the wallet balance
        let balance = self.get_balance().await?;
        info!("Wallet balance: {} sats (confirmed: {} sats, unconfirmed: {} sats)",
            balance.confirmed + balance.trusted_pending + balance.untrusted_pending,
            balance.confirmed,
            balance.untrusted_pending);
        
        Ok(())
    }
    
    /// Save wallet state to disk
    pub async fn save(&self) -> Result<()> {
        info!("Saving wallet state to {}", self.config.wallet_path);
        
        let wallet_data = self.wallet_data.lock().await;
        if let Some(data) = wallet_data.as_ref() {
            let json_data = serde_json::to_string_pretty(data)
                .context("Failed to serialize wallet data")?;
            
            fs::write(&self.config.wallet_path, json_data).await
                .context("Failed to write wallet file")?;
            
            info!("Wallet state saved successfully");
        } else {
            warn!("No wallet data to save");
        }
        
        Ok(())
    }
    
    /// Get the wallet balance by querying Sandshrew directly
    pub async fn get_balance(&self) -> Result<bdk::Balance> {
        // Get the wallet address
        let address = self.get_address().await?;
        debug!("Getting balance for address: {}", address);
        
        // Query Sandshrew for UTXOs at this address using esplora interface
        match self.rpc_client.get_address_utxos(&address).await {
            Ok(utxos_response) => {
                debug!("UTXOs response from Sandshrew: {:?}", utxos_response);
                
                let mut confirmed_balance = 0u64;
                let mut unconfirmed_balance = 0u64;
                
                // Parse the UTXOs response
                if let Some(utxos_array) = utxos_response.as_array() {
                    for utxo in utxos_array {
                        if let Some(utxo_obj) = utxo.as_object() {
                            // Get the value (amount in satoshis)
                            if let Some(value) = utxo_obj.get("value").and_then(|v| v.as_u64()) {
                                // Check if the UTXO is confirmed
                                let is_confirmed = utxo_obj.get("status")
                                    .and_then(|s| s.get("confirmed"))
                                    .and_then(|c| c.as_bool())
                                    .unwrap_or(false);
                                
                                if is_confirmed {
                                    confirmed_balance += value;
                                } else {
                                    unconfirmed_balance += value;
                                }
                                
                                debug!("Found UTXO: {} sats (confirmed: {})", value, is_confirmed);
                            }
                        }
                    }
                }
                
                info!("Balance from Sandshrew - Confirmed: {} sats, Unconfirmed: {} sats",
                      confirmed_balance, unconfirmed_balance);
                
                // Return balance in BDK format
                Ok(bdk::Balance {
                    immature: 0,
                    trusted_pending: 0,
                    untrusted_pending: unconfirmed_balance,
                    confirmed: confirmed_balance,
                })
            },
            Err(e) => {
                warn!("Failed to get UTXOs from Sandshrew: {}, falling back to local wallet", e);
                // Fall back to local wallet balance
                let wallet = self.wallet.lock().await;
                Ok(wallet.get_balance()?)
            }
        }
    }
    
    /// Create a transaction
    pub async fn create_transaction(&self, params: SendParams) -> Result<(bdk::bitcoin::Transaction, bdk::TransactionDetails)> {
        info!("Creating transaction to {} for {} sats", params.address, params.amount);
        
        let mut wallet = self.wallet.lock().await;
        
        // Parse recipient address
        let recipient = Address::from_str(&params.address)
            .context("Invalid recipient address")?
            .require_network(self.config.network)
            .context("Address network mismatch")?;
        
        // Create transaction builder
        let mut tx_builder = wallet.build_tx();
        
        if params.send_all {
            tx_builder.drain_wallet().drain_to(recipient.script_pubkey());
        } else {
            tx_builder.add_recipient(recipient.script_pubkey(), params.amount);
        }
        
        // Set fee rate if provided
        if let Some(fee_rate) = params.fee_rate {
            tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate));
        } else {
            // Use default fee rate or estimate from network
            match self.estimate_fee_rate().await {
                Ok(estimated_fee) => {
                    tx_builder.fee_rate(FeeRate::from_sat_per_vb(estimated_fee));
                },
                Err(e) => {
                    warn!("Failed to estimate fee rate: {}, using default", e);
                    tx_builder.fee_rate(FeeRate::from_sat_per_vb(1.0));
                }
            }
        }
        
        // Apply frozen UTXOs filter
        let frozen_utxos = self.frozen_utxos.lock().await;
        if !frozen_utxos.is_empty() {
            let available_utxos: Vec<_> = wallet.list_unspent()?
                .into_iter()
                .filter(|utxo| !frozen_utxos.contains_key(&utxo.outpoint))
                .collect();
            
            // TODO: Apply UTXO filter to transaction builder
            debug!("Filtered {} frozen UTXOs", frozen_utxos.len());
        }
        
        // Finish building the transaction
        let (mut psbt, tx_details) = tx_builder.finish()
            .context("Failed to build transaction")?;
        
        // Sign the transaction
        let finalized = wallet.sign(&mut psbt, SignOptions::default())
            .context("Failed to sign transaction")?;
        
        if !finalized {
            return Err(anyhow!("Transaction could not be finalized"));
        }
        
        let tx = psbt.extract_tx();
        
        info!("Transaction created successfully: {}", tx.txid());
        debug!("Transaction details: {:?}", tx_details);
        
        Ok((tx, tx_details))
    }
    
    /// Broadcast a transaction
    pub async fn broadcast_transaction(&self, tx: &bdk::bitcoin::Transaction) -> Result<String> {
        info!("Broadcasting transaction: {}", tx.txid());
        
        let tx_hex = hex::encode(bdk::bitcoin::consensus::serialize(tx));
        let txid = self.rpc_client.broadcast_transaction(&tx_hex).await?;
        
        info!("Transaction broadcast successfully: {}", txid);
        Ok(txid)
    }
    
    /// Send Bitcoin to an address
    pub async fn send(&self, params: SendParams) -> Result<String> {
        let (tx, _details) = self.create_transaction(params).await?;
        let txid = self.broadcast_transaction(&tx).await?;
        Ok(txid)
    }
    
    /// Get UTXOs by querying Sandshrew directly
    pub async fn get_utxos(&self) -> Result<Vec<UtxoInfo>> {
        // Get the wallet address
        let address = self.get_address().await?;
        debug!("Getting UTXOs for address: {}", address);
        
        let frozen_utxos = self.frozen_utxos.lock().await;
        let mut utxo_infos = Vec::new();
        
        // Query Sandshrew for UTXOs at this address using esplora interface
        match self.rpc_client.get_address_utxos(&address).await {
            Ok(utxos_response) => {
                debug!("UTXOs response from Sandshrew: {:?}", utxos_response);
                
                // Parse the UTXOs response
                if let Some(utxos_array) = utxos_response.as_array() {
                    for utxo in utxos_array {
                        if let Some(utxo_obj) = utxo.as_object() {
                            // Get the transaction ID
                            let txid = utxo_obj.get("txid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            
                            // Get the output index
                            let vout = utxo_obj.get("vout")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            
                            // Get the value (amount in satoshis)
                            let amount = utxo_obj.get("value")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            
                            // Get confirmation status and block height
                            let (confirmations, is_confirmed) = if let Some(status) = utxo_obj.get("status") {
                                let confirmed = status.get("confirmed")
                                    .and_then(|c| c.as_bool())
                                    .unwrap_or(false);
                                
                                let block_height = status.get("block_height")
                                    .and_then(|h| h.as_u64())
                                    .unwrap_or(0) as u32;
                                
                                // Calculate confirmations (simplified - would need current height)
                                let confirmations = if confirmed {
                                    std::cmp::max(1, block_height.saturating_sub(0))
                                } else {
                                    0
                                };
                                
                                (confirmations, confirmed)
                            } else {
                                (0, false)
                            };
                            
                            // Check if this UTXO is frozen
                            let outpoint = if let Ok(parsed_txid) = Txid::from_str(&txid) {
                                OutPoint {
                                    txid: parsed_txid,
                                    vout,
                                }
                            } else {
                                // Skip invalid txids
                                continue;
                            };
                            let frozen = frozen_utxos.contains_key(&outpoint);
                            
                            let utxo_info = UtxoInfo {
                                txid,
                                vout,
                                amount,
                                address: address.clone(),
                                confirmations,
                                frozen,
                            };
                            
                            utxo_infos.push(utxo_info);
                        }
                    }
                }
                
                debug!("Found {} UTXOs for address {}", utxo_infos.len(), address);
            },
            Err(e) => {
                warn!("Failed to get UTXOs from Sandshrew: {}, falling back to local wallet", e);
                // Fall back to local wallet UTXOs
                let wallet = self.wallet.lock().await;
                let utxos = wallet.list_unspent()?;
                
                for utxo in utxos {
                    // Get address for this UTXO
                    let utxo_address = Address::from_script(&utxo.txout.script_pubkey, self.config.network)
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "Unknown".to_string());
                    
                    let utxo_info = UtxoInfo {
                        txid: utxo.outpoint.txid.to_string(),
                        vout: utxo.outpoint.vout,
                        amount: utxo.txout.value,
                        address: utxo_address,
                        confirmations: 1, // Placeholder
                        frozen: frozen_utxos.contains_key(&utxo.outpoint),
                    };
                    
                    utxo_infos.push(utxo_info);
                }
            }
        }
        
        Ok(utxo_infos)
    }
    
    /// Freeze a UTXO
    pub async fn freeze_utxo(&self, txid: &str, vout: u32) -> Result<()> {
        let outpoint = OutPoint {
            txid: Txid::from_str(txid).context("Invalid txid")?,
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
            txid: Txid::from_str(txid).context("Invalid txid")?,
            vout,
        };
        
        let mut frozen_utxos = self.frozen_utxos.lock().await;
        frozen_utxos.remove(&outpoint);
        
        info!("Unfrozen UTXO: {}:{}", txid, vout);
        Ok(())
    }
    
    /// Get transaction history
    pub async fn get_transaction_history(&self, limit: Option<usize>) -> Result<Vec<TransactionHistoryEntry>> {
        info!("Getting transaction history");
        
        // Get all addresses from wallet
        let wallet = self.wallet.lock().await;
        let addresses = wallet.list_unspent()?;
        drop(wallet);
        
        let mut all_transactions = Vec::new();
        
        // Get transaction history for each address
        for utxo in addresses.iter().take(limit.unwrap_or(10)) {
            let address = match Address::from_script(&utxo.txout.script_pubkey, self.config.network) {
                Ok(addr) => addr.to_string(),
                Err(_) => continue,
            };
            
            match self.rpc_client.get_address_transactions(&address).await {
                Ok(txs) => {
                    if let Some(tx_array) = txs.as_array() {
                        for tx in tx_array {
                            if let Some(tx_obj) = tx.as_object() {
                                let txid = tx_obj.get("txid")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                
                                let amount = tx_obj.get("value")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0);
                                
                                let confirmations = tx_obj.get("status")
                                    .and_then(|s| s.get("block_height"))
                                    .and_then(|h| h.as_u64())
                                    .map(|h| {
                                        // Calculate confirmations (simplified)
                                        1u32
                                    })
                                    .unwrap_or(0);
                                
                                let entry = TransactionHistoryEntry {
                                    txid,
                                    amount,
                                    fee: None, // TODO: Extract fee information
                                    confirmations,
                                    block_height: None, // TODO: Extract block height
                                    timestamp: None, // TODO: Extract timestamp
                                    tx_type: if amount > 0 { "received" } else { "sent" }.to_string(),
                                };
                                
                                all_transactions.push(entry);
                            }
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to get transaction history for address {}: {}", address, e);
                }
            }
        }
        
        // Sort by timestamp (most recent first) and limit
        all_transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        if let Some(limit) = limit {
            all_transactions.truncate(limit);
        }
        
        Ok(all_transactions)
    }
    
    /// Estimate fee rate
    pub async fn estimate_fee_rate(&self) -> Result<f32> {
        match self.rpc_client.get_fee_estimates().await {
            Ok(estimates) => {
                // Extract fee rate from estimates (simplified)
                if let Some(fee_obj) = estimates.as_object() {
                    if let Some(fee_1) = fee_obj.get("1").and_then(|v| v.as_f64()) {
                        return Ok(fee_1 as f32);
                    }
                }
                Ok(1.0) // Default fallback
            },
            Err(_) => Ok(1.0), // Default fallback
        }
    }
    
    /// Get the RPC client
    pub fn get_rpc_client(&self) -> Arc<RpcClient> {
        Arc::clone(&self.rpc_client)
    }
    
    /// Get the Esplora backend
    pub fn get_backend(&self) -> SandshrewEsploraBackend {
        self.backend.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wallet_creation() {
        // Basic test for wallet creation
        let config = WalletConfig {
            wallet_path: "test_wallet.dat".to_string(),
            network: Network::Testnet,
            bitcoin_rpc_url: "http://localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
        };
        
        let wallet_manager = WalletManager::new(config).await;
        assert!(wallet_manager.is_ok());
        
        if let Ok(manager) = wallet_manager {
            // Test getting an address
            let address = manager.get_address().await;
            assert!(address.is_ok());
            
            // Test getting the balance
            let balance = manager.get_balance().await;
            assert!(balance.is_ok());
            
            // Test getting the RPC client
            let rpc_client = manager.get_rpc_client();
            // Just verify we got a valid RPC client reference
            assert!(Arc::strong_count(&rpc_client) >= 1);
            
            // Test getting the backend
            let _backend = manager.get_backend();
        }
    }
}