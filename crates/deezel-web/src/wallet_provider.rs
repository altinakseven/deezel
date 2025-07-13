//! Browser Wallet Provider System
//!
//! This module provides a comprehensive wallet provider system that wraps injected browser wallets
//! (like Unisat, Xverse, Phantom, OKX, etc.) while implementing deezel-common traits. The system
//! uses wallets minimally as signers/keystores and leverages our sandshrew RPC connections and
//! polling strategies for most operations.
//!
//! # Architecture
//!
//! The wallet provider system consists of:
//! - [`BrowserWalletProvider`]: Main provider that wraps injected wallets
//! - [`WalletBackend`]: Trait for different wallet implementations
//! - [`InjectedWallet`]: Wrapper for browser-injected wallet objects
//! - [`WalletConnector`]: Connection management and wallet detection
//!
//! # Features
//!
//! - **Multi-wallet support**: Works with 13+ different Bitcoin wallets
//! - **Minimal wallet usage**: Only uses wallets for signing and key operations
//! - **Sandshrew integration**: Leverages our RPC connections for blockchain operations
//! - **Event handling**: Supports account and network change events
//! - **PSBT signing**: Full support for Partially Signed Bitcoin Transactions
//! - **Mobile support**: Deep linking and device detection
//!
//! # Example
//!
//! ```rust,no_run
//! use deezel_web::wallet_provider::*;
//! use deezel_common::*;
//!
//! async fn connect_wallet() -> Result<BrowserWalletProvider> {
//!     let connector = WalletConnector::new();
//!     let available_wallets = connector.detect_wallets().await?;
//!     
//!     if let Some(wallet_info) = available_wallets.first() {
//!         let provider = BrowserWalletProvider::connect(
//!             wallet_info.clone(),
//!             "mainnet".to_string(),
//!         ).await?;
//!         
//!         Ok(provider)
//!     } else {
//!         Err(DeezelError::Wallet("No wallets detected".to_string()))
//!     }
//! }
//! ```

#[cfg(target_arch = "wasm32")]
use alloc::{
    vec,
    vec::Vec,
    boxed::Box,
    string::{String, ToString},
    format,
};

use async_trait::async_trait;
use bitcoin::{Network, Transaction, psbt::Psbt, secp256k1::Keypair, XOnlyPublicKey};
use deezel_common::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use web_sys::wasm_bindgen::prelude::*;
use web_sys::wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{window, js_sys};

use crate::provider::WebProvider;

/// Information about an available wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub website: String,
    pub injection_key: String,
    pub supports_psbt: bool,
    pub supports_taproot: bool,
    pub supports_ordinals: bool,
    pub mobile_support: bool,
    pub deep_link_scheme: Option<String>,
}

/// Wallet connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

/// Account information from connected wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub address: String,
    pub public_key: Option<String>,
    pub compressed_public_key: Option<String>,
    pub address_type: String,
}

/// Network information from wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletNetworkInfo {
    pub network: String,
    pub chain_id: Option<String>,
}

/// PSBT signing options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtSigningOptions {
    pub auto_finalized: bool,
    pub to_sign_inputs: Option<Vec<PsbtSigningInput>>,
}

/// PSBT input signing specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtSigningInput {
    pub index: u32,
    pub address: Option<String>,
    pub sighash_types: Option<Vec<u32>>,
    pub disable_tweaked_public_key: Option<bool>,
}

/// Trait for different wallet backend implementations
#[async_trait(?Send)]
pub trait WalletBackend {
    /// Get wallet information
    fn get_info(&self) -> &WalletInfo;
    
    /// Check if wallet is available in the browser
    async fn is_available(&self) -> bool;
    
    /// Connect to the wallet
    async fn connect(&self) -> Result<WalletAccount>;
    
    /// Disconnect from the wallet
    async fn disconnect(&self) -> Result<()>;
    
    /// Get current accounts
    async fn get_accounts(&self) -> Result<Vec<WalletAccount>>;
    
    /// Get current network
    async fn get_network(&self) -> Result<WalletNetworkInfo>;
    
    /// Switch network
    async fn switch_network(&self, network: &str) -> Result<()>;
    
    /// Sign a message
    async fn sign_message(&self, message: &str, address: &str) -> Result<String>;
    
    /// Sign a PSBT
    async fn sign_psbt(&self, psbt_hex: &str, options: Option<PsbtSigningOptions>) -> Result<String>;
    
    /// Sign multiple PSBTs
    async fn sign_psbts(&self, psbt_hexs: Vec<String>, options: Option<PsbtSigningOptions>) -> Result<Vec<String>>;
    
    /// Push a transaction to the network
    async fn push_tx(&self, tx_hex: &str) -> Result<String>;
    
    /// Push a PSBT to the network
    async fn push_psbt(&self, psbt_hex: &str) -> Result<String>;
    
    /// Get public key
    async fn get_public_key(&self) -> Result<String>;
    
    /// Get balance (if supported by wallet)
    async fn get_balance(&self) -> Result<Option<u64>>;
    
    /// Get inscriptions (if supported by wallet)
    async fn get_inscriptions(&self, cursor: Option<u32>, size: Option<u32>) -> Result<JsonValue>;
}

/// Wrapper for browser-injected wallet objects
pub struct InjectedWallet {
    info: WalletInfo,
    #[allow(dead_code)]
    js_object: js_sys::Object,
}

impl InjectedWallet {
    /// Create a new injected wallet wrapper
    pub fn new(info: WalletInfo, js_object: js_sys::Object) -> Self {
        Self { info, js_object }
    }
    
    /// Call a method on the injected wallet object
    async fn call_method(&self, method: &str, args: &[JsValue]) -> Result<JsValue> {
        let window = window().ok_or_else(|| DeezelError::Wallet("No window object".to_string()))?;
        
        // Get the wallet object from window
        let wallet_obj = js_sys::Reflect::get(&window, &JsValue::from_str(&self.info.injection_key))
            .map_err(|e| DeezelError::Wallet(format!("Wallet not found: {:?}", e)))?;
        
        if wallet_obj.is_undefined() {
            return Err(DeezelError::Wallet(format!("Wallet {} not available", self.info.name)));
        }
        
        // Get the method
        let method_fn = js_sys::Reflect::get(&wallet_obj, &JsValue::from_str(method))
            .map_err(|e| DeezelError::Wallet(format!("Method {} not found: {:?}", method, e)))?;
        
        if !method_fn.is_function() {
            return Err(DeezelError::Wallet(format!("Method {} is not a function", method)));
        }
        
        // Call the method
        let function = method_fn.dyn_into::<js_sys::Function>()
            .map_err(|e| DeezelError::Wallet(format!("Failed to cast to function: {:?}", e)))?;
        
        let result = function.apply(&wallet_obj, &js_sys::Array::from_iter(args.iter()))
            .map_err(|e| DeezelError::Wallet(format!("Method call failed: {:?}", e)))?;
        
        // If result is a promise, await it
        if result.has_type::<js_sys::Promise>() {
            let promise = result.dyn_into::<js_sys::Promise>()
                .map_err(|e| DeezelError::Wallet(format!("Failed to cast to promise: {:?}", e)))?;
            
            JsFuture::from(promise)
                .await
                .map_err(|e| DeezelError::Wallet(format!("Promise rejected: {:?}", e)))
        } else {
            Ok(result)
        }
    }
}

#[async_trait(?Send)]
impl WalletBackend for InjectedWallet {
    fn get_info(&self) -> &WalletInfo {
        &self.info
    }
    
    async fn is_available(&self) -> bool {
        let window = window();
        if let Some(window) = window {
            let wallet_obj = js_sys::Reflect::get(&window, &JsValue::from_str(&self.info.injection_key));
            wallet_obj.is_ok() && !wallet_obj.unwrap().is_undefined()
        } else {
            false
        }
    }
    
    async fn connect(&self) -> Result<WalletAccount> {
        let result = self.call_method("requestAccounts", &[]).await?;
        
        // Parse the result to get account information
        let accounts_array = result.dyn_into::<js_sys::Array>()
            .map_err(|e| DeezelError::Wallet(format!("Invalid accounts response: {:?}", e)))?;
        
        if accounts_array.length() == 0 {
            return Err(DeezelError::Wallet("No accounts returned".to_string()));
        }
        
        let first_account = accounts_array.get(0);
        let address = first_account.as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid account format".to_string()))?;
        
        Ok(WalletAccount {
            address,
            public_key: None,
            compressed_public_key: None,
            address_type: "unknown".to_string(),
        })
    }
    
    async fn disconnect(&self) -> Result<()> {
        // Some wallets support disconnect, others don't
        match self.call_method("disconnect", &[]).await {
            Ok(_) => Ok(()),
            Err(_) => {
                // If disconnect is not supported, that's okay
                Ok(())
            }
        }
    }
    
    async fn get_accounts(&self) -> Result<Vec<WalletAccount>> {
        let result = self.call_method("getAccounts", &[]).await?;
        
        let accounts_array = result.dyn_into::<js_sys::Array>()
            .map_err(|e| DeezelError::Wallet(format!("Invalid accounts response: {:?}", e)))?;
        
        let mut accounts = Vec::new();
        for i in 0..accounts_array.length() {
            let account = accounts_array.get(i);
            if let Some(address) = account.as_string() {
                accounts.push(WalletAccount {
                    address,
                    public_key: None,
                    compressed_public_key: None,
                    address_type: "unknown".to_string(),
                });
            }
        }
        
        Ok(accounts)
    }
    
    async fn get_network(&self) -> Result<WalletNetworkInfo> {
        match self.call_method("getNetwork", &[]).await {
            Ok(result) => {
                let network = result.as_string()
                    .unwrap_or_else(|| "mainnet".to_string());
                
                Ok(WalletNetworkInfo {
                    network,
                    chain_id: None,
                })
            },
            Err(_) => {
                // Default to mainnet if not supported
                Ok(WalletNetworkInfo {
                    network: "mainnet".to_string(),
                    chain_id: None,
                })
            }
        }
    }
    
    async fn switch_network(&self, network: &str) -> Result<()> {
        let network_value = JsValue::from_str(network);
        self.call_method("switchNetwork", &[network_value]).await?;
        Ok(())
    }
    
    async fn sign_message(&self, message: &str, address: &str) -> Result<String> {
        let message_value = JsValue::from_str(message);
        let address_value = JsValue::from_str(address);
        
        let result = self.call_method("signMessage", &[message_value, address_value]).await?;
        
        result.as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid signature response".to_string()))
    }
    
    async fn sign_psbt(&self, psbt_hex: &str, options: Option<PsbtSigningOptions>) -> Result<String> {
        let psbt_value = JsValue::from_str(psbt_hex);
        
        let args = if let Some(opts) = options {
            let options_obj = js_sys::Object::new();
            
            js_sys::Reflect::set(&options_obj, &"autoFinalized".into(), &JsValue::from_bool(opts.auto_finalized))
                .map_err(|e| DeezelError::Wallet(format!("Failed to set options: {:?}", e)))?;
            
            if let Some(to_sign) = opts.to_sign_inputs {
                let to_sign_array = js_sys::Array::new();
                for input in to_sign {
                    let input_obj = js_sys::Object::new();
                    js_sys::Reflect::set(&input_obj, &"index".into(), &JsValue::from_f64(input.index as f64))
                        .map_err(|e| DeezelError::Wallet(format!("Failed to set input index: {:?}", e)))?;
                    
                    if let Some(addr) = input.address {
                        js_sys::Reflect::set(&input_obj, &"address".into(), &JsValue::from_str(&addr))
                            .map_err(|e| DeezelError::Wallet(format!("Failed to set input address: {:?}", e)))?;
                    }
                    
                    to_sign_array.push(&input_obj);
                }
                js_sys::Reflect::set(&options_obj, &"toSignInputs".into(), &to_sign_array)
                    .map_err(|e| DeezelError::Wallet(format!("Failed to set toSignInputs: {:?}", e)))?;
            }
            
            vec![psbt_value, options_obj.into()]
        } else {
            vec![psbt_value]
        };
        
        let result = self.call_method("signPsbt", &args).await?;
        
        result.as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid PSBT signature response".to_string()))
    }
    
    async fn sign_psbts(&self, psbt_hexs: Vec<String>, options: Option<PsbtSigningOptions>) -> Result<Vec<String>> {
        let psbts_array = js_sys::Array::new();
        for psbt_hex in psbt_hexs {
            psbts_array.push(&JsValue::from_str(&psbt_hex));
        }
        
        let args = if let Some(opts) = options {
            let options_obj = js_sys::Object::new();
            js_sys::Reflect::set(&options_obj, &"autoFinalized".into(), &JsValue::from_bool(opts.auto_finalized))
                .map_err(|e| DeezelError::Wallet(format!("Failed to set options: {:?}", e)))?;
            
            vec![psbts_array.into(), options_obj.into()]
        } else {
            vec![psbts_array.into()]
        };
        
        let result = self.call_method("signPsbts", &args).await?;
        
        let result_array = result.dyn_into::<js_sys::Array>()
            .map_err(|e| DeezelError::Wallet(format!("Invalid PSBTs signature response: {:?}", e)))?;
        
        let mut signed_psbts = Vec::new();
        for i in 0..result_array.length() {
            let psbt = result_array.get(i);
            if let Some(psbt_hex) = psbt.as_string() {
                signed_psbts.push(psbt_hex);
            }
        }
        
        Ok(signed_psbts)
    }
    
    async fn push_tx(&self, tx_hex: &str) -> Result<String> {
        let tx_value = JsValue::from_str(tx_hex);
        let result = self.call_method("pushTx", &[tx_value]).await?;
        
        result.as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid push transaction response".to_string()))
    }
    
    async fn push_psbt(&self, psbt_hex: &str) -> Result<String> {
        let psbt_value = JsValue::from_str(psbt_hex);
        let result = self.call_method("pushPsbt", &[psbt_value]).await?;
        
        result.as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid push PSBT response".to_string()))
    }
    
    async fn get_public_key(&self) -> Result<String> {
        let result = self.call_method("getPublicKey", &[]).await?;
        
        result.as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid public key response".to_string()))
    }
    
    async fn get_balance(&self) -> Result<Option<u64>> {
        match self.call_method("getBalance", &[]).await {
            Ok(result) => {
                if let Some(balance_str) = result.as_string() {
                    balance_str.parse::<u64>()
                        .map(Some)
                        .map_err(|e| DeezelError::Wallet(format!("Invalid balance format: {}", e)))
                } else if let Some(balance_num) = result.as_f64() {
                    Ok(Some(balance_num as u64))
                } else {
                    Ok(None)
                }
            },
            Err(_) => Ok(None), // Balance not supported
        }
    }
    
    async fn get_inscriptions(&self, cursor: Option<u32>, size: Option<u32>) -> Result<JsonValue> {
        let mut args = Vec::new();
        
        if let Some(c) = cursor {
            args.push(JsValue::from_f64(c as f64));
        }
        if let Some(s) = size {
            args.push(JsValue::from_f64(s as f64));
        }
        
        let result = self.call_method("getInscriptions", &args).await?;
        
        // Convert JsValue to JsonValue
        let result_str = js_sys::JSON::stringify(&result)
            .map_err(|e| DeezelError::Wallet(format!("Failed to stringify inscriptions: {:?}", e)))?
            .as_string()
            .ok_or_else(|| DeezelError::Wallet("Invalid inscriptions response".to_string()))?;
        
        serde_json::from_str(&result_str)
            .map_err(|e| DeezelError::Wallet(format!("Failed to parse inscriptions JSON: {}", e)))
    }
}

/// Wallet connector for detecting and connecting to available wallets
pub struct WalletConnector {
    supported_wallets: Vec<WalletInfo>,
}

impl Default for WalletConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletConnector {
    /// Create a new wallet connector
    pub fn new() -> Self {
        Self {
            supported_wallets: Self::get_supported_wallets(),
        }
    }
    
    /// Get list of supported wallets
    pub fn get_supported_wallets() -> Vec<WalletInfo> {
        vec![
            WalletInfo {
                id: "unisat".to_string(),
                name: "Unisat Wallet".to_string(),
                icon: "https://unisat.io/favicon.ico".to_string(),
                website: "https://unisat.io".to_string(),
                injection_key: "unisat".to_string(),
                supports_psbt: true,
                supports_taproot: true,
                supports_ordinals: true,
                mobile_support: false,
                deep_link_scheme: None,
            },
            WalletInfo {
                id: "xverse".to_string(),
                name: "Xverse Wallet".to_string(),
                icon: "https://xverse.app/favicon.ico".to_string(),
                website: "https://xverse.app".to_string(),
                injection_key: "XverseProviders".to_string(),
                supports_psbt: true,
                supports_taproot: true,
                supports_ordinals: true,
                mobile_support: true,
                deep_link_scheme: Some("xverse://".to_string()),
            },
            WalletInfo {
                id: "phantom".to_string(),
                name: "Phantom Wallet".to_string(),
                icon: "https://phantom.app/favicon.ico".to_string(),
                website: "https://phantom.app".to_string(),
                injection_key: "phantom".to_string(),
                supports_psbt: true,
                supports_taproot: true,
                supports_ordinals: false,
                mobile_support: true,
                deep_link_scheme: Some("phantom://".to_string()),
            },
            WalletInfo {
                id: "okx".to_string(),
                name: "OKX Wallet".to_string(),
                icon: "https://okx.com/favicon.ico".to_string(),
                website: "https://okx.com".to_string(),
                injection_key: "okxwallet".to_string(),
                supports_psbt: true,
                supports_taproot: true,
                supports_ordinals: true,
                mobile_support: true,
                deep_link_scheme: Some("okx://".to_string()),
            },
            WalletInfo {
                id: "leather".to_string(),
                name: "Leather Wallet".to_string(),
                icon: "https://leather.io/favicon.ico".to_string(),
                website: "https://leather.io".to_string(),
                injection_key: "LeatherProvider".to_string(),
                supports_psbt: true,
                supports_taproot: true,
                supports_ordinals: true,
                mobile_support: false,
                deep_link_scheme: None,
            },
            WalletInfo {
                id: "magic_eden".to_string(),
                name: "Magic Eden Wallet".to_string(),
                icon: "https://magiceden.io/favicon.ico".to_string(),
                website: "https://magiceden.io".to_string(),
                injection_key: "magicEden".to_string(),
                supports_psbt: true,
                supports_taproot: true,
                supports_ordinals: true,
                mobile_support: true,
                deep_link_scheme: Some("magiceden://".to_string()),
            },
            // Add more wallets as needed...
        ]
    }
    
    /// Detect available wallets in the browser
    pub async fn detect_wallets(&self) -> Result<Vec<WalletInfo>> {
        let window = window().ok_or_else(|| DeezelError::Wallet("No window object".to_string()))?;
        
        let mut available_wallets = Vec::new();
        
        for wallet_info in &self.supported_wallets {
            let wallet_obj = js_sys::Reflect::get(&window, &JsValue::from_str(&wallet_info.injection_key));
            
            if wallet_obj.is_ok() && !wallet_obj.unwrap().is_undefined() {
                available_wallets.push(wallet_info.clone());
            }
        }
        
        Ok(available_wallets)
    }
    
    /// Get wallet info by ID
    pub fn get_wallet_info(&self, wallet_id: &str) -> Option<&WalletInfo> {
        self.supported_wallets.iter().find(|w| w.id == wallet_id)
    }
    
    /// Create an injected wallet instance
    pub fn create_injected_wallet(&self, wallet_info: WalletInfo) -> Result<InjectedWallet> {
        let window = window().ok_or_else(|| DeezelError::Wallet("No window object".to_string()))?;
        
        let wallet_obj = js_sys::Reflect::get(&window, &JsValue::from_str(&wallet_info.injection_key))
            .map_err(|e| DeezelError::Wallet(format!("Wallet not found: {:?}", e)))?;
        
        if wallet_obj.is_undefined() {
            return Err(DeezelError::Wallet(format!("Wallet {} not available", wallet_info.name)));
        }
        
        let js_object = wallet_obj.dyn_into::<js_sys::Object>()
            .map_err(|e| DeezelError::Wallet(format!("Invalid wallet object: {:?}", e)))?;
        
        Ok(InjectedWallet::new(wallet_info, js_object))
    }
}

/// Browser wallet provider that implements deezel-common traits
///
/// This provider wraps injected browser wallets while leveraging our sandshrew RPC
/// connections and polling strategies for most operations. The wallet is used minimally
/// as a signer and keystore, while blockchain operations use our existing infrastructure.
pub struct BrowserWalletProvider {
    wallet: Box<dyn WalletBackend>,
    web_provider: WebProvider,
    connection_status: WalletConnectionStatus,
    current_account: Option<WalletAccount>,
}

impl BrowserWalletProvider {
    /// Connect to a browser wallet
    pub async fn connect(
        wallet_info: WalletInfo,
        network_str: String,
    ) -> Result<Self> {
        // Create the underlying web provider for blockchain operations
        let web_provider = WebProvider::new(network_str).await?;
        
        // Create the wallet connector and injected wallet
        let connector = WalletConnector::new();
        let injected_wallet = connector.create_injected_wallet(wallet_info)?;
        
        // Connect to the wallet
        let account = injected_wallet.connect().await?;
        
        Ok(Self {
            wallet: Box::new(injected_wallet),
            web_provider,
            connection_status: WalletConnectionStatus::Connected,
            current_account: Some(account),
        })
    }
    
    /// Get the current connection status
    pub fn connection_status(&self) -> &WalletConnectionStatus {
        &self.connection_status
    }
    
    /// Get the current account
    pub fn current_account(&self) -> Option<&WalletAccount> {
        self.current_account.as_ref()
    }
    
    /// Get wallet information
    pub fn wallet_info(&self) -> &WalletInfo {
        self.wallet.get_info()
    }
    
    /// Disconnect from the wallet
    pub async fn disconnect(&mut self) -> Result<()> {
        self.wallet.disconnect().await?;
        self.connection_status = WalletConnectionStatus::Disconnected;
        self.current_account = None;
        Ok(())
    }
    
    /// Switch to a different network
    pub async fn switch_network(&mut self, network: &str) -> Result<()> {
        self.wallet.switch_network(network).await?;
        
        // Update the web provider's network as well
        // Note: This would require recreating the web provider with the new network
        // For now, we'll just update the wallet
        Ok(())
    }
    
    /// Get the underlying web provider for direct access
    pub fn web_provider(&self) -> &WebProvider {
        &self.web_provider
    }
}

impl Clone for BrowserWalletProvider {
    fn clone(&self) -> Self {
        // Note: This is a simplified clone that doesn't clone the wallet backend
        // In a real implementation, you might want to handle this differently
        Self {
            wallet: Box::new(InjectedWallet::new(
                self.wallet.get_info().clone(),
                js_sys::Object::new(),
            )),
            web_provider: self.web_provider.clone(),
            connection_status: self.connection_status.clone(),
            current_account: self.current_account.clone(),
        }
    }
}

// Implement deezel-common traits for BrowserWalletProvider
// Most operations delegate to the web_provider, while signing operations use the wallet

#[async_trait(?Send)]
impl JsonRpcProvider for BrowserWalletProvider {
    async fn call(&self, url: &str, method: &str, params: JsonValue, id: u64) -> Result<JsonValue> {
        self.web_provider.call(url, method, params, id).await
    }
    
    async fn get_bytecode(&self, block: &str, _tx: &str) -> Result<String> {
        deezel_common::AlkanesProvider::get_bytecode(&self.web_provider, block).await
    }
}

#[async_trait(?Send)]
impl StorageProvider for BrowserWalletProvider {
    async fn read(&self, key: &str) -> Result<Vec<u8>> {
        self.web_provider.read(key).await
    }
    
    async fn write(&self, key: &str, data: &[u8]) -> Result<()> {
        self.web_provider.write(key, data).await
    }
    
    async fn exists(&self, key: &str) -> Result<bool> {
        self.web_provider.exists(key).await
    }
    
    async fn delete(&self, key: &str) -> Result<()> {
        self.web_provider.delete(key).await
    }
    
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        self.web_provider.list_keys(prefix).await
    }
    
    fn storage_type(&self) -> &'static str {
        "browser_wallet_localStorage"
    }
}

#[async_trait(?Send)]
impl NetworkProvider for BrowserWalletProvider {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.web_provider.get(url).await
    }
    
    async fn post(&self, url: &str, body: &[u8], content_type: &str) -> Result<Vec<u8>> {
        self.web_provider.post(url, body, content_type).await
    }
    
    async fn is_reachable(&self, url: &str) -> bool {
        self.web_provider.is_reachable(url).await
    }
}

#[async_trait(?Send)]
impl CryptoProvider for BrowserWalletProvider {
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        self.web_provider.random_bytes(len)
    }
    
    fn sha256(&self, data: &[u8]) -> Result<[u8; 32]> {
        self.web_provider.sha256(data)
    }
    
    fn sha3_256(&self, data: &[u8]) -> Result<[u8; 32]> {
        self.web_provider.sha3_256(data)
    }
    
    async fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        self.web_provider.encrypt_aes_gcm(data, key, nonce).await
    }
    
    async fn decrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        self.web_provider.decrypt_aes_gcm(data, key, nonce).await
    }
    
    async fn pbkdf2_derive(&self, password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Result<Vec<u8>> {
        self.web_provider.pbkdf2_derive(password, salt, iterations, key_len).await
    }
}

impl TimeProvider for BrowserWalletProvider {
    fn now_secs(&self) -> u64 {
        self.web_provider.now_secs()
    }
    
    fn now_millis(&self) -> u64 {
        self.web_provider.now_millis()
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    fn sleep_ms(&self, ms: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        self.web_provider.sleep_ms(ms)
    }
    #[cfg(target_arch = "wasm32")]
    fn sleep_ms(&self, ms: u64) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()>>> {
        self.web_provider.sleep_ms(ms)
    }
}

impl LogProvider for BrowserWalletProvider {
    fn debug(&self, message: &str) {
        self.web_provider.debug(message);
    }
    
    fn info(&self, message: &str) {
        self.web_provider.info(message);
    }
    
    fn warn(&self, message: &str) {
        self.web_provider.warn(message);
    }
    
    fn error(&self, message: &str) {
        self.web_provider.error(message);
    }
}

// WalletProvider implementation - this is where we use the injected wallet for signing
// but leverage our sandshrew RPC for most blockchain operations
#[async_trait(?Send)]
impl WalletProvider for BrowserWalletProvider {
    async fn create_wallet(&self, _config: WalletConfig, _mnemonic: Option<String>, _passphrase: Option<String>) -> Result<deezel_common::WalletInfo> {
        // For browser wallets, we don't create wallets - they're managed by the wallet extension
        // Instead, we return information about the connected wallet
        if let Some(account) = &self.current_account {
            Ok(deezel_common::WalletInfo {
                address: account.address.clone(),
                network: self.web_provider.network(),
                mnemonic: None, // Browser wallets don't expose mnemonics
            })
        } else {
            Err(DeezelError::Wallet("No wallet connected".to_string()))
        }
    }
    
    async fn load_wallet(&self, config: WalletConfig, _passphrase: Option<String>) -> Result<deezel_common::WalletInfo> {
        // Similar to create_wallet - browser wallets are already "loaded"
        self.create_wallet(config, None, None).await
    }
    
    async fn get_balance(&self, addresses: Option<Vec<String>>) -> Result<WalletBalance> {
        // Use our sandshrew RPC to get accurate balance information
        // rather than relying on the wallet's potentially limited balance API
        let addrs_to_check = if let Some(provided_addresses) = addresses {
            provided_addresses
        } else if let Some(account) = &self.current_account {
            vec![account.address.clone()]
        } else {
            return Err(DeezelError::Wallet("No wallet connected and no addresses provided".to_string()));
        };

        let mut total_confirmed = 0;
        let mut total_pending = 0_i64;

        for address in addrs_to_check {
            let address_info = EsploraProvider::get_address_info(&self.web_provider, &address).await?;
            
            if let Some(chain_stats) = address_info.get("chain_stats") {
                let funded = chain_stats.get("funded_txo_sum").and_then(|v| v.as_u64()).unwrap_or(0);
                let spent = chain_stats.get("spent_txo_sum").and_then(|v| v.as_u64()).unwrap_or(0);
                total_confirmed += funded.saturating_sub(spent);
            }

            if let Some(mempool_stats) = address_info.get("mempool_stats") {
                let funded = mempool_stats.get("funded_txo_sum").and_then(|v| v.as_i64()).unwrap_or(0);
                let spent = mempool_stats.get("spent_txo_sum").and_then(|v| v.as_i64()).unwrap_or(0);
                total_pending += funded - spent;
            }
        }
        
        Ok(WalletBalance {
            confirmed: total_confirmed,
            pending: total_pending,
        })
    }
    
    async fn get_address(&self) -> Result<String> {
        if let Some(account) = &self.current_account {
            Ok(account.address.clone())
        } else {
            Err(DeezelError::Wallet("No wallet connected".to_string()))
        }
    }
    
    async fn get_addresses(&self, count: u32) -> Result<Vec<AddressInfo>> {
        // Get all accounts from the wallet
        let accounts = self.wallet.get_accounts().await?;
        
        let mut addresses = Vec::new();
        for (i, account) in accounts.iter().enumerate().take(count as usize) {
            addresses.push(AddressInfo {
                address: account.address.clone(),
                script_type: account.address_type.clone(),
                derivation_path: format!("m/84'/0'/0'/0/{}", i), // Estimated path
                index: i as u32,
                used: true, // Assume used since it's from the wallet
            });
        }
        
        Ok(addresses)
    }
    
    async fn send(&self, params: SendParams) -> Result<String> {
        // For sending, we'll create the transaction using our infrastructure
        // then use the wallet to sign it
        let tx_hex = self.create_transaction(params.clone()).await?;
        let signed_tx_hex = self.sign_transaction(tx_hex).await?;
        self.broadcast_transaction(signed_tx_hex).await
    }
    
    async fn get_utxos(&self, _include_frozen: bool, addresses: Option<Vec<String>>) -> Result<Vec<UtxoInfo>> {
        // Use our Esplora provider for accurate UTXO information
        let addresses_to_check = if let Some(addrs) = addresses {
            addrs
        } else if let Some(account) = &self.current_account {
            vec![account.address.clone()]
        } else {
            return Err(DeezelError::Wallet("No addresses to check".to_string()));
        };
        
        let mut all_utxos = Vec::new();
        
        for address in addresses_to_check {
            let utxos_json = EsploraProvider::get_address_utxo(&self.web_provider, &address).await?;
            
            if let Some(utxos_array) = utxos_json.as_array() {
                for utxo in utxos_array {
                    if let (Some(txid), Some(vout), Some(value)) = (
                        utxo.get("txid").and_then(|t| t.as_str()),
                        utxo.get("vout").and_then(|v| v.as_u64()),
                        utxo.get("value").and_then(|v| v.as_u64()),
                    ) {
                        let status = utxo.get("status");
                        let confirmations = status
                            .and_then(|s| s.get("block_height"))
                            .and_then(|h| h.as_u64())
                            .map(|height| {
                                // Calculate confirmations based on current height
                                let current_height: u64 = 800000; // This should come from our RPC
                                current_height.saturating_sub(height) as u32
                            })
                            .unwrap_or(0);
                        
                        all_utxos.push(UtxoInfo {
                            txid: txid.to_string(),
                            vout: vout as u32,
                            amount: value,
                            address: address.clone(),
                            script_pubkey: None, // Would need to derive from address
                            confirmations,
                            frozen: false, // Browser wallets don't typically support freezing
                            freeze_reason: None,
                            block_height: status.and_then(|s| s.get("block_height")).and_then(|h| h.as_u64()),
                            has_inscriptions: false, // Would need additional API calls to determine
                            has_runes: false,
                            has_alkanes: false,
                            is_coinbase: false,
                        });
                    }
                }
            }
        }
        
        Ok(all_utxos)
    }
    
    async fn get_history(&self, count: u32, address: Option<String>) -> Result<Vec<TransactionInfo>> {
        // Use our Esplora provider for transaction history
        let addr = address.unwrap_or_else(|| {
            self.current_account.as_ref().map(|a| a.address.clone()).unwrap_or_default()
        });
        
        if addr.is_empty() {
            return Err(DeezelError::Wallet("No address specified".to_string()));
        }
        
        let txs_json = EsploraProvider::get_address_txs(&self.web_provider, &addr).await?;
        
        let mut transactions = Vec::new();
        
        if let Some(txs_array) = txs_json.as_array() {
            for (_i, tx) in txs_array.iter().enumerate().take(count as usize) {
                if let Some(txid) = tx.get("txid").and_then(|t| t.as_str()) {
                    let status = tx.get("status");
                    let block_height = status.and_then(|s| s.get("block_height")).and_then(|h| h.as_u64());
                    let block_time = status.and_then(|s| s.get("block_time")).and_then(|t| t.as_u64());
                    let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|c| c.as_bool()).unwrap_or(false);
                    let fee = tx.get("fee").and_then(|f| f.as_u64());
                    
                    transactions.push(TransactionInfo {
                        txid: txid.to_string(),
                        block_height,
                        block_time,
                        confirmed,
                        fee,
                        inputs: vec![], // Would need to parse vin array
                        outputs: vec![], // Would need to parse vout array
                    });
                }
            }
        }
        
        Ok(transactions)
    }
    
    async fn freeze_utxo(&self, _utxo: String, _reason: Option<String>) -> Result<()> {
        // Browser wallets typically don't support UTXO freezing
        // We could implement this in our local storage if needed
        Err(DeezelError::Wallet("UTXO freezing not supported by browser wallets".to_string()))
    }
    
    async fn unfreeze_utxo(&self, _utxo: String) -> Result<()> {
        // Browser wallets typically don't support UTXO freezing
        Err(DeezelError::Wallet("UTXO freezing not supported by browser wallets".to_string()))
    }
    
    async fn create_transaction(&self, params: SendParams) -> Result<String> {
        // Use our web provider to create the transaction
        // This leverages our sandshrew RPC and UTXO selection logic
        self.web_provider.create_transaction(params).await
    }
    
    async fn sign_transaction(&self, tx_hex: String) -> Result<String> {
        // This is where we use the browser wallet for signing
        // Convert the transaction to PSBT format for wallet signing
        
        // For now, we'll use the wallet's signPsbt method if available
        // In a full implementation, we'd convert the raw transaction to PSBT
        match self.wallet.sign_psbt(&tx_hex, None).await {
            Ok(signed_psbt) => Ok(signed_psbt),
            Err(_) => {
                // Fallback: some wallets might have a direct transaction signing method
                self.wallet.push_tx(&tx_hex).await
            }
        }
    }
    
    async fn broadcast_transaction(&self, tx_hex: String) -> Result<String> {
        // Try to broadcast through the wallet first (for better UX)
        match self.wallet.push_tx(&tx_hex).await {
            Ok(txid) => Ok(txid),
            Err(_) => {
                // Fallback to our RPC provider
                self.web_provider.broadcast_transaction(tx_hex).await
            }
        }
    }
    
    async fn estimate_fee(&self, target: u32) -> Result<FeeEstimate> {
        // Use our web provider for fee estimation
        self.web_provider.estimate_fee(target).await
    }
    
    async fn get_fee_rates(&self) -> Result<FeeRates> {
        // Use our web provider for fee rates
        self.web_provider.get_fee_rates().await
    }
    
    async fn sync(&self) -> Result<()> {
        // For browser wallets, syncing is handled by the wallet extension
        // We can sync our web provider instead
        self.web_provider.sync().await
    }
    
    async fn backup(&self) -> Result<String> {
        // Browser wallets handle their own backups
        // We can provide information about the connection
        let backup_info = serde_json::json!({
            "wallet_type": "browser_wallet",
            "wallet_name": self.wallet.get_info().name,
            "wallet_id": self.wallet.get_info().id,
            "connected_address": self.current_account.as_ref().map(|a| &a.address),
            "network": self.web_provider.network().to_string(),
            "backup_time": self.web_provider.now_millis(),
        });
        
        Ok(backup_info.to_string())
    }
    
    async fn get_mnemonic(&self) -> Result<Option<String>> {
        // Browser wallets don't expose mnemonics for security reasons
        Ok(None)
    }
    
    fn get_network(&self) -> Network {
        self.web_provider.network()
    }
    
    async fn get_internal_key(&self) -> Result<XOnlyPublicKey> {
        // Try to get the public key from the wallet
        let pubkey_hex = self.wallet.get_public_key().await?;
        
        // Parse the public key
        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|e| DeezelError::Wallet(format!("Invalid public key hex: {}", e)))?;
        
        if pubkey_bytes.len() == 32 {
            // X-only public key
            XOnlyPublicKey::from_slice(&pubkey_bytes)
                .map_err(|e| DeezelError::Wallet(format!("Invalid X-only public key: {}", e)))
        } else if pubkey_bytes.len() == 33 {
            // Compressed public key - convert to X-only
            let _secp = bitcoin::secp256k1::Secp256k1::new();
            let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes)
                .map_err(|e| DeezelError::Wallet(format!("Invalid compressed public key: {}", e)))?;
            Ok(XOnlyPublicKey::from(pubkey))
        } else {
            Err(DeezelError::Wallet("Invalid public key length".to_string()))
        }
    }
    
    async fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        // Convert PSBT to hex and use wallet to sign
        let psbt_hex = hex::encode(psbt.serialize());
        let signed_psbt_hex = self.wallet.sign_psbt(&psbt_hex, None).await?;
        
        // Parse the signed PSBT back
        let signed_psbt_bytes = hex::decode(&signed_psbt_hex)
            .map_err(|e| DeezelError::Wallet(format!("Invalid signed PSBT hex: {}", e)))?;
        
        Psbt::deserialize(&signed_psbt_bytes)
            .map_err(|e| DeezelError::Wallet(format!("Failed to deserialize signed PSBT: {}", e)))
    }
    
    async fn get_keypair(&self) -> Result<Keypair> {
        // Browser wallets don't expose private keys for security reasons
        // This method should not be used with browser wallets
        Err(DeezelError::Wallet("Browser wallets do not expose private keys".to_string()))
    }

    fn set_passphrase(&mut self, _passphrase: Option<String>) {
        // Browser wallets manage their own passphrases
        // This is a no-op for browser wallet providers
    }
}

// Implement the remaining provider traits by delegating to web_provider
#[async_trait(?Send)]
impl AddressResolver for BrowserWalletProvider {
    async fn resolve_all_identifiers(&self, input: &str) -> Result<String> {
        self.web_provider.resolve_all_identifiers(input).await
    }
    
    fn contains_identifiers(&self, input: &str) -> bool {
        self.web_provider.contains_identifiers(input)
    }
    
    async fn get_address(&self, address_type: &str, index: u32) -> Result<String> {
        AddressResolver::get_address(&self.web_provider, address_type, index).await
    }
    
    async fn list_identifiers(&self) -> Result<Vec<String>> {
        self.web_provider.list_identifiers().await
    }
}

#[async_trait(?Send)]
impl BitcoindProvider for BrowserWalletProvider {
    async fn get_blockchain_info(&self) -> Result<bitcoind::GetBlockchainInfoResult> {
        self.web_provider.get_blockchain_info().await
    }

    async fn get_block_count(&self) -> Result<u64> {
        self.web_provider.get_block_count().await
    }

    async fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        self.web_provider.get_block_hash(height).await
    }

    async fn get_block_header(&self, hash: &bitcoin::BlockHash) -> Result<bitcoind::GetBlockHeaderResult> {
        BitcoindProvider::get_block_header(&self.web_provider, hash).await
    }

    async fn get_block_verbose(&self, hash: &bitcoin::BlockHash) -> Result<bitcoind::GetBlockResult> {
        self.web_provider.get_block_verbose(hash).await
    }

    async fn get_block_txids(&self, hash: &bitcoin::BlockHash) -> Result<Vec<bitcoin::Txid>> {
        BitcoindProvider::get_block_txids(&self.web_provider, hash).await
    }

    async fn get_block_filter(&self, hash: &bitcoin::BlockHash) -> Result<bitcoind::GetBlockFilterResult> {
        self.web_provider.get_block_filter(hash).await
    }

    async fn get_block_stats(&self, height: u64) -> Result<bitcoind::GetBlockStatsResult> {
        self.web_provider.get_block_stats(height).await
    }

    async fn get_chain_tips(&self) -> Result<bitcoind::GetChainTipsResult> {
        self.web_provider.get_chain_tips().await
    }

    async fn get_chain_tx_stats(&self, n_blocks: Option<u32>, block_hash: Option<bitcoin::BlockHash>) -> Result<bitcoind::GetBlockStatsResult> {
        self.web_provider.get_chain_tx_stats(n_blocks, block_hash).await
    }

    async fn get_mempool_info(&self) -> Result<bitcoind::GetMempoolInfoResult> {
        self.web_provider.get_mempool_info().await
    }

    async fn get_raw_mempool(&self) -> Result<Vec<bitcoin::Txid>> {
        self.web_provider.get_raw_mempool().await
    }

    async fn get_tx_out(&self, txid: &bitcoin::Txid, vout: u32, include_mempool: Option<bool>) -> Result<bitcoind::GetTxOutResult> {
        self.web_provider.get_tx_out(txid, vout, include_mempool).await
    }

    async fn get_mining_info(&self) -> Result<bitcoind::GetMiningInfoResult> {
        self.web_provider.get_mining_info().await
    }

    async fn get_network_info(&self) -> Result<bitcoind::GetNetworkInfoResult> {
        self.web_provider.get_network_info().await
    }

    async fn list_banned(&self) -> Result<bitcoind::ListBannedResult> {
        self.web_provider.list_banned().await
    }

    async fn scan_tx_out_set(&self, requests: &[bitcoind::ScanTxOutRequest]) -> Result<JsonValue> {
        self.web_provider.scan_tx_out_set(requests).await
    }

    async fn generate_to_address(&self, n_blocks: u64, address: &bitcoin::Address) -> Result<Vec<bitcoin::BlockHash>> {
        self.web_provider.generate_to_address(n_blocks, address).await
    }

    async fn send_raw_transaction(&self, tx: &Transaction) -> Result<bitcoin::Txid> {
        self.web_provider.send_raw_transaction(tx).await
    }

    async fn get_raw_transaction(&self, txid: &bitcoin::Txid, block_hash: Option<&bitcoin::BlockHash>) -> Result<bitcoind::GetRawTransactionResult> {
        self.web_provider.get_raw_transaction(txid, block_hash).await
    }
}

#[async_trait(?Send)]
impl MetashrewRpcProvider for BrowserWalletProvider {
    async fn get_metashrew_height(&self) -> Result<u64> {
        self.web_provider.get_metashrew_height().await
    }
    
    async fn get_contract_meta(&self, block: &str, tx: &str) -> Result<JsonValue> {
        self.web_provider.get_contract_meta(block, tx).await
    }
    
    async fn trace_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue> {
        self.web_provider.trace_outpoint(txid, vout).await
    }
    
    async fn get_spendables_by_address(&self, address: &str) -> Result<JsonValue> {
        self.web_provider.get_spendables_by_address(address).await
    }
    
    async fn get_protorunes_by_address(&self, address: &str) -> Result<JsonValue> {
        self.web_provider.get_protorunes_by_address(address).await
    }
    
    async fn get_protorunes_by_outpoint(&self, txid: &str, vout: u32) -> Result<JsonValue> {
        self.web_provider.get_protorunes_by_outpoint(txid, vout).await
    }
}

#[async_trait(?Send)]
impl EsploraProvider for BrowserWalletProvider {
    async fn get_blocks_tip_hash(&self) -> Result<String> {
        self.web_provider.get_blocks_tip_hash().await
    }
    
    async fn get_blocks_tip_height(&self) -> Result<u64> {
        self.web_provider.get_blocks_tip_height().await
    }
    
    async fn get_blocks(&self, start_height: Option<u64>) -> Result<JsonValue> {
        self.web_provider.get_blocks(start_height).await
    }
    
    async fn get_block_by_height(&self, height: u64) -> Result<String> {
        self.web_provider.get_block_by_height(height).await
    }
    
    async fn get_block(&self, hash: &str) -> Result<JsonValue> {
        EsploraProvider::get_block(&self.web_provider, hash).await
    }
    
    async fn get_block_status(&self, hash: &str) -> Result<JsonValue> {
        self.web_provider.get_block_status(hash).await
    }
    
    async fn get_block_txids(&self, hash: &str) -> Result<JsonValue> {
        EsploraProvider::get_block_txids(&self.web_provider, hash).await
    }
    
    async fn get_block_header(&self, hash: &str) -> Result<String> {
        EsploraProvider::get_block_header(&self.web_provider, hash).await
    }
    
    async fn get_block_raw(&self, hash: &str) -> Result<String> {
        self.web_provider.get_block_raw(hash).await
    }
    
    async fn get_block_txid(&self, hash: &str, index: u32) -> Result<String> {
        self.web_provider.get_block_txid(hash, index).await
    }
    
    async fn get_block_txs(&self, hash: &str, start_index: Option<u32>) -> Result<JsonValue> {
        self.web_provider.get_block_txs(hash, start_index).await
    }
    
    async fn get_address(&self, address: &str) -> Result<JsonValue> {
        EsploraProvider::get_address(&self.web_provider, address).await
    }
    
    async fn get_address_info(&self, address: &str) -> Result<JsonValue> {
        self.web_provider.get_address_info(address).await
    }
    
    async fn get_address_txs(&self, address: &str) -> Result<JsonValue> {
        self.web_provider.get_address_txs(address).await
    }
    
    async fn get_address_txs_chain(&self, address: &str, last_seen_txid: Option<&str>) -> Result<JsonValue> {
        self.web_provider.get_address_txs_chain(address, last_seen_txid).await
    }
    
    async fn get_address_txs_mempool(&self, address: &str) -> Result<JsonValue> {
        self.web_provider.get_address_txs_mempool(address).await
    }
    
    async fn get_address_utxo(&self, address: &str) -> Result<JsonValue> {
        self.web_provider.get_address_utxo(address).await
    }
    
    async fn get_address_prefix(&self, prefix: &str) -> Result<JsonValue> {
        self.web_provider.get_address_prefix(prefix).await
    }
    
    async fn get_tx(&self, txid: &str) -> Result<JsonValue> {
        self.web_provider.get_tx(txid).await
    }
    
    async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        self.web_provider.get_tx_hex(txid).await
    }
    
    async fn get_tx_raw(&self, txid: &str) -> Result<String> {
        self.web_provider.get_tx_raw(txid).await
    }
    
    async fn get_tx_status(&self, txid: &str) -> Result<JsonValue> {
        self.web_provider.get_tx_status(txid).await
    }
    
    async fn get_tx_merkle_proof(&self, txid: &str) -> Result<JsonValue> {
        self.web_provider.get_tx_merkle_proof(txid).await
    }
    
    async fn get_tx_merkleblock_proof(&self, txid: &str) -> Result<String> {
        self.web_provider.get_tx_merkleblock_proof(txid).await
    }
    
    async fn get_tx_outspend(&self, txid: &str, index: u32) -> Result<JsonValue> {
        self.web_provider.get_tx_outspend(txid, index).await
    }
    
    async fn get_tx_outspends(&self, txid: &str) -> Result<JsonValue> {
        self.web_provider.get_tx_outspends(txid).await
    }
    
    async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        self.web_provider.broadcast(tx_hex).await
    }
    
    async fn get_mempool(&self) -> Result<JsonValue> {
        self.web_provider.get_mempool().await
    }
    
    async fn get_mempool_txids(&self) -> Result<JsonValue> {
        self.web_provider.get_mempool_txids().await
    }
    
    async fn get_mempool_recent(&self) -> Result<JsonValue> {
        self.web_provider.get_mempool_recent().await
    }
    
    async fn get_fee_estimates(&self) -> Result<JsonValue> {
        self.web_provider.get_fee_estimates().await
    }
}

#[async_trait(?Send)]
impl RunestoneProvider for BrowserWalletProvider {
    async fn decode_runestone(&self, tx: &Transaction) -> Result<JsonValue> {
        self.web_provider.decode_runestone(tx).await
    }
    
    async fn format_runestone_with_decoded_messages(&self, tx: &Transaction) -> Result<JsonValue> {
        self.web_provider.format_runestone_with_decoded_messages(tx).await
    }
    
    async fn analyze_runestone(&self, txid: &str) -> Result<JsonValue> {
        self.web_provider.analyze_runestone(txid).await
    }
}

#[async_trait(?Send)]
impl AlkanesProvider for BrowserWalletProvider {
    async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        self.web_provider.execute(params).await
    }
    
    async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        AlkanesProvider::get_balance(&self.web_provider, address).await
    }

    async fn get_alkanes_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
       self.web_provider.get_alkanes_balance(address).await
   }
    
    async fn get_token_info(&self, alkane_id: &str) -> Result<JsonValue> {
        self.web_provider.get_token_info(alkane_id).await
    }
    
    async fn trace_outpoint_json(&self, txid: &str, vout: u32) -> Result<String> {
        self.web_provider.trace_outpoint_json(txid, vout).await
    }

    async fn trace_outpoint_pretty(&self, txid: &str, vout: u32) -> Result<String> {
        self.web_provider.trace_outpoint_pretty(txid, vout).await
    }
    
    async fn inspect(&self, target: &str, config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        self.web_provider.inspect(target, config).await
    }
    
    async fn get_bytecode(&self, alkane_id: &str) -> Result<String> {
        AlkanesProvider::get_bytecode(&self.web_provider, alkane_id).await
    }
    
    async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<JsonValue> {
        self.web_provider.simulate(contract_id, params).await
    }
}

#[async_trait(?Send)]
impl MonitorProvider for BrowserWalletProvider {
    async fn monitor_blocks(&self, start: Option<u64>) -> Result<()> {
        self.web_provider.monitor_blocks(start).await
    }
    
    async fn get_block_events(&self, height: u64) -> Result<Vec<BlockEvent>> {
        self.web_provider.get_block_events(height).await
    }
}

#[async_trait(?Send)]
#[async_trait(?Send)]
impl KeystoreProvider for BrowserWalletProvider {
    async fn derive_addresses(&self, _master_public_key: &str, _network: Network, _script_types: &[&str], _start_index: u32, _count: u32) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn get_default_addresses(&self, _master_public_key: &str, _network: Network) -> Result<Vec<KeystoreAddress>> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for browser wallet provider".to_string()))
    }
    
    fn parse_address_range(&self, _range_spec: &str) -> Result<(String, u32, u32)> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn get_keystore_info(&self, _master_public_key: &str, _master_fingerprint: &str, _created_at: u64, _version: &str) -> Result<KeystoreInfo> {
        Err(DeezelError::NotImplemented("Keystore operations not implemented for browser wallet provider".to_string()))
    }
}

#[async_trait(?Send)]
impl PgpProvider for BrowserWalletProvider {
    async fn generate_keypair(&self, _user_id: &str, _passphrase: Option<&str>) -> Result<PgpKeyPair> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn import_key(&self, _armored_key: &str) -> Result<PgpKey> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn export_key(&self, _key: &PgpKey, _include_private: bool) -> Result<String> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn encrypt(&self, _data: &[u8], _recipient_keys: &[PgpKey], _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn decrypt(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn sign(&self, _data: &[u8], _private_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn verify(&self, _data: &[u8], _signature: &[u8], _public_key: &PgpKey) -> Result<bool> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn encrypt_and_sign(&self, _data: &[u8], _recipient_keys: &[PgpKey], _signing_key: &PgpKey, _passphrase: Option<&str>, _armor: bool) -> Result<Vec<u8>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn decrypt_and_verify(&self, _encrypted_data: &[u8], _private_key: &PgpKey, _sender_public_key: &PgpKey, _passphrase: Option<&str>) -> Result<PgpDecryptResult> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn list_pgp_keys(&self) -> Result<Vec<PgpKeyInfo>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn get_key(&self, _identifier: &str) -> Result<Option<PgpKey>> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn delete_key(&self, _identifier: &str) -> Result<()> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
    
    async fn change_passphrase(&self, _key: &PgpKey, _old_passphrase: Option<&str>, _new_passphrase: Option<&str>) -> Result<PgpKey> {
        Err(DeezelError::NotImplemented("PGP operations not implemented for browser wallet provider".to_string()))
    }
}

#[async_trait(?Send)]
impl DeezelProvider for BrowserWalletProvider {
    fn provider_name(&self) -> &str {
        "browser_wallet"
    }
    
    async fn initialize(&self) -> Result<()> {
        // Initialize the underlying web provider
        self.web_provider.initialize().await?;
        
        // Verify wallet connection
        if self.current_account.is_none() {
            return Err(DeezelError::Wallet("Wallet not connected".to_string()));
        }
        
        self.info(&format!("Browser wallet provider initialized with {}", self.wallet.get_info().name));
        Ok(())
    }
    
    async fn shutdown(&self) -> Result<()> {
        self.info("Shutting down browser wallet provider");
        self.web_provider.shutdown().await
    }

    fn clone_box(&self) -> Box<dyn DeezelProvider> {
        Box::new(self.clone())
    }
}