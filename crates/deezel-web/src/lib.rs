//! Deezel Web Library
//!
//! This library provides web-compatible implementations of deezel-common traits
//! using web-sys APIs for browser environments. It enables running deezel
//! functionality in web applications and WASM environments.
//!
//! ## Architecture
//!
//! The library implements all deezel-common traits using browser APIs:
//! - `JsonRpcProvider`: Uses fetch API for HTTP requests
//! - `StorageProvider`: Uses localStorage for persistent storage
//! - `NetworkProvider`: Uses fetch API for general HTTP operations
//! - `CryptoProvider`: Uses Web Crypto API for cryptographic operations
//! - `TimeProvider`: Uses Performance API for timing
//! - `LogProvider`: Uses console API for logging
//! - `WalletProvider`: Browser-compatible wallet operations
//! - All other providers: Web-compatible implementations
//!
//! ## Usage
//!
//! ```rust,no_run
//! use deezel_web::WebProvider;
//! use deezel_common::*;
//!
//! async fn example() -> Result<()> {
//!     // Create a web provider instance
//!     let provider = WebProvider::new(
//!         "http://localhost:8332".to_string(),
//!         "http://localhost:8080".to_string(),
//!         "regtest".to_string(),
//!     ).await?;
//!
//!     // Use any deezel-common functionality
//!     let balance = WalletProvider::get_balance(&provider).await?;
//!     Ok(())
//! }
//! ```

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
use alloc::{
    vec::Vec,
    boxed::Box,
    string::String,
    collections::BTreeMap,
    format,
    vec,
};

#[cfg(not(target_arch = "wasm32"))]
use std::{
    vec::Vec,
    boxed::Box,
    string::String,
    collections::HashMap as BTreeMap,
    format,
    vec,
};

// Re-export common types for WASM compatibility
pub use alloc::string::ToString;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Core modules
pub mod provider;
pub mod storage;
pub mod network;
pub mod crypto;
pub mod time;
pub mod logging;
pub mod utils;
pub mod wallet_provider;

// Provider trait implementations (included in provider module)
mod provider_traits;
mod provider_traits_extended;

// Re-export the main providers
pub use provider::WebProvider;
pub use wallet_provider::{BrowserWalletProvider, WalletConnector, WalletInfo, WalletBackend, InjectedWallet};


// Re-export deezel-common for convenience
pub use deezel_common::*;

/// Initialize the web library
///
/// This sets up panic hooks and other WASM-specific initialization
#[wasm_bindgen(start)]
pub fn init() {
    // Set up better panic messages in debug mode
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    // Initialize logging
    #[cfg(target_arch = "wasm32")]
    {
        use log::Level;
        console_log::init_with_level(Level::Info).expect("Failed to initialize logger");
    }
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Utility functions for web environments
pub mod prelude {
    pub use crate::provider::WebProvider;
    pub use deezel_common::prelude::*;
    pub use wasm_bindgen::prelude::*;
    pub use web_sys;
    pub use js_sys;
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert_eq!(NAME, "deezel-web");
    }

    #[wasm_bindgen_test]
    async fn test_web_provider_creation() {
        let provider = WebProvider::new(
            "http://localhost:8332".to_string(),
            "http://localhost:8080".to_string(),
            "regtest".to_string(),
        ).await;
        
        assert!(provider.is_ok());
    }
}