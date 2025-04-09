//! Network parameters for different Bitcoin networks
//!
//! This module provides functionality for configuring network parameters
//! for different Bitcoin networks, including custom networks.

use bdk::bitcoin::Network;

/// Network parameters for address encoding
#[derive(Clone, Debug)]
pub struct NetworkParams {
    /// Bech32 prefix (e.g., "bc" for mainnet, "tb" for testnet)
    pub bech32_prefix: String,
    /// P2PKH address prefix (e.g., 0x00 for mainnet, 0x6f for testnet)
    pub p2pkh_prefix: u8,
    /// P2SH address prefix (e.g., 0x05 for mainnet, 0xc4 for testnet)
    pub p2sh_prefix: u8,
    /// Bitcoin network (mainnet, testnet, regtest)
    pub network: Network,
}

impl NetworkParams {
    /// Create network parameters for mainnet
    pub fn mainnet() -> Self {
        Self {
            bech32_prefix: String::from("bc"),
            p2pkh_prefix: 0x00,
            p2sh_prefix: 0x05,
            network: Network::Bitcoin,
        }
    }

    /// Create network parameters for testnet
    pub fn testnet() -> Self {
        Self {
            bech32_prefix: String::from("tb"),
            p2pkh_prefix: 0x6f,
            p2sh_prefix: 0xc4,
            network: Network::Testnet,
        }
    }

    /// Create network parameters for regtest
    pub fn regtest() -> Self {
        Self {
            bech32_prefix: String::from("bcrt"),
            p2pkh_prefix: 0x64,
            p2sh_prefix: 0xc4,
            network: Network::Regtest,
        }
    }

    /// Create network parameters from a magic string
    /// Format: "p2sh_prefix:p2pkh_prefix:bech32_prefix"
    /// Example: "05:00:bc" for mainnet
    pub fn from_magic(magic: &str) -> Result<Self, String> {
        let parts: Vec<&str> = magic.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("Invalid magic format. Expected 'p2sh_prefix:p2pkh_prefix:bech32_prefix', got '{}'", magic));
        }

        let p2sh_prefix = u8::from_str_radix(parts[0], 16)
            .map_err(|_| format!("Invalid p2sh_prefix: {}", parts[0]))?;
        
        let p2pkh_prefix = u8::from_str_radix(parts[1], 16)
            .map_err(|_| format!("Invalid p2pkh_prefix: {}", parts[1]))?;
        
        let bech32_prefix = parts[2].to_string();
        
        // Default to Bitcoin network for custom magic values
        Ok(Self {
            bech32_prefix,
            p2pkh_prefix,
            p2sh_prefix,
            network: Network::Bitcoin,
        })
    }

    /// Get the network parameters for a given provider preset
    pub fn from_provider(provider: &str) -> Result<Self, String> {
        match provider {
            "mainnet" => Ok(Self::mainnet()),
            "testnet" | "signet" => Ok(Self::testnet()),
            "regtest" | "localhost" => Ok(Self::regtest()),
            _ => Err(format!("Unknown provider: {}", provider)),
        }
    }
}

/// Get the RPC URL for a given provider preset
pub fn get_rpc_url(provider: &str) -> String {
    match provider {
        "mainnet" => "https://mainnet.sandshrew.io/v2/lasereyes".to_string(),
        "signet" | "testnet" => "https://signet.sandshrew.io/v2/lasereyes".to_string(),
        "localhost" | "regtest" => "http://localhost:18888".to_string(),
        url if url.starts_with("http://") || url.starts_with("https://") => url.to_string(),
        _ => "https://mainnet.sandshrew.io/v2/lasereyes".to_string(),
    }
}