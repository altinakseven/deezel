//! Network parameters for different Bitcoin networks
//!
//! This module provides functionality for configuring network parameters
//! for different Bitcoin networks, including custom networks.

use bitcoin::Network;

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

    /// Create network parameters for signet (uses testnet address encoding)
    pub fn signet() -> Self {
        Self {
            bech32_prefix: String::from("tb"),
            p2pkh_prefix: 0x6f,
            p2sh_prefix: 0xc4,
            network: Network::Signet,
        }
    }

    /// Create network parameters for dogecoin
    pub fn dogecoin() -> Self {
        Self {
            bech32_prefix: String::from("dc"),
            p2pkh_prefix: 0x1e,
            p2sh_prefix: 0x16,
            network: Network::Bitcoin, // Use Bitcoin network type for BDK compatibility
        }
    }

    /// Create network parameters for luckycoin
    pub fn luckycoin() -> Self {
        Self {
            bech32_prefix: String::from("lky"),
            p2pkh_prefix: 0x2f,
            p2sh_prefix: 0x05,
            network: Network::Bitcoin, // Use Bitcoin network type for BDK compatibility
        }
    }

    /// Create network parameters for bellscoin
    pub fn bellscoin() -> Self {
        Self {
            bech32_prefix: String::from("bel"),
            p2pkh_prefix: 0x19,
            p2sh_prefix: 0x1e,
            network: Network::Bitcoin, // Use Bitcoin network type for BDK compatibility
        }
    }

    /// Create network parameters from a magic string or network name
    /// Supports both network names (mainnet, testnet, signet, regtest, dogecoin, luckycoin, bellscoin)
    /// and magic format: "p2sh_prefix:p2pkh_prefix:bech32_prefix"
    /// Example: "05:00:bc" for mainnet or just "mainnet"
    pub fn from_magic(magic: &str) -> Result<Self, String> {
        // First try to parse as a network name
        match magic.to_lowercase().as_str() {
            "mainnet" => Ok(Self::mainnet()),
            "testnet" => Ok(Self::testnet()),
            "signet" => Ok(Self::signet()),
            "regtest" => Ok(Self::regtest()),
            "dogecoin" | "doge" => Ok(Self::dogecoin()),
            "luckycoin" | "lucky" => Ok(Self::luckycoin()),
            "bellscoin" | "bells" => Ok(Self::bellscoin()),
            _ => {
                // If not a network name, try to parse as magic format
                let parts: Vec<&str> = magic.split(':').collect();
                if parts.len() != 3 {
                    return Err(format!(
                        "Invalid magic format. Expected network name (mainnet, testnet, signet, regtest, dogecoin, luckycoin, bellscoin) or 'p2sh_prefix:p2pkh_prefix:bech32_prefix', got '{}'",
                        magic
                    ));
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
        }
    }

    /// Convert to protorune_support::network::NetworkParams
    pub fn to_protorune_params(&self) -> protorune_support::network::NetworkParams {
        protorune_support::network::NetworkParams {
            p2pkh_prefix: self.p2pkh_prefix,
            p2sh_prefix: self.p2sh_prefix,
            bech32_prefix: self.bech32_prefix.clone(),
        }
    }

    /// Get the network parameters for a given provider preset
    pub fn from_provider(provider: &str) -> Result<Self, String> {
        match provider.to_lowercase().as_str() {
            "mainnet" => Ok(Self::mainnet()),
            "testnet" => Ok(Self::testnet()),
            "signet" => Ok(Self::signet()),
            "regtest" | "localhost" => Ok(Self::regtest()),
            "dogecoin" | "doge" => Ok(Self::dogecoin()),
            "luckycoin" | "lucky" => Ok(Self::luckycoin()),
            "bellscoin" | "bells" => Ok(Self::bellscoin()),
            _ => Err(format!("Unknown provider: {}. Supported networks: mainnet, testnet, signet, regtest, dogecoin, luckycoin, bellscoin", provider)),
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