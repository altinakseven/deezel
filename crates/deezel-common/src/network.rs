//! Network configuration and parameters
//!
//! This module provides network configuration for different Bitcoin networks
//! including mainnet, testnet, signet, regtest, and custom networks.

use crate::{Result, DeezelError};
use alloc::{string::ToString, format};
use bitcoin::Network;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use alloc::vec;

#[cfg(not(target_arch = "wasm32"))]
use std::string::String;
#[cfg(target_arch = "wasm32")]
use alloc::string::String;

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use alloc::collections::BTreeMap as HashMap;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct NetworkParams {
    pub network: Network,
    pub magic: u32,
    pub bech32_prefix: String,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub bitcoin_rpc_url: String,
    pub metashrew_rpc_url: String,
    pub esplora_url: Option<String>,
    pub custom_params: HashMap<String, String>,
}

/// Serde module for Network
mod network_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(dead_code)]
    pub fn serialize<S>(network: &Network, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let network_str = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown", // Handle non-exhaustive enum
        };
        serializer.serialize_str(network_str)
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(serde::de::Error::custom(format!("Unknown network: {s}"))),
        }
    }
}

impl Serialize for NetworkParams {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("NetworkParams", 9)?;
        
        let network_str = match self.network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        };
        state.serialize_field("network", network_str)?;
        state.serialize_field("magic", &self.magic)?;
        state.serialize_field("bech32_prefix", &self.bech32_prefix)?;
        state.serialize_field("p2pkh_prefix", &self.p2pkh_prefix)?;
        state.serialize_field("p2sh_prefix", &self.p2sh_prefix)?;
        state.serialize_field("bitcoin_rpc_url", &self.bitcoin_rpc_url)?;
        state.serialize_field("metashrew_rpc_url", &self.metashrew_rpc_url)?;
        state.serialize_field("esplora_url", &self.esplora_url)?;
        state.serialize_field("custom_params", &self.custom_params)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for NetworkParams {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Network,
            Magic,
            Bech32Prefix,
            P2pkhPrefix,
            P2shPrefix,
            BitcoinRpcUrl,
            MetashrewRpcUrl,
            EsploraUrl,
            CustomParams,
        }

        struct NetworkParamsVisitor;

        impl<'de> serde::de::Visitor<'de> for NetworkParamsVisitor {
            type Value = NetworkParams;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct NetworkParams")
            }

            fn visit_map<V>(self, mut map: V) -> core::result::Result<NetworkParams, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut network = None;
                let mut magic = None;
                let mut bech32_prefix = None;
                let mut p2pkh_prefix = None;
                let mut p2sh_prefix = None;
                let mut bitcoin_rpc_url = None;
                let mut metashrew_rpc_url = None;
                let mut esplora_url = None;
                let mut custom_params = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Network => {
                            if network.is_some() {
                                return Err(serde::de::Error::duplicate_field("network"));
                            }
                            let network_str: String = map.next_value()?;
                            network = Some(match network_str.as_str() {
                                "mainnet" => Network::Bitcoin,
                                "testnet" => Network::Testnet,
                                "signet" => Network::Signet,
                                "regtest" => Network::Regtest,
                                _ => return Err(serde::de::Error::custom(format!("Unknown network: {network_str}"))),
                            });
                        }
                        Field::Magic => {
                            if magic.is_some() {
                                return Err(serde::de::Error::duplicate_field("magic"));
                            }
                            magic = Some(map.next_value()?);
                        }
                        Field::Bech32Prefix => {
                            if bech32_prefix.is_some() {
                                return Err(serde::de::Error::duplicate_field("bech32_prefix"));
                            }
                            bech32_prefix = Some(map.next_value()?);
                        }
                        Field::P2pkhPrefix => {
                            if p2pkh_prefix.is_some() {
                                return Err(serde::de::Error::duplicate_field("p2pkh_prefix"));
                            }
                            p2pkh_prefix = Some(map.next_value()?);
                        }
                        Field::P2shPrefix => {
                            if p2sh_prefix.is_some() {
                                return Err(serde::de::Error::duplicate_field("p2sh_prefix"));
                            }
                            p2sh_prefix = Some(map.next_value()?);
                        }
                        Field::BitcoinRpcUrl => {
                            if bitcoin_rpc_url.is_some() {
                                return Err(serde::de::Error::duplicate_field("bitcoin_rpc_url"));
                            }
                            bitcoin_rpc_url = Some(map.next_value()?);
                        }
                        Field::MetashrewRpcUrl => {
                            if metashrew_rpc_url.is_some() {
                                return Err(serde::de::Error::duplicate_field("metashrew_rpc_url"));
                            }
                            metashrew_rpc_url = Some(map.next_value()?);
                        }
                        Field::EsploraUrl => {
                            if esplora_url.is_some() {
                                return Err(serde::de::Error::duplicate_field("esplora_url"));
                            }
                            esplora_url = Some(map.next_value()?);
                        }
                        Field::CustomParams => {
                            if custom_params.is_some() {
                                return Err(serde::de::Error::duplicate_field("custom_params"));
                            }
                            custom_params = Some(map.next_value()?);
                        }
                    }
                }

                let network = network.ok_or_else(|| serde::de::Error::missing_field("network"))?;
                let magic = magic.ok_or_else(|| serde::de::Error::missing_field("magic"))?;
                let bech32_prefix = bech32_prefix.ok_or_else(|| serde::de::Error::missing_field("bech32_prefix"))?;
                let p2pkh_prefix = p2pkh_prefix.ok_or_else(|| serde::de::Error::missing_field("p2pkh_prefix"))?;
                let p2sh_prefix = p2sh_prefix.ok_or_else(|| serde::de::Error::missing_field("p2sh_prefix"))?;
                let bitcoin_rpc_url = bitcoin_rpc_url.ok_or_else(|| serde::de::Error::missing_field("bitcoin_rpc_url"))?;
                let metashrew_rpc_url = metashrew_rpc_url.ok_or_else(|| serde::de::Error::missing_field("metashrew_rpc_url"))?;
                let esplora_url = esplora_url.unwrap_or(None);
                let custom_params = custom_params.unwrap_or_else(HashMap::new);

                Ok(NetworkParams {
                    network,
                    magic,
                    bech32_prefix,
                    p2pkh_prefix,
                    p2sh_prefix,
                    bitcoin_rpc_url,
                    metashrew_rpc_url,
                    esplora_url,
                    custom_params,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "network",
            "magic", 
            "bech32_prefix",
            "p2pkh_prefix",
            "p2sh_prefix",
            "bitcoin_rpc_url",
            "metashrew_rpc_url",
            "esplora_url",
            "custom_params",
        ];
        deserializer.deserialize_struct("NetworkParams", FIELDS, NetworkParamsVisitor)
    }
}

impl NetworkParams {
    /// Create network parameters for Bitcoin mainnet
    pub fn mainnet() -> Self {
        Self {
            network: Network::Bitcoin,
            magic: 0xd9b4bef9,
            bech32_prefix: "bc".to_string(),
            p2pkh_prefix: 0x00,
            p2sh_prefix: 0x05,
            bitcoin_rpc_url: "http://bitcoinrpc:bitcoinrpc@localhost:8332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: Some("https://blockstream.info/api".to_string()),
            custom_params: HashMap::new(),
        }
    }
    
    /// Create network parameters for Bitcoin testnet
    pub fn testnet() -> Self {
        Self {
            network: Network::Testnet,
            magic: 0x0709110b,
            bech32_prefix: "tb".to_string(),
            p2pkh_prefix: 0x6f,
            p2sh_prefix: 0xc4,
            bitcoin_rpc_url: "http://bitcoinrpc:bitcoinrpc@localhost:18332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: Some("https://blockstream.info/testnet/api".to_string()),
            custom_params: HashMap::new(),
        }
    }
    
    /// Create network parameters for Bitcoin signet
    pub fn signet() -> Self {
        Self {
            network: Network::Signet,
            magic: 0x40cf030a,
            bech32_prefix: "tb".to_string(),
            p2pkh_prefix: 0x6f,
            p2sh_prefix: 0xc4,
            bitcoin_rpc_url: "http://bitcoinrpc:bitcoinrpc@localhost:38332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: Some("https://mempool.space/signet/api".to_string()),
            custom_params: HashMap::new(),
        }
    }
    
    /// Create network parameters for Bitcoin regtest
    pub fn regtest() -> Self {
        Self {
            network: Network::Regtest,
            magic: 0xdab5bffa,
            bech32_prefix: "bcrt".to_string(),
            p2pkh_prefix: 0x6f,
            p2sh_prefix: 0xc4,
            bitcoin_rpc_url: "http://bitcoinrpc:bitcoinrpc@localhost:18443".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: None,
            custom_params: HashMap::new(),
        }
    }
    
    /// Create network parameters for Dogecoin
    pub fn dogecoin() -> Self {
        Self {
            network: Network::Bitcoin, // Use Bitcoin network type for compatibility
            magic: 0xc0c0c0c0, // Dogecoin magic bytes
            bech32_prefix: "dc".to_string(),
            p2pkh_prefix: 0x1e,
            p2sh_prefix: 0x16,
            bitcoin_rpc_url: "http://dogeuser:dogepass@localhost:22555".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: None,
            custom_params: HashMap::new(),
        }
    }
    
    /// Create network parameters for Luckycoin
    pub fn luckycoin() -> Self {
        Self {
            network: Network::Bitcoin, // Use Bitcoin network type for compatibility
            magic: 0xfbc0b6db, // Luckycoin magic bytes
            bech32_prefix: "lky".to_string(),
            p2pkh_prefix: 0x2f,
            p2sh_prefix: 0x05,
            bitcoin_rpc_url: "http://luckyuser:luckypass@localhost:9332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: None,
            custom_params: HashMap::new(),
        }
    }
    
    /// Create network parameters for Bellscoin
    pub fn bellscoin() -> Self {
        Self {
            network: Network::Bitcoin, // Use Bitcoin network type for compatibility
            magic: 0xbeb4d9f9, // Bellscoin magic bytes
            bech32_prefix: "bel".to_string(),
            p2pkh_prefix: 0x19,
            p2sh_prefix: 0x05,
            bitcoin_rpc_url: "http://belluser:bellpass@localhost:19332".to_string(),
            metashrew_rpc_url: "http://localhost:8080".to_string(),
            esplora_url: None,
            custom_params: HashMap::new(),
        }
    }
    
    /// Create custom network parameters
    pub fn custom(
        network: Network,
        magic: u32,
        bech32_prefix: String,
        p2pkh_prefix: u8,
        p2sh_prefix: u8,
        bitcoin_rpc_url: String,
        metashrew_rpc_url: String,
    ) -> Self {
        Self {
            network,
            magic,
            bech32_prefix,
            p2pkh_prefix,
            p2sh_prefix,
            bitcoin_rpc_url,
            metashrew_rpc_url,
            esplora_url: None,
            custom_params: HashMap::new(),
        }
    }
    
    /// Get network from string
    pub fn from_network_str(network_str: &str) -> Result<Self> {
        match network_str.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Ok(Self::mainnet()),
            "testnet" => Ok(Self::testnet()),
            "signet" => Ok(Self::signet()),
            "regtest" => Ok(Self::regtest()),
            "dogecoin" | "doge" => Ok(Self::dogecoin()),
            "luckycoin" | "lucky" => Ok(Self::luckycoin()),
            "bellscoin" | "bells" => Ok(Self::bellscoin()),
            _ => Err(DeezelError::Parse(format!("Unknown network: {network_str}"))),
        }
    }
    
    /// Parse custom magic bytes from string format "bech32_hrp:p2pkh_prefix:p2sh_prefix" or "p2pkh_prefix,p2sh_prefix,bech32_hrp"
    pub fn from_magic_str(magic_str: &str) -> Result<(u8, u8, String)> {
        // Support both formats: "tb:6f:c4" and "0x6f,0xc4,tb"
        let parts: Vec<&str> = if magic_str.contains(':') {
            magic_str.split(':').collect()
        } else {
            magic_str.split(',').collect()
        };
        
        if parts.len() != 3 {
            return Err(DeezelError::Parse(
                "Magic bytes must be in format: bech32_hrp:p2pkh_prefix:p2sh_prefix (e.g., 'tb:6f:c4') or p2pkh_prefix,p2sh_prefix,bech32_hrp (e.g., '0x6f,0xc4,tb')".to_string()
            ));
        }
        
        let (p2pkh_prefix, p2sh_prefix, bech32_hrp) = if magic_str.contains(':') {
            // New format: "tb:6f:c4"
            let bech32_hrp = parts[0].trim().to_string();
            if bech32_hrp.is_empty() {
                return Err(DeezelError::Parse("Bech32 HRP cannot be empty".to_string()));
            }
            
            let p2pkh_prefix = u8::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                .map_err(|_| DeezelError::Parse(format!("Invalid p2pkh prefix: {}", parts[1])))?;
            
            let p2sh_prefix = u8::from_str_radix(parts[2].trim_start_matches("0x"), 16)
                .map_err(|_| DeezelError::Parse(format!("Invalid p2sh prefix: {}", parts[2])))?;
            
            (p2pkh_prefix, p2sh_prefix, bech32_hrp)
        } else {
            // Legacy format: "0x6f,0xc4,tb"
            let p2pkh_prefix = u8::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                .map_err(|_| DeezelError::Parse(format!("Invalid p2pkh prefix: {}", parts[0])))?;
            
            let p2sh_prefix = u8::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                .map_err(|_| DeezelError::Parse(format!("Invalid p2sh prefix: {}", parts[1])))?;
            
            let bech32_hrp = parts[2].trim().to_string();
            if bech32_hrp.is_empty() {
                return Err(DeezelError::Parse("Bech32 HRP cannot be empty".to_string()));
            }
            
            (p2pkh_prefix, p2sh_prefix, bech32_hrp)
        };
        
        Ok((p2pkh_prefix, p2sh_prefix, bech32_hrp))
    }
    
    /// Create network parameters with custom magic bytes
    pub fn with_custom_magic(
        base_network: Network,
        p2pkh_prefix: u8,
        p2sh_prefix: u8,
        bech32_prefix: String,
    ) -> Self {
        let mut params = match base_network {
            Network::Bitcoin => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Signet => Self::signet(),
            Network::Regtest => Self::regtest(),
            _ => Self::mainnet(),
        };
        
        params.p2pkh_prefix = p2pkh_prefix;
        params.p2sh_prefix = p2sh_prefix;
        params.bech32_prefix = bech32_prefix;
        
        params
    }
    
    /// Get all supported network names
    pub fn supported_networks() -> Vec<&'static str> {
        vec![
            "mainnet", "bitcoin",
            "testnet",
            "signet",
            "regtest",
            "dogecoin", "doge",
            "luckycoin", "lucky",
            "bellscoin", "bells",
        ]
    }
    
    /// Convert to protorune-support NetworkParams
    pub fn to_protorune_params(&self) -> protorune_support::network::NetworkParams {
        protorune_support::network::NetworkParams {
            bech32_prefix: self.bech32_prefix.clone(),
            p2pkh_prefix: self.p2pkh_prefix,
            p2sh_prefix: self.p2sh_prefix,
        }
    }
    
    /// Get network string representation
    pub fn network_str(&self) -> &'static str {
        match self.network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        }
    }
    
    /// Check if this is a test network
    pub fn is_testnet(&self) -> bool {
        matches!(self.network, Network::Testnet | Network::Signet | Network::Regtest)
    }
    
    /// Get default port for Bitcoin RPC
    pub fn default_rpc_port(&self) -> u16 {
        match self.network {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
            _ => 8332,
        }
    }
    
    /// Update Bitcoin RPC URL
    pub fn with_bitcoin_rpc_url(mut self, url: String) -> Self {
        self.bitcoin_rpc_url = url;
        self
    }
    
    /// Update Metashrew RPC URL
    pub fn with_metashrew_rpc_url(mut self, url: String) -> Self {
        self.metashrew_rpc_url = url;
        self
    }
    
    /// Update Esplora URL
    pub fn with_esplora_url(mut self, url: Option<String>) -> Self {
        self.esplora_url = url;
        self
    }
    
    /// Add custom parameter
    pub fn with_custom_param(mut self, key: String, value: String) -> Self {
        self.custom_params.insert(key, value);
        self
    }
}

impl Default for NetworkParams {
    fn default() -> Self {
        Self::mainnet()
    }
}

/// Network configuration manager
pub struct NetworkConfig {
    params: NetworkParams,
}

impl NetworkConfig {
    /// Create new network configuration
    pub fn new(params: NetworkParams) -> Self {
        Self { params }
    }
    
    /// Get network parameters
    pub fn params(&self) -> &NetworkParams {
        &self.params
    }
    
    /// Get mutable network parameters
    pub fn params_mut(&mut self) -> &mut NetworkParams {
        &mut self.params
    }
    
    /// Update network parameters
    pub fn update_params(&mut self, params: NetworkParams) {
        self.params = params;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_params_creation() {
        let mainnet = NetworkParams::mainnet();
        assert!(matches!(mainnet.network, Network::Bitcoin));
        assert_eq!(mainnet.magic, 0xd9b4bef9);
        assert_eq!(mainnet.bech32_prefix, "bc");
        
        let testnet = NetworkParams::testnet();
        assert!(matches!(testnet.network, Network::Testnet));
        assert_eq!(testnet.magic, 0x0709110b);
        assert_eq!(testnet.bech32_prefix, "tb");
    }
    
    #[test]
    fn test_network_from_string() {
        assert!(NetworkParams::from_network_str("mainnet").is_ok());
        assert!(NetworkParams::from_network_str("testnet").is_ok());
        assert!(NetworkParams::from_network_str("signet").is_ok());
        assert!(NetworkParams::from_network_str("regtest").is_ok());
        assert!(NetworkParams::from_network_str("dogecoin").is_ok());
        assert!(NetworkParams::from_network_str("luckycoin").is_ok());
        assert!(NetworkParams::from_network_str("bellscoin").is_ok());
        assert!(NetworkParams::from_network_str("invalid").is_err());
    }
    
    #[test]
    fn test_network_serialization() {
        let params = NetworkParams::mainnet();
        let serialized = serde_json::to_string(&params).unwrap();
        let deserialized: NetworkParams = serde_json::from_str(&serialized).unwrap();
        
        assert!(matches!(deserialized.network, Network::Bitcoin));
        assert_eq!(deserialized.magic, params.magic);
        assert_eq!(deserialized.bech32_prefix, params.bech32_prefix);
    }
    
    #[test]
    fn test_is_testnet() {
        assert!(!NetworkParams::mainnet().is_testnet());
        assert!(NetworkParams::testnet().is_testnet());
        assert!(NetworkParams::signet().is_testnet());
        assert!(NetworkParams::regtest().is_testnet());
    }
    
    #[test]
    fn test_default_rpc_ports() {
        assert_eq!(NetworkParams::mainnet().default_rpc_port(), 8332);
        assert_eq!(NetworkParams::testnet().default_rpc_port(), 18332);
        assert_eq!(NetworkParams::signet().default_rpc_port(), 38332);
        assert_eq!(NetworkParams::regtest().default_rpc_port(), 18443);
    }
    
    #[test]
    fn test_altcoin_networks() {
        let dogecoin = NetworkParams::dogecoin();
        assert_eq!(dogecoin.p2pkh_prefix, 0x1e);
        assert_eq!(dogecoin.p2sh_prefix, 0x16);
        assert_eq!(dogecoin.bech32_prefix, "dc");
        
        let luckycoin = NetworkParams::luckycoin();
        assert_eq!(luckycoin.p2pkh_prefix, 0x2f);
        assert_eq!(luckycoin.p2sh_prefix, 0x05);
        assert_eq!(luckycoin.bech32_prefix, "lky");
        
        let bellscoin = NetworkParams::bellscoin();
        assert_eq!(bellscoin.p2pkh_prefix, 0x19);
        assert_eq!(bellscoin.p2sh_prefix, 0x05);
        assert_eq!(bellscoin.bech32_prefix, "bel");
    }
    
    #[test]
    fn test_magic_bytes_parsing() {
        // Test legacy format: "p2pkh,p2sh,bech32"
        let result = NetworkParams::from_magic_str("0x00,0x05,bc");
        assert!(result.is_ok());
        let (p2pkh, p2sh, hrp) = result.unwrap();
        assert_eq!(p2pkh, 0x00);
        assert_eq!(p2sh, 0x05);
        assert_eq!(hrp, "bc");
        
        // Test without 0x prefix
        let result = NetworkParams::from_magic_str("6f,c4,tb");
        assert!(result.is_ok());
        let (p2pkh, p2sh, hrp) = result.unwrap();
        assert_eq!(p2pkh, 0x6f);
        assert_eq!(p2sh, 0xc4);
        assert_eq!(hrp, "tb");
        
        // Test new format: "bech32:p2pkh:p2sh"
        let result = NetworkParams::from_magic_str("tb:6f:c4");
        assert!(result.is_ok());
        let (p2pkh, p2sh, hrp) = result.unwrap();
        assert_eq!(p2pkh, 0x6f);
        assert_eq!(p2sh, 0xc4);
        assert_eq!(hrp, "tb");
        
        // Test dogecoin format
        let result = NetworkParams::from_magic_str("dc:1e:16");
        assert!(result.is_ok());
        let (p2pkh, p2sh, hrp) = result.unwrap();
        assert_eq!(p2pkh, 0x1e);
        assert_eq!(p2sh, 0x16);
        assert_eq!(hrp, "dc");
        
        // Test invalid format
        assert!(NetworkParams::from_magic_str("invalid").is_err());
        assert!(NetworkParams::from_magic_str("00,05").is_err());
        assert!(NetworkParams::from_magic_str("xx,05,bc").is_err());
        assert!(NetworkParams::from_magic_str("tb:xx:c4").is_err());
    }
    
    #[test]
    fn test_custom_magic_bytes() {
        let params = NetworkParams::with_custom_magic(
            Network::Bitcoin,
            0x1e,
            0x16,
            "dc".to_string()
        );
        assert_eq!(params.p2pkh_prefix, 0x1e);
        assert_eq!(params.p2sh_prefix, 0x16);
        assert_eq!(params.bech32_prefix, "dc");
        assert!(matches!(params.network, Network::Bitcoin));
    }
    
    #[test]
    fn test_supported_networks() {
        let networks = NetworkParams::supported_networks();
        assert!(networks.contains(&"mainnet"));
        assert!(networks.contains(&"dogecoin"));
        assert!(networks.contains(&"luckycoin"));
        assert!(networks.contains(&"bellscoin"));
    }
}