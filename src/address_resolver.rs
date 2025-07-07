//! Address identifier resolution system for deezel CLI
//!
//! This module provides functionality to resolve special address identifiers like:
//! - [self:p2tr] - Taproot address from wallet
//! - [self:p2pkh] - Legacy P2PKH address from wallet
//! - [self:p2sh] - P2SH address from wallet
//! - [self:p2wpkh] - Native SegWit address from wallet
//! - [self:p2wsh] - Native SegWit script hash address from wallet
//! - [self:p2tr:0] - Indexed addresses (derivation index)
//! - [self:mainnet:p2tr] - Network-specific addresses

use anyhow::{Context, Result, anyhow};
use bitcoin::Network;
use log::{debug, warn};
use regex::Regex;
use std::str::FromStr;
use std::sync::Arc;

use crate::wallet::WalletManager;

/// Address type for identifier resolution
#[derive(Debug, Clone, PartialEq)]
pub enum AddressType {
    /// Legacy P2PKH address
    P2PKH,
    /// P2SH address
    P2SH,
    /// Native SegWit P2WPKH address
    P2WPKH,
    /// Native SegWit P2WSH address
    P2WSH,
    /// Taproot P2TR address
    P2TR,
}

impl FromStr for AddressType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "p2pkh" => Ok(AddressType::P2PKH),
            "p2sh" => Ok(AddressType::P2SH),
            "p2wpkh" => Ok(AddressType::P2WPKH),
            "p2wsh" => Ok(AddressType::P2WSH),
            "p2tr" => Ok(AddressType::P2TR),
            _ => Err(anyhow!("Unknown address type: {}", s)),
        }
    }
}

/// Address identifier components
#[derive(Debug, Clone)]
pub struct AddressIdentifier {
    /// Source of the address (e.g., "self")
    pub source: String,
    /// Network specification (optional)
    pub network: Option<Network>,
    /// Address type
    pub address_type: AddressType,
    /// Derivation index (optional)
    pub index: Option<u32>,
}

/// Address resolver for converting identifiers to actual Bitcoin addresses
pub struct AddressResolver {
    /// Wallet manager for generating addresses
    wallet_manager: Option<Arc<WalletManager>>,
}

impl AddressResolver {
    /// Create a new address resolver
    pub fn new() -> Self {
        Self {
            wallet_manager: None,
        }
    }

    /// Create a new address resolver with wallet manager
    pub fn with_wallet(wallet_manager: Arc<WalletManager>) -> Self {
        Self {
            wallet_manager: Some(wallet_manager),
        }
    }

    /// Set the wallet manager
    pub fn set_wallet(&mut self, wallet_manager: Arc<WalletManager>) {
        self.wallet_manager = Some(wallet_manager);
    }

    /// Check if a string contains address identifiers
    pub fn contains_identifiers(input: &str) -> bool {
        let re = Regex::new(r"\[self:[^\]]+\]").unwrap();
        re.is_match(input)
    }

    /// Parse an address identifier string
    pub fn parse_identifier(identifier: &str) -> Result<AddressIdentifier> {
        // Remove brackets
        let identifier = identifier.trim_start_matches('[').trim_end_matches(']');
        
        // Split by colons
        let parts: Vec<&str> = identifier.split(':').collect();
        
        if parts.len() < 2 {
            return Err(anyhow!("Invalid identifier format. Expected at least 'source:type'"));
        }

        let source = parts[0].to_string();
        if source != "self" {
            return Err(anyhow!("Only 'self' source is currently supported"));
        }

        // Parse the remaining parts to determine network, type, and index
        let mut network = None;
        let mut index = None;

        // Check different patterns:
        // [self:p2tr] -> source=self, type=p2tr
        // [self:p2tr:0] -> source=self, type=p2tr, index=0
        // [self:mainnet:p2tr] -> source=self, network=mainnet, type=p2tr
        // [self:mainnet:p2tr:0] -> source=self, network=mainnet, type=p2tr, index=0

        let mut remaining_parts = &parts[1..];

        // Check if the first remaining part is a network
        if remaining_parts.len() > 1 {
            if let Ok(net) = Self::parse_network(remaining_parts[0]) {
                network = Some(net);
                remaining_parts = &remaining_parts[1..];
            }
        }

        // Next part should be the address type
        if remaining_parts.is_empty() {
            return Err(anyhow!("Missing address type in identifier"));
        }

        let address_type = Some(AddressType::from_str(remaining_parts[0])?);
        remaining_parts = &remaining_parts[1..];

        // Check if there's an index
        if !remaining_parts.is_empty() {
            index = Some(remaining_parts[0].parse::<u32>()
                .context("Invalid index in identifier")?);
        }

        Ok(AddressIdentifier {
            source,
            network,
            address_type: address_type.unwrap(),
            index,
        })
    }

    /// Parse network string
    fn parse_network(network_str: &str) -> Result<Network> {
        match network_str.to_lowercase().as_str() {
            "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(anyhow!("Unknown network: {}", network_str)),
        }
    }

    /// Resolve an address identifier to a Bitcoin address
    pub async fn resolve_identifier(&self, identifier: &AddressIdentifier) -> Result<String> {
        match identifier.source.as_str() {
            "self" => self.resolve_self_address(identifier).await,
            _ => Err(anyhow!("Unsupported address source: {}", identifier.source)),
        }
    }

    /// Resolve a self-referencing address identifier
    async fn resolve_self_address(&self, identifier: &AddressIdentifier) -> Result<String> {
        let wallet_manager = self.wallet_manager.as_ref()
            .ok_or_else(|| anyhow!("No wallet manager available for self address resolution"))?;

        let index = identifier.index.unwrap_or(0);
        
        // Generate address based on type and index
        match identifier.address_type {
            AddressType::P2WPKH => {
                // This is the default address type used by the wallet
                if index == 0 {
                    wallet_manager.get_address().await
                } else {
                    self.generate_address_at_index(wallet_manager, &identifier.address_type, index).await
                }
            },
            AddressType::P2TR => {
                self.generate_address_at_index(wallet_manager, &identifier.address_type, index).await
            },
            AddressType::P2PKH => {
                self.generate_address_at_index(wallet_manager, &identifier.address_type, index).await
            },
            AddressType::P2SH => {
                self.generate_address_at_index(wallet_manager, &identifier.address_type, index).await
            },
            AddressType::P2WSH => {
                self.generate_address_at_index(wallet_manager, &identifier.address_type, index).await
            },
        }
    }

    /// Generate an address of a specific type at a specific index
    async fn generate_address_at_index(
        &self,
        wallet_manager: &WalletManager,
        address_type: &AddressType,
        index: u32,
    ) -> Result<String> {
        let address_type_str = match address_type {
            AddressType::P2PKH => "p2pkh",
            AddressType::P2SH => "p2sh",
            AddressType::P2WPKH => "p2wpkh",
            AddressType::P2WSH => {
                warn!("P2WSH address generation not yet implemented, returning P2WPKH address");
                "p2wpkh"
            },
            AddressType::P2TR => "p2tr",
        };
        
        wallet_manager.get_address_of_type_at_index(address_type_str, index, false).await
    }

    /// Resolve all address identifiers in a string
    pub async fn resolve_all_identifiers(&self, input: &str) -> Result<String> {
        let re = Regex::new(r"\[self:[^\]]+\]").unwrap();
        let mut result = input.to_string();
        
        // Find all matches
        let matches: Vec<_> = re.find_iter(input).collect();
        
        // Process matches in reverse order to avoid offset issues
        for mat in matches.iter().rev() {
            let identifier_str = mat.as_str();
            debug!("Resolving identifier: {}", identifier_str);
            
            match Self::parse_identifier(identifier_str) {
                Ok(identifier) => {
                    match self.resolve_identifier(&identifier).await {
                        Ok(address) => {
                            debug!("Resolved {} to {}", identifier_str, address);
                            result.replace_range(mat.range(), &address);
                        },
                        Err(e) => {
                            warn!("Failed to resolve identifier {}: {}", identifier_str, e);
                            return Err(anyhow!("Failed to resolve identifier {}: {}", identifier_str, e));
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to parse identifier {}: {}", identifier_str, e);
                    return Err(anyhow!("Failed to parse identifier {}: {}", identifier_str, e));
                }
            }
        }
        
        Ok(result)
    }

    /// Get a list of supported identifier patterns
    pub fn get_supported_patterns() -> Vec<String> {
        vec![
            "[self:p2tr]".to_string(),
            "[self:p2pkh]".to_string(),
            "[self:p2sh]".to_string(),
            "[self:p2wpkh]".to_string(),
            "[self:p2wsh]".to_string(),
            "[self:p2tr:0]".to_string(),
            "[self:p2tr:1]".to_string(),
            "[self:mainnet:p2tr]".to_string(),
            "[self:testnet:p2tr]".to_string(),
            "[self:regtest:p2tr]".to_string(),
            "[self:mainnet:p2tr:0]".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_identifier() {
        let identifier = AddressResolver::parse_identifier("[self:p2tr]").unwrap();
        assert_eq!(identifier.source, "self");
        assert_eq!(identifier.address_type, AddressType::P2TR);
        assert_eq!(identifier.network, None);
        assert_eq!(identifier.index, None);
    }

    #[test]
    fn test_parse_indexed_identifier() {
        let identifier = AddressResolver::parse_identifier("[self:p2tr:5]").unwrap();
        assert_eq!(identifier.source, "self");
        assert_eq!(identifier.address_type, AddressType::P2TR);
        assert_eq!(identifier.network, None);
        assert_eq!(identifier.index, Some(5));
    }

    #[test]
    fn test_parse_network_identifier() {
        let identifier = AddressResolver::parse_identifier("[self:mainnet:p2tr]").unwrap();
        assert_eq!(identifier.source, "self");
        assert_eq!(identifier.address_type, AddressType::P2TR);
        assert_eq!(identifier.network, Some(Network::Bitcoin));
        assert_eq!(identifier.index, None);
    }

    #[test]
    fn test_parse_full_identifier() {
        let identifier = AddressResolver::parse_identifier("[self:testnet:p2tr:3]").unwrap();
        assert_eq!(identifier.source, "self");
        assert_eq!(identifier.address_type, AddressType::P2TR);
        assert_eq!(identifier.network, Some(Network::Testnet));
        assert_eq!(identifier.index, Some(3));
    }

    #[test]
    fn test_contains_identifiers() {
        assert!(AddressResolver::contains_identifiers("Send to [self:p2tr]"));
        assert!(AddressResolver::contains_identifiers("[self:p2pkh] and [self:p2tr:1]"));
        assert!(!AddressResolver::contains_identifiers("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
    }

    #[test]
    fn test_address_type_parsing() {
        assert_eq!(AddressType::from_str("p2tr").unwrap(), AddressType::P2TR);
        assert_eq!(AddressType::from_str("P2TR").unwrap(), AddressType::P2TR);
        assert_eq!(AddressType::from_str("p2pkh").unwrap(), AddressType::P2PKH);
        assert_eq!(AddressType::from_str("p2wpkh").unwrap(), AddressType::P2WPKH);
        assert!(AddressType::from_str("invalid").is_err());
    }

    #[test]
    fn test_supported_patterns() {
        let patterns = AddressResolver::get_supported_patterns();
        assert!(patterns.contains(&"[self:p2tr]".to_string()));
        assert!(patterns.contains(&"[self:p2pkh]".to_string()));
        assert!(patterns.contains(&"[self:mainnet:p2tr]".to_string()));
    }
}