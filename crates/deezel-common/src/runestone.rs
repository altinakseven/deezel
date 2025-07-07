//! Runestone analysis and decoding functionality
//!
//! This module provides comprehensive runestone functionality including:
//! - Runestone decoding from transactions
//! - Message formatting and analysis
//! - Protostone analysis
//! - Human-readable and JSON output formatting
//! - Enhanced formatting with emoji and colors

use crate::{Result, DeezelError};
use crate::traits::*;
use bitcoin::{Network, Transaction};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::collections::HashMap;

/// Runestone manager that works with any provider
pub struct RunestoneManager<P: DeezelProvider> {
    provider: P,
}

impl<P: DeezelProvider> RunestoneManager<P> {
    /// Create a new runestone manager
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
    
    /// Decode runestone from transaction
    pub async fn decode(&self, txid: String, _enhanced: bool) -> Result<RunestoneDecodeResult> {
        // Convert string to Transaction - this is a placeholder implementation
        // In a real implementation, you'd fetch the transaction by txid
        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let _result = self.provider.decode_runestone(&tx).await?;
        
        // Convert JsonValue result to RunestoneDecodeResult
        Ok(RunestoneDecodeResult {
            txid,
            runestone: None, // TODO: Parse from JsonValue
            raw_data: None,
            error: None,
        })
    }
    
    /// Analyze runestone message
    pub async fn analyze_message(&self, message: String, format: MessageFormat) -> Result<MessageAnalysis> {
        // Use the analyze_runestone method from the trait
        let _result = self.provider.analyze_runestone(&message).await?;
        
        // Convert JsonValue result to MessageAnalysis
        Ok(MessageAnalysis {
            format,
            decoded: message,
            runestone: None, // TODO: Parse from JsonValue
            metadata: std::collections::HashMap::new(),
        })
    }
    
    /// Analyze protostone
    pub async fn analyze_protostone(&self, data: String, format: ProtostoneFormat) -> Result<ProtostoneAnalysis> {
        // Use the analyze_runestone method from the trait as a fallback
        let _result = self.provider.analyze_runestone(&data).await?;
        
        // Convert JsonValue result to ProtostoneAnalysis
        Ok(ProtostoneAnalysis {
            format,
            decoded: data.into_bytes(),
            fields: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
        })
    }
    
    /// Get runestone from transaction hex
    pub async fn from_transaction_hex(&self, tx_hex: String) -> Result<Option<RunestoneInfo>> {
        // Parse transaction from hex
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|e| DeezelError::Parse(format!("Invalid hex: {}", e)))?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|e| DeezelError::Parse(format!("Invalid transaction: {}", e)))?;
        
        // Use decode_runestone trait method
        let _result = self.provider.decode_runestone(&tx).await?;
        
        // TODO: Parse JsonValue result to extract RunestoneInfo
        Ok(None)
    }
    
    /// Get runestone from raw transaction
    pub async fn from_transaction(&self, tx: Transaction) -> Result<Option<RunestoneInfo>> {
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
        self.from_transaction_hex(tx_hex).await
    }
    
    /// Format runestone for display
    pub fn format_runestone(&self, runestone: &RunestoneInfo, enhanced: bool) -> String {
        if enhanced {
            self.format_enhanced(runestone)
        } else {
            self.format_basic(runestone)
        }
    }
    
    /// Format runestone with enhanced styling
    fn format_enhanced(&self, runestone: &RunestoneInfo) -> String {
        let mut output = String::new();
        
        output.push_str("🪨 Runestone Analysis\n");
        output.push_str("═══════════════════\n\n");
        
        if let Some(ref etching) = runestone.etching {
            output.push_str("🎯 Etching:\n");
            if let Some(ref rune) = etching.rune {
                output.push_str(&format!("  📛 Rune: {}\n", rune));
            }
            if let Some(ref divisibility) = etching.divisibility {
                output.push_str(&format!("  🔢 Divisibility: {}\n", divisibility));
            }
            if let Some(ref premine) = etching.premine {
                output.push_str(&format!("  ⛏️  Premine: {}\n", premine));
            }
            if let Some(ref spacers) = etching.spacers {
                output.push_str(&format!("  📏 Spacers: {}\n", spacers));
            }
            if let Some(ref symbol) = etching.symbol {
                output.push_str(&format!("  🔤 Symbol: {}\n", symbol));
            }
            if let Some(ref terms) = etching.terms {
                output.push_str("  📋 Terms:\n");
                if let Some(ref amount) = terms.amount {
                    output.push_str(&format!("    💰 Amount: {}\n", amount));
                }
                if let Some(ref cap) = terms.cap {
                    output.push_str(&format!("    🧢 Cap: {}\n", cap));
                }
                if let Some(ref height) = terms.height {
                    output.push_str(&format!("    📏 Height: {} - {}\n", 
                        height.0.unwrap_or(0), height.1.unwrap_or(0)));
                }
                if let Some(ref offset) = terms.offset {
                    output.push_str(&format!("    📍 Offset: {} - {}\n", 
                        offset.0.unwrap_or(0), offset.1.unwrap_or(0)));
                }
            }
            output.push('\n');
        }
        
        if !runestone.edicts.is_empty() {
            output.push_str("📜 Edicts:\n");
            for (i, edict) in runestone.edicts.iter().enumerate() {
                output.push_str(&format!("  {}. ID: {}, Amount: {}, Output: {}\n", 
                    i + 1, edict.id, edict.amount, edict.output));
            }
            output.push('\n');
        }
        
        if let Some(ref mint) = runestone.mint {
            output.push_str(&format!("🏭 Mint: {}\n\n", mint));
        }
        
        if let Some(ref pointer) = runestone.pointer {
            output.push_str(&format!("👉 Pointer: {}\n\n", pointer));
        }
        
        if !runestone.cenotaph.is_empty() {
            output.push_str("⚠️  Cenotaph Issues:\n");
            for issue in &runestone.cenotaph {
                output.push_str(&format!("  • {}\n", issue));
            }
            output.push('\n');
        }
        
        output
    }
    
    /// Format runestone with basic styling
    fn format_basic(&self, runestone: &RunestoneInfo) -> String {
        let mut output = String::new();
        
        output.push_str("Runestone Analysis\n");
        output.push_str("==================\n\n");
        
        if let Some(ref etching) = runestone.etching {
            output.push_str("Etching:\n");
            if let Some(ref rune) = etching.rune {
                output.push_str(&format!("  Rune: {}\n", rune));
            }
            if let Some(ref divisibility) = etching.divisibility {
                output.push_str(&format!("  Divisibility: {}\n", divisibility));
            }
            if let Some(ref premine) = etching.premine {
                output.push_str(&format!("  Premine: {}\n", premine));
            }
            if let Some(ref spacers) = etching.spacers {
                output.push_str(&format!("  Spacers: {}\n", spacers));
            }
            if let Some(ref symbol) = etching.symbol {
                output.push_str(&format!("  Symbol: {}\n", symbol));
            }
            if let Some(ref terms) = etching.terms {
                output.push_str("  Terms:\n");
                if let Some(ref amount) = terms.amount {
                    output.push_str(&format!("    Amount: {}\n", amount));
                }
                if let Some(ref cap) = terms.cap {
                    output.push_str(&format!("    Cap: {}\n", cap));
                }
                if let Some(ref height) = terms.height {
                    output.push_str(&format!("    Height: {} - {}\n", 
                        height.0.unwrap_or(0), height.1.unwrap_or(0)));
                }
                if let Some(ref offset) = terms.offset {
                    output.push_str(&format!("    Offset: {} - {}\n", 
                        offset.0.unwrap_or(0), offset.1.unwrap_or(0)));
                }
            }
            output.push('\n');
        }
        
        if !runestone.edicts.is_empty() {
            output.push_str("Edicts:\n");
            for (i, edict) in runestone.edicts.iter().enumerate() {
                output.push_str(&format!("  {}. ID: {}, Amount: {}, Output: {}\n", 
                    i + 1, edict.id, edict.amount, edict.output));
            }
            output.push('\n');
        }
        
        if let Some(ref mint) = runestone.mint {
            output.push_str(&format!("Mint: {}\n\n", mint));
        }
        
        if let Some(ref pointer) = runestone.pointer {
            output.push_str(&format!("Pointer: {}\n\n", pointer));
        }
        
        if !runestone.cenotaph.is_empty() {
            output.push_str("Cenotaph Issues:\n");
            for issue in &runestone.cenotaph {
                output.push_str(&format!("  - {}\n", issue));
            }
            output.push('\n');
        }
        
        output
    }
}

/// Runestone decode result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunestoneDecodeResult {
    pub txid: String,
    pub runestone: Option<RunestoneInfo>,
    pub raw_data: Option<String>,
    pub error: Option<String>,
}

/// Runestone information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunestoneInfo {
    pub etching: Option<Etching>,
    pub edicts: Vec<Edict>,
    pub mint: Option<String>,
    pub pointer: Option<u32>,
    pub cenotaph: Vec<String>,
}

/// Etching information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Etching {
    pub rune: Option<String>,
    pub divisibility: Option<u8>,
    pub premine: Option<u128>,
    pub spacers: Option<u32>,
    pub symbol: Option<char>,
    pub terms: Option<Terms>,
}

/// Terms information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Terms {
    pub amount: Option<u128>,
    pub cap: Option<u128>,
    pub height: Option<(Option<u64>, Option<u64>)>,
    pub offset: Option<(Option<u64>, Option<u64>)>,
}

/// Edict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edict {
    pub id: String,
    pub amount: u128,
    pub output: u32,
}

/// Message format for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageFormat {
    Hex,
    Base64,
    Raw,
}

/// Message analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAnalysis {
    pub format: MessageFormat,
    pub decoded: String,
    pub runestone: Option<RunestoneInfo>,
    pub metadata: HashMap<String, String>,
}

/// Protostone format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtostoneFormat {
    Hex,
    Base64,
    Binary,
}

/// Protostone analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtostoneAnalysis {
    pub format: ProtostoneFormat,
    pub decoded: Vec<u8>,
    pub fields: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
}

/// Network wrapper for serde compatibility
#[derive(Debug, Clone)]
pub struct NetworkWrapper(pub Network);

impl Serialize for NetworkWrapper {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let network_str = match self.0 {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        };
        serializer.serialize_str(network_str)
    }
}

impl<'de> Deserialize<'de> for NetworkWrapper {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let network = match s.as_str() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            _ => return Err(serde::de::Error::custom(format!("Unknown network: {}", s))),
        };
        Ok(NetworkWrapper(network))
    }
}

/// Runestone configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunestoneConfig {
    #[serde(with = "network_serde")]
    pub network: Network,
    pub enhanced_formatting: bool,
    pub include_raw_data: bool,
}

/// Serde module for Network
mod network_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(network: &Network, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let network_str = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        };
        serializer.serialize_str(network_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(serde::de::Error::custom(format!("Unknown network: {}", s))),
        }
    }
}

impl Default for RunestoneConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            enhanced_formatting: true,
            include_raw_data: false,
        }
    }
}

/// Runestone utilities
pub mod utils {
    use super::*;
    
    /// Parse rune name
    pub fn parse_rune_name(name: &str) -> Result<String> {
        // Basic validation - rune names should be uppercase letters and dots
        if name.chars().all(|c| c.is_ascii_uppercase() || c == '.') {
            Ok(name.to_string())
        } else {
            Err(DeezelError::Parse(format!("Invalid rune name: {}", name)))
        }
    }
    
    /// Format rune amount with divisibility
    pub fn format_rune_amount(amount: u128, divisibility: u8) -> String {
        if divisibility == 0 {
            return amount.to_string();
        }
        
        let divisor = 10_u128.pow(divisibility as u32);
        let whole = amount / divisor;
        let fractional = amount % divisor;
        
        if fractional == 0 {
            whole.to_string()
        } else {
            format!("{}.{:0width$}", whole, fractional, width = divisibility as usize)
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        }
    }
    
    /// Parse rune amount with divisibility
    pub fn parse_rune_amount(amount_str: &str, divisibility: u8) -> Result<u128> {
        if divisibility == 0 {
            return amount_str.parse::<u128>()
                .map_err(|_| DeezelError::Parse(format!("Invalid amount: {}", amount_str)));
        }
        
        let parts: Vec<&str> = amount_str.split('.').collect();
        if parts.len() > 2 {
            return Err(DeezelError::Parse(format!("Invalid amount format: {}", amount_str)));
        }
        
        let whole: u128 = parts[0].parse()
            .map_err(|_| DeezelError::Parse(format!("Invalid whole part: {}", parts[0])))?;
        
        let fractional = if parts.len() == 2 {
            let frac_str = parts[1];
            if frac_str.len() > divisibility as usize {
                return Err(DeezelError::Parse(format!("Too many decimal places: {}", frac_str)));
            }
            
            let padded = format!("{:0<width$}", frac_str, width = divisibility as usize);
            padded.parse::<u128>()
                .map_err(|_| DeezelError::Parse(format!("Invalid fractional part: {}", frac_str)))?
        } else {
            0
        };
        
        let divisor = 10_u128.pow(divisibility as u32);
        Ok(whole * divisor + fractional)
    }
    
    /// Validate edict
    pub fn validate_edict(edict: &Edict) -> Result<()> {
        if edict.amount == 0 {
            return Err(DeezelError::Validation("Edict amount cannot be zero".to_string()));
        }
        Ok(())
    }
    
    /// Validate etching
    pub fn validate_etching(etching: &Etching) -> Result<()> {
        if let Some(ref rune) = etching.rune {
            parse_rune_name(rune)?;
        }
        
        if let Some(divisibility) = etching.divisibility {
            if divisibility > 38 {
                return Err(DeezelError::Validation("Divisibility cannot exceed 38".to_string()));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;
    
    #[test]
    fn test_rune_name_parsing() {
        assert!(parse_rune_name("BITCOIN").is_ok());
        assert!(parse_rune_name("HELLO.WORLD").is_ok());
        assert!(parse_rune_name("invalid").is_err());
        assert!(parse_rune_name("HELLO123").is_err());
    }
    
    #[test]
    fn test_rune_amount_formatting() {
        assert_eq!(format_rune_amount(1000, 0), "1000");
        assert_eq!(format_rune_amount(1000, 2), "10");
        assert_eq!(format_rune_amount(1050, 2), "10.5");
        assert_eq!(format_rune_amount(1001, 3), "1.001");
    }
    
    #[test]
    fn test_rune_amount_parsing() {
        assert_eq!(parse_rune_amount("1000", 0).unwrap(), 1000);
        assert_eq!(parse_rune_amount("10", 2).unwrap(), 1000);
        assert_eq!(parse_rune_amount("10.5", 2).unwrap(), 1050);
        assert_eq!(parse_rune_amount("1.001", 3).unwrap(), 1001);
        
        assert!(parse_rune_amount("10.123", 2).is_err()); // Too many decimals
        assert!(parse_rune_amount("invalid", 0).is_err());
    }
    
    #[test]
    fn test_network_wrapper_serde() {
        let wrapper = NetworkWrapper(Network::Bitcoin);
        let serialized = serde_json::to_string(&wrapper).unwrap();
        assert_eq!(serialized, "\"mainnet\"");
        
        let deserialized: NetworkWrapper = serde_json::from_str("\"mainnet\"").unwrap();
        assert!(matches!(deserialized.0, Network::Bitcoin));
    }
}