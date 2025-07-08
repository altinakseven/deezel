//! Alkanes smart contract functionality
//!
//! This module provides comprehensive alkanes smart contract support including:
//! - Contract execution and simulation
//! - Bytecode inspection and analysis
//! - WASM runtime integration
//! - Fuzzing and testing capabilities
//! - Metadata extraction
//! - Balance management

use crate::{Result, DeezelError};
use crate::traits::*;

// Re-export all alkanes modules
pub mod inspector;
pub mod types;
pub mod execute;
pub mod simulation;
pub mod contract;
pub mod token;
pub mod envelope;
pub mod amm;
pub mod fee_validation;

// Re-export key types
pub use types::*;
#[cfg(feature = "wasm-inspection")]
pub use inspector::{AlkaneInspector, InspectionConfig, InspectionResult};

/// Alkanes manager that works with any provider
pub struct AlkanesManager<P: DeezelProvider> {
    provider: P,
}

impl<P: DeezelProvider> AlkanesManager<P> {
    /// Create a new alkanes manager
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
    
    /// Execute alkanes smart contract
    pub async fn execute(&self, params: AlkanesExecuteParams) -> Result<AlkanesExecuteResult> {
        self.provider.execute(params).await
    }
    
    /// Get alkanes balance for an address
    pub async fn get_balance(&self, address: Option<&str>) -> Result<Vec<AlkanesBalance>> {
        AlkanesProvider::get_balance(&self.provider, address).await
    }
    
    /// Get token information
    pub async fn get_token_info(&self, alkane_id: &str) -> Result<serde_json::Value> {
        self.provider.get_token_info(alkane_id).await
    }
    
    /// Trace alkanes transaction
    pub async fn trace_transaction(&self, txid: &str, vout: u32) -> Result<serde_json::Value> {
        let outpoint = format!("{}:{}", txid, vout);
        self.provider.trace(&outpoint).await
    }
    
    /// Trace alkanes by outpoint
    pub async fn trace(&self, outpoint: &str) -> Result<serde_json::Value> {
        self.provider.trace(outpoint).await
    }
    
    /// Inspect alkanes bytecode
    pub async fn inspect(&self, target: &str, config: AlkanesInspectConfig) -> Result<AlkanesInspectResult> {
        self.provider.inspect(target, config).await
    }
    
    /// Get bytecode for alkanes contract
    pub async fn get_bytecode(&self, alkane_id: &str) -> Result<String> {
        AlkanesProvider::get_bytecode(&self.provider, alkane_id).await
    }
    
    /// Simulate alkanes execution
    pub async fn simulate(&self, contract_id: &str, params: Option<&str>) -> Result<serde_json::Value> {
        self.provider.simulate(contract_id, params).await
    }
    
    /// Create alkanes inspector
    #[cfg(feature = "wasm-inspection")]
    pub fn create_inspector(&self) -> AlkaneInspector<P> {
        AlkaneInspector::new(self.provider.clone())
    }
}

/// Enhanced alkanes executor for complex operations
pub struct EnhancedAlkanesExecutor<P: DeezelProvider> {
    provider: P,
}

impl<P: DeezelProvider> EnhancedAlkanesExecutor<P> {
    /// Create a new enhanced executor
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
    
    /// Execute with enhanced parameters
    pub async fn execute(&self, params: EnhancedExecuteParams) -> Result<EnhancedExecuteResult> {
        // This would implement the enhanced execution logic from the reference
        // For now, convert to basic params and delegate
        let basic_params = AlkanesExecuteParams {
            inputs: params.input_requirements.iter()
                .map(|req| format!("{}:{}", req.requirement_type, req.amount))
                .collect::<Vec<_>>()
                .join(","),
            to: params.to_addresses.join(","),
            change: params.change_address,
            fee_rate: params.fee_rate,
            envelope: params.envelope_data.as_ref().map(|_| "envelope".to_string()),
            protostones: params.protostones.iter()
                .map(|p| format!("{}:{}", p.protocol_tag, p.message))
                .collect::<Vec<_>>()
                .join(","),
            trace: params.trace_enabled,
            mine: params.mine_enabled,
            auto_confirm: params.auto_confirm,
            rebar: params.rebar,
        };
        
        let result = self.provider.execute(basic_params).await?;
        
        Ok(EnhancedExecuteResult {
            commit_txid: result.commit_txid,
            reveal_txid: result.reveal_txid,
            commit_fee: result.commit_fee,
            reveal_fee: result.reveal_fee,
            inputs_used: result.inputs_used,
            outputs_created: result.outputs_created,
            traces: result.traces,
        })
    }
}

/// Enhanced execute parameters
#[derive(Debug, Clone)]
pub struct EnhancedExecuteParams {
    pub fee_rate: Option<f32>,
    pub to_addresses: Vec<String>,
    pub change_address: Option<String>,
    pub input_requirements: Vec<InputRequirement>,
    pub protostones: Vec<ProtostoneSpec>,
    pub envelope_data: Option<Vec<u8>>,
    pub raw_output: bool,
    pub trace_enabled: bool,
    pub mine_enabled: bool,
    pub auto_confirm: bool,
    pub rebar: bool,
}

/// Enhanced execute result
#[derive(Debug, Clone)]
pub struct EnhancedExecuteResult {
    pub commit_txid: Option<String>,
    pub reveal_txid: String,
    pub commit_fee: Option<u64>,
    pub reveal_fee: u64,
    pub inputs_used: Vec<String>,
    pub outputs_created: Vec<String>,
    pub traces: Option<Vec<String>>,
}

/// Input requirement for alkanes execution
#[derive(Debug, Clone)]
pub struct InputRequirement {
    pub requirement_type: String, // "B" for Bitcoin, "block:tx" for alkanes
    pub amount: u64,
}

/// Protostone specification
#[derive(Debug, Clone)]
pub struct ProtostoneSpec {
    pub protocol_tag: u128,
    pub message: String,
}

/// Parse input requirements from string
pub fn parse_input_requirements(inputs: &str) -> Result<Vec<InputRequirement>> {
    let mut requirements = Vec::new();
    
    for input in inputs.split(',') {
        let input = input.trim();
        if input.starts_with("B:") {
            // Bitcoin input: B:amount
            let amount_str = &input[2..];
            let amount = amount_str.parse::<u64>()
                .map_err(|_| DeezelError::Parse(format!("Invalid Bitcoin amount: {}", amount_str)))?;
            
            requirements.push(InputRequirement {
                requirement_type: "B".to_string(),
                amount,
            });
        } else {
            // Alkanes input: block:tx:amount
            let parts: Vec<&str> = input.split(':').collect();
            if parts.len() == 3 {
                let amount = parts[2].parse::<u64>()
                    .map_err(|_| DeezelError::Parse(format!("Invalid alkanes amount: {}", parts[2])))?;
                
                requirements.push(InputRequirement {
                    requirement_type: format!("{}:{}", parts[0], parts[1]),
                    amount,
                });
            } else {
                return Err(DeezelError::Parse(format!("Invalid input requirement format: {}", input)));
            }
        }
    }
    
    Ok(requirements)
}

/// Parse protostone specifications from string
pub fn parse_protostones(protostones: &str) -> Result<Vec<ProtostoneSpec>> {
    let mut specs = Vec::new();
    
    for protostone in protostones.split(',') {
        let protostone = protostone.trim();
        if protostone.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = protostone.split(':').collect();
        if parts.len() >= 2 {
            let protocol_tag = parts[0].parse::<u128>()
                .map_err(|_| DeezelError::Parse(format!("Invalid protocol tag: {}", parts[0])))?;
            
            let message = parts[1..].join(":");
            
            specs.push(ProtostoneSpec {
                protocol_tag,
                message,
            });
        } else {
            return Err(DeezelError::Parse(format!("Invalid protostone format: {}", protostone)));
        }
    }
    
    Ok(specs)
}

/// Alkanes utilities
pub mod utils {
    use super::*;
    
    /// Format alkane ID as string
    pub fn format_alkane_id(alkane_id: &crate::traits::AlkaneId) -> String {
        format!("{}:{}", alkane_id.block, alkane_id.tx)
    }
    
    /// Parse alkane ID from string
    pub fn parse_alkane_id(alkane_id_str: &str) -> Result<types::AlkaneId> {
        let parts: Vec<&str> = alkane_id_str.split(':').collect();
        if parts.len() != 2 {
            return Err(DeezelError::Parse("Invalid alkane ID format. Expected 'block:tx'".to_string()));
        }
        
        let block = parts[0].parse::<u64>()
            .map_err(|_| DeezelError::Parse("Invalid block number in alkane ID".to_string()))?;
        let tx = parts[1].parse::<u64>()
            .map_err(|_| DeezelError::Parse("Invalid transaction number in alkane ID".to_string()))?;
        
        Ok(types::AlkaneId { block, tx })
    }
    
    /// Check if string is valid alkane ID format
    pub fn is_valid_alkane_id(s: &str) -> bool {
        parse_alkane_id(s).is_ok()
    }
    
    /// Format alkanes balance for display
    pub fn format_balance(balance: &AlkanesBalance) -> String {
        // Convert types::AlkaneId to traits::AlkaneId
        let trait_alkane_id = crate::traits::AlkaneId {
            block: balance.alkane_id.block,
            tx: balance.alkane_id.tx,
        };
        format!("{} {} ({})", balance.balance, balance.symbol, format_alkane_id(&trait_alkane_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_input_requirements() {
        let requirements = parse_input_requirements("B:1000,123:456:500").unwrap();
        assert_eq!(requirements.len(), 2);
        
        assert_eq!(requirements[0].requirement_type, "B");
        assert_eq!(requirements[0].amount, 1000);
        
        assert_eq!(requirements[1].requirement_type, "123:456");
        assert_eq!(requirements[1].amount, 500);
        
        assert!(parse_input_requirements("invalid").is_err());
    }
    
    #[test]
    fn test_parse_protostones() {
        let specs = parse_protostones("1:message1,2:message2").unwrap();
        assert_eq!(specs.len(), 2);
        
        assert_eq!(specs[0].protocol_tag, 1);
        assert_eq!(specs[0].message, "message1");
        
        assert_eq!(specs[1].protocol_tag, 2);
        assert_eq!(specs[1].message, "message2");
        
        assert!(parse_protostones("invalid").is_err());
    }
    
    #[test]
    fn test_utils() {
        let alkane_id = types::AlkaneId { block: 123, tx: 456 };
        let trait_alkane_id = crate::traits::AlkaneId {
            block: alkane_id.block,
            tx: alkane_id.tx,
        };
        assert_eq!(utils::format_alkane_id(&trait_alkane_id), "123:456");
        
        let parsed = utils::parse_alkane_id("123:456").unwrap();
        assert_eq!(parsed.block, 123);
        assert_eq!(parsed.tx, 456);
        
        assert!(utils::is_valid_alkane_id("123:456"));
        assert!(!utils::is_valid_alkane_id("invalid"));
    }
}