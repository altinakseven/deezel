//! Types for alkanes smart contract operations

use serde::{Deserialize, Serialize};
use alkanes_support::cellpack::Cellpack;

#[cfg(not(target_arch = "wasm32"))]
use std::{string::String, vec::Vec};
#[cfg(target_arch = "wasm32")]
use alloc::{string::String, vec::Vec};

/// Alkane ID representing a smart contract or token
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlkaneId {
    pub block: u64,
    pub tx: u64,
}

/// Input requirement specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputRequirement {
    /// Alkanes token requirement: (block, tx, amount) where 0 means ALL
    Alkanes { block: u64, tx: u64, amount: u64 },
    /// Bitcoin requirement: amount in satoshis
    Bitcoin { amount: u64 },
}

/// Output target specification for protostones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputTarget {
    /// Target specific output index (vN)
    Output(u32),
    /// Target specific protostone (pN)
    Protostone(u32),
    /// Split across all spendable outputs
    Split,
}

/// Protostone edict specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtostoneEdict {
    pub alkane_id: AlkaneId,
    pub amount: u64,
    pub target: OutputTarget,
}

/// Protostone specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtostoneSpec {
    /// Optional cellpack message (using alkanes_support::cellpack::Cellpack)
    #[serde(skip)]
    pub cellpack: Option<Cellpack>,
    /// List of edicts for this protostone
    pub edicts: Vec<ProtostoneEdict>,
    /// Bitcoin transfer specification (for B: transfers)
    pub bitcoin_transfer: Option<BitcoinTransfer>,
}

/// Bitcoin transfer specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTransfer {
    pub amount: u64,
    pub target: OutputTarget,
}

/// Alkane balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkaneBalance {
    pub alkane_id: AlkaneId,
    pub name: String,
    pub symbol: String,
    pub balance: u64,
}

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub alkane_id: AlkaneId,
    pub name: String,
    pub symbol: String,
    pub total_supply: u64,
    pub cap: u64,
    pub amount_per_mint: u64,
    pub minted: u64,
}

/// Contract deployment parameters
#[derive(Debug, Clone)]
pub struct ContractDeployParams {
    pub wasm_file: String,
    pub calldata: Vec<String>,
    pub tokens: Vec<TokenAmount>,
    pub fee_rate: Option<f32>,
}

/// Contract execution parameters
#[derive(Debug, Clone)]
pub struct ContractExecuteParams {
    pub target: AlkaneId,
    pub calldata: Vec<String>,
    pub edicts: Vec<Edict>,
    pub tokens: Vec<TokenAmount>,
    pub fee_rate: Option<f32>,
}

/// Token deployment parameters
#[derive(Debug, Clone)]
pub struct TokenDeployParams {
    pub name: String,
    pub symbol: String,
    pub cap: u64,
    pub amount_per_mint: u64,
    pub reserve_number: u64,
    pub premine: Option<u64>,
    pub image: Option<String>,
    pub fee_rate: Option<f32>,
}

/// Token send parameters
#[derive(Debug, Clone)]
pub struct TokenSendParams {
    pub token: AlkaneId,
    pub amount: u64,
    pub to: String,
    pub from: Option<String>,
    pub fee_rate: Option<f32>,
}

/// Pool creation parameters
#[derive(Debug, Clone)]
pub struct PoolCreateParams {
    pub calldata: Vec<String>,
    pub tokens: Vec<TokenAmount>,
    pub fee_rate: Option<f32>,
}

/// Liquidity addition parameters
#[derive(Debug, Clone)]
pub struct LiquidityAddParams {
    pub pool: AlkaneId,
    pub calldata: Vec<String>,
    pub tokens: Vec<TokenAmount>,
    pub fee_rate: Option<f32>,
}

/// Liquidity removal parameters
#[derive(Debug, Clone)]
pub struct LiquidityRemoveParams {
    pub calldata: Vec<String>,
    pub token: AlkaneId,
    pub amount: u64,
    pub fee_rate: Option<f32>,
}

/// Swap parameters
#[derive(Debug, Clone)]
pub struct SwapParams {
    pub pool: AlkaneId,
    pub calldata: Vec<String>,
    pub token: AlkaneId,
    pub amount: u64,
    pub fee_rate: Option<f32>,
}

/// Advanced simulation parameters
#[derive(Debug, Clone)]
pub struct SimulationParams {
    pub target: AlkaneId,
    pub inputs: Vec<String>,
    pub tokens: Option<Vec<TokenAmount>>,
    pub decoder: Option<String>,
}

/// Token amount for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAmount {
    pub alkane_id: AlkaneId,
    pub amount: u64,
}

/// Edict for protostone operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edict {
    pub alkane_id: AlkaneId,
    pub amount: u64,
    pub output: u32,
}

/// Liquidity removal preview result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityRemovalPreview {
    pub token_a_amount: u64,
    pub token_b_amount: u64,
    pub lp_tokens_burned: u64,
}

/// Contract deployment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployResult {
    pub contract_id: AlkaneId,
    pub txid: String,
    pub fee: u64,
}

/// Token deployment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDeployResult {
    pub token_id: AlkaneId,
    pub txid: String,
    pub fee: u64,
}

/// Transaction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub txid: String,
    pub fee: u64,
}

/// Enhanced execute parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Enhanced execute result for commit/reveal pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedExecuteResult {
    pub commit_txid: Option<String>,
    pub reveal_txid: String,
    pub commit_fee: Option<u64>,
    pub reveal_fee: u64,
    pub inputs_used: Vec<String>,
    pub outputs_created: Vec<String>,
    pub traces: Option<Vec<serde_json::Value>>,
}

/// Alkanes inspect configuration
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct AlkanesInspectConfig {
    pub disasm: bool,
    pub fuzz: bool,
    pub fuzz_ranges: Option<String>,
    pub meta: bool,
    pub codehash: bool,
    pub raw: bool,
}

/// Alkanes inspect result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesInspectResult {
    pub alkane_id: AlkaneId,
    pub bytecode_length: usize,
    pub disassembly: Option<String>,
    pub metadata: Option<AlkaneMetadata>,
    pub codehash: Option<String>,
    pub fuzzing_results: Option<FuzzingResults>,
}

/// Alkane metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkaneMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub methods: Vec<AlkaneMethod>,
}

/// Alkane method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkaneMethod {
    pub name: String,
    pub opcode: u128,
    pub params: Vec<String>,
    pub returns: String,
}

/// Fuzzing results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingResults {
    pub total_opcodes_tested: usize,
    pub opcodes_filtered_out: usize,
    pub successful_executions: usize,
    pub failed_executions: usize,
    pub implemented_opcodes: Vec<u128>,
    pub opcode_results: Vec<ExecutionResult>,
}


/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_value: Option<i32>,
    pub return_data: Vec<u8>,
    pub error: Option<String>,
    pub execution_time_micros: u128,
    pub opcode: u128,
    pub host_calls: Vec<HostCall>,
}

/// Host call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCall {
    pub function_name: String,
    pub parameters: Vec<String>,
    pub result: String,
    pub timestamp_micros: u128,
}