//! Types for alkanes smart contract operations

use serde::{Deserialize, Serialize};

/// Alkane ID representing a smart contract or token
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlkaneId {
    pub block: u64,
    pub tx: u64,
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
    pub fee_rate: Option<f32>,
}

/// Contract execution parameters
#[derive(Debug, Clone)]
pub struct ContractExecuteParams {
    pub calldata: Vec<String>,
    pub edicts: Option<Vec<Edict>>,
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