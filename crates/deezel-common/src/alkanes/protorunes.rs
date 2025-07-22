//! Data structures for protorunes commands
use crate::index_pointer::StubPointer;
use bitcoin::{TxOut, OutPoint};
use protorune_support::balance_sheet::BalanceSheet;
use serde::{Deserialize, Serialize};

/// Represents the response for a single outpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoruneOutpointResponse {
    pub output: TxOut,
    pub outpoint: OutPoint,
    pub balance_sheet: BalanceSheet<StubPointer>,
}

/// Represents the response for a wallet's protorunes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoruneWalletResponse {
    pub balances: Vec<ProtoruneOutpointResponse>,
}