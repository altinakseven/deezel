//! Data structures for protorunes commands
use crate::index_pointer::StubPointer;
use bitcoin::{TxOut, OutPoint};
use protorune_support::balance_sheet::{BalanceSheet, BalanceSheetOperations};
use serde::{Deserialize, Serialize};

/// Represents the response for a single outpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoruneOutpointResponse {
    pub output: TxOut,
    pub outpoint: OutPoint,
    pub balance_sheet: BalanceSheet<StubPointer>,
}

impl Default for ProtoruneOutpointResponse {
    fn default() -> Self {
        Self {
            output: TxOut { value: bitcoin::Amount::from_sat(0), script_pubkey: Default::default() },
            outpoint: OutPoint::null(),
            balance_sheet: BalanceSheet::new(),
        }
    }
}

/// Represents the response for a wallet's protorunes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtoruneWalletResponse {
    pub balances: Vec<ProtoruneOutpointResponse>,
}