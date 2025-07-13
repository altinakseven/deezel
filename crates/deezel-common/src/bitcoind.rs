//! # Bitcoind RPC
//!
//! This module provides types for interacting with the Bitcoin Core RPC.
//! It uses the types from `bitcoincore-rpc` crate where possible.


pub use bitcoincore_rpc::bitcoincore_rpc_json::{
    GetBlockchainInfoResult, GetBlockFilterResult, GetBlockHeaderResult, GetBlockStatsResult,
    GetChainTipsResult, GetMempoolInfoResult, GetMiningInfoResult, GetNetworkInfoResult,
    GetTxOutResult, ListBannedResult, ScanTxOutRequest, GetBlockResult, GetRawTransactionResult,
};
