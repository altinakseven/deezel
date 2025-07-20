//! # CLI Commands for `deezel`
//!
//! This module defines the `clap`-based command structure for the `deezel` CLI,
//! including subcommands for interacting with `bitcoind`. It also contains
//! the logic for pretty-printing complex JSON responses.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

/// Bitcoin Core RPC subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum BitcoindCommands {
    /// Get information about the blockchain state.
    GetBlockchainInfo {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get information about the network.
    GetNetworkInfo {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get a raw transaction from the mempool or a block.
    GetRawTransaction {
        /// The transaction id
        txid: String,
        /// The block hash
        #[arg(long)]
        block_hash: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get a block from the blockchain.
    GetBlock {
        /// The block hash
        hash: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get the hash of the block at a given height.
    GetBlockHash {
        /// The block height
        height: u64,
    },
    /// Get a block header from the blockchain.
    GetBlockHeader {
        /// The block hash
        hash: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get statistics about a block.
    GetBlockStats {
        /// The block hash
        hash: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get the tips of all chains.
    GetChainTips {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get information about the mempool.
    GetMempoolInfo {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get the raw mempool.
    GetRawMempool {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get a transaction output.
    GetTxOut {
        /// The transaction id
        txid: String,
        /// The vout
        vout: u32,
        /// Include mempool
        #[arg(long)]
        include_mempool: bool,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Send a raw transaction.
    SendRawTransaction {
        /// The raw transaction hex
        tx_hex: String,
    },
    /// Generate blocks to an address (regtest only)
    GenerateToAddress {
        /// Number of blocks to generate
        nblocks: u32,
        /// Address to generate to
        address: String,
    },
}

/// Ord subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum OrdCommands {
    /// Get inscription by ID
    Inscription {
        /// The inscription ID
        id: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get inscriptions for a block
    InscriptionsInBlock {
        /// The block hash
        hash: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get address information
    AddressInfo {
        /// The address
        address: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get block information
    BlockInfo {
        /// The block hash or height
        query: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get latest block count
    BlockCount,
    /// Get latest blocks
    Blocks {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get children of an inscription
    Children {
        /// The inscription ID
        id: String,
        /// Page number
        #[arg(long)]
        page: Option<u32>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get inscription content
    Content {
        /// The inscription ID
        id: String,
    },
    /// Get all inscriptions
    Inscriptions {
        /// Page number
        #[arg(long)]
        page: Option<u32>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get output information
    Output {
        /// The outpoint
        outpoint: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get parents of an inscription
    Parents {
        /// The inscription ID
        id: String,
        /// Page number
        #[arg(long)]
        page: Option<u32>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get rune information
    Rune {
        /// The rune name or ID
        rune: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get all runes
    Runes {
        /// Page number
        #[arg(long)]
        page: Option<u32>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get sat information
    Sat {
        /// The sat number
        sat: u64,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get transaction information
    TxInfo {
        /// The transaction ID
        txid: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}
