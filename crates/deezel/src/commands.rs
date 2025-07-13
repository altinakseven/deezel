//! # CLI Commands for `deezel`
//!
//! This module defines the `clap`-based command structure for the `deezel` CLI,
//! including subcommands for interacting with `bitcoind`. It also contains
//! the logic for pretty-printing complex JSON responses.

use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

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

/// Pretty-prints a JSON value as a stylized tree.
pub fn pretty_print_json(value: &JsonValue) -> String {
    let mut output = String::new();
    print_value(&mut output, value, "", true, true);
    output
}

fn print_value(output: &mut String, value: &JsonValue, prefix: &str, is_last: bool, is_root: bool) {
    let (marker, new_prefix) = if is_root {
        ("", "".to_string())
    } else if is_last {
        ("└── ", format!("{}    ", prefix))
    } else {
        ("├── ", format!("{}│   ", prefix))
    };

    match value {
        JsonValue::Object(map) => {
            if !is_root {
                output.push_str(&format!("{}{}\n", marker, "Object"));
            }
            let len = map.len();
            for (i, (k, v)) in map.iter().enumerate() {
                let key_marker = if i == len - 1 { "└── " } else { "├── " };
                output.push_str(&format!("{}{}{}: ", new_prefix, key_marker, k));
                print_value(output, v, &new_prefix, i == len - 1, false);
            }
        }
        JsonValue::Array(arr) => {
            if !is_root {
                output.push_str(&format!("{}{}\n", marker, "Array"));
            }
            let len = arr.len();
            for (i, v) in arr.iter().enumerate() {
                print_value(output, v, &new_prefix, i == len - 1, false);
            }
        }
        JsonValue::String(s) => {
            output.push_str(&format!("{}{}\n", if is_root { "" } else { "📝 " }, s));
        }
        JsonValue::Number(n) => {
            output.push_str(&format!("{}{}\n", if is_root { "" } else { "🔢 " }, n));
        }
        JsonValue::Bool(b) => {
            output.push_str(&format!("{}{}\n", if is_root { "" } else { "✅ " }, b));
        }
        JsonValue::Null => {
            output.push_str(&format!("{}\n", if is_root { "" } else { "❌ null" }));
        }
    }
}