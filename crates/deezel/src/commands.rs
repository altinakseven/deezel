//! # CLI Commands for `deezel`
//!
//! This module defines the `clap`-based command structure for the `deezel` CLI,
//! including subcommands for interacting with `bitcoind`. It also contains
//! the logic for pretty-printing complex JSON responses.

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Deezel is a command-line tool for interacting with Bitcoin and Ordinals
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct DeezelCommands {
    /// Path to the keystore file
    #[arg(long)]
    pub keystore: Option<String>,
    /// Bitcoin RPC URL
    #[arg(long)]
    pub bitcoin_rpc_url: Option<String>,
    /// Esplora API URL
    #[arg(long)]
    pub esplora_api_url: Option<String>,
    /// Ord server URL
    #[arg(long)]
    pub ord_server_url: Option<String>,
    /// Metashrew server URL
    #[arg(long)]
    pub metashrew_server_url: Option<String>,
    /// Network provider
    #[arg(short, long, default_value = "regtest")]
    pub provider: String,
    /// Subcommands
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum Commands {
    /// Bitcoin Core RPC commands
    #[command(subcommand)]
    Bitcoind(BitcoindCommands),
    /// Ord subcommands
    #[command(subcommand)]
    Ord(OrdCommands),
    /// Alkanes subcommands
    #[command(subcommand)]
    Alkanes(Alkanes),
    /// Runestone subcommands
    #[command(subcommand)]
    Runestone(Runestone),
    /// Protorunes subcommands
    #[command(subcommand)]
    Protorunes(Protorunes),
    /// Wallet subcommands
    #[command(subcommand)]
    Wallet(WalletCommands),
}

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

/// Alkanes subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum Alkanes {
    /// Execute an alkanes transaction
    Execute(AlkanesExecute),
    /// Inspect an alkanes contract
    Inspect {
        /// The outpoint of the contract
        outpoint: String,
        /// Disassemble the contract bytecode
        #[arg(long)]
        disasm: bool,
        /// Fuzz the contract with a range of opcodes
        #[arg(long)]
        fuzz: bool,
        /// The range of opcodes to fuzz
        #[arg(long)]
        fuzz_ranges: Option<String>,
        /// Show contract metadata
        #[arg(long)]
        meta: bool,
        /// Show the contract code hash
        #[arg(long)]
        codehash: bool,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Runestone subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum Runestone {
    /// Analyze a runestone in a transaction
    Analyze {
        /// The transaction ID
        txid: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Protorunes subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum Protorunes {
    /// Get protorunes by address
    ByAddress {
        /// Address to query
        address: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Block tag to query (e.g., "latest" or a block height)
        #[arg(long)]
        block_tag: Option<String>,
        /// Protocol tag
        #[arg(long, default_value = "1")]
        protocol_tag: u128,
    },
    /// Get protorunes by outpoint
    ByOutpoint {
        /// Outpoint to query
        outpoint: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Block tag to query (e.g., "latest" or a block height)
        #[arg(long)]
        block_tag: Option<String>,
        /// Protocol tag
        #[arg(long, default_value = "1")]
        protocol_tag: u128,
    },
}

/// Wallet subcommands
#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        /// The passphrase for the new wallet
        passphrase: Option<String>,
        mnemonic: Option<String>,
    },
    /// Get an address from the wallet
    Address {
        /// The index of the address to get
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// List UTXOs in the wallet
    Utxos {
        /// Show all UTXOs, including frozen ones
        #[arg(long)]
        all: bool,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Freeze a UTXO
    Freeze {
        /// The outpoint of the UTXO to freeze
        outpoint: String,
    },
    /// Unfreeze a UTXO
    Unfreeze {
        /// The outpoint of the UTXO to unfreeze
        outpoint: String,
    },
    /// Sign a PSBT
    Sign {
        /// The PSBT to sign, as a base64 string
        psbt: String,
    },
}

/// Arguments for the `alkanes execute` command
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
pub struct AlkanesExecute {
    /// Input requirements for the transaction
    #[arg(long)]
    pub inputs: Option<String>,
    /// Recipient addresses
    #[arg(long, num_args = 1..)]
    pub to: Vec<String>,
    /// Addresses to source UTXOs from
    #[arg(long, num_args = 1..)]
    pub from: Option<Vec<String>>,
    /// Change address
    #[arg(long)]
    pub change: Option<String>,
    /// Fee rate in sat/vB
    #[arg(long)]
    pub fee_rate: Option<f32>,
    /// Path to the envelope file (for contract deployment)
    #[arg(long)]
    pub envelope: Option<String>,
    /// Protostone specifications
    pub protostones: Vec<String>,
    /// Show raw JSON output
    #[arg(long)]
    pub raw: bool,
    /// Enable transaction tracing
    #[arg(long)]
    pub trace: bool,
    /// Mine a block after broadcasting (regtest only)
    #[arg(long)]
    pub mine: bool,
    /// Automatically confirm the transaction preview
    #[arg(long, short = 'y')]
    pub auto_confirm: bool,
}

impl From<WalletCommands> for deezel_common::commands::WalletCommands {
    fn from(cmd: WalletCommands) -> Self {
        serde_json::from_value(serde_json::to_value(cmd).unwrap()).unwrap()
    }
}

impl From<BitcoindCommands> for deezel_common::commands::BitcoindCommands {
    fn from(cmd: BitcoindCommands) -> Self {
        serde_json::from_value(serde_json::to_value(cmd).unwrap()).unwrap()
    }
}

impl From<OrdCommands> for deezel_common::commands::OrdCommands {
    fn from(cmd: OrdCommands) -> Self {
        serde_json::from_value(serde_json::to_value(cmd).unwrap()).unwrap()
    }
}

impl From<Runestone> for deezel_common::commands::RunestoneCommands {
    fn from(cmd: Runestone) -> Self {
        serde_json::from_value(serde_json::to_value(cmd).unwrap()).unwrap()
    }
}

impl From<&DeezelCommands> for deezel_common::commands::Args {
    fn from(args: &DeezelCommands) -> Self {
        deezel_common::commands::Args {
            keystore: args.keystore.clone(),
            wallet_file: None,
            passphrase: None,
            sandshrew_rpc_url: None,
            bitcoin_rpc_url: args.bitcoin_rpc_url.clone(),
            esplora_url: args.esplora_api_url.clone(),
            ord_url: args.ord_server_url.clone(),
            metashrew_rpc_url: args.metashrew_server_url.clone(),
            provider: args.provider.clone(),
            magic: None,
            log_level: "info".to_string(),
            command: deezel_common::commands::Commands::Bitcoind {
                command: deezel_common::commands::BitcoindCommands::Getblockchaininfo { raw: false },
            },
        }
    }
}
