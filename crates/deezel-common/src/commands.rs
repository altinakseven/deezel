//! CLI command definitions for deezel
//!
//! This module contains the clap-based command definitions, which are
//! shared between the deezel CLI crate and the deezel-sys library crate.

use clap::{Parser, Subcommand};

/// Main CLI arguments
#[derive(Parser, Debug, Clone)]
#[command(name = "deezel")]
#[command(about = "DEEZEL - DIESEL token minting and alkanes smart contract CLI")]
#[command(version = "0.1.0")]
pub struct Args {
    /// Bitcoin RPC URL
    #[arg(long, default_value = "http://bitcoinrpc:bitcoinrpc@localhost:8332")]
    pub bitcoin_rpc_url: Option<String>,

    /// Sandshrew/Metashrew RPC URL
    #[arg(long)]
    pub sandshrew_rpc_url: Option<String>,

    /// Network provider
    #[arg(short = 'p', long, default_value = "regtest")]
    pub provider: String,

    /// Custom network magic (overrides provider)
    #[arg(long)]
    pub magic: Option<String>,

    /// Wallet file path
    #[arg(short = 'w', long)]
    pub wallet_file: Option<String>,

    /// Wallet passphrase for encrypted wallets
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Command to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Available commands
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Legacy wallet info command (deprecated, use 'wallet info' instead)
    Walletinfo {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Bitcoin Core RPC operations
    Bitcoind {
        #[command(subcommand)]
        command: BitcoindCommands,
    },
    /// Metashrew RPC operations
    Metashrew {
        #[command(subcommand)]
        command: MetashrewCommands,
    },
    /// Alkanes smart contract operations
    Alkanes {
        #[command(subcommand)]
        command: AlkanesCommands,
    },
    /// Runestone analysis and decoding
    Runestone {
        #[command(subcommand)]
        command: RunestoneCommands,
    },
    /// Protorunes operations
    Protorunes {
        #[command(subcommand)]
        command: ProtorunesCommands,
    },
    /// Monitor blockchain for events
    Monitor {
        #[command(subcommand)]
        command: MonitorCommands,
    },
    /// Esplora API operations
    Esplora {
        #[command(subcommand)]
        command: EsploraCommands,
    },
    /// PGP operations
    Pgp {
        #[command(subcommand)]
        command: PgpCommands,
    },
}

/// Wallet subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Optional mnemonic phrase (if not provided, a new one will be generated)
        #[arg(long)]
        mnemonic: Option<String>,
    },
    /// Restore wallet from mnemonic
    Restore {
        /// Mnemonic phrase to restore from
        mnemonic: String,
    },
    /// Show wallet information
    Info,
    /// List wallet addresses with flexible range specification
    Addresses {
        /// Address range specifications (e.g., "p2tr:0-1000", "p2sh:0-500")
        /// If not provided, shows first 5 addresses of each type for current network
        #[arg(value_delimiter = ' ')]
        ranges: Option<Vec<String>>,
        /// Custom HD derivation path (overrides default paths)
        #[arg(long)]
        hd_path: Option<String>,
        /// Network to derive addresses for (overrides global -p flag)
        #[arg(short = 'n', long)]
        network: Option<String>,
        /// Show addresses for all networks (mainnet, testnet, signet, regtest)
        #[arg(long)]
        all_networks: bool,
        /// Custom magic bytes in format "p2pkh_prefix,p2sh_prefix,bech32_hrp"
        #[arg(long)]
        magic: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Show wallet balance
    Balance {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Send Bitcoin to an address
    Send {
        /// Recipient address or identifier
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Send all available funds
        #[arg(long)]
        send_all: bool,
        /// Source address (optional)
        #[arg(long)]
        from: Option<String>,
        /// Change address (optional)
        #[arg(long)]
        change: Option<String>,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Send all Bitcoin to an address
    SendAll {
        /// Recipient address or identifier
        address: String,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Create a transaction (without broadcasting)
    CreateTx {
        /// Recipient address or identifier
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Send all available funds
        #[arg(long)]
        send_all: bool,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Sign a transaction
    SignTx {
        /// Transaction hex to sign
        tx_hex: String,
    },
    /// Broadcast a transaction
    BroadcastTx {
        /// Transaction hex to broadcast
        tx_hex: String,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// List UTXOs
    Utxos {
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Include frozen UTXOs
        #[arg(long)]
        include_frozen: bool,
        /// Filter UTXOs by specific addresses (comma-separated, supports identifiers like p2tr:0)
        #[arg(long)]
        addresses: Option<String>,
    },
    /// Freeze a UTXO
    FreezeUtxo {
        /// UTXO to freeze (format: txid:vout)
        utxo: String,
        /// Reason for freezing
        #[arg(long)]
        reason: Option<String>,
    },
    /// Unfreeze a UTXO
    UnfreezeUtxo {
        /// UTXO to unfreeze (format: txid:vout)
        utxo: String,
    },
    /// Show transaction history
    History {
        /// Number of transactions to show
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Specific address to check (supports identifiers like p2tr:0)
        #[arg(long)]
        address: Option<String>,
    },
    /// Show transaction details
    TxDetails {
        /// Transaction ID
        txid: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Estimate transaction fee
    EstimateFee {
        /// Target confirmation blocks
        #[arg(default_value = "6")]
        target: u32,
    },
    /// Get current fee rates
    FeeRates,
    /// Synchronize wallet with blockchain
    Sync,
    /// Backup wallet
    Backup,
    /// List address identifiers
    ListIdentifiers,
}

/// Bitcoin Core RPC subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum BitcoindCommands {
    /// Get current block count
    Getblockcount,
    /// Generate blocks to an address (regtest only)
    Generatetoaddress {
        /// Number of blocks to generate
        nblocks: u32,
        /// Address to generate to
        address: String,
    },
}

/// Metashrew RPC subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum MetashrewCommands {
    /// Get Metashrew height
    Height,
}

/// Alkanes smart contract subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum AlkanesCommands {
    /// Get bytecode for an alkanes contract
    Getbytecode {
        /// Alkane ID (format: block:tx)
        alkane_id: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Execute alkanes smart contract with commit/reveal pattern
    Execute {
        /// Input requirements (format: "B:amount" for Bitcoin, "block:tx:amount" for alkanes)
        #[arg(long)]
        inputs: Option<String>,
        /// Recipient addresses or identifiers
        #[arg(long)]
        to: String,
        /// Change address or identifier
        #[arg(long)]
        change: Option<String>,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Envelope data file for commit/reveal pattern
        #[arg(long)]
        envelope: Option<String>,
        /// Protostone specifications
        protostones: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Enable transaction tracing
        #[arg(long)]
        trace: bool,
        /// Auto-mine blocks on regtest after transaction broadcast
        #[arg(long)]
        mine: bool,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
        /// Use Rebar Labs Shield for private transaction relay (mainnet only)
        #[arg(long)]
        rebar: bool,
    },
    /// Get alkanes balance for an address
    Balance {
        /// Address to check (defaults to wallet address)
        #[arg(long)]
        address: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get token information
    TokenInfo {
        /// Alkane ID (format: block:tx)
        alkane_id: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Trace an alkanes transaction
    Trace {
        /// Transaction outpoint (format: txid:vout)
        outpoint: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Inspect alkanes bytecode
    Inspect {
        /// Alkane ID (format: block:tx) or bytecode file/hex string
        target: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
        /// Enable disassembly to WAT format
        #[arg(long)]
        disasm: bool,
        /// Enable fuzzing analysis
        #[arg(long)]
        fuzz: bool,
        /// Opcode ranges for fuzzing (e.g., "100-150,200-250")
        #[arg(long)]
        fuzz_ranges: Option<String>,
        /// Extract and display metadata
        #[arg(long)]
        meta: bool,
        /// Compute and display codehash
        #[arg(long)]
        codehash: bool,
    },
    /// Simulate alkanes execution
    Simulate {
        /// Contract ID (format: txid:vout)
        contract_id: String,
        /// Simulation parameters
        #[arg(long)]
        params: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Runestone analysis subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum RunestoneCommands {
    /// Decode runestone from transaction hex
    Decode {
        /// Transaction hex
        tx_hex: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Analyze runestone from transaction ID
    Analyze {
        /// Transaction ID
        txid: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Protorunes subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum ProtorunesCommands {
    /// Get protorunes by address
    ByAddress {
        /// Address to query
        address: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Get protorunes by outpoint
    ByOutpoint {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Monitor subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum MonitorCommands {
    /// Monitor blocks for events
    Blocks {
        /// Starting block height
        #[arg(long)]
        start: Option<u64>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
}

/// Esplora API subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum EsploraCommands {
    /// Get blocks tip hash
    BlocksTipHash,
    /// Get blocks tip height
    BlocksTipHeight,
    /// Get blocks starting from height
    Blocks {
        /// Starting height (optional)
        start_height: Option<u64>,
    },
    /// Get block by height
    BlockHeight {
        /// Block height
        height: u64,
    },
    /// Get block information
    Block {
        /// Block hash
        hash: String,
    },
    /// Get block status
    BlockStatus {
        /// Block hash
        hash: String,
    },
    /// Get block transaction IDs
    BlockTxids {
        /// Block hash
        hash: String,
    },
    /// Get block header
    BlockHeader {
        /// Block hash
        hash: String,
    },
    /// Get raw block data
    BlockRaw {
        /// Block hash
        hash: String,
    },
    /// Get transaction ID by block hash and index
    BlockTxid {
        /// Block hash
        hash: String,
        /// Transaction index
        index: u32,
    },
    /// Get block transactions
    BlockTxs {
        /// Block hash
        hash: String,
        /// Start index (optional)
        start_index: Option<u32>,
    },
    /// Get address information
    Address {
        /// Address or colon-separated parameters
        params: String,
    },
    /// Get address transactions
    AddressTxs {
        /// Address or colon-separated parameters
        params: String,
    },
    /// Get address chain transactions
    AddressTxsChain {
        /// Address or colon-separated parameters (address:last_seen_txid)
        params: String,
    },
    /// Get address mempool transactions
    AddressTxsMempool {
        /// Address
        address: String,
    },
    /// Get address UTXOs
    AddressUtxo {
        /// Address
        address: String,
    },
    /// Search addresses by prefix
    AddressPrefix {
        /// Address prefix
        prefix: String,
    },
    /// Get transaction information
    Tx {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction hex
    TxHex {
        /// Transaction ID
        txid: String,
    },
    /// Get raw transaction
    TxRaw {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction status
    TxStatus {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction merkle proof
    TxMerkleProof {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction merkle block proof
    TxMerkleblockProof {
        /// Transaction ID
        txid: String,
    },
    /// Get transaction output spend status
    TxOutspend {
        /// Transaction ID
        txid: String,
        /// Output index
        index: u32,
    },
    /// Get transaction output spends
    TxOutspends {
        /// Transaction ID
        txid: String,
    },
    /// Broadcast transaction
    Broadcast {
        /// Transaction hex
        tx_hex: String,
    },
    /// Post transaction (alias for broadcast)
    PostTx {
        /// Transaction hex
        tx_hex: String,
    },
    /// Get mempool information
    Mempool,
    /// Get mempool transaction IDs
    MempoolTxids,
    /// Get recent mempool transactions
    MempoolRecent,
    /// Get fee estimates
    FeeEstimates,
}

/// PGP subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum PgpCommands {
    /// Generate a new PGP key pair
    GenerateKey {
        /// User ID for the key (e.g., "John Doe <john@example.com>")
        user_id: String,
        /// Passphrase for the private key
        #[arg(long)]
        passphrase: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Import a PGP key from file or stdin
    ImportKey {
        /// Path to armored key file (use "-" for stdin)
        key_file: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Export a PGP key
    ExportKey {
        /// Key identifier (fingerprint, key ID, or user ID)
        identifier: String,
        /// Include private key in export
        #[arg(long)]
        private: bool,
        /// Output file (use "-" for stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// List PGP keys
    ListKeys {
        /// Show private keys only
        #[arg(long)]
        private: bool,
        /// Show public keys only
        #[arg(long)]
        public: bool,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Delete a PGP key
    DeleteKey {
        /// Key identifier (fingerprint, key ID, or user ID)
        identifier: String,
        /// Auto-confirm without user prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Encrypt data with PGP
    Encrypt {
        /// Input file (use "-" for stdin)
        input: String,
        /// Output file (use "-" for stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Recipient key identifiers (comma-separated)
        #[arg(short, long)]
        recipients: String,
        /// Output ASCII armored text instead of binary
        #[arg(long)]
        armor: bool,
        /// Sign the encrypted data
        #[arg(long)]
        sign: bool,
        /// Signing key identifier (required if --sign is used)
        #[arg(long)]
        sign_key: Option<String>,
        /// Passphrase for signing key
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Decrypt PGP encrypted data
    Decrypt {
        /// Input file (use "-" for stdin)
        input: String,
        /// Output file (use "-" for stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Private key identifier
        #[arg(short, long)]
        key: String,
        /// Passphrase for private key
        #[arg(long)]
        passphrase: Option<String>,
        /// Verify signature if present
        #[arg(long)]
        verify: bool,
        /// Expected signer key identifier (for verification)
        #[arg(long)]
        signer: Option<String>,
    },
    /// Sign data with PGP
    Sign {
        /// Input file (use "-" for stdin)
        input: String,
        /// Output file (use "-" for stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Signing key identifier
        #[arg(short, long)]
        key: String,
        /// Passphrase for signing key
        #[arg(long)]
        passphrase: Option<String>,
        /// Output ASCII armored text instead of binary
        #[arg(long)]
        armor: bool,
        /// Create detached signature
        #[arg(long)]
        detached: bool,
    },
    /// Verify a PGP signature
    Verify {
        /// Input file (use "-" for stdin)
        input: String,
        /// Signature file (for detached signatures)
        #[arg(short, long)]
        signature: Option<String>,
        /// Signer's public key identifier
        #[arg(short, long)]
        key: String,
        /// Show raw JSON output
        #[arg(long)]
        raw: bool,
    },
    /// Change passphrase of a PGP key
    ChangePassphrase {
        /// Key identifier (fingerprint, key ID, or user ID)
        identifier: String,
        /// Current passphrase
        #[arg(long)]
        old_passphrase: Option<String>,
        /// New passphrase
        #[arg(long)]
        new_passphrase: Option<String>,
    },
}