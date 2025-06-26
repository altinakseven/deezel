//! CLI command definitions for the Deezel application

use clap::Subcommand;

#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Wallet name
        name: String,
        /// Optional mnemonic phrase (if not provided, one will be generated)
        #[arg(long)]
        mnemonic: Option<String>,
        /// Optional passphrase for the mnemonic
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// List all wallets
    List,
    /// Load a wallet
    Load {
        /// Wallet name
        name: String,
    },
    /// Get wallet balance
    Balance {
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Get wallet addresses
    Addresses {
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
        /// Number of addresses to generate
        #[arg(long, default_value = "5")]
        count: u32,
    },
    /// Get wallet UTXOs
    Utxos {
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Backup wallet
    Backup {
        /// Wallet name
        name: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
    /// Restore wallet from backup
    Restore {
        /// Backup file path
        input: String,
        /// New wallet name
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TransactionCommands {
    /// Send Bitcoin
    Send {
        /// Recipient address
        to: String,
        /// Amount in satoshis
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Create a DIESEL token minting transaction
    Mint {
        /// Amount of DIESEL tokens to mint
        amount: u64,
        /// Fee rate in sat/vB
        #[arg(long)]
        fee_rate: Option<f32>,
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Broadcast a transaction
    Broadcast {
        /// Transaction hex
        tx_hex: String,
    },
    /// Get transaction details
    Get {
        /// Transaction ID
        txid: String,
    },
    /// List transaction history
    History {
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
        /// Maximum number of transactions to show
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Estimate fee for a transaction
    EstimateFee {
        /// Target confirmation blocks
        #[arg(long, default_value = "6")]
        target: u32,
    },
}

#[derive(Subcommand)]
pub enum AlkanesCommands {
    /// Deploy an alkanes contract
    Deploy {
        /// WASM file path
        wasm_file: String,
        /// Contract name
        #[arg(long)]
        name: Option<String>,
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Execute an alkanes contract function
    Execute {
        /// Contract address or name
        contract: String,
        /// Function name
        function: String,
        /// Function arguments (JSON format)
        #[arg(long)]
        args: Option<String>,
        /// Wallet name (optional, uses loaded wallet if not specified)
        #[arg(long)]
        wallet: Option<String>,
    },
    /// Simulate contract execution
    Simulate {
        /// Contract address or name
        contract: String,
        /// Function name
        function: String,
        /// Function arguments (JSON format)
        #[arg(long)]
        args: Option<String>,
        /// Block height for simulation
        #[arg(long)]
        block_height: Option<u64>,
    },
    /// Get contract information
    Info {
        /// Contract address or name
        contract: String,
    },
    /// List deployed contracts
    List,
    /// Get contract bytecode
    Bytecode {
        /// Contract address or name
        contract: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum DeployCommands {
    /// Start the deezel infrastructure
    Start {
        /// Use testnet configuration
        #[arg(long)]
        testnet: bool,
        /// Custom configuration file
        #[arg(long)]
        config: Option<String>,
    },
    /// Stop the deezel infrastructure
    Stop,
    /// Show infrastructure status
    Status,
    /// View logs from infrastructure components
    Logs {
        /// Component to show logs for (bitcoin, metashrew, all)
        #[arg(default_value = "all")]
        component: String,
        /// Follow logs in real-time
        #[arg(short, long)]
        follow: bool,
        /// Number of lines to show
        #[arg(long, default_value = "100")]
        lines: u32,
    },
    /// Reset infrastructure (stop and remove all data)
    Reset {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
    /// Get a configuration value
    Get {
        /// Configuration key
        key: String,
    },
    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Export configuration to file
    Export {
        /// Output file path
        output: String,
    },
    /// Import configuration from file
    Import {
        /// Input file path
        input: String,
    },
}