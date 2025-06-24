# Deezel Alkanes Enhancement Plan

## Overview
This document outlines the plan to enhance deezel's alkanes functionality to match and exceed the capabilities of oyl-sdk, providing comprehensive alkanes smart contract interaction capabilities.

## Current Deezel Alkanes Commands
```bash
deezel alkanes getbytecode <contract_id>
deezel alkanes protorunesbyaddress <address>
deezel alkanes protorunesbyoutpoint <outpoint>
deezel alkanes spendablesbyaddress <address>
deezel alkanes traceblock <block_height>
deezel alkanes trace <outpoint>
deezel alkanes simulate <params>
deezel alkanes meta <contract_id>
```

## Planned Enhanced Alkanes Commands

### 1. Contract Management
```bash
# Deploy new smart contracts
deezel alkanes deploy-contract <wasm_file> --calldata <data> [--fee-rate <rate>]

# Execute contract functions
deezel alkanes execute --calldata <data> [--edicts <edicts>] [--fee-rate <rate>]

# Get contract metadata and bytecode
deezel alkanes contract-info <block:tx>
deezel alkanes contract-bytecode <block:tx>
```

### 2. Token Operations
```bash
# Deploy new alkanes tokens
deezel alkanes deploy-token --name <name> --symbol <symbol> --cap <cap> 
    --amount-per-mint <amount> --reserve-number <num> [--premine <amount>] 
    [--image <file>] [--fee-rate <rate>]

# Send alkanes tokens
deezel alkanes send-token --token <block:tx> --amount <amount> --to <address> [--fee-rate <rate>]

# Check token balances
deezel alkanes balance [--address <address>]
deezel alkanes token-info <block:tx>
```

### 3. AMM/DEX Operations
```bash
# Create liquidity pools
deezel alkanes create-pool --calldata <data> --tokens <token0:amount0,token1:amount1> [--fee-rate <rate>]

# Add liquidity to pools
deezel alkanes add-liquidity --calldata <data> --tokens <token0:amount0,token1:amount1> [--fee-rate <rate>]

# Remove liquidity from pools
deezel alkanes remove-liquidity --calldata <data> --token <block:tx> --amount <amount> [--fee-rate <rate>]

# Swap tokens
deezel alkanes swap --calldata <data> --token <block:tx> --amount <amount> [--fee-rate <rate>]

# Preview operations
deezel alkanes preview-remove-liquidity --token <block:tx> --amount <amount>
```

### 4. Pool Management & Analysis
```bash
# Get all pools information
deezel alkanes list-pools --factory <block:tx>

# Get specific pool details
deezel alkanes pool-info <block:tx>

# Get pool reserves and pricing
deezel alkanes pool-reserves <block:tx>
```

### 5. Simulation & Testing
```bash
# Simulate contract execution
deezel alkanes simulate --target <block:tx> --inputs <inputs> [--tokens <tokens>] [--decoder <type>]

# Trace specific transactions
deezel alkanes trace-tx --txid <txid> --vout <vout>

# Trace blocks for alkanes activity
deezel alkanes trace-block <height>
```

### 6. Advanced Operations
```bash
# Batch operations
deezel alkanes batch --operations <file.json>

# Multi-call operations
deezel alkanes multicall --calls <call1,call2,call3>

# Contract upgrade operations
deezel alkanes upgrade-contract --proxy <block:tx> --implementation <block:tx>
```

## Implementation Strategy

### Phase 1: Core Infrastructure
1. **Enhanced RPC Methods**: Add missing alkanes RPC methods to support all operations
2. **Protorune Support**: Implement proper protorune encoding/decoding
3. **Transaction Building**: Enhanced transaction construction for alkanes operations
4. **WASM Handling**: Support for contract deployment with WASM files

### Phase 2: Token Operations
1. **Token Deployment**: Complete token creation workflow
2. **Token Transfers**: Send/receive alkanes tokens
3. **Balance Management**: Query and display token balances
4. **Token Metadata**: Display token information and properties

### Phase 3: AMM/DEX Features
1. **Pool Creation**: Create new liquidity pools
2. **Liquidity Management**: Add/remove liquidity operations
3. **Token Swapping**: Swap between different alkanes tokens
4. **Pool Analytics**: Display pool information and statistics

### Phase 4: Advanced Features
1. **Simulation Engine**: Advanced simulation capabilities
2. **Batch Operations**: Execute multiple operations in single transaction
3. **Contract Upgrades**: Support for upgradeable contracts
4. **Analytics Dashboard**: Comprehensive alkanes ecosystem overview

## Technical Implementation Details

### New Rust Modules
```rust
// src/alkanes/mod.rs - Main alkanes module
// src/alkanes/contract.rs - Contract deployment and execution
// src/alkanes/token.rs - Token operations
// src/alkanes/amm.rs - AMM/DEX operations
// src/alkanes/simulation.rs - Simulation and testing
// src/alkanes/types.rs - Alkanes-specific types
```

### Enhanced RPC Methods
```rust
// Contract operations
pub async fn deploy_contract(&self, wasm: &[u8], calldata: &[u64]) -> Result<String>
pub async fn execute_contract(&self, calldata: &[u64], edicts: &[Edict]) -> Result<String>

// Token operations
pub async fn deploy_token(&self, params: TokenDeployParams) -> Result<String>
pub async fn send_token(&self, params: TokenSendParams) -> Result<String>

// AMM operations
pub async fn create_pool(&self, params: PoolCreateParams) -> Result<String>
pub async fn add_liquidity(&self, params: LiquidityParams) -> Result<String>
pub async fn remove_liquidity(&self, params: LiquidityParams) -> Result<String>
pub async fn swap_tokens(&self, params: SwapParams) -> Result<String>

// Simulation
pub async fn simulate_operation(&self, params: SimulationParams) -> Result<SimulationResult>
```

### Data Structures
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlkaneId {
    pub block: u64,
    pub tx: u64,
}

#[derive(Debug, Clone)]
pub struct TokenDeployParams {
    pub name: String,
    pub symbol: String,
    pub cap: u64,
    pub amount_per_mint: u64,
    pub reserve_number: u64,
    pub premine: Option<u64>,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TokenSendParams {
    pub token_id: AlkaneId,
    pub amount: u64,
    pub to_address: String,
}

#[derive(Debug, Clone)]
pub struct PoolCreateParams {
    pub token0: AlkaneId,
    pub token0_amount: u64,
    pub token1: AlkaneId,
    pub token1_amount: u64,
    pub calldata: Vec<u64>,
}
```

### CLI Command Structure
```rust
#[derive(Subcommand, Debug)]
enum AlkanesCommands {
    // Contract operations
    DeployContract {
        wasm_file: String,
        #[clap(long)]
        calldata: String,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    Execute {
        #[clap(long)]
        calldata: String,
        #[clap(long)]
        edicts: Option<String>,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    
    // Token operations
    DeployToken {
        #[clap(long)]
        name: String,
        #[clap(long)]
        symbol: String,
        #[clap(long)]
        cap: u64,
        #[clap(long)]
        amount_per_mint: u64,
        #[clap(long)]
        reserve_number: u64,
        #[clap(long)]
        premine: Option<u64>,
        #[clap(long)]
        image: Option<String>,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    SendToken {
        #[clap(long)]
        token: String, // block:tx format
        #[clap(long)]
        amount: u64,
        #[clap(long)]
        to: String,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    
    // AMM operations
    CreatePool {
        #[clap(long)]
        calldata: String,
        #[clap(long)]
        tokens: String, // token0:amount0,token1:amount1
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    AddLiquidity {
        #[clap(long)]
        calldata: String,
        #[clap(long)]
        tokens: String,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    RemoveLiquidity {
        #[clap(long)]
        calldata: String,
        #[clap(long)]
        token: String,
        #[clap(long)]
        amount: u64,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    Swap {
        #[clap(long)]
        calldata: String,
        #[clap(long)]
        token: String,
        #[clap(long)]
        amount: u64,
        #[clap(long)]
        fee_rate: Option<f32>,
    },
    
    // Information and analysis
    Balance {
        #[clap(long)]
        address: Option<String>,
    },
    TokenInfo {
        token: String, // block:tx format
    },
    ListPools {
        #[clap(long)]
        factory: String,
    },
    PoolInfo {
        pool: String, // block:tx format
    },
    
    // Simulation
    Simulate {
        #[clap(long)]
        target: String, // block:tx format
        #[clap(long)]
        inputs: String, // comma-separated
        #[clap(long)]
        tokens: Option<String>,
        #[clap(long)]
        decoder: Option<String>,
    },
    PreviewRemoveLiquidity {
        #[clap(long)]
        token: String,
        #[clap(long)]
        amount: u64,
    },
}
```

## Integration with Existing Wallet

### Wallet Integration Points
1. **UTXO Management**: Use existing wallet UTXOs for alkanes transactions
2. **Transaction Signing**: Leverage existing signing infrastructure
3. **Fee Management**: Use existing fee estimation and management
4. **Address Management**: Use wallet addresses for alkanes operations

### Enhanced Wallet Commands for Alkanes
```bash
# Show alkanes balances in wallet info
deezel wallet info --include-alkanes

# Send alkanes tokens using wallet
deezel wallet send-alkanes --token <block:tx> --amount <amount> --to <address>

# Show alkanes transaction history
deezel wallet history --alkanes-only
```

## Example Usage Scenarios

### Deploy and Use a Token
```bash
# 1. Deploy a new token
deezel alkanes deploy-token --name "MyToken" --symbol "MTK" --cap 1000000 
    --amount-per-mint 100 --reserve-number 77 --premine 10000

# 2. Send tokens to another address
deezel alkanes send-token --token "123:456" --amount 500 
    --to "bc1qexampleaddress"

# 3. Check token balance
deezel alkanes balance --address "bc1qmyaddress"
```

### Create and Use AMM Pool
```bash
# 1. Create a new pool
deezel alkanes create-pool --calldata "2,1,1" 
    --tokens "123:456:1000,789:012:2000"

# 2. Add liquidity
deezel alkanes add-liquidity --calldata "2,8,1" 
    --tokens "123:456:500,789:012:1000"

# 3. Swap tokens
deezel alkanes swap --calldata "2,7,3,160" --token "123:456" --amount 200

# 4. Remove liquidity
deezel alkanes remove-liquidity --calldata "2,9,1" 
    --token "345:678" --amount 100
```

### Simulation and Testing
```bash
# Simulate a pool operation
deezel alkanes simulate --target "2:1" --inputs "1,2,6,2,7" 
    --tokens "2:6:1000,2:7:2000" --decoder "factory"

# Preview liquidity removal
deezel alkanes preview-remove-liquidity --token "2:1" --amount 1000000
```

## Benefits of Enhanced Alkanes Support

1. **Complete Ecosystem**: Full alkanes smart contract interaction capabilities
2. **DeFi Integration**: Native AMM/DEX operations for decentralized trading
3. **Developer Tools**: Comprehensive simulation and testing capabilities
4. **User-Friendly**: Simple CLI commands for complex operations
5. **Wallet Integration**: Seamless integration with existing wallet functionality
6. **Extensible**: Modular design for easy addition of new features

## Timeline

- **Week 1-2**: Core infrastructure and RPC enhancements
- **Week 3-4**: Contract and token operations
- **Week 5-6**: AMM/DEX functionality
- **Week 7-8**: Advanced features and testing
- **Week 9-10**: Documentation and optimization

This enhancement will make deezel a comprehensive tool for alkanes ecosystem interaction, matching and potentially exceeding the capabilities of oyl-sdk while maintaining the robust wallet functionality we've already implemented.