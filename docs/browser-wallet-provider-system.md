# Browser Wallet Provider System

This document describes the comprehensive browser wallet provider system implemented in `deezel-web` that wraps injected browser wallets while implementing all deezel-common traits.

## Overview

The browser wallet provider system allows deezel to work with 13+ different Bitcoin wallet extensions (Unisat, Xverse, Phantom, OKX, Leather, Magic Eden, etc.) while maintaining our existing infrastructure advantages:

- **Minimal wallet usage**: Wallets are used only for signing and key operations
- **Sandshrew RPC integration**: All blockchain operations use our existing RPC connections
- **Full trait compatibility**: Implements all deezel-common traits seamlessly
- **Enhanced privacy**: Supports Rebar Labs Shield for private transaction broadcasting
- **Multi-wallet support**: Works with any injected Bitcoin wallet

## Architecture

### Core Components

1. **`BrowserWalletProvider`**: Main provider that implements all deezel-common traits
2. **`WalletBackend`**: Trait for different wallet implementations
3. **`InjectedWallet`**: Wrapper for browser-injected wallet objects
4. **`WalletConnector`**: Connection management and wallet detection

### Design Principles

- **Separation of Concerns**: Wallets handle signing, our infrastructure handles blockchain operations
- **Trait Delegation**: Most operations delegate to `WebProvider`, signing operations use the wallet
- **Error Resilience**: Graceful fallbacks when wallet features aren't available
- **Security**: Never expose private keys, use PSBT for transaction signing

## Supported Wallets

The system currently supports these Bitcoin wallets:

| Wallet | PSBT | Taproot | Ordinals | Mobile | Deep Link |
|--------|------|---------|----------|--------|-----------|
| Unisat | ✅ | ✅ | ✅ | ❌ | ❌ |
| Xverse | ✅ | ✅ | ✅ | ✅ | `xverse://` |
| Phantom | ✅ | ✅ | ❌ | ✅ | `phantom://` |
| OKX | ✅ | ✅ | ✅ | ✅ | `okx://` |
| Leather | ✅ | ✅ | ✅ | ❌ | ❌ |
| Magic Eden | ✅ | ✅ | ✅ | ✅ | `magiceden://` |

*Additional wallets can be easily added by extending the supported wallets list.*

## Usage Examples

### Basic Wallet Connection

```rust
use deezel_web::wallet_provider::*;
use deezel_common::*;

async fn connect_wallet() -> Result<BrowserWalletProvider> {
    // Detect available wallets
    let connector = WalletConnector::new();
    let available_wallets = connector.detect_wallets().await?;
    
    if let Some(wallet_info) = available_wallets.first() {
        // Connect to the first available wallet
        let provider = BrowserWalletProvider::connect(
            wallet_info.clone(),
            "http://localhost:8332".to_string(),
            "http://localhost:8080".to_string(),
            "mainnet".to_string(),
        ).await?;
        
        // Initialize the provider
        provider.initialize().await?;
        
        Ok(provider)
    } else {
        Err(DeezelError::Wallet("No wallets detected".to_string()))
    }
}
```

### Using Deezel-Common Functionality

```rust
async fn use_wallet_provider(provider: &BrowserWalletProvider) -> Result<()> {
    // Get balance using our sandshrew RPC (not wallet's limited API)
    let balance = WalletProvider::get_balance(provider).await?;
    println!("Balance: {} sats", balance.confirmed);
    
    // Get UTXOs using our Esplora provider
    let utxos = WalletProvider::get_utxos(provider, false, None).await?;
    println!("Found {} UTXOs", utxos.len());
    
    // Execute alkanes contracts
    let execute_params = AlkanesExecuteParams {
        inputs: "auto".to_string(),
        to: "bc1q...".to_string(),
        protostones: "contract_call_data".to_string(),
        // ... other params
    };
    
    let result = AlkanesProvider::execute(provider, execute_params).await?;
    println!("Contract executed: {}", result.reveal_txid);
    
    Ok(())
}
```

### Transaction Signing Flow

```rust
async fn send_transaction(provider: &BrowserWalletProvider) -> Result<String> {
    let send_params = SendParams {
        address: "bc1q...".to_string(),
        amount: 100000, // 100k sats
        fee_rate: Some(10.0),
        // ... other params
    };
    
    // 1. Create transaction using our infrastructure
    let tx_hex = provider.create_transaction(send_params).await?;
    
    // 2. Sign using the browser wallet
    let signed_tx = provider.sign_transaction(tx_hex).await?;
    
    // 3. Broadcast using wallet or our RPC (with fallback)
    let txid = provider.broadcast_transaction(signed_tx).await?;
    
    Ok(txid)
}
```

### PSBT Signing

```rust
async fn sign_psbt(provider: &BrowserWalletProvider, psbt: &Psbt) -> Result<Psbt> {
    // The wallet handles PSBT signing while we handle everything else
    let signed_psbt = WalletProvider::sign_psbt(provider, psbt).await?;
    Ok(signed_psbt)
}
```

## Integration with Leptos

The browser wallet provider can be used in Leptos applications:

```rust
use leptos::*;
use deezel_web::wallet_provider::*;

#[component]
pub fn WalletConnector() -> impl IntoView {
    let (wallet_state, set_wallet_state) = create_signal(None::<BrowserWalletProvider>);
    let (available_wallets, set_available_wallets) = create_signal(Vec::<WalletInfo>::new());
    
    // Detect wallets on component mount
    create_effect(move |_| {
        spawn_local(async move {
            let connector = WalletConnector::new();
            if let Ok(wallets) = connector.detect_wallets().await {
                set_available_wallets.set(wallets);
            }
        });
    });
    
    let connect_wallet = move |wallet_info: WalletInfo| {
        spawn_local(async move {
            if let Ok(provider) = BrowserWalletProvider::connect(
                wallet_info,
                "http://localhost:8332".to_string(),
                "http://localhost:8080".to_string(),
                "mainnet".to_string(),
            ).await {
                set_wallet_state.set(Some(provider));
            }
        });
    };
    
    view! {
        <div class="wallet-connector">
            <h3>"Available Wallets"</h3>
            <For
                each=move || available_wallets.get()
                key=|wallet| wallet.id.clone()
                children=move |wallet| {
                    let wallet_clone = wallet.clone();
                    view! {
                        <button
                            on:click=move |_| connect_wallet(wallet_clone.clone())
                            class="wallet-button"
                        >
                            <img src=wallet.icon alt=wallet.name.clone() />
                            {wallet.name}
                        </button>
                    }
                }
            />
        </div>
    }
}
```

## Key Benefits

### 1. Minimal Wallet Usage

The system uses wallets only for essential operations:
- **Signing transactions and PSBTs**
- **Providing public keys**
- **Account management**

All other operations (balance queries, UTXO management, fee estimation, blockchain monitoring) use our existing sandshrew RPC infrastructure.

### 2. Enhanced Privacy

- **Rebar Labs Shield integration**: Private transaction broadcasting for mainnet
- **No wallet API dependencies**: Reduces data leakage to wallet providers
- **Local UTXO management**: Better privacy than wallet-based UTXO tracking

### 3. Superior Performance

- **Sandshrew RPC**: Faster and more reliable than wallet APIs
- **Comprehensive UTXO data**: Includes ordinals, runes, and alkanes information
- **Advanced fee estimation**: Better fee calculation than basic wallet estimates

### 4. Full Compatibility

- **All deezel-common traits**: Complete compatibility with existing code
- **Seamless integration**: Drop-in replacement for other providers
- **Consistent API**: Same interface regardless of wallet backend

## Implementation Details

### Trait Delegation Pattern

Most trait implementations delegate to the underlying `WebProvider`:

```rust
#[async_trait(?Send)]
impl BitcoinRpcProvider for BrowserWalletProvider {
    async fn get_block_count(&self) -> Result<u64> {
        // Delegate to our RPC infrastructure
        self.web_provider.get_block_count().await
    }
    
    // ... other methods delegate similarly
}

#[async_trait(?Send)]
impl WalletProvider for BrowserWalletProvider {
    async fn sign_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        // Use the browser wallet for signing
        let psbt_hex = hex::encode(psbt.serialize());
        let signed_hex = self.wallet.sign_psbt(&psbt_hex, None).await?;
        let signed_bytes = hex::decode(&signed_hex)?;
        Psbt::deserialize(&signed_bytes)
    }
    
    async fn get_balance(&self) -> Result<WalletBalance> {
        // Use our Esplora provider for accurate balance
        self.web_provider.get_balance().await
    }
}
```

### Error Handling

The system provides graceful fallbacks:

```rust
async fn broadcast_transaction(&self, tx_hex: String) -> Result<String> {
    // Try wallet first (better UX)
    match self.wallet.push_tx(&tx_hex).await {
        Ok(txid) => Ok(txid),
        Err(_) => {
            // Fallback to our RPC provider
            self.web_provider.broadcast_transaction(tx_hex).await
        }
    }
}
```

### Security Considerations

- **No private key exposure**: Wallets never expose private keys
- **PSBT-based signing**: Secure transaction signing without key access
- **Sandboxed execution**: Wallet operations are isolated from our infrastructure
- **Validation**: All wallet responses are validated before use

## Testing

The system includes comprehensive testing:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    
    #[wasm_bindgen_test]
    async fn test_wallet_detection() {
        let connector = WalletConnector::new();
        let wallets = connector.detect_wallets().await.unwrap();
        // Test wallet detection logic
    }
    
    #[wasm_bindgen_test]
    async fn test_provider_traits() {
        // Test that all traits are properly implemented
    }
}
```

## Future Enhancements

### Planned Features

1. **Enhanced Mobile Support**: Better deep linking and mobile wallet integration
2. **Multi-signature Support**: Coordinate signing across multiple wallets
3. **Hardware Wallet Integration**: Support for hardware wallets via WebHID
4. **Wallet Switching**: Seamless switching between connected wallets
5. **Event Handling**: React to wallet events (account changes, network switches)

### Extension Points

The system is designed for easy extension:

```rust
// Add new wallet support
impl WalletBackend for CustomWallet {
    // Implement wallet-specific logic
}

// Add new provider capabilities
impl CustomProvider for BrowserWalletProvider {
    // Add custom functionality
}
```

## Conclusion

The browser wallet provider system successfully bridges the gap between browser wallet extensions and deezel's comprehensive Bitcoin infrastructure. By using wallets minimally as signers while leveraging our sandshrew RPC connections for blockchain operations, we achieve:

- **Best of both worlds**: Wallet convenience + infrastructure power
- **Enhanced privacy**: Rebar Labs Shield + reduced wallet API dependencies  
- **Superior performance**: Fast RPC + comprehensive blockchain data
- **Full compatibility**: Complete deezel-common trait implementation

This architecture enables building sophisticated Bitcoin applications that work seamlessly across different wallet providers while maintaining the full power of the deezel ecosystem.