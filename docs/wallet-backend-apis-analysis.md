# Wallet Backend APIs Analysis - LaserEyes Mono Reference

## Overview

This document analyzes the JavaScript APIs exposed by Bitcoin wallet extensions that are supported by LaserEyes Mono. This analysis is based on the reference implementation in `./reference/lasereyes-mono` and provides the foundation for building a provider object for web applications and connect wallet buttons.

## Supported Wallets

LaserEyes Mono supports **13 different wallet providers**:

1. **Unisat** (`unisat`)
2. **Xverse** (`xverse`) 
3. **Phantom** (`phantom`)
4. **Leather** (`leather`)
5. **Magic Eden** (`magic-eden`)
6. **OKX** (`okx`)
7. **Wizz** (`wizz`)
8. **Orange** (`orange`)
9. **OP_NET** (`op_net`)
10. **Sparrow** (`sparrow`)
11. **Tokeo** (`tokeo`)
12. **Keplr** (`keplr`)
13. **OYL** (`oyl`)

## Common JavaScript Injection Patterns

### 1. Window Object Injection

Each wallet injects its API into the browser's `window` object with specific patterns:

```typescript
// Unisat
window.unisat

// Xverse  
window.XverseProviders?.BitcoinProvider

// Phantom
window.phantom?.bitcoin

// Leather
window.LeatherProvider

// Magic Eden
window.magicEden?.bitcoin

// OKX (network-dependent)
window.okxwallet?.bitcoin        // mainnet/fractal mainnet
window.okxwallet?.bitcoinTestnet // testnet/signet/fractal testnet
```

### 2. Detection Pattern

All wallets use a **MutationObserver** pattern for detection:

```typescript
initialize() {
  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    this.observer = new window.MutationObserver(() => {
      if (this.library) {
        // Wallet detected - update provider availability
        this.$store.setKey('hasProvider', {
          ...this.$store.get().hasProvider,
          [WALLET_NAME]: true,
        })
        this.observer?.disconnect()
      }
    })
    this.observer.observe(document, { childList: true, subtree: true })
  }
}
```

## Core API Methods

### 1. Connection & Account Management

All wallets implement these core connection methods:

```typescript
interface WalletConnectionAPI {
  // Request wallet connection and get accounts
  requestAccounts(): Promise<string[]>
  
  // Connect to wallet (may trigger permission popup)
  connect(): Promise<void>
  
  // Get current accounts
  getAccounts(): Promise<string[]>
  
  // Get public key(s)
  getPublicKey(): Promise<string>
}
```

**Implementation Examples:**

```typescript
// Unisat
await window.unisat.requestAccounts()
await window.unisat.getPublicKey()

// Phantom  
await window.phantom.bitcoin.requestAccounts()
// Returns: [{ address: string, publicKey: string, purpose: 'ordinals'|'payment' }]

// Leather
await window.LeatherProvider.request('getAddresses')
// Returns: { addresses: [{ address: string, publicKey: string, type: 'p2tr'|'p2wpkh' }] }
```

### 2. Network Management

```typescript
interface NetworkAPI {
  // Get current network
  getNetwork(): Promise<string>
  
  // Switch network (not all wallets support)
  switchNetwork(network: string): Promise<void>
  
  // Get chain info (Unisat-specific)
  getChain(): Promise<{ enum: string, name: string, network: string }>
}
```

**Network Values:**
- `mainnet` / `bitcoin` / `livenet`
- `testnet` / `testnet4` / `signet`
- `fractal-mainnet` / `fractal-testnet`

### 3. Transaction Signing

#### PSBT Signing (Primary Method)

```typescript
interface PSBTSigningAPI {
  signPsbt(
    psbtHex: string, 
    options?: {
      autoFinalized?: boolean
      toSignInputs?: Array<{
        index: number
        address: string
        sighashTypes?: number[]
      }>
    }
  ): Promise<string>
}
```

**Implementation Examples:**

```typescript
// Unisat
const signedPsbt = await window.unisat.signPsbt(psbtHex, {
  autoFinalized: true,
  toSignInputs: [{ index: 0, address: "bc1p..." }]
})

// Phantom
const signedPsbt = await window.phantom.bitcoin.signPSBT(
  psbtBuffer, 
  {
    inputsToSign: [{ 
      address: "bc1p...", 
      signingIndexes: [0, 1] 
    }]
  }
)

// Xverse (uses sats-connect)
import { request } from 'sats-connect'
const response = await request('signPsbt', {
  psbt: psbtBase64,
  broadcast: false,
  signInputs: { [address]: [0, 1] }
})
```

#### Message Signing

```typescript
interface MessageSigningAPI {
  signMessage(
    message: string, 
    protocol?: 'bip322' | 'ecdsa'
  ): Promise<string>
}
```

### 4. Bitcoin Transactions

```typescript
interface BitcoinTransactionAPI {
  // Send Bitcoin
  sendBitcoin(toAddress: string, amount: number): Promise<string>
  
  // Get balance
  getBalance(): Promise<{ total: number, confirmed: number, unconfirmed: number }>
}
```

### 5. Inscriptions & Ordinals

```typescript
interface InscriptionsAPI {
  // Get inscriptions owned by wallet
  getInscriptions(offset?: number, limit?: number): Promise<Inscription[]>
  
  // Send inscriptions
  sendInscriptions(inscriptionIds: string[], toAddress: string): Promise<string>
}

interface Inscription {
  inscriptionId: string
  inscriptionNumber: number
  address: string
  outputValue: number
  preview: string
  content: string
  contentType: string
  location: string
  output: string
}
```

## Wallet-Specific API Differences

### 1. Unisat
- **Injection**: `window.unisat`
- **Strengths**: Full Bitcoin ecosystem support, extensive inscription APIs
- **Unique Features**: 
  - `getChain()` for detailed network info
  - Rich inscription metadata
  - Event listeners: `accountsChanged`, `networkChanged`

```typescript
// Unisat-specific
window.unisat.on('accountsChanged', (accounts) => { /* handle */ })
window.unisat.on('networkChanged', (network) => { /* handle */ })
```

### 2. Xverse
- **Injection**: `window.XverseProviders?.BitcoinProvider`
- **Strengths**: Uses standardized `sats-connect` library
- **Unique Features**:
  - Separate ordinals and payment addresses
  - Mobile deep-linking support
  - Network switching capabilities

```typescript
// Xverse uses sats-connect
import { request, addListener } from 'sats-connect'

// Connection
await request('wallet_connect', {
  addresses: ['ordinals', 'payment'],
  message: 'Connect to app'
})

// Signing
await request('signPsbt', { psbt: psbtBase64, broadcast: false })
```

### 3. Phantom
- **Injection**: `window.phantom?.bitcoin`
- **Strengths**: Multi-chain support (Bitcoin + Solana)
- **Limitations**: Mainnet only, no testnet support
- **Unique Features**:
  - Returns account objects with purpose (`ordinals` vs `payment`)
  - Buffer-based PSBT signing

```typescript
// Phantom account structure
const accounts = await window.phantom.bitcoin.requestAccounts()
// Returns: [
//   { address: "bc1p...", publicKey: "...", purpose: "ordinals" },
//   { address: "bc1q...", publicKey: "...", purpose: "payment" }
// ]
```

### 4. Leather (formerly Hiro)
- **Injection**: `window.LeatherProvider`
- **Strengths**: Bitcoin + Stacks integration
- **Unique Features**:
  - RPC-style API with `request()` method
  - Detailed address type information
  - Built-in network validation

```typescript
// Leather RPC pattern
const response = await window.LeatherProvider.request('getAddresses')
const signResponse = await window.LeatherProvider.request('signPsbt', {
  hex: psbtHex,
  broadcast: false,
  network: 'mainnet'
})
```

### 5. Magic Eden
- **Injection**: `window.magicEden?.bitcoin`
- **Strengths**: NFT marketplace integration
- **Uses**: `sats-connect` library (similar to Xverse)
- **Limitations**: Mainnet only

### 6. OKX
- **Injection**: Network-dependent
  - `window.okxwallet?.bitcoin` (mainnet)
  - `window.okxwallet?.bitcoinTestnet` (testnet)
- **Strengths**: Multi-network support
- **Unique Features**: Automatic network detection

## Event Handling Patterns

### 1. Account Changes
```typescript
// Unisat & OKX pattern
wallet.on('accountsChanged', (accounts: string[]) => {
  if (accounts.length === 0) {
    // Wallet disconnected
  } else {
    // Account switched
  }
})

// Xverse pattern (sats-connect)
addListener('accountChange', (event) => {
  // Handle account change
})
```

### 2. Network Changes
```typescript
// Unisat pattern
wallet.on('networkChanged', (network: string) => {
  // Handle network switch
})

// Xverse pattern
addListener('networkChange', (event) => {
  if (event.type === 'networkChange') {
    // Handle network change
  }
})
```

## Mobile Wallet Support

### Deep Linking Patterns

```typescript
// Xverse mobile detection and deep linking
if (isMobile() && !this.library) {
  const url = `xverse://browser?url=${encodeURIComponent(window.location.href)}`
  window.location.href = url
  return
}

// Device detection utility
function isMobile(): boolean {
  const userAgent = navigator.userAgent.toLowerCase()
  const mobileRegex = /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i
  return mobileRegex.test(userAgent)
}
```

### Connection Method Suggestions

```typescript
function getSuggestedConnectionMethod(): 'qr-code' | 'deep-link' | 'browser-extension' | 'web-wallet' {
  const deviceInfo = getDeviceInfo()
  
  if (deviceInfo.deviceType === 'mobile') {
    return 'deep-link'
  } else if (deviceInfo.deviceType === 'tablet') {
    return 'qr-code'  
  } else {
    return 'browser-extension'
  }
}
```

## Error Handling Patterns

### Common Error Types

```typescript
// User rejection (all wallets)
if (error.code === 'USER_REJECTION' || error.message.includes('User rejected')) {
  throw new Error('User canceled the request')
}

// Wallet not installed
if (!window.walletProvider) {
  throw new Error('Wallet is not installed')
}

// Network mismatch
if (address.startsWith('tb1') && network === 'mainnet') {
  throw new Error('Please switch to mainnet in wallet settings')
}
```

### Standardized Error Codes (sats-connect)

```typescript
import { RpcErrorCode } from 'sats-connect'

if (response.error.code === RpcErrorCode.USER_REJECTION) {
  throw new Error('User rejected the request')
}
```

## Provider Implementation Strategy

### 1. Universal Provider Interface

```typescript
interface UniversalWalletProvider {
  // Core identification
  name: string
  icon: string
  installed: boolean
  
  // Connection
  connect(): Promise<void>
  disconnect(): Promise<void>
  
  // Account management  
  getAccounts(): Promise<string[]>
  getPublicKey(): Promise<string>
  getNetwork(): Promise<string>
  
  // Transaction signing
  signPsbt(options: SignPsbtOptions): Promise<SignPsbtResponse>
  signMessage(message: string, options?: SignMessageOptions): Promise<string>
  
  // Bitcoin operations
  sendBitcoin(to: string, amount: number): Promise<string>
  getBalance(): Promise<bigint>
  
  // Events
  on(event: 'accountsChanged' | 'networkChanged', handler: Function): void
  off(event: string, handler: Function): void
}
```

### 2. Detection & Initialization

```typescript
class WalletDetector {
  private providers: Map<string, WalletProvider> = new Map()
  
  async detectWallets(): Promise<WalletProvider[]> {
    const detectedWallets: WalletProvider[] = []
    
    // Check each wallet injection pattern
    if (window.unisat) {
      detectedWallets.push(new UnisatProvider(window.unisat))
    }
    
    if (window.XverseProviders?.BitcoinProvider) {
      detectedWallets.push(new XverseProvider())
    }
    
    if (window.phantom?.bitcoin) {
      detectedWallets.push(new PhantomProvider(window.phantom.bitcoin))
    }
    
    // ... continue for all wallets
    
    return detectedWallets
  }
  
  // Use MutationObserver for dynamic detection
  startDetection(): void {
    const observer = new MutationObserver(() => {
      this.detectWallets().then(wallets => {
        // Update available wallets
        this.emit('walletsChanged', wallets)
      })
    })
    
    observer.observe(document, { childList: true, subtree: true })
  }
}
```

### 3. Connect Wallet Button Implementation

```typescript
interface ConnectWalletButtonProps {
  onConnect: (provider: WalletProvider) => void
  onError: (error: Error) => void
  preferredWallets?: string[]
  showAllWallets?: boolean
}

class ConnectWalletButton {
  private detector = new WalletDetector()
  
  async showWalletModal(): Promise<void> {
    const availableWallets = await this.detector.detectWallets()
    
    // Show modal with available wallets
    const modal = new WalletSelectionModal({
      wallets: availableWallets,
      onSelect: async (wallet) => {
        try {
          await wallet.connect()
          this.props.onConnect(wallet)
        } catch (error) {
          this.props.onError(error)
        }
      }
    })
    
    modal.show()
  }
}
```

## Best Practices for Implementation

### 1. Graceful Degradation
- Always check for wallet availability before calling methods
- Provide fallback options for unsupported features
- Handle network mismatches gracefully

### 2. User Experience
- Show clear installation links for missing wallets
- Provide appropriate connection methods based on device type
- Cache wallet preferences and auto-reconnect when possible

### 3. Security Considerations
- Validate all addresses and amounts before signing
- Never store private keys or sensitive data
- Always show transaction details before signing

### 4. Performance
- Use lazy loading for wallet detection
- Implement connection pooling for multiple operations
- Cache network and account information appropriately

## Conclusion

The LaserEyes Mono reference provides a comprehensive foundation for building Bitcoin wallet integrations. The key insights are:

1. **Standardization**: While each wallet has unique injection patterns, the core APIs are remarkably similar
2. **sats-connect**: Emerging as a standard for Bitcoin wallet interactions (Xverse, Magic Eden)
3. **Mobile Support**: Deep linking and device detection are crucial for mobile wallet support
4. **Error Handling**: Consistent patterns across wallets for common error scenarios
5. **Event Management**: Account and network change events are essential for reactive UIs

This analysis provides the foundation for building a robust, multi-wallet Bitcoin provider system for web applications.