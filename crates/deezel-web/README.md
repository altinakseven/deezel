# deezel-web

Web-compatible implementation of deezel-common traits using web-sys APIs for browser environments.

## Overview

`deezel-web` provides a complete implementation of all deezel-common traits that can run in web browsers via WebAssembly (WASM). It uses browser APIs like localStorage, fetch, Web Crypto API, and console for all operations.

## Features

- **localStorage Storage**: Persistent storage using browser localStorage
- **Fetch API Networking**: HTTP requests using the browser's fetch API
- **Web Crypto API**: Cryptographic operations using the browser's Web Crypto API
- **Console Logging**: Logging to browser console with timestamps
- **Performance API Timing**: High-resolution timing using Performance API
- **Full deezel-common Compatibility**: Implements all traits from deezel-common
- **Rebar Labs Shield Support**: Private transaction broadcasting for mainnet

## Architecture

The library is organized into several modules:

- `provider`: Main WebProvider implementation
- `storage`: localStorage-based storage implementation
- `network`: Fetch API-based networking
- `crypto`: Web Crypto API-based cryptographic operations
- `time`: Performance API-based timing
- `logging`: Console API-based logging
- `utils`: Web-specific utilities and helpers

## Usage

### Basic Setup

```rust
use deezel_web::prelude::*;

// Create a web provider
let provider = WebProvider::new(
    "http://localhost:8332".to_string(),  // Bitcoin RPC URL
    "http://localhost:8080".to_string(),  // Metashrew RPC URL
    "regtest".to_string(),                // Network
).await?;

// Initialize the provider
provider.initialize().await?;
```

### Storage Operations

```rust
// Write data to localStorage
provider.write("my_key", b"my_data").await?;

// Read data from localStorage
let data = provider.read("my_key").await?;

// Check if key exists
let exists = provider.exists("my_key").await?;

// Delete data
provider.delete("my_key").await?;
```

### Wallet Operations

```rust
// Create a wallet
let config = provider.get_wallet_config();
let wallet_info = provider.create_wallet(config, None, None).await?;

// Get balance
let balance = provider.get_balance().await?;
println!("Balance: {} sats", balance.confirmed);

// Get address
let address = provider.get_address().await?;
println!("Address: {}", address);
```

### Alkanes Operations

```rust
// Execute alkanes smart contract
let params = AlkanesExecuteParams {
    inputs: "inputs".to_string(),
    to: "address".to_string(),
    change: None,
    fee_rate: Some(10.0),
    envelope: None,
    protostones: "protostones".to_string(),
    trace: true,
    mine: false,
    auto_confirm: false,
    rebar: false,
};

let result = provider.execute(params).await?;
println!("Transaction ID: {}", result.reveal_txid);
```

### Rebar Labs Shield Integration

For mainnet transactions, you can use Rebar Labs Shield for private broadcasting:

```rust
let params = AlkanesExecuteParams {
    // ... other params
    rebar: true,  // Enable Rebar Labs Shield
};

let result = provider.execute(params).await?;
// Transaction will be broadcast privately through Rebar Labs Shield
```

## Browser Compatibility

The library requires modern browser features:

- **localStorage**: For persistent storage
- **Fetch API**: For HTTP requests
- **Web Crypto API**: For cryptographic operations (requires HTTPS)
- **Performance API**: For high-resolution timing
- **Console API**: For logging

You can check browser compatibility:

```rust
use deezel_web::utils::WebUtils;

let capabilities = WebUtils::get_browser_capabilities();
if !capabilities.has_required_capabilities() {
    let missing = capabilities.missing_capabilities();
    eprintln!("Missing capabilities: {:?}", missing);
}
```

## WASM Setup

To use this library in a web application:

1. Add to your `Cargo.toml`:

```toml
[dependencies]
deezel-web = { path = "../deezel-web" }
wasm-bindgen = "0.2"

[lib]
crate-type = ["cdylib"]
```

2. Build for WASM:

```bash
wasm-pack build --target web --out-dir pkg
```

3. Use in JavaScript:

```javascript
import init, { test_web_provider } from './pkg/your_crate.js';

async function run() {
    await init();
    await test_web_provider();
}

run();
```

## Security Considerations

- **HTTPS Required**: Web Crypto API requires a secure context (HTTPS)
- **CORS**: Ensure your RPC endpoints support CORS for browser requests
- **Private Keys**: Never expose private keys in browser environments
- **localStorage Limits**: Browser storage has size limitations

## Testing

Run tests in a browser environment:

```bash
wasm-pack test --headless --firefox
```

Or with Chrome:

```bash
wasm-pack test --headless --chrome
```

## Examples

See the `examples/` directory for complete usage examples:

- `web_example.rs`: Comprehensive example showing all features

## Error Handling

All operations return `Result<T, DeezelError>`. Common error types:

- `DeezelError::Network`: Network/fetch failures
- `DeezelError::Storage`: localStorage failures
- `DeezelError::Crypto`: Web Crypto API failures
- `DeezelError::Configuration`: Invalid configuration

## Logging

Use the built-in logging macros:

```rust
web_info!("Information message");
web_warn!("Warning message");
web_error!("Error message: {}", error);
web_debug!("Debug message");
```

## Limitations

- **No File System**: Uses localStorage instead of file system
- **CORS Restrictions**: Limited by browser CORS policies
- **Storage Limits**: Browser storage size limitations
- **No Process Control**: Cannot spawn processes or access system resources
- **Network Restrictions**: Limited to HTTP/HTTPS requests

## Contributing

When contributing to deezel-web:

1. Ensure all trait implementations are complete
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Test in multiple browsers
5. Consider WASM size implications

## License

Licensed under MIT OR Apache-2.0