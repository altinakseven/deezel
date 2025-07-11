# Deezel Keystore Architecture

## Overview

The Deezel keystore system provides secure, production-ready Bitcoin wallet functionality with PGP encryption, dynamic address derivation, and multi-network support. This document describes the architecture, security features, and usage patterns.

## Architecture Components

### 1. KeystoreManager (`crates/deezel-sys/src/keystore.rs`)

The core keystore management system that handles:
- **Keystore Creation**: Generates new HD wallets with PGP-encrypted seed storage
- **Dynamic Address Derivation**: Derives addresses on-demand from master public key
- **Secure Passphrase Input**: Terminal UI for secure password entry
- **Multi-Network Support**: Single keystore works across all Bitcoin networks

### 2. Keystore Structure

```json
{
  "encrypted_seed": "-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----\n",
  "master_public_key": "xpub661MyMwAqRbcH2nt...",
  "master_fingerprint": "0680d909",
  "created_at": 1752253820,
  "version": "0.1.0",
  "pbkdf2_params": {
    "salt": [225, 13, 187, 67, 31, 223, 21, 20],
    "iterations": 100000,
    "hash_algorithm": "SHA256"
  }
}
```

### 3. Security Features

#### PGP Encryption
- **ASCII Armored**: Standard PGP message format for encrypted seed
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA256
- **Stored Parameters**: Salt and iteration count stored for decryption
- **No Hardcoded Passwords**: Secure passphrase input required

#### HD Wallet Security
- **BIP32 Compliance**: Hierarchical deterministic key derivation
- **Master Public Key Storage**: Only public key stored, private key encrypted
- **Non-Hardened Derivation**: Allows address generation without private key
- **Network-Agnostic**: Single keystore supports all Bitcoin networks

## Usage Examples

### 1. Creating a Wallet

#### With Secure Passphrase Prompt
```bash
# System prompts for passphrase with confirmation
./deezel --wallet-file ~/.deezel/my-wallet.json wallet create
```

#### With CLI Passphrase (Less Secure)
```bash
# Passphrase provided via command line
./deezel --wallet-file ~/.deezel/my-wallet.json --passphrase "my-secure-password" wallet create
```

### 2. Viewing Addresses

#### Default View (First 5 of Each Type)
```bash
./deezel --wallet-file ~/.deezel/my-wallet.json wallet addresses
```

#### Specific Address Ranges
```bash
# Get first 10 Taproot addresses
./deezel --wallet-file ~/.deezel/my-wallet.json wallet addresses p2tr:0-10

# Get multiple ranges
./deezel --wallet-file ~/.deezel/my-wallet.json wallet addresses p2tr:0-5 p2wpkh:0-10 p2sh:100-200

# JSON output for programmatic use
./deezel --wallet-file ~/.deezel/my-wallet.json wallet addresses p2tr:0-5 --raw
```

### 3. Network Support

#### Mainnet
```bash
./deezel --provider mainnet --wallet-file ~/.deezel/mainnet.json wallet create
```

#### Testnet
```bash
./deezel --provider testnet --wallet-file ~/.deezel/testnet.json wallet create
```

#### Regtest (Development)
```bash
./deezel --provider regtest --wallet-file ~/.deezel/regtest.json wallet create
```

## Address Types and Derivation Paths

| Address Type | Description | Derivation Path | Example |
|--------------|-------------|-----------------|---------|
| P2PKH | Legacy addresses | `m/44'/coin_type'/0'/0/index` | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| P2SH | Script hash addresses | `m/49'/coin_type'/0'/0/index` | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |
| P2WPKH | Native SegWit | `m/84'/coin_type'/0'/0/index` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| P2WSH | SegWit Script | `m/84'/coin_type'/0'/0/index` | `bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3` |
| P2TR | Taproot | `m/86'/coin_type'/0'/0/index` | `bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297` |

### Coin Types
- **Mainnet**: `coin_type = 0`
- **Testnet/Signet/Regtest**: `coin_type = 1`

## Implementation Details

### 1. Dynamic Address Derivation

The system uses the `KeystoreProvider` trait for dynamic address generation:

```rust
pub trait KeystoreProvider {
    async fn derive_addresses(
        &self,
        master_public_key: &str,
        network: Network,
        script_types: &[&str],
        start_index: u32,
        count: u32,
    ) -> Result<Vec<KeystoreAddress>>;
}
```

### 2. Secure Passphrase Input

The `prompt_for_passphrase` function provides GPG-like secure input:

```rust
pub fn prompt_for_passphrase(prompt: &str, confirm: bool) -> AnyhowResult<String> {
    // Uses dialoguer crate for secure terminal input
    // Supports passphrase confirmation for new wallets
    // Validates non-empty passphrases
}
```

### 3. PGP Integration

Uses the `deezel-rpgp` library for encryption:

```rust
fn encrypt_seed_with_pgp(&self, mnemonic: &str, passphrase: &str) -> AnyhowResult<(String, PbkdfParams)> {
    // AES256 symmetric encryption
    // SHA256 hash algorithm
    // 100,000 PBKDF2 iterations
    // Returns ASCII armored message and parameters
}
```

## Security Considerations

### 1. Passphrase Security
- **Never use CLI passphrases in production** - they appear in shell history
- **Use secure passphrase prompts** for production deployments
- **Store passphrases securely** - consider password managers

### 2. Keystore Storage
- **File permissions**: Ensure keystore files have restricted permissions (600)
- **Backup strategy**: Securely backup both keystore and mnemonic
- **Network isolation**: Use different keystores for different networks

### 3. Mnemonic Handling
- **Secure storage**: Store mnemonic phrases in secure, offline locations
- **Recovery testing**: Regularly test mnemonic recovery procedures
- **Multiple copies**: Maintain multiple secure copies of mnemonics

## Migration from Legacy Systems

### From Pre-Generated Addresses
The new system replaces pre-generated address storage with dynamic derivation:

1. **Export existing mnemonics** from legacy keystores
2. **Create new keystores** using the mnemonic import feature
3. **Verify address generation** matches legacy addresses
4. **Update applications** to use dynamic address derivation

### Compatibility Notes
- **Address derivation paths** follow BIP44/49/84/86 standards
- **Network handling** is now unified across all Bitcoin networks
- **JSON format** includes new fields for PBKDF2 parameters

## Troubleshooting

### Common Issues

#### 1. Passphrase Mismatch
```
Error: Failed to decrypt keystore
```
**Solution**: Verify passphrase is correct, check for typos

#### 2. Missing Keystore File
```
Error: No keystore found. Please create a wallet first
```
**Solution**: Create wallet with `wallet create` command

#### 3. Invalid Address Range
```
Error: Invalid range specification
```
**Solution**: Use format `script_type:start-end` (e.g., `p2tr:0-10`)

### Debug Mode
Enable debug logging for troubleshooting:
```bash
RUST_LOG=debug ./deezel wallet create
```

## Future Enhancements

### Planned Features
1. **Hardware wallet integration** for enhanced security
2. **Multi-signature support** for shared custody
3. **Custom derivation paths** via `--hd-path` argument
4. **Keystore encryption upgrades** for quantum resistance
5. **Backup and recovery tools** for disaster recovery

### API Extensions
1. **REST API** for programmatic access
2. **WebAssembly bindings** for browser integration
3. **Mobile SDK** for mobile applications
4. **Plugin architecture** for custom address types

## Conclusion

The Deezel keystore architecture provides a secure, flexible foundation for Bitcoin wallet functionality. The combination of PGP encryption, dynamic address derivation, and multi-network support makes it suitable for both development and production use cases.

For additional support or questions, refer to the project documentation or open an issue on the project repository.