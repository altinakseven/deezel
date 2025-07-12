// Keystore Logic
//
// This module handles the creation, encryption, and serialization of
// the JSON keystore for deezel wallets. It uses a custom PGP-style ASCII armoring
// for the encrypted seed and includes PBKDF2 parameters for key derivation.
//
// The keystore is designed to be a one-time creation, with all necessary
// address derivations pre-calculated and stored for various networks.

use serde::{Deserialize, Serialize};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    Network as BitcoinNetwork,
    secp256k1::{Secp256k1},
    Address, PublicKey,
    bip32::Xpub,
};
use bip39::{Language, Mnemonic, Seed};
use rand::{rngs::OsRng, RngCore};
use deezel_rpgp::{
    composed::{ArmorOptions, MessageBuilder},
    crypto::{sym::SymmetricKeyAlgorithm, hash::HashAlgorithm},
    types::{Password, StringToKey},
};
use std::collections::HashMap;
use std::str::FromStr;
use crate::{DeezelError, Result};
use crate::address::{DeezelAddress, NetworkConfig};

/// Represents the entire JSON keystore.
#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    /// The PGP-armored, encrypted HD seed.
    pub encrypted_seed: String,
    /// PBKDF2/S2K parameters used for key derivation from the passphrase.
    pub pbkdf2_params: Pbkdf2Params,
    /// A map of network type to a list of derived addresses.
    pub addresses: HashMap<String, Vec<AddressInfo>>,
    /// Keystore format version.
    pub version: u32,
}

/// Parameters for the PBKDF2/S2K key derivation function.
#[derive(Serialize, Deserialize, Debug)]
pub struct Pbkdf2Params {
    /// The salt used in the S2K derivation.
    pub salt: String,
    /// The number of iterations for the S2K function.
    pub iterations: u32,
    /// The symmetric key algorithm used.
    pub algorithm: String,
}

/// Information about a derived address.
#[derive(Serialize, Deserialize, Debug)]
pub struct AddressInfo {
    /// The derivation path for the address.
    pub path: String,
    /// The address string.
    pub address: String,
    /// The type of address (e.g., "p2wpkh", "p2tr").
    pub address_type: String,
}

/// Convert Bitcoin network to our NetworkConfig
fn network_to_config(network: BitcoinNetwork) -> NetworkConfig {
    match network {
        BitcoinNetwork::Bitcoin => NetworkConfig::mainnet(),
        BitcoinNetwork::Testnet => NetworkConfig::testnet(),
        BitcoinNetwork::Signet => NetworkConfig::signet(),
        BitcoinNetwork::Regtest => NetworkConfig::regtest(),
        _ => NetworkConfig::mainnet(), // Default fallback for any future network types
    }
}

/// Creates a new encrypted keystore.
pub fn create_keystore(passphrase: &str) -> Result<Keystore> {
    let secp = Secp256k1::new();
    
    // 1. Generate mnemonic and seed
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    // 2. Derive addresses
    let root_key = Xpriv::new_master(BitcoinNetwork::Bitcoin, seed.as_bytes())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;
    
    let mut addresses = HashMap::new();
    let networks = [
        ("mainnet", BitcoinNetwork::Bitcoin),
        ("testnet", BitcoinNetwork::Testnet),
        ("signet", BitcoinNetwork::Signet),
        ("regtest", BitcoinNetwork::Regtest),
    ];

    for (net_name, network) in &networks {
        let network_config = network_to_config(*network);
        let mut address_infos = Vec::new();
        for i in 0..10 {
            // P2WPKH
            let path_str = format!("m/84'/0'/0'/0/{}", i);
            let path = DerivationPath::from_str(&path_str).unwrap();
            let child_key = root_key.derive_priv(&secp, &path).unwrap();
            let secp_pubkey = Xpub::from_priv(&secp, &child_key).public_key;
            let bitcoin_pubkey = PublicKey::new(secp_pubkey);
            let address = DeezelAddress::p2wpkh(&bitcoin_pubkey, &network_config).unwrap();
            address_infos.push(AddressInfo {
                path: path_str,
                address: address.to_string().unwrap(),
                address_type: "p2wpkh".to_string(),
            });

            // P2TR
            let path_str = format!("m/86'/0'/0'/0/{}", i);
            let path = DerivationPath::from_str(&path_str).unwrap();
            let child_key = root_key.derive_priv(&secp, &path).unwrap();
            let (internal_key, _) = Xpub::from_priv(&secp, &child_key).public_key.x_only_public_key();
            let address = DeezelAddress::p2tr(&secp, internal_key, None, &network_config);
            address_infos.push(AddressInfo {
                path: path_str,
                address: address.to_string().unwrap(),
                address_type: "p2tr".to_string(),
            });
        }
        addresses.insert(net_name.to_string(), address_infos);
    }

    // 3. Prepare PGP symmetric encryption
    let iterations = 100_000;
    let mut salt = [0u8; 8];
    OsRng.fill_bytes(&mut salt);
    let count = encode_count(iterations);
    let s2k = StringToKey::IteratedAndSalted {
        hash_alg: HashAlgorithm::Sha256,
        salt,
        count,
    };
    
    let sym_key_algo = SymmetricKeyAlgorithm::AES256;

    // 4. Encrypt and armor the message
    let message = MessageBuilder::from_reader("deezel-keystore", &entropy[..]);
    let mut enc_builder = message.seipd_v1(&mut OsRng, sym_key_algo);
    enc_builder.encrypt_with_password(s2k, &Password::from(passphrase))
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;

    let armored_message = enc_builder.to_armored_string(OsRng, ArmorOptions::default())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;

    // 5. Populate Keystore struct
    Ok(Keystore {
        encrypted_seed: armored_message,
        pbkdf2_params: Pbkdf2Params {
            salt: hex::encode(salt),
            iterations,
            algorithm: format!("{:?}", sym_key_algo),
        },
        addresses,
        version: 1,
    })
}

/// Creates a new encrypted keystore from a given mnemonic.
pub fn new_from_mnemonic(passphrase: &str, mnemonic_str: &str, network: BitcoinNetwork) -> Result<Keystore> {
    let secp = Secp256k1::new();
    
    // 1. Use provided mnemonic and generate seed
    let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English)
        .map_err(|e| DeezelError::Wallet(format!("Invalid mnemonic: {:?}", e)))?;
    let seed = Seed::new(&mnemonic, "");

    // 2. Derive addresses for the specified network
    let root_key = Xpriv::new_master(network, seed.as_bytes())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;
    
    let mut addresses = HashMap::new();
    let mut address_infos = Vec::new();

    // P2WPKH
    let path_str = "m/84'/1'/0'/0/0".to_string();
    let path = DerivationPath::from_str(&path_str).unwrap();
    let child_key = root_key.derive_priv(&secp, &path).unwrap();
    let keypair = child_key.to_keypair(&secp);
    let secp_pubkey = keypair.public_key();
    let bitcoin_pubkey = PublicKey::new(secp_pubkey);
    let network_config = network_to_config(network);
    let address = DeezelAddress::p2wpkh(&bitcoin_pubkey, &network_config).unwrap();
    address_infos.push(AddressInfo {
        path: path_str,
        address: address.to_string().unwrap(),
        address_type: "p2wpkh".to_string(),
    });
    
    addresses.insert(network.to_string(), address_infos);

    // 3. Prepare PGP symmetric encryption
    let iterations = 100_000;
    let mut salt = [0u8; 8];
    OsRng.fill_bytes(&mut salt);
    let count = encode_count(iterations);
    let s2k = StringToKey::IteratedAndSalted {
        hash_alg: HashAlgorithm::Sha256,
        salt,
        count,
    };
    
    let sym_key_algo = SymmetricKeyAlgorithm::AES256;

    // 4. Encrypt and armor the seed's entropy
    let message = MessageBuilder::from_reader("deezel-keystore", mnemonic.entropy());
    let mut enc_builder = message.seipd_v1(&mut OsRng, sym_key_algo);
    enc_builder.encrypt_with_password(s2k, &Password::from(passphrase))
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;

    let armored_message = enc_builder.to_armored_string(OsRng, ArmorOptions::default())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;

    // 5. Populate Keystore struct
    Ok(Keystore {
        encrypted_seed: armored_message,
        pbkdf2_params: Pbkdf2Params {
            salt: hex::encode(salt),
            iterations,
            algorithm: format!("{:?}", sym_key_algo),
        },
        addresses,
        version: 1,
    })
}

// This is a reimplementation of the logic in deezel-rpgp, as it is not public.
// https://www.rfc-editor.org/rfc/rfc4880#section-3.7.1.3
fn encode_count(iterations: u32) -> u8 {
    if iterations >= 65011712 {
        return 255;
    }
    if iterations == 0 {
        return 0;
    }

    let mut c = iterations;
    let mut e = 0;
    while c > 32 {
        c = (c + 15) / 16;
        e += 1;
    }
    c -= 16;

    (e << 4) | c as u8
}

/// Decrypts the seed from a keystore using the provided passphrase.
pub fn decrypt_seed(keystore: &Keystore, passphrase: &str) -> Result<Seed> {
    let (message, _headers) = deezel_rpgp::composed::Message::from_armor(keystore.encrypted_seed.as_bytes())
        .map_err(|e| DeezelError::Crypto(format!("Failed to parse armored message: {}", e)))?;

    let mut decryptor = message.decrypt_with_password(&Password::from(passphrase))
        .map_err(|e| {
            DeezelError::Crypto(format!("Failed to create decryptor: {}", e))
        })?;

    let decrypted_bytes = decryptor.as_data_vec()
        .map_err(|e| DeezelError::Crypto(format!("Failed to get decrypted data: {}", e)))?;
        
    let mnemonic = Mnemonic::from_entropy(&decrypted_bytes, Language::English)
        .map_err(|e| DeezelError::Wallet(format!("Failed to create mnemonic from decrypted seed: {:?}", e)))?;

    Ok(Seed::new(&mnemonic, ""))
}

/// Derives a Bitcoin address from a seed, derivation path, and network.
pub fn derive_address(seed: &Seed, path: &DerivationPath, network: BitcoinNetwork) -> Result<Address> {
    let secp = Secp256k1::new();
    let root_key = Xpriv::new_master(network, seed.as_bytes())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;
    
    let child_key = root_key.derive_priv(&secp, path)
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;
        
    let (internal_key, _) = Xpub::from_priv(&secp, &child_key).public_key.x_only_public_key();
    let network_config = network_to_config(network);
    let deezel_address = DeezelAddress::p2tr(&secp, internal_key, None, &network_config);
    
    // Convert back to bitcoin::Address for compatibility
    let address_str = deezel_address.to_string().map_err(|e| DeezelError::AddressResolution(e.to_string()))?;
    Address::from_str(&address_str)?.require_network(network).map_err(|e| DeezelError::AddressResolution(e.to_string()))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_keystore() {
        let passphrase = "testtesttest";
        let result = create_keystore(passphrase);
        // The deezel-rpgp bug has been fixed! Keystore creation should now succeed.
        assert!(result.is_ok());
        
        let keystore = result.unwrap();
        assert_eq!(keystore.version, 1);
        assert!(!keystore.encrypted_seed.is_empty());
        assert!(keystore.encrypted_seed.contains("-----BEGIN PGP MESSAGE-----"));
        assert!(keystore.encrypted_seed.contains("-----END PGP MESSAGE-----"));
        
        // Verify we have addresses for all networks
        assert!(keystore.addresses.contains_key("mainnet"));
        assert!(keystore.addresses.contains_key("testnet"));
        assert!(keystore.addresses.contains_key("signet"));
        assert!(keystore.addresses.contains_key("regtest"));
        
        // Verify each network has 20 addresses (10 P2WPKH + 10 P2TR)
        for (network, addresses) in &keystore.addresses {
            assert_eq!(addresses.len(), 20, "Network {} should have 20 addresses", network);
            
            // Check that we have both P2WPKH and P2TR addresses
            let p2wpkh_count = addresses.iter().filter(|a| a.address_type == "p2wpkh").count();
            let p2tr_count = addresses.iter().filter(|a| a.address_type == "p2tr").count();
            assert_eq!(p2wpkh_count, 10, "Network {} should have 10 P2WPKH addresses", network);
            assert_eq!(p2tr_count, 10, "Network {} should have 10 P2TR addresses", network);
        }
    }
    
    #[test]
    fn test_symmetric_encryption_roundtrip() {
        let passphrase = "test_password";
        let data = "hello world";
    
        // Encrypt
        let iterations = 100_000;
        let mut salt = [0u8; 8];
        OsRng.fill_bytes(&mut salt);
        let count = encode_count(iterations);
        let s2k = StringToKey::IteratedAndSalted {
            hash_alg: HashAlgorithm::Sha256,
            salt,
            count,
        };
        let sym_key_algo = SymmetricKeyAlgorithm::AES256;
        let message = MessageBuilder::from_reader("test", data.as_bytes());
        let mut enc_builder = message.seipd_v1(&mut OsRng, sym_key_algo);
        enc_builder.encrypt_with_password(s2k, &Password::from(passphrase)).unwrap();
        let armored_message = enc_builder.to_armored_string(OsRng, ArmorOptions::default()).unwrap();
    
        // Decrypt
        let (decrypted_message, _headers) = deezel_rpgp::composed::Message::from_armor(armored_message.as_bytes()).unwrap();
        let mut decryptor = decrypted_message.decrypt_with_password(&Password::from(passphrase)).unwrap();
        let decrypted_bytes = decryptor.as_data_vec().unwrap();
    
        assert_eq!(data.as_bytes(), decrypted_bytes.as_slice());
    }

    #[test]
    fn test_decrypt_keystore() {
        // The deezel-rpgp bug has been fixed! We can now encrypt and decrypt in the same process.
        let passphrase = "testtesttest";
        
        // Create a keystore
        let keystore = create_keystore(passphrase).expect("Failed to create keystore");
        
        let decrypted_seed = decrypt_seed(&keystore, passphrase);
        assert!(decrypted_seed.is_ok());
        assert!(!keystore.encrypted_seed.is_empty());
        assert!(keystore.encrypted_seed.contains("-----BEGIN PGP MESSAGE-----"));
        assert!(keystore.encrypted_seed.contains("-----END PGP MESSAGE-----"));
        
        println!("Successfully created and verified keystore structure");
        println!("Encrypted seed length: {}", keystore.encrypted_seed.len());
        println!("Number of networks: {}", keystore.addresses.len());
    }
}