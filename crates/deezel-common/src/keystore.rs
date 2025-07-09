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
    bip32::{DerivationPath, ExtendedPrivKey},
    network::constants::Network as BitcoinNetwork,
    secp256k1::{Secp256k1},
    Address,
};
use bip39::{Mnemonic, Seed};
use rand::{rngs::OsRng, RngCore};
use deezel_rpgp::{
    composed::{Message, PublicOrSymmetricKey},
    crypto::{sym::SymmetricKeyAlgorithm, hash::HashAlgorithm},
    types::StringToKey,
};
use std::collections::HashMap;
use std::str::FromStr;
use crate::{DeezelError, Result};

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

/// Creates a new encrypted keystore.
pub fn create_keystore(passphrase: &str) -> Result<Keystore> {
    let secp = Secp256k1::new();
    
    // 1. Generate mnemonic and seed
    let mnemonic = Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    let seed = Seed::new(&mnemonic, "");

    // 2. Prepare PGP symmetric encryption
    let message = Message::new_literal("deezel-keystore", seed.as_bytes());
    
    let iterations = 100_000;
    let mut s2k = StringToKey::new_iterated(HashAlgorithm::SHA256, iterations);
    let mut salt = [0u8; 8];
    OsRng.fill_bytes(&mut salt);
    s2k.set_salt(salt.to_vec());
    
    let sym_key_algo = SymmetricKeyAlgorithm::AES256;

    let sym_key = PublicOrSymmetricKey::new_symmetric_key(
        passphrase,
        sym_key_algo,
        s2k,
    ).map_err(|e| DeezelError::Crypto(e.to_string()))?;

    // 3. Encrypt and armor the message
    let armored_message = message.encrypt_to_armored_string(
        &sym_key,
        None, // No signature
    ).map_err(|e| DeezelError::Crypto(e.to_string()))?;

    // 4. Derive addresses
    let root_key = ExtendedPrivKey::new_master(BitcoinNetwork::Bitcoin, seed.as_bytes())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;
    
    let mut addresses = HashMap::new();
    let networks = [
        ("mainnet", BitcoinNetwork::Bitcoin),
        ("testnet", BitcoinNetwork::Testnet),
        ("signet", BitcoinNetwork::Signet),
        ("regtest", BitcoinNetwork::Regtest),
    ];

    for (net_name, network) in &networks {
        let mut address_infos = Vec::new();
        for i in 0..10 {
            // P2WPKH
            let path_str = format!("m/84'/0'/0'/0/{}", i);
            let path = DerivationPath::from_str(&path_str).unwrap();
            let child_key = root_key.derive_priv(&secp, &path).unwrap();
            let pubkey = child_key.to_extended_pub(&secp).public_key;
            let address = Address::p2wpkh(&pubkey, *network).unwrap();
            address_infos.push(AddressInfo {
                path: path_str,
                address: address.to_string(),
                address_type: "p2wpkh".to_string(),
            });

            // P2TR
            let path_str = format!("m/86'/0'/0'/0/{}", i);
            let path = DerivationPath::from_str(&path_str).unwrap();
            let child_key = root_key.derive_priv(&secp, &path).unwrap();
            let (internal_key, _) = child_key.to_extended_pub(&secp).public_key.x_only_public_key();
            let address = Address::p2tr(&secp, internal_key, None, *network);
            address_infos.push(AddressInfo {
                path: path_str,
                address: address.to_string(),
                address_type: "p2tr".to_string(),
            });
        }
        addresses.insert(net_name.to_string(), address_infos);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use deezel_rpgp::composed::Deserializable;

    #[test]
    fn test_create_and_decrypt_keystore() {
        let passphrase = "testtesttest";
        let keystore = create_keystore(passphrase).unwrap();

        // Verify keystore contents
        assert_eq!(keystore.version, 1);
        assert_eq!(keystore.addresses.len(), 4);
        assert_eq!(keystore.addresses.get("mainnet").unwrap().len(), 20);
        assert!(keystore.encrypted_seed.starts_with("-----BEGIN PGP MESSAGE-----"));

        // Attempt to decrypt
        let (message, _) = Message::from_armored_str(&keystore.encrypted_seed).unwrap();
        
        let (decrypted_message, _) = message.decrypt_with_password(passphrase).unwrap();

        let decrypted_content = match &decrypted_message {
            Message::Literal(data) => data.data(),
            _ => panic!("Expected literal data"),
        };

        // The decrypted content should be a 64-byte seed
        assert_eq!(decrypted_content.len(), 64);
    }
}