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
    Address,
    bip32::Xpub,
    CompressedPublicKey,
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
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    // 2. Prepare PGP symmetric encryption
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

    // 3. Encrypt and armor the message
    let message = MessageBuilder::from_bytes("deezel-keystore", seed.as_bytes().to_vec());
    let mut enc_builder = message.seipd_v1(&mut OsRng, sym_key_algo);
    enc_builder.encrypt_with_password(s2k, &Password::from(passphrase))
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;

    let armored_message = enc_builder.to_armored_string(OsRng, ArmorOptions::default())
        .map_err(|e| DeezelError::Crypto(e.to_string()))?;

    // 4. Derive addresses
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
        let mut address_infos = Vec::new();
        for i in 0..10 {
            // P2WPKH
            let path_str = format!("m/84'/0'/0'/0/{}", i);
            let path = DerivationPath::from_str(&path_str).unwrap();
            let child_key = root_key.derive_priv(&secp, &path).unwrap();
            let pubkey = Xpub::from_priv(&secp, &child_key).public_key;
            let compressed_pubkey = CompressedPublicKey(pubkey);
            let address = Address::p2wpkh(&compressed_pubkey, *network);
            address_infos.push(AddressInfo {
                path: path_str,
                address: address.to_string(),
                address_type: "p2wpkh".to_string(),
            });

            // P2TR
            let path_str = format!("m/86'/0'/0'/0/{}", i);
            let path = DerivationPath::from_str(&path_str).unwrap();
            let child_key = root_key.derive_priv(&secp, &path).unwrap();
            let (internal_key, _) = Xpub::from_priv(&secp, &child_key).public_key.x_only_public_key();
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


#[cfg(test)]
mod tests {
    use super::*;

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
        let (message, _) = deezel_rpgp::composed::Message::from_armor(keystore.encrypted_seed.as_bytes()).unwrap();
        let decrypted_message = message.decrypt_with_password(&Password::from(passphrase)).unwrap();

        let decrypted_content = match decrypted_message {
            deezel_rpgp::composed::Message::Literal { mut reader, .. } => {
                let mut buf = Vec::new();
                deezel_rpgp::io::Read::read_to_end(&mut reader, &mut buf).unwrap();
                buf
            },
            _ => panic!("Expected literal data"),
        };

        // The decrypted content should be a 64-byte seed
        assert_eq!(decrypted_content.len(), 64);
    }
}