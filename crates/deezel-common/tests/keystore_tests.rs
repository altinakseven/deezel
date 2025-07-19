// This file is part of the deezel project.
// Copyright (c) 2024, The Deezel Developers, all rights reserved.
// Deezel is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

//! Keystore encryption and decryption tests for deezel-common.

use deezel_common::keystore::Keystore;
use bip39::{Mnemonic, MnemonicType};
use bitcoin::bip32::DerivationPath;
use bitcoin::network::Network;
use std::str::FromStr;
use deezel_common::keystore::{derive_address, derive_address_from_public_key};

#[test]
fn test_address_derivation_consistency() {
    // 1. Generate a new mnemonic
    let mnemonic = Mnemonic::new(MnemonicType::Words12, bip39::Language::English);
    let network = Network::Regtest;

    // 2. Create a Keystore, which will generate the account_xpub internally
    let keystore = Keystore::new(&mnemonic, network, "test-password", None).unwrap();
    let account_xpub = &keystore.account_xpub;

    // 3. Define script types and derivation paths to test
    // These paths are relative to the account xpub (m/86'/0'/0')
    let test_cases = vec![
        ("p2tr", "m/0/0"),
        ("p2tr", "m/0/1"),
        ("p2tr", "m/1/0"),
    ];

    for (script_type, path_str) in test_cases {
        println!("Testing {}: {}", script_type, path_str);
        let path = DerivationPath::from_str(path_str).unwrap();

        // 4. Derive address from the public key path (account_xpub)
        let from_pubkey = derive_address_from_public_key(account_xpub, &path, network).unwrap();

        // 5. Derive address from the private key path (mnemonic)
        // The full path needs to be constructed relative to the master key.
        let full_path_str = format!("m/86'/0'/0'/{}", path_str.strip_prefix("m/").unwrap());
        let full_path = DerivationPath::from_str(&full_path_str).unwrap();
        let from_privkey = derive_address(mnemonic.phrase(), &full_path, network).unwrap();

        // 6. Compare the addresses
        assert_eq!(
            from_pubkey, from_privkey,
            "Address mismatch for {} at path {}",
            script_type, path_str
        );
    }
}

#[test]
fn test_keystore_encryption_decryption_roundtrip() {
    // 1. Generate a new mnemonic and passphrase
    let mnemonic = Mnemonic::new(MnemonicType::Words12, bip39::Language::English);
    let mnemonic_phrase = mnemonic.to_string();
    let passphrase = "supersecretpassword";
    let network = Network::Regtest;

    // 2. Create a new keystore, which encrypts the mnemonic
    let keystore = Keystore::new(&mnemonic, network, passphrase, None).unwrap();

    // 3. Decrypt the mnemonic from the keystore
    let decrypted_mnemonic_phrase = keystore.decrypt_mnemonic(passphrase).unwrap();

    // 4. Verify that the decrypted mnemonic is the same as the original
    assert_eq!(mnemonic_phrase, decrypted_mnemonic_phrase);

    // 5. Verify that decryption fails with the wrong password
    let wrong_passphrase = "wrongpassword";
    assert!(keystore.decrypt_mnemonic(wrong_passphrase).is_err());
}