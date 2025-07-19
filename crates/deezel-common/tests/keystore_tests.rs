// This file is part of the deezel project.
// Copyright (c) 2024, The Deezel Developers, all rights reserved.
// Deezel is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

//! Keystore encryption and decryption tests for deezel-common.

use deezel_common::keystore::Keystore;
use bip39::{Mnemonic, Seed};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::network::Network;
use bip39::MnemonicType;
use std::str::FromStr;

#[test]
fn test_keystore_armoring_dearmoring_roundtrip() {
    // 1. Generate a new mnemonic
    let mnemonic = Mnemonic::new(MnemonicType::Words12, bip39::Language::English);
    let mnemonic_phrase = mnemonic.to_string();

    // 2. Armor the mnemonic
    let mut armored_seed = Vec::new();
    deezel_asc::armor::writer::write(
        mnemonic_phrase.as_bytes(),
        deezel_asc::armor::reader::BlockType::PrivateKey,
        &mut armored_seed,
        None,
        true,
    )
    .unwrap();
    let armored_seed_str = String::from_utf8(armored_seed).unwrap();

    // 3. Create a Keystore instance
    let keystore = Keystore {
        encrypted_seed: armored_seed_str,
        master_fingerprint: "mock_fingerprint".to_string(),
        created_at: 0,
        version: "1.0".to_string(),
        pbkdf2_params: Default::default(),
        account_xpub: "mock_xpub".to_string(),
        addresses: Default::default(),
    };

    // 4. Dearmor the seed from the keystore
    let dearmored_seed_bytes = keystore.get_seed_from_armor().unwrap();
    let dearmored_mnemonic_phrase = dearmored_seed_bytes;

    // 5. Verify that the dearmored mnemonic is the same as the original
    assert_eq!(mnemonic_phrase, dearmored_mnemonic_phrase);

    // 6. Derive a private key from the original mnemonic
    let seed = Seed::new(&mnemonic, "");
    let root = Xpriv::new_master(Network::Regtest, seed.as_bytes()).unwrap();
    let path = DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
    let original_xpriv = root.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &path).unwrap();

    // 7. Derive a private key from the dearmored mnemonic
    let dearmored_mnemonic =
        Mnemonic::from_phrase(&dearmored_mnemonic_phrase, bip39::Language::English).unwrap();
    let dearmored_seed = Seed::new(&dearmored_mnemonic, "");
    let dearmored_root = Xpriv::new_master(Network::Regtest, dearmored_seed.as_bytes()).unwrap();
    let dearmored_xpriv =
        dearmored_root.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &path).unwrap();

    // 8. Verify that the derived private keys are identical
    assert_eq!(original_xpriv, dearmored_xpriv);
}