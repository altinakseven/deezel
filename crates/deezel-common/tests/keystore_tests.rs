// This file is part of the deezel project.
// Copyright (c) 2024, The Deezel Developers, all rights reserved.
// Deezel is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

//! Keystore encryption and decryption tests for deezel-common.

use deezel_common::keystore::{Keystore, PbkdfParams};
use deezel_common::Result;
use bip39::{Mnemonic, Seed};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::network::Network;
use deezel_rpgp::{
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{Password, StringToKey},
    ser::Serialize,
    packet::{SymKeyEncryptedSessionKey, SymEncryptedProtectedData},
};
use bip39::MnemonicType;
use std::str::FromStr;

fn encrypt_mnemonic(mnemonic: &str, passphrase: &str) -> Result<(String, PbkdfParams)> {
    let mut rng = rand::thread_rng();
    let s2k = StringToKey::new_iterated(
        &mut rng,
        HashAlgorithm::Sha256,
        96, // Corresponds to 65536 iterations
    );

    let salt = match s2k.clone() {
        StringToKey::IteratedAndSalted { salt, .. } => salt,
        _ => return Err(anyhow::anyhow!("Expected iterated S2K").into()),
    };

    let sym_alg = SymmetricKeyAlgorithm::AES256;
    let session_key = sym_alg.new_session_key(&mut rng);

    let esk = SymKeyEncryptedSessionKey::encrypt_v4(
        &Password::from(passphrase.as_bytes()),
        &session_key,
        s2k,
        sym_alg,
    ).map_err(|e| anyhow::anyhow!(e))?;

    let seipd = SymEncryptedProtectedData::encrypt_seipdv1(
        &mut rng,
        sym_alg,
        &session_key,
        mnemonic.as_bytes(),
    ).map_err(|e| anyhow::anyhow!(e))?;

    let mut armored_writer = Vec::new();
    {
        let mut armor = deezel_rpgp::armor::ArmorWriter::new(&mut armored_writer, deezel_rpgp::armor::BlockType::Message.to_str(), Default::default())
            .map_err(|e| anyhow::anyhow!(e))?;
        esk.to_writer(&mut armor).map_err(|e| anyhow::anyhow!(e))?;
        seipd.to_writer(&mut armor).map_err(|e| anyhow::anyhow!(e))?;
        armor.finish().map_err(|e| anyhow::anyhow!(e))?;
    }
    let armored_message = String::from_utf8(armored_writer).map_err(|e| anyhow::anyhow!(e))?;

    Ok((
        armored_message,
        PbkdfParams {
            salt: hex::encode(salt),
            iterations: 65536, // The actual iteration count, not the coded one
            algorithm: Some("AES256".to_string()),
        },
    ))
}

#[test]
fn test_keystore_encryption_decryption_roundtrip() {
    // 1. Generate a new mnemonic
    let mnemonic = Mnemonic::new(MnemonicType::Words12, bip39::Language::English);
    let mnemonic_phrase = mnemonic.to_string();
    let passphrase = "test_password";

    // 2. Encrypt the mnemonic to create the keystore components
    let (encrypted_seed, pbkdf2_params) =
        encrypt_mnemonic(&mnemonic_phrase, passphrase).unwrap();

    // 3. Create a Keystore instance
    let keystore = Keystore {
        encrypted_seed,
        master_public_key: "mock_mpk".to_string(),
        master_fingerprint: "mock_fingerprint".to_string(),
        created_at: 0,
        version: "1.0".to_string(),
        pbkdf2_params,
        account_xpub: "mock_xpub".to_string(),
        addresses: Default::default(),
    };

    // 4. Decrypt the seed from the keystore
    let decrypted_mnemonic_phrase = keystore.decrypt_seed(passphrase).unwrap();

    // 5. Verify that the decrypted mnemonic is the same as the original
    assert_eq!(mnemonic_phrase, decrypted_mnemonic_phrase);

    // 6. Derive a private key from the original mnemonic
    let seed = Seed::new(&mnemonic, "");
    let root = Xpriv::new_master(Network::Regtest, seed.as_bytes()).unwrap();
    let path = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
    let original_xpriv = root.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &path).unwrap();

    // 7. Derive a private key from the decrypted mnemonic
    let decrypted_mnemonic = Mnemonic::from_phrase(&decrypted_mnemonic_phrase, bip39::Language::English).unwrap();
    let decrypted_seed = Seed::new(&decrypted_mnemonic, "");
    let decrypted_root = Xpriv::new_master(Network::Regtest, decrypted_seed.as_bytes()).unwrap();
    let decrypted_xpriv = decrypted_root.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &path).unwrap();

    // 8. Verify that the derived private keys are identical
    assert_eq!(original_xpriv, decrypted_xpriv);

    panic!("---\n{}\n---", keystore.encrypted_seed);
}