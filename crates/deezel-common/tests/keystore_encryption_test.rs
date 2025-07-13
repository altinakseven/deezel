use deezel_common::keystore;
use deezel_common::DeezelError;

#[test]
fn test_keystore_encrypt_decrypt_cycle() -> Result<(), DeezelError> {
    let passphrase = "a_very_secure_password";
    let (keystore, mnemonic) = keystore::create_keystore(passphrase, None)?;

    println!("Created keystore with encrypted seed: {}", keystore.encrypted_seed);

    let decrypted_mnemonic = keystore.decrypt_seed(passphrase)?;

    assert_eq!(mnemonic, decrypted_mnemonic, "Decrypted mnemonic does not match original");

    Ok(())
}