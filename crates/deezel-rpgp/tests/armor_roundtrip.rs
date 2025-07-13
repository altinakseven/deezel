use deezel_rpgp::{
    composed::{
        message::MessageBuilder,
        types::{ArmorOptions, Message},
    },
    crypto::sym::SymmetricKeyAlgorithm,
    types::{Password, StringToKey},
};
use rand::thread_rng;

#[test]
fn test_armor_roundtrip_with_password() {
    let mut rng = thread_rng();
    let passphrase = "test_password";
    let content = "This is a secret message.";

    // 1. Encrypt and Armor
    let armored_message = {
        let s2k = StringToKey::new_default(&mut rng);
        let builder = MessageBuilder::from_bytes("test.txt", content.as_bytes());
        let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_with_password(s2k, &passphrase.into())
            .expect("Encryption failed");

        builder
            .to_armored_string(
                &mut rng,
                ArmorOptions {
                    headers: None,
                    include_checksum: true,
                },
            )
            .expect("Armoring failed")
    };

    println!("---BEGIN ARMORED MESSAGE---\n{}\n---END ARMORED MESSAGE---", armored_message);

    // 2. De-armor and Decrypt (the part that fails)
    let (message, _headers) = Message::from_armor(armored_message.as_bytes())
        .expect("Failed to parse armored message (de-armor failed)");

    let mut decryptor = message
        .decrypt_with_password(&Password::from(passphrase))
        .expect("Failed to create decryptor");

    let decrypted_bytes = decryptor
        .as_data_vec()
        .expect("Failed to get decrypted data");

    let decrypted_content = String::from_utf8(decrypted_bytes).expect("Failed to decode UTF-8");

    assert_eq!(content, decrypted_content);
}