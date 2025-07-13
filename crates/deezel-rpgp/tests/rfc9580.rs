#![cfg(feature = "std")]
use deezel_rpgp::io::Read;
use deezel_rpgp::{
    composed::{
        CleartextSignedMessage, Deserializable, KeyType, Message, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        sym::SymmetricKeyAlgorithm,
    },
    types::{KeyVersion, Password},
};
use deezel_rpgp::composed::MessageBuilder;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const MSG: &str = "hello world\n";

// Test cases based on keys with new formats from RFC9580
const CASES_9580: &[&str] = &[
    ("tests/rfc9580/v6-25519-annex-a-4"), // TSK from RFC 9580 Annex A.4 (Ed25519/X25519)
    ("tests/rfc9580/v6-ed448-x448"),      // TSK using Ed448/X448
    ("tests/rfc9580/v6-ed25519-x448"), // TSK using Ed25519/X448 (mixed 25519 and 448 component keys)
    ("tests/rfc9580/v6-rsa"),          // TSK using RSA
    ("tests/rfc9580/v6-nistp"),        // TSK using NIST P-256
    ("tests/rfc9580/v4-ed25519-x25519"), // Version 4 TSK using the RFC 9580 Ed25519/X25519 formats
];

// Test cases based on keys that don't use new formats from RFC9580.
// These keys are traditional v4 keys, but they have the SEIPDv2 feature flag enabled.
const CASES_PRE_9580: &[&str] = &[
    ("tests/rfc9580/v4-rsa"),    // Version 4 TSK using RSA
    ("tests/rfc9580/v4-nistp"),  // Version 4 TSK using NIST P-256
    ("tests/rfc9580/v4-legacy"), // Version 4 TSK using Ed25519Legacy and Curve25519Legacy
];

fn load_ssk(filename: &str) -> SignedSecretKey {
    let bytes = std::fs::read(filename).unwrap();
    let (key, _) = SignedSecretKey::from_armor_single(&bytes).unwrap();
    key
}

fn try_decrypt(keyfile: &str, msg_file: &str) {
    use deezel_rpgp::io::Read;
    let ssk = load_ssk(keyfile);

    // load seipdv1 msg, decrypt
    let msg_bytes = std::fs::read(msg_file).unwrap();
    let (message, _) = Message::from_armor(&msg_bytes).expect("ok");
    let mut dec = message.decrypt(&Password::empty(), &ssk).expect("decrypt");

    let mut decrypted = String::new();
    dec.read_to_string(&mut decrypted).unwrap();

    assert_eq!(decrypted, MSG);
}

#[test]
fn rfc9580_decrypt_seipdv1_msg() {
    for case in CASES_9580 {
        try_decrypt(
            &format!("{}/tsk.asc", case),
            &format!("{}/enc-seipdv1.msg", case),
        );
    }
}

#[test]
fn rfc9580_decrypt_seipdv2_msg() {
    for case in CASES_9580.iter().chain(CASES_PRE_9580.iter()) {
        try_decrypt(
            &format!("{}/tsk.asc", case),
            &format!("{}/enc-seipdv2.msg", case),
        );
    }
}

#[test]
fn rfc9580_verify_csf() {
    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let csffile = format!("{}/csf.msg", case);

        let ssk = load_ssk(&keyfile);
        let spk = SignedPublicKey::from(ssk.clone());

        spk.verify().expect("SignedPublicKey::verify");

        // load+verify csf msg
        let csf_bytes = std::fs::read(csffile).unwrap();
        let (csf, _) =
            CleartextSignedMessage::from_armor(&csf_bytes).expect("csf loaded");

        csf.verify(&spk).expect("verify ok");
    }
}

#[test]
fn rfc9580_seipdv1_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());
        let enc_subkey = &spk.public_subkeys.first().unwrap().key;

        // SEIPDv1 encrypt/decrypt roundtrip
        let mut builder =
            MessageBuilder::from_bytes("", MSG.as_bytes()).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.encrypt_to_key(&mut rng, enc_subkey).unwrap();
        let enc = builder.to_vec(&mut rng).unwrap();

        let msg = Message::from_bytes(&enc[..]).unwrap();
        let mut dec = msg.decrypt(&Password::empty(), &ssk).expect("decrypt");

        let mut data = String::new();
        dec.read_to_string(&mut data).unwrap();
        assert_eq!(data, MSG);
    }
}

#[test]
fn rfc9580_seipdv2_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580.iter().chain(CASES_PRE_9580.iter()) {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());
        let enc_subkey = &spk.public_subkeys.first().unwrap().key;

        // SEIPDv2 encrypt/decrypt roundtrip
        let mut builder = MessageBuilder::from_bytes("", MSG.as_bytes()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder.encrypt_to_key(&mut rng, enc_subkey).unwrap();
        let enc = builder.to_vec(&mut rng).unwrap();

        let msg = Message::from_bytes(&enc[..]).unwrap();
        let mut dec = msg.decrypt(&Password::empty(), &ssk).expect("decrypt");

        let mut data = String::new();
        dec.read_to_string(&mut data).unwrap();
        assert_eq!(data, MSG);
    }
}

#[test]
fn rfc9580_roundtrip_csf() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());

        // roundtrip sign+verify csf
        let csf =
            CleartextSignedMessage::sign(&mut rng, MSG, &*ssk, &Password::empty()).expect("sign");
        csf.verify(&spk).expect("verify");
    }
}

#[test]
fn rfc9580_roundtrip_sign_verify_inline_msg() {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for case in CASES_9580 {
        let keyfile = format!("{}/tsk.asc", case);
        let ssk = load_ssk(&keyfile);

        let spk = SignedPublicKey::from(ssk.clone());

        use deezel_rpgp::crypto::hash::HashAlgorithm;
        use deezel_rpgp::io::Read;

        let mut builder = MessageBuilder::from_bytes("", MSG.as_bytes());
        builder.sign(&*ssk, Password::empty(), HashAlgorithm::Sha256);
        let msg = builder.to_vec(&mut rng).unwrap();

        let mut msg = Message::from_bytes(&msg[..]).unwrap();
        let _ = msg.verify_read(&spk).expect("verify");
        let mut data = Vec::new();
        msg.read_to_end(&mut data).unwrap();
        assert_eq!(data, MSG.as_bytes());
    }
}

#[test]
fn rfc9580_legacy_25519_illegal_in_v6() {
    // Ensure that rPGP rejects v6 EdDSA legacy or ECDH(Curve25519) keys

    // "The deprecated OIDs for Ed25519Legacy and Curve25519Legacy are used only in version 4 keys
    // and signatures. [..] Implementations MUST NOT accept or generate version 6 key material
    // using the deprecated OIDs."
    //
    // See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.2-6

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    // -- Try (and fail) to load a v6/legacy key --
    let key_bytes = std::fs::read("tests/rfc9580/v6-legacy_illegal/tsk.asc").unwrap();
    let res = SignedSecretKey::from_armor_single(&key_bytes);

    // we expect an error about the illegal legacy parameters in a v6 key
    assert!(res.is_err());

    // -- Create a v6 ed25519 legacy signing key, expect failure --
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519Legacy)
        .version(KeyVersion::V6)
        .can_sign(true)
        .primary_user_id("Me <me@example.com>".into());
    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");
    let res = secret_key_params.generate(&mut rng);

    assert!(res.is_err());

    // -- Create a v6 curve 25519 legacy encryption key, expect failure --
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::ECDH(ECCCurve::Curve25519))
        .version(KeyVersion::V6)
        .can_encrypt(true)
        .primary_user_id("Me <me@example.com>".into());
    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");
    let res = secret_key_params.generate(&mut rng);

    assert!(res.is_err());
}
