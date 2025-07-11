use deezel_rpgp::armor;

fn main() {
    let test_key = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=XyBX
-----END PGP PUBLIC KEY BLOCK-----"#;

    println!("Testing armor decode...");
    match armor::decode(test_key.as_bytes()) {
        Ok((typ, headers, decoded)) => {
            println!("Success!");
            println!("Type: {:?}", typ);
            println!("Headers: {:?}", headers);
            println!("Decoded length: {}", decoded.len());
            println!("First 50 bytes: {:?}", &decoded[..50.min(decoded.len())]);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}