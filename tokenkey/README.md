# tokenkey

Private-key operations on PKCS#11 tokens.

- ECDSA signing on P-256, P-384 and P-521, with SHA-256, SHA-384 or SHA-512
- ECDH key agreement with P-256, P-384 and P-521.

PIN pads are not currently supported.

## Usage

Open a key and use it:

```rust,no_run
use tokenkey::{Hash, KeyLocator, KeySelect, SignScheme, SlotSelect, TokenKey};

fn example(pin: &str, peer_public_key: &[u8]) -> tokenkey::Result<()> {
    let locator = KeyLocator {
        module: "/usr/lib/softhsm/libsofthsm2.so".into(),
        slot: SlotSelect::TokenLabel("my-token".into()),
        key: KeySelect::Label("my-key".into()),
    };
    let key = TokenKey::open(&locator, pin)?;

    let signature = key.sign(SignScheme::Ecdsa(Hash::Sha256), b"message")?;

    // `peer_public_key` is an uncompressed point, `0x04 || X || Y`.
    let shared_secret = key.derive_ecdh(peer_public_key)?;
    Ok(())
}
```

Or find keys by their certificates first:

```rust,no_run
use tokenkey::{ModuleSpec, TokenKey, discover};

fn example(pin: &str) -> tokenkey::Result<()> {
    let found = discover(&[ModuleSpec {
        name: "opensc-pkcs11".into(),
        paths: vec!["/usr/lib/opensc-pkcs11.so".into()],
    }]);
    for key in &found.keys {
        println!("{} (slot {}): {:?}", key.token_label, key.slot_id, key.usage);
    }

    if let Some(found_key) = found.keys.first() {
        let key = TokenKey::open_discovered(found_key, pin)?;
        println!("{:?}", key.algorithm()?);
    }
    Ok(())
}
```

## License

Apache-2.0
