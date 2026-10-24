# esteid-cryptoki

Estonian ID cards over PKCS#11, built on [tokenkey](https://crates.io/crates/tokenkey).

- Finds the connected card and pairs its authentication (PIN1) and signing (PIN2) keys
- Signing and ECDH with either key, through tokenkey's `TokenKey`

Requires [OpenSC](https://github.com/OpenSC/OpenSC).

## Usage

```rust,no_run
use esteid_cryptoki::IdCard;
use tokenkey::{Hash, SignScheme};

fn example(pin1: &str, pin2: &str) -> esteid_cryptoki::Result<()> {
    let card = IdCard::find()?;
    println!("Document number: {}", card.document_number());

    let auth = card.open_auth(pin1)?;
    let challenge_signature = auth.sign(SignScheme::Ecdsa(Hash::Sha384), b"challenge")?;

    let signing = card.open_signing(pin2)?;
    let document_signature = signing.sign(SignScheme::Ecdsa(Hash::Sha384), b"document")?;
    Ok(())
}
```

`IdCard::find` errors unless exactly one card is connected. Use `IdCard::list`
to get every connected card.

## Examples

With a card connected:

```sh
cargo run -p esteid-cryptoki --example detect_card
cargo run -p esteid-cryptoki --example ecdh
```

## License

Apache-2.0
