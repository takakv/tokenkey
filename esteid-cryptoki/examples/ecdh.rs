//! Checks the ID card's ECDH against a software ECDH with the same keys.
//!
//! Run with:
//!   cargo run -p esteid-cryptoki --example ecdh

use esteid_cryptoki::{EstEidError, IdCard};
use p384::ecdh::EphemeralSecret;
use p384::elliptic_curve::Generate;
use p384::elliptic_curve::sec1::ToSec1Point;
use x509_cert::der::Decode;

fn main() {
    let card = match IdCard::find() {
        Ok(card) => card,
        Err(EstEidError::NoCard) => {
            println!(
                "No Estonian ID card detected.\n  Make sure a card is inserted into the reader."
            );
            return;
        }
        Err(e) => {
            println!("Could not find an ID card: {e}");
            return;
        }
    };
    println!("Using ID card {}", card.document_number());

    let card_public_key = match auth_public_key(card.auth_certificate_der()) {
        Ok(key) => key,
        Err(e) => {
            println!("Could not read the card's public key: {e}");
            return;
        }
    };

    let ephemeral = EphemeralSecret::generate();
    let ephemeral_public = ephemeral.public_key().as_affine().to_uncompressed_point();
    let software = ephemeral.diffie_hellman(&card_public_key);

    let pin1 = match rpassword::prompt_password("PIN1: ") {
        Ok(pin) => pin,
        Err(e) => {
            println!("Could not read PIN1: {e}");
            return;
        }
    };
    let token = match card.open_auth(&pin1) {
        Ok(token) => token,
        Err(e) => {
            println!("Could not open the authentication key: {e}");
            return;
        }
    };
    drop(pin1);

    let on_card = match token.derive_ecdh(&ephemeral_public) {
        Ok(secret) => secret,
        Err(e) => {
            println!("ECDH on the card failed: {e}");
            return;
        }
    };

    let software = software.raw_secret_bytes().as_slice();
    if on_card == software {
        println!("Shared secrets match ({} bytes).", on_card.len());
    } else {
        println!(
            "Shared secrets DO NOT match (card {} bytes, software {} bytes).",
            on_card.len(),
            software.len()
        );
    }
}

/// The P-384 public key from the authentication certificate.
fn auth_public_key(cert_der: &[u8]) -> Result<p384::PublicKey, String> {
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|e| e.to_string())?;
    let point = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    p384::PublicKey::from_sec1_bytes(point).map_err(|_| "not a P-384 public key".into())
}
