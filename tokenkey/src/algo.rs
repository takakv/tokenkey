use cryptoki::mechanism::Mechanism;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::der::Decode;
use x509_cert::der::oid::ObjectIdentifier;

use crate::error::{Result, TokenkeyError};

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ec(EcCurve),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignScheme {
    Ecdsa(Hash),
}

impl EcCurve {
    /// Length of the curve's field elements in bytes.
    pub(crate) fn field_len(self) -> usize {
        match self {
            EcCurve::P256 => 32,
            EcCurve::P384 => 48,
            EcCurve::P521 => 66,
        }
    }

    /// The curve of an uncompressed SEC1 point, `0x04 || X || Y`, by its length.
    pub(crate) fn from_uncompressed_point(point: &[u8]) -> Option<EcCurve> {
        if point.first() != Some(&0x04) {
            return None;
        }
        [EcCurve::P256, EcCurve::P384, EcCurve::P521]
            .into_iter()
            .find(|curve| point.len() == 2 * curve.field_len() + 1)
    }
}

impl KeyAlgorithm {
    pub fn from_certificate_der(cert_der: &[u8]) -> Result<KeyAlgorithm> {
        let cert = x509_cert::Certificate::from_der(cert_der).map_err(|e| {
            TokenkeyError::Certificate(format!("certificate is not valid DER: {e}"))
        })?;
        let spki = cert.tbs_certificate().subject_public_key_info();
        let alg_oid = spki.algorithm.oid;

        if alg_oid == OID_EC_PUBLIC_KEY {
            let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
                TokenkeyError::Unsupported("explicit EC parameters are not supported".into())
            })?;
            let curve: ObjectIdentifier = params.decode_as().map_err(|e| {
                TokenkeyError::Certificate(format!("named curve parameter is not an OID: {e}"))
            })?;
            if curve == OID_P256 {
                return Ok(KeyAlgorithm::Ec(EcCurve::P256));
            }
            if curve == OID_P384 {
                return Ok(KeyAlgorithm::Ec(EcCurve::P384));
            }
            if curve == OID_P521 {
                return Ok(KeyAlgorithm::Ec(EcCurve::P521));
            }
            return Err(TokenkeyError::Unsupported(format!(
                "unsupported EC curve {curve} (only P-256/P-384/P-521)"
            )));
        }

        Err(TokenkeyError::Unsupported(format!(
            "unsupported key algorithm {alg_oid} (only EC P-256/P-384/P-521)"
        )))
    }
}

pub(crate) fn mechanism_and_input(
    scheme: SignScheme,
    data: &[u8],
) -> Result<(Mechanism<'static>, Vec<u8>)> {
    match scheme {
        SignScheme::Ecdsa(hash) => Ok((Mechanism::Ecdsa, digest(hash, data))),
    }
}

fn digest(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => Sha256::digest(data).to_vec(),
        Hash::Sha384 => Sha384::digest(data).to_vec(),
        Hash::Sha512 => Sha512::digest(data).to_vec(),
    }
}
