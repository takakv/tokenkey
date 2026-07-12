use std::path::PathBuf;

use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::KeyUsage;

use crate::algo::KeyAlgorithm;
use crate::error::Result;
use crate::pkcs11::initialize;
use crate::TokenkeyError;

/// A named PKCS#11 module and the candidate paths to search for it.
pub struct ModuleSpec {
    /// Friendly name for diagnostics.
    pub name: String,
    /// Candidate filesystem paths, tried in order.
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    Authentication,
    Signing,
    Other,
}

pub struct DiscoveredKey {
    pub module: PathBuf,
    pub slot_id: u64,
    pub token_label: String,
    pub token_serial: String,
    pub cert_der: Vec<u8>,
    /// `CKA_ID` of the certificate object, if present.
    pub key_id: Option<Vec<u8>>,
    /// `CKA_LABEL` of the certificate object, if present.
    pub key_label: Option<String>,
    pub usage: KeyClass,
}

impl DiscoveredKey {
    pub fn algorithm(&self) -> Result<KeyAlgorithm> {
        KeyAlgorithm::from_certificate_der(&self.cert_der)
    }
}

pub struct SkippedModule {
    pub path: PathBuf,
    pub error: TokenkeyError,
}

pub struct Discovery {
    pub keys: Vec<DiscoveredKey>,
    pub skipped: Vec<SkippedModule>,
}

pub fn discover(modules: &[ModuleSpec]) -> Discovery {
    let mut keys = Vec::new();
    let mut skipped = Vec::new();

    for spec in modules {
        let Some(path) = spec.paths.iter().find(|p| p.exists()) else {
            continue;
        };
        match enumerate_module(path, &mut keys) {
            Ok(()) => {}
            Err(error) => skipped.push(SkippedModule {
                path: path.clone(),
                error,
            }),
        }
    }

    Discovery { keys, skipped }
}

fn enumerate_module(path: &std::path::Path, keys: &mut Vec<DiscoveredKey>) -> Result<()> {
    let pkcs11 = initialize(path)?;
    let slots = pkcs11
        .get_slots_with_initialized_token()
        .map_err(|source| TokenkeyError::Pkcs11 {
            call: "C_GetSlotList",
            source,
        })?;

    for slot in slots {
        let token_info = pkcs11
            .get_token_info(slot)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_GetTokenInfo",
                source,
            })?;

        let session = pkcs11
            .open_ro_session(slot)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_OpenSession",
                source,
            })?;

        let cert_handles = session
            .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_FindObjects",
                source,
            })?;

        for handle in cert_handles {
            let attrs = session
                .get_attributes(
                    handle,
                    &[
                        AttributeType::Value,
                        AttributeType::Id,
                        AttributeType::Label,
                    ],
                )
                .map_err(|source| TokenkeyError::Pkcs11 {
                    call: "C_GetAttributeValue",
                    source,
                })?;

            let mut cert_der = None;
            let mut key_id = None;
            let mut key_label = None;
            for attr in attrs {
                match attr {
                    Attribute::Value(v) => cert_der = Some(v),
                    Attribute::Id(v) => key_id = Some(v),
                    Attribute::Label(v) => {
                        key_label = Some(String::from_utf8_lossy(&v).into_owned())
                    }
                    _ => {}
                }
            }

            let Some(cert_der) = cert_der else { continue };
            let usage = classify(&cert_der);

            keys.push(DiscoveredKey {
                module: path.to_path_buf(),
                slot_id: slot.id(),
                token_label: token_info.label().to_string(),
                token_serial: token_info.serial_number().to_string(),
                cert_der,
                key_id,
                key_label,
                usage,
            });
        }
    }

    Ok(())
}

fn classify(cert_der: &[u8]) -> KeyClass {
    let Ok(cert) = x509_cert::Certificate::from_der(cert_der) else {
        return KeyClass::Other;
    };
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return KeyClass::Other;
    };
    let Some(ext) = extensions.iter().find(|e| e.extn_id == KeyUsage::OID) else {
        return KeyClass::Other;
    };
    let Ok(key_usage) = KeyUsage::from_der(ext.extn_value.as_bytes()) else {
        return KeyClass::Other;
    };
    if key_usage.non_repudiation() {
        KeyClass::Signing
    } else if key_usage.digital_signature() {
        KeyClass::Authentication
    } else {
        KeyClass::Other
    }
}
