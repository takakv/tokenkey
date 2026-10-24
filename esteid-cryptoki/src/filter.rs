use std::path::PathBuf;

use tokenkey::ModuleSpec;
use x509_cert::der::Decode;
use x509_cert::der::asn1::{PrintableStringRef, Utf8StringRef};
use x509_cert::der::oid::ObjectIdentifier;

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Certificate issuer CN prefixes accepted as an ID-card CA.
const ESTEID_ISSUER_CN_PREFIXES: &[&str] = &["ESTEID", "Test ESTEID"];

/// OpenSC module candidates.
pub fn modules() -> Vec<ModuleSpec> {
    vec![ModuleSpec {
        name: "opensc-pkcs11".into(),
        paths: vec![
            // macOS
            PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"),
            PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so"),
            // Linux
            PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib64/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/opensc-pkcs11.so"),
            // Windows
            PathBuf::from(r"C:\Windows\System32\opensc-pkcs11.dll"),
        ],
    }]
}

/// Whether `cert_der`'s issuer common name starts with an accepted ESTEID CA prefix.
pub(crate) fn is_esteid_issued(cert_der: &[u8]) -> bool {
    let Ok(cert) = x509_cert::Certificate::from_der(cert_der) else {
        return false;
    };
    let Some(cn) = issuer_common_name(&cert) else {
        return false;
    };
    ESTEID_ISSUER_CN_PREFIXES
        .iter()
        .any(|prefix| cn.starts_with(prefix))
}

/// The issuer's `CN` attribute.
fn issuer_common_name(cert: &x509_cert::Certificate) -> Option<String> {
    cert.tbs_certificate().issuer().iter().find_map(|atv| {
        if atv.oid != OID_COMMON_NAME {
            return None;
        }
        atv.value
            .decode_as::<Utf8StringRef>()
            .map(|s| s.to_string())
            .or_else(|_| {
                atv.value
                    .decode_as::<PrintableStringRef>()
                    .map(|s| s.to_string())
            })
            .ok()
    })
}
