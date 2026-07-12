use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cryptoki::context::Pkcs11;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::algo::{mechanism_and_input, KeyAlgorithm, SignScheme};
use crate::discover::DiscoveredKey;
use crate::error::{Result, TokenkeyError};
use crate::pkcs11::{
    find_unique, initialize, map_login_result, select_single_initialized_slot, select_unique_slot,
};

pub enum SlotSelect {
    /// The sole slot with an initialized token; errors if several are present.
    SoleToken,
    /// A specific slot id (`CK_SLOT_ID`).
    Id(u64),
    /// A token by its `CKA_LABEL`.
    TokenLabel(String),
}

pub enum KeySelect {
    /// By `CKA_LABEL`.
    Label(String),
    /// By `CKA_ID`.
    Id(Vec<u8>),
    /// By both `CKA_LABEL` and `CKA_ID`.
    LabelAndId(String, Vec<u8>),
}

pub struct KeyLocator {
    /// Path to the PKCS#11 module.
    pub module: PathBuf,
    /// Which token to use.
    pub slot: SlotSelect,
    /// Which private key to use.
    pub key: KeySelect,
}

/// A private key opened on a PKCS#11 token.
pub struct TokenKey {
    session: Arc<Mutex<Session>>,
    key_handle: ObjectHandle,
    cert_der: Option<Vec<u8>>,
    always_authenticate: bool,
    pin: Option<AuthPin>,
    #[allow(dead_code)]
    provider: Pkcs11,
}

impl TokenKey {
    pub fn open(locator: &KeyLocator, pin: &str) -> Result<TokenKey> {
        Self::open_inner(locator, pin, None)
    }

    pub fn open_discovered(key: &DiscoveredKey, pin: &str) -> Result<TokenKey> {
        let key_select = match (&key.key_id, &key.key_label) {
            (Some(id), _) => KeySelect::Id(id.clone()),
            (None, Some(label)) => KeySelect::Label(label.clone()),
            (None, None) => {
                return Err(TokenkeyError::NotFound(
                    "discovered key has neither CKA_ID nor CKA_LABEL to locate the private key"
                        .into(),
                ));
            }
        };
        let locator = KeyLocator {
            module: key.module.clone(),
            slot: SlotSelect::Id(key.slot_id),
            key: key_select,
        };
        Self::open_inner(&locator, pin, Some(key.cert_der.clone()))
    }

    fn open_inner(
        locator: &KeyLocator,
        pin: &str,
        cert_override: Option<Vec<u8>>,
    ) -> Result<TokenKey> {
        let provider = initialize(&locator.module)?;
        let slot = select_slot(&provider, &locator.slot)?;

        let token_info = provider
            .get_token_info(slot)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_GetTokenInfo",
                source,
            })?;
        if token_info.protected_authentication_path() {
            return Err(TokenkeyError::Unsupported("PIN pads not supported".into()));
        }

        let session = provider
            .open_rw_session(slot)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_OpenSession",
                source,
            })?;

        let auth_pin = AuthPin::new(pin.to_owned().into());
        map_login_result(session.login(UserType::User, Some(&auth_pin)))?;

        let key_handle = resolve_private_key(&session, &locator.key)?;

        let always_authenticate = read_always_authenticate(&session, key_handle)?;

        let cert_der = match cert_override {
            Some(der) => Some(der),
            None => resolve_certificate(&session, key_handle)?,
        };

        let pin = if always_authenticate {
            Some(auth_pin)
        } else {
            None
        };

        let session = Arc::new(Mutex::new(session));

        Ok(TokenKey {
            session,
            key_handle,
            cert_der,
            always_authenticate,
            pin,
            provider,
        })
    }

    /// The public-key algorithm, parsed from the key's certificate SPKI.
    /// Errors if the key has no associated certificate.
    pub fn algorithm(&self) -> Result<KeyAlgorithm> {
        let der = self.cert_der.as_deref().ok_or_else(|| {
            TokenkeyError::NotFound("no certificate is associated with this key".into())
        })?;
        KeyAlgorithm::from_certificate_der(der)
    }

    /// The DER of the key's certificate, or `None` for an HSM key with no
    /// certificate object on the token.
    pub fn certificate_der(&self) -> Option<&[u8]> {
        self.cert_der.as_deref()
    }

    /// Whether this key has `CKA_ALWAYS_AUTHENTICATE` set.
    pub fn always_authenticate(&self) -> bool {
        self.always_authenticate
    }

    /// Sign data.
    pub fn sign(&self, scheme: SignScheme, data: &[u8]) -> Result<Vec<u8>> {
        let (mechanism, input) = mechanism_and_input(scheme, data)?;

        if self.always_authenticate {
            return self.sign_context_specific(mechanism, &input);
        }

        let session = self.session.lock().map_err(|_| TokenkeyError::Poisoned)?;
        session
            .sign(&mechanism, self.key_handle, &input)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_Sign",
                source,
            })
    }

    /// Sign with a `CKA_ALWAYS_AUTHENTICATE` key.
    fn sign_context_specific(
        &self,
        mechanism: cryptoki::mechanism::Mechanism<'_>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let pin = self.pin.as_ref().ok_or_else(|| {
            TokenkeyError::Unsupported("missing PIN for always authenticated key".into())
        })?;

        let session = self.session.lock().map_err(|_| TokenkeyError::Poisoned)?;

        session
            .sign_init(&mechanism, self.key_handle)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_SignInit",
                source,
            })?;

        map_login_result(session.login(UserType::ContextSpecific, Some(pin)))?;

        // CKM_ECDSA is formally one-shot, but OpenSC accepts passes by buffering.
        session
            .sign_update(input)
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_SignUpdate",
                source,
            })?;
        session
            .sign_final()
            .map_err(|source| TokenkeyError::Pkcs11 {
                call: "C_SignFinal",
                source,
            })
    }
}

/// Select the slot per `select`.
fn select_slot(provider: &Pkcs11, select: &SlotSelect) -> Result<Slot> {
    match select {
        SlotSelect::SoleToken => {
            let slots = provider
                .get_slots_with_initialized_token()
                .map_err(|source| TokenkeyError::Pkcs11 {
                    call: "C_GetSlotList",
                    source,
                })?;
            select_single_initialized_slot(&slots)
        }
        SlotSelect::Id(id) => {
            let slot = Slot::try_from(*id).map_err(|e| {
                TokenkeyError::NotFound(format!("invalid PKCS#11 slot id {id}: {e}"))
            })?;
            let token_info =
                provider
                    .get_token_info(slot)
                    .map_err(|source| TokenkeyError::Pkcs11 {
                        call: "C_GetTokenInfo",
                        source,
                    })?;
            if !token_info.token_initialized() {
                return Err(TokenkeyError::NotFound(format!(
                    "slot {id} does not contain an initialized token"
                )));
            }
            Ok(slot)
        }
        SlotSelect::TokenLabel(label) => {
            let slots = provider
                .get_slots_with_initialized_token()
                .map_err(|source| TokenkeyError::Pkcs11 {
                    call: "C_GetSlotList",
                    source,
                })?;
            let mut matches = Vec::new();
            for slot in slots {
                let token_info =
                    provider
                        .get_token_info(slot)
                        .map_err(|source| TokenkeyError::Pkcs11 {
                            call: "C_GetTokenInfo",
                            source,
                        })?;
                if token_info.label() == label {
                    matches.push(slot);
                }
            }
            select_unique_slot(
                &matches,
                || format!("no initialized token matches label {label:?}"),
                || format!("multiple initialized tokens match label {label:?}; select by slot id"),
            )
        }
    }
}

/// Resolve the private key handle per `select`.
fn resolve_private_key(session: &Session, select: &KeySelect) -> Result<ObjectHandle> {
    let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
    match select {
        KeySelect::Label(label) => template.push(Attribute::Label(label.as_bytes().to_vec())),
        KeySelect::Id(id) => template.push(Attribute::Id(id.clone())),
        KeySelect::LabelAndId(label, id) => {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
            template.push(Attribute::Id(id.clone()));
        }
    }
    find_unique(session, &template, "private key")
}

/// Read `CKA_ALWAYS_AUTHENTICATE` from the private key.
fn read_always_authenticate(session: &Session, key: ObjectHandle) -> Result<bool> {
    let attrs = session
        .get_attributes(key, &[AttributeType::AlwaysAuthenticate])
        .map_err(|source| TokenkeyError::Pkcs11 {
            call: "C_GetAttributeValue",
            source,
        })?;
    Ok(attrs
        .iter()
        .any(|a| matches!(a, Attribute::AlwaysAuthenticate(true))))
}

/// Find the certificate matching the private key's `CKA_ID`.
fn resolve_certificate(session: &Session, key: ObjectHandle) -> Result<Option<Vec<u8>>> {
    let id_attrs = session
        .get_attributes(key, &[AttributeType::Id])
        .map_err(|source| TokenkeyError::Pkcs11 {
            call: "C_GetAttributeValue",
            source,
        })?;
    let Some(id) = id_attrs.into_iter().find_map(|a| match a {
        Attribute::Id(v) => Some(v),
        _ => None,
    }) else {
        return Ok(None);
    };

    let template = [
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Id(id),
    ];
    let mut handles = session
        .find_objects(&template)
        .map_err(|source| TokenkeyError::Pkcs11 {
            call: "C_FindObjects",
            source,
        })?;
    let Some(handle) = handles.drain(..).next() else {
        return Ok(None);
    };

    let attrs = session
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|source| TokenkeyError::Pkcs11 {
            call: "C_GetAttributeValue",
            source,
        })?;
    Ok(attrs.into_iter().find_map(|a| match a {
        Attribute::Value(v) => Some(v),
        _ => None,
    }))
}
