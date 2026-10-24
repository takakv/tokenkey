use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use cryptoki::context::Pkcs11;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::algo::{KeyAlgorithm, SignScheme, mechanism_and_input};
use crate::discover::DiscoveredKey;
use crate::error::{Result, TokenkeyError};
use crate::pkcs11::{CkResultExt, exactly_one, find_unique, initialize, initialized_slots, login};

pub enum SlotSelect {
    /// The unique slot with an initialized token.
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
    session: Mutex<Session>,
    key_handle: ObjectHandle,
    cert_der: Option<Vec<u8>>,
    /// The PIN, kept only for `CKA_ALWAYS_AUTHENTICATE` keys.
    context_pin: Option<AuthPin>,
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
        let pkcs11 = initialize(&locator.module)?;
        let slot = select_slot(&pkcs11, &locator.slot)?;

        let token_info = pkcs11.get_token_info(slot).ck("C_GetTokenInfo")?;
        if token_info.protected_authentication_path() {
            return Err(TokenkeyError::Unsupported("PIN pads not supported".into()));
        }

        let session = pkcs11.open_rw_session(slot).ck("C_OpenSession")?;
        let pin = AuthPin::new(pin.into());
        login(&session, UserType::User, &pin)?;

        let key_handle = resolve_private_key(&session, &locator.key)?;
        let cert_der = match cert_override {
            Some(der) => Some(der),
            None => resolve_certificate(&session, key_handle)?,
        };
        let context_pin = read_always_authenticate(&session, key_handle)?.then_some(pin);

        Ok(TokenKey {
            session: Mutex::new(session),
            key_handle,
            cert_der,
            context_pin,
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
        self.context_pin.is_some()
    }

    /// Hash `data` and sign it. ECDSA signatures are raw `r || s`.
    pub fn sign(&self, scheme: SignScheme, data: &[u8]) -> Result<Vec<u8>> {
        let (mechanism, input) = mechanism_and_input(scheme, data)?;
        let session = self.lock()?;

        if self.context_pin.is_none() {
            return session
                .sign(&mechanism, self.key_handle, &input)
                .ck("C_Sign");
        }

        // The PIN must be entered between C_SignInit and C_Sign, but cryptoki's
        // `sign` does both in one call. Work around this by finishing with C_SignUpdate
        // and C_SignFinal instead. While not spec-compliant, it works with OpenSC.
        session
            .sign_init(&mechanism, self.key_handle)
            .ck("C_SignInit")?;
        self.context_login(&session)?;
        session.sign_update(&input).ck("C_SignUpdate")?;
        session.sign_final().ck("C_SignFinal")
    }

    fn lock(&self) -> Result<MutexGuard<'_, Session>> {
        self.session.lock().map_err(|_| TokenkeyError::Poisoned)
    }

    /// Re-enter the PIN for the operation just started, if the key requires it.
    fn context_login(&self, session: &Session) -> Result<()> {
        match &self.context_pin {
            Some(pin) => login(session, UserType::ContextSpecific, pin),
            None => Ok(()),
        }
    }
}

fn select_slot(pkcs11: &Pkcs11, select: &SlotSelect) -> Result<Slot> {
    match select {
        SlotSelect::SoleToken => exactly_one(
            &initialized_slots(pkcs11)?,
            || "no slots with an initialized token found".into(),
            |many| {
                let ids: Vec<String> = many.iter().map(|slot| slot.id().to_string()).collect();
                format!(
                    "multiple initialized token slots found ({}); select the token by slot id or label",
                    ids.join(", ")
                )
            },
        ),
        SlotSelect::Id(id) => {
            let slot = Slot::try_from(*id).map_err(|e| {
                TokenkeyError::NotFound(format!("invalid PKCS#11 slot id {id}: {e}"))
            })?;
            let token_info = pkcs11.get_token_info(slot).ck("C_GetTokenInfo")?;
            if !token_info.token_initialized() {
                return Err(TokenkeyError::NotFound(format!(
                    "slot {id} does not contain an initialized token"
                )));
            }
            Ok(slot)
        }
        SlotSelect::TokenLabel(label) => {
            let mut matches = Vec::new();
            for slot in initialized_slots(pkcs11)? {
                if pkcs11.get_token_info(slot).ck("C_GetTokenInfo")?.label() == label {
                    matches.push(slot);
                }
            }
            exactly_one(
                &matches,
                || format!("no initialized token matches label {label:?}"),
                |_| format!("multiple initialized tokens match label {label:?}; select by slot id"),
            )
        }
    }
}

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
        .ck("C_GetAttributeValue")?;
    Ok(attrs
        .iter()
        .any(|a| matches!(a, Attribute::AlwaysAuthenticate(true))))
}

/// Find the certificate matching the private key's `CKA_ID`.
fn resolve_certificate(session: &Session, key: ObjectHandle) -> Result<Option<Vec<u8>>> {
    let id_attrs = session
        .get_attributes(key, &[AttributeType::Id])
        .ck("C_GetAttributeValue")?;
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
    let handles = session.find_objects(&template).ck("C_FindObjects")?;
    let Some(&handle) = handles.first() else {
        return Ok(None);
    };

    let attrs = session
        .get_attributes(handle, &[AttributeType::Value])
        .ck("C_GetAttributeValue")?;
    Ok(attrs.into_iter().find_map(|a| match a {
        Attribute::Value(v) => Some(v),
        _ => None,
    }))
}
