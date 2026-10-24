use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::error::{Result, TokenkeyError};

/// Tags a cryptoki error with the PKCS#11 function that produced it.
pub(crate) trait CkResultExt<T> {
    fn ck(self, call: &'static str) -> Result<T>;
}

impl<T> CkResultExt<T> for cryptoki::error::Result<T> {
    fn ck(self, call: &'static str) -> Result<T> {
        self.map_err(|source| TokenkeyError::Pkcs11 { call, source })
    }
}

/// Load a PKCS#11 library and initialize it.
pub(crate) fn initialize(path: &Path) -> Result<Pkcs11> {
    let module_load_err = |source| TokenkeyError::ModuleLoad {
        path: path.to_path_buf(),
        source,
    };
    let pkcs11 = Pkcs11::new(path).map_err(module_load_err)?;
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(pkcs11),
        Err(source) => Err(module_load_err(source)),
    }
}

/// Slots that contain an initialized token.
pub(crate) fn initialized_slots(pkcs11: &Pkcs11) -> Result<Vec<Slot>> {
    pkcs11
        .get_slots_with_initialized_token()
        .ck("C_GetSlotList")
}

/// The sole item of `items`, or an error.
pub(crate) fn exactly_one<T: Copy>(
    items: &[T],
    not_found: impl FnOnce() -> String,
    ambiguous: impl FnOnce(&[T]) -> String,
) -> Result<T> {
    match items {
        [] => Err(TokenkeyError::NotFound(not_found())),
        [item] => Ok(*item),
        many => Err(TokenkeyError::Ambiguous(ambiguous(many))),
    }
}

/// The sole object matching `template`.
pub(crate) fn find_unique(
    session: &Session,
    template: &[Attribute],
    what: &str,
) -> Result<ObjectHandle> {
    let objects = session.find_objects(template).ck("C_FindObjects")?;
    exactly_one(
        &objects,
        || format!("no {what} object matched the query"),
        |many| format!("{} {what} objects matched the query", many.len()),
    )
}

/// `C_Login`, mapping PIN errors to their own variants.
pub(crate) fn login(session: &Session, user: UserType, pin: &AuthPin) -> Result<()> {
    match session.login(user, Some(pin)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(CkError::Pkcs11(RvError::PinIncorrect, _)) => Err(TokenkeyError::IncorrectPin),
        Err(CkError::Pkcs11(RvError::PinLocked, _)) => Err(TokenkeyError::PinLocked),
        Err(source) => Err(TokenkeyError::Pkcs11 {
            call: "C_Login",
            source,
        }),
    }
}
