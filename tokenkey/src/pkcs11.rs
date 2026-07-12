use std::path::Path;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::slot::Slot;

use crate::error::{Result, TokenkeyError};

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

/// Select the sole slot with an initialized token.
// Adapted from kryptering 0.4.1 `src/pkcs11/mod.rs:149`.
pub(crate) fn select_single_initialized_slot(slots: &[Slot]) -> Result<Slot> {
    select_unique_slot(
        slots,
        || "no slots with an initialized token found".into(),
        || {
            format!(
                "multiple initialized token slots found ({}); pin the token by slot id or label",
                format_slot_list(slots)
            )
        },
    )
}

/// Select the sole slot in `slots`.
pub(crate) fn select_unique_slot(
    slots: &[Slot],
    not_found: impl FnOnce() -> String,
    ambiguous: impl FnOnce() -> String,
) -> Result<Slot> {
    match slots {
        [] => Err(TokenkeyError::NotFound(not_found())),
        [slot] => Ok(*slot),
        _ => Err(TokenkeyError::Ambiguous(ambiguous())),
    }
}

// Adapted from kryptering 0.4.1 `src/pkcs11/mod.rs:187`.
fn format_slot_list(slots: &[Slot]) -> String {
    slots
        .iter()
        .map(|slot| slot.id().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// Adapted from kryptering 0.4.1 `src/pkcs11/mod.rs:271` (BSD-2-Clause).
pub(crate) fn find_unique(
    session: &Session,
    template: &[Attribute],
    what: &str,
) -> Result<ObjectHandle> {
    let mut objects = session
        .find_objects(template)
        .map_err(|source| TokenkeyError::Pkcs11 {
            call: "C_FindObjects",
            source,
        })?;
    match objects.len() {
        0 => Err(TokenkeyError::NotFound(format!(
            "no {what} object matched the query"
        ))),
        1 => Ok(objects.remove(0)),
        n => Err(TokenkeyError::Ambiguous(format!(
            "ambiguous {what} lookup: {n} objects matched the query; narrow it with a CKA_ID"
        ))),
    }
}

/// Map the result of a `C_Login` to local types.
pub(crate) fn map_login_result(result: std::result::Result<(), CkError>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(CkError::Pkcs11(RvError::PinIncorrect, _)) => Err(TokenkeyError::IncorrectPin),
        Err(CkError::Pkcs11(RvError::PinLocked, _)) => Err(TokenkeyError::PinLocked),
        Err(source) => Err(TokenkeyError::Pkcs11 {
            call: "C_Login",
            source,
        }),
    }
}
