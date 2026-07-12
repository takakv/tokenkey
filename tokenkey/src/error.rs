use std::path::PathBuf;

/// An error from a `tokenkey` operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenkeyError {
    /// A PKCS#11 module could not be loaded from `path`.
    #[error("failed to load PKCS#11 module {path}: {source}")]
    ModuleLoad {
        /// The module path that failed to load.
        path: PathBuf,
        /// The underlying cryptoki error.
        source: cryptoki::error::Error,
    },

    /// A PKCS#11 C function failed.
    #[error("{call} failed: {source}")]
    Pkcs11 {
        /// The C function that failed.
        call: &'static str,
        /// The underlying cryptoki error.
        source: cryptoki::error::Error,
    },

    /// The PIN was incorrect (`CKR_PIN_INCORRECT`).
    #[error("incorrect PIN")]
    IncorrectPin,

    /// The PIN is locked (`CKR_PIN_LOCKED`).
    #[error("PIN is locked")]
    PinLocked,

    /// A lookup found no matching object.
    #[error("{0}")]
    NotFound(String),

    /// A lookup matched more than one object.
    #[error("{0}")]
    Ambiguous(String),

    /// The token or key cannot satisfy the request.
    #[error("{0}")]
    Unsupported(String),

    /// A certificate could not be parsed.
    #[error("certificate parsing failed: {0}")]
    Certificate(String),

    /// The session mutex was poisoned by a panic in another thread.
    #[error("session lock poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, TokenkeyError>;
