/// An error from an `esteid` operation.
#[derive(Debug, thiserror::Error)]
pub enum EstEidError {
    /// No Estonian ID card was found.
    #[error("no Estonian ID card found")]
    NoCard,

    /// More than one ID card was found.
    #[error("multiple Estonian ID cards found: {0:?}")]
    MultipleCards(Vec<String>),

    /// The ID card is missing an expected key.
    #[error("token looks like an ID card but lacks {0}")]
    IncompleteCard(String),

    /// A `tokenkey` operation failed.
    #[error(transparent)]
    Token(#[from] tokenkey::TokenkeyError),
}

pub type Result<T> = std::result::Result<T, EstEidError>;
