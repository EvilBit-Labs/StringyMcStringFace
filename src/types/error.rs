//! Error types for the stringy library

/// Error types for the stringy library
#[derive(Debug, thiserror::Error)]
pub enum StringyError {
    #[error("Unsupported file format (supported: ELF, PE, Mach-O)")]
    UnsupportedFormat,

    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    ParseError(String),

    #[error("Invalid encoding in string at offset {offset}")]
    EncodingError { offset: u64 },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Memory mapping error: {0}")]
    MemoryMapError(String),
}

/// Result type alias for the stringy library
pub type Result<T> = std::result::Result<T, StringyError>;

impl From<goblin::error::Error> for StringyError {
    fn from(err: goblin::error::Error) -> Self {
        StringyError::ParseError(err.to_string())
    }
}

impl From<pelite::Error> for StringyError {
    fn from(err: pelite::Error) -> Self {
        StringyError::ParseError(err.to_string())
    }
}

impl From<pelite::resources::FindError> for StringyError {
    fn from(err: pelite::resources::FindError) -> Self {
        StringyError::ParseError(format!("Resource lookup error: {}", err))
    }
}
