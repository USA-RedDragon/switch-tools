//! The one error type of the format readers.

use std::fmt;
use std::io;

/// A failure to read, decrypt or verify a Switch container.
///
/// Messages never carry key material: a missing or wrong key is named, never
/// shown.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reading the underlying file failed.
    Io(io::Error),
    /// The bytes do not have the expected shape.
    Format(String),
    /// A key the operation needs is not in the key file or the tickets.
    MissingKey(String),
    /// A key was found but decryption produced garbage, so it is wrong (or
    /// the first hashed bytes are corrupt).
    WrongKey(String),
    /// A hash in a verified region does not match its data.
    Hash(String),
    /// A valid container uses a feature these readers do not handle.
    Unsupported(String),
}

/// The result type of the format readers.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o: {e}"),
            Error::Format(m) => write!(f, "malformed: {m}"),
            Error::MissingKey(m) => write!(f, "missing key: {m}"),
            Error::WrongKey(m) => write!(f, "wrong key: {m}"),
            Error::Hash(m) => write!(f, "hash mismatch: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// Shorthand for a [`Error::Format`].
pub(crate) fn malformed<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Format(msg.into()))
}
