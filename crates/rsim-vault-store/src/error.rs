use std::fmt;

use crate::key::KmsError;

/// A fault of the seal or the open of a bundle.
#[derive(Debug)]
pub enum Error {
    /// The data does not start with the magic of a bundle.
    NotABundle,
    /// The bundle has a format version that is not known.
    Version(u8),
    /// The bundle has a cipher ID that is not known.
    Cipher(u8),
    /// The bundle ends before its last field.
    Truncated,
    /// The text field is not UTF-8.
    NotUtf8(&'static str),
    /// The field has a length out of the range 1 to `max`.
    FieldLength {
        field: &'static str,
        len: usize,
        max: usize,
    },
    /// The class, the device, the command or the bundle name of the bundle
    /// is different from the expected header.
    HeaderMismatch,
    /// The KMS call failed.
    Kms(KmsError),
    /// The ciphertext or the associated data was changed, or the data key is wrong.
    Authentication,
    /// The cipher refused the plaintext.
    Encrypt,
    /// The random source of the operating system failed.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotABundle => f.write_str("the data is not a bundle"),
            Self::Version(version) => write!(f, "the bundle format version {version} is not known"),
            Self::Cipher(cipher) => write!(f, "the cipher ID {cipher} is not known"),
            Self::Truncated => f.write_str("the bundle ends before its last field"),
            Self::NotUtf8(field) => write!(f, "the field {field} is not UTF-8"),
            Self::FieldLength { field, len, max } => {
                write!(
                    f,
                    "the field {field} has {len} bytes and must have 1 to {max} bytes"
                )
            }
            Self::HeaderMismatch => {
                f.write_str("the bundle header is different from the expected header")
            }
            Self::Kms(error) => fmt::Display::fmt(error, f),
            Self::Authentication => f.write_str("the bundle failed the authentication"),
            Self::Encrypt => f.write_str("the cipher refused the plaintext"),
            Self::Random => f.write_str("the random source of the operating system failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Kms(error) => Some(error),
            _ => None,
        }
    }
}

impl From<KmsError> for Error {
    fn from(error: KmsError) -> Self {
        Self::Kms(error)
    }
}
