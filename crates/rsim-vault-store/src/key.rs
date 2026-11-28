//! The data keys of the bundles and the KMS traits.

use std::fmt;

use zeroize::Zeroizing;

/// The length of a data key in bytes.
pub const DATA_KEY_LEN: usize = 32;

/// The plaintext data key of one bundle. The bytes are set to zero on drop.
pub struct DataKey(pub(crate) Zeroizing<[u8; DATA_KEY_LEN]>);

impl DataKey {
    /// Copies the plaintext data key of a KMS reply.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KmsError> {
        if bytes.len() != DATA_KEY_LEN {
            return Err(KmsError::KeyLength(bytes.len()));
        }
        let mut key = Zeroizing::new([0u8; DATA_KEY_LEN]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; DATA_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(..)")
    }
}

/// A data key that a KMS key wraps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey(pub Vec<u8>);

/// The KMS encryption context of a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionContext<'a> {
    pub class: &'a str,
    pub bundle: &'a str,
}

impl EncryptionContext<'_> {
    /// The keys and the values of the KMS encryption context.
    pub fn pairs(&self) -> [(&'static str, &str); 2] {
        [("class", self.class), ("bundle", self.bundle)]
    }
}

/// Makes a data key and wraps it.
pub trait KeyMaker {
    /// Makes a random data key and wraps it with the KMS key `key_id`.
    fn make_key(
        &self,
        key_id: &str,
        context: EncryptionContext<'_>,
    ) -> impl Future<Output = Result<(DataKey, WrappedKey), KmsError>> + Send;
}

/// Opens a wrapped data key.
pub trait KeyOpener {
    /// Opens a data key that the KMS key `key_id` wrapped with the same context.
    fn open_key(
        &self,
        key_id: &str,
        wrapped: &WrappedKey,
        context: EncryptionContext<'_>,
    ) -> impl Future<Output = Result<DataKey, KmsError>> + Send;
}

/// A fault of a KMS call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsError {
    /// The KMS refused the caller for the key.
    AccessDenied,
    /// The KMS key does not exist.
    UnknownKey,
    /// The wrapped key does not open with the KMS key and the context.
    InvalidCiphertext,
    /// The KMS reply has a data key with this number of bytes.
    KeyLength(usize),
    /// The KMS call failed with this message.
    Service(String),
}

impl fmt::Display for KmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => f.write_str("the KMS refused the caller"),
            Self::UnknownKey => f.write_str("the KMS key does not exist"),
            Self::InvalidCiphertext => {
                f.write_str("the wrapped data key does not open with the KMS key and the context")
            }
            Self::KeyLength(len) => write!(f, "the KMS returned a data key of {len} bytes"),
            Self::Service(message) => write!(f, "the KMS call failed with the message {message}"),
        }
    }
}

impl std::error::Error for KmsError {}
