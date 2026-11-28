//! The encrypted bundles and their keys.

mod bundle;
mod error;
#[cfg(test)]
mod fake;
mod key;

pub use bundle::{
    Bundle, CIPHER_XCHACHA20_POLY1305, FORMAT_VERSION, Header, MAX_FIELD_LEN, MAX_WRAPPED_KEY_LEN,
    new_bundle_name, open, seal, seal_with_key,
};
pub use error::Error;
pub use key::{
    DATA_KEY_LEN, DataKey, EncryptionContext, KeyMaker, KeyOpener, KmsError, WrappedKey,
};
