//! A local KMS for the tests. It makes its master keys at run time.

use std::collections::HashMap;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::key::{
    DATA_KEY_LEN, DataKey, EncryptionContext, KeyMaker, KeyOpener, KmsError, WrappedKey,
};

const NONCE_LEN: usize = 24;

/// Polls a future that is ready at the first poll.
pub(crate) fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future is pending"),
    }
}

/// Holds 1 master key for each KMS key ID. Each caller can make a data key.
pub(crate) struct FakeKms {
    keys: HashMap<String, XChaCha20Poly1305>,
}

impl FakeKms {
    pub(crate) fn new(key_ids: &[&str]) -> Self {
        let keys = key_ids
            .iter()
            .map(|&key_id| {
                let mut master = Zeroizing::new([0u8; DATA_KEY_LEN]);
                getrandom::fill(master.as_mut_slice()).expect("random master key");
                let cipher =
                    XChaCha20Poly1305::new_from_slice(master.as_slice()).expect("master key");
                (key_id.to_owned(), cipher)
            })
            .collect();
        Self { keys }
    }

    /// A caller that can open the data keys of the KMS keys `key_ids`.
    pub(crate) fn caller(&self, key_ids: &[&str]) -> FakeCaller<'_> {
        FakeCaller {
            kms: self,
            allowed: key_ids.iter().map(|&key_id| key_id.to_owned()).collect(),
        }
    }

    fn wrap(
        &self,
        key_id: &str,
        context: EncryptionContext<'_>,
    ) -> Result<(DataKey, WrappedKey), KmsError> {
        let cipher = self.keys.get(key_id).ok_or(KmsError::UnknownKey)?;
        let mut key = Zeroizing::new([0u8; DATA_KEY_LEN]);
        getrandom::fill(key.as_mut_slice()).map_err(|e| KmsError::Service(e.to_string()))?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| KmsError::Service(e.to_string()))?;
        let aad = associated_data(key_id, context);
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: key.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| KmsError::Service("the wrap failed".to_owned()))?;
        let mut wrapped = nonce.to_vec();
        wrapped.extend_from_slice(&sealed);
        Ok((DataKey(key), WrappedKey(wrapped)))
    }
}

impl KeyMaker for FakeKms {
    fn make_key(
        &self,
        key_id: &str,
        context: EncryptionContext<'_>,
    ) -> impl Future<Output = Result<(DataKey, WrappedKey), KmsError>> + Send {
        std::future::ready(self.wrap(key_id, context))
    }
}

/// A caller with the grants for some KMS keys.
pub(crate) struct FakeCaller<'a> {
    kms: &'a FakeKms,
    allowed: Vec<String>,
}

impl FakeCaller<'_> {
    fn unwrap_key(
        &self,
        key_id: &str,
        wrapped: &WrappedKey,
        context: EncryptionContext<'_>,
    ) -> Result<DataKey, KmsError> {
        if !self.allowed.iter().any(|allowed| allowed == key_id) {
            return Err(KmsError::AccessDenied);
        }
        let cipher = self.kms.keys.get(key_id).ok_or(KmsError::UnknownKey)?;
        let (nonce, sealed) = wrapped
            .0
            .split_at_checked(NONCE_LEN)
            .ok_or(KmsError::InvalidCiphertext)?;
        let nonce = XNonce::try_from(nonce).map_err(|_| KmsError::InvalidCiphertext)?;
        let aad = associated_data(key_id, context);
        let key = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| KmsError::InvalidCiphertext)?;
        DataKey::from_slice(&key)
    }
}

impl KeyOpener for FakeCaller<'_> {
    fn open_key(
        &self,
        key_id: &str,
        wrapped: &WrappedKey,
        context: EncryptionContext<'_>,
    ) -> impl Future<Output = Result<DataKey, KmsError>> + Send {
        std::future::ready(self.unwrap_key(key_id, wrapped, context))
    }
}

/// The key ID and the context pairs, each value with its length as 8 bytes.
fn associated_data(key_id: &str, context: EncryptionContext<'_>) -> Vec<u8> {
    let mut aad = Vec::new();
    let pairs = context.pairs();
    let values = [key_id, pairs[0].0, pairs[0].1, pairs[1].0, pairs[1].1];
    for value in values {
        aad.extend_from_slice(&value.len().to_be_bytes());
        aad.extend_from_slice(value.as_bytes());
    }
    aad
}
