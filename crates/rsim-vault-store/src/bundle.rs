//! The format of a bundle.
//!
//! | Bytes | Content |
//! |---|---|
//! | 4 | The magic `RSVB` |
//! | 1 | The format version |
//! | 1 | The cipher ID |
//! | 2 + n | The class |
//! | 2 + n | The KMS key ID |
//! | 2 + n | The device |
//! | 2 + n | The command |
//! | 2 + n | The bundle name |
//! | 2 + n | The wrapped data key |
//! | 24 | The nonce |
//! | 16 or more | The ciphertext and the tag of 16 bytes |
//!
//! Each length is a big-endian `u16`. The associated data of the cipher is all
//! bytes before the ciphertext.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::key::{DataKey, EncryptionContext, KeyMaker, KeyOpener, WrappedKey};

const MAGIC: &[u8; 4] = b"RSVB";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const BUNDLE_NAME_BYTES: usize = 16;

/// The format version that `seal` writes.
pub const FORMAT_VERSION: u8 = 1;
/// The cipher ID of XChaCha20-Poly1305.
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;
/// The maximum length in bytes of a text field of the header.
pub const MAX_FIELD_LEN: usize = 2048;
/// The maximum length in bytes of the wrapped data key.
pub const MAX_WRAPPED_KEY_LEN: usize = 1024;

/// The header of a bundle. The cipher authenticates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub class: String,
    pub key_id: String,
    pub device: String,
    pub command: String,
    pub bundle: String,
}

impl Header {
    /// The KMS encryption context of the bundle.
    pub fn context(&self) -> EncryptionContext<'_> {
        EncryptionContext {
            class: &self.class,
            bundle: &self.bundle,
        }
    }

    fn fields(&self) -> [(&'static str, &str); 5] {
        [
            ("class", self.class.as_str()),
            ("key ID", self.key_id.as_str()),
            ("device", self.device.as_str()),
            ("command", self.command.as_str()),
            ("bundle name", self.bundle.as_str()),
        ]
    }

    fn same_subject(&self, other: &Self) -> bool {
        self.class == other.class
            && self.device == other.device
            && self.command == other.command
            && self.bundle == other.bundle
    }
}

/// Makes a random bundle name of 32 lowercase hex digits.
pub fn new_bundle_name() -> Result<String, Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0u8; BUNDLE_NAME_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
    let mut name = String::with_capacity(BUNDLE_NAME_BYTES * 2);
    for byte in bytes {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(name)
}

/// Gets a data key from `maker` and seals `plaintext` into a bundle.
pub async fn seal<M: KeyMaker>(
    maker: &M,
    header: &Header,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let (key, wrapped) = maker.make_key(&header.key_id, header.context()).await?;
    seal_with_key(header, &key, &wrapped, plaintext)
}

/// Seals `plaintext` into a bundle with a data key and its wrapped form.
pub fn seal_with_key(
    header: &Header,
    key: &DataKey,
    wrapped: &WrappedKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(512 + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(CIPHER_XCHACHA20_POLY1305);
    for (field, value) in header.fields() {
        put_field(&mut out, field, value.as_bytes(), MAX_FIELD_LEN)?;
    }
    put_field(&mut out, "wrapped key", &wrapped.0, MAX_WRAPPED_KEY_LEN)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
    out.extend_from_slice(&nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::Encrypt)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|_| Error::Encrypt)?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a bundle with a data key from `opener`.
///
/// The class, the device, the command and the bundle name of the bundle must
/// be equal to those of `expected`. The KMS key ID comes from the bundle.
pub async fn open<O: KeyOpener>(
    opener: &O,
    expected: &Header,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let bundle = Bundle::parse(bytes)?;
    if !bundle.header.same_subject(expected) {
        return Err(Error::HeaderMismatch);
    }
    let key = opener
        .open_key(
            &bundle.header.key_id,
            &bundle.wrapped,
            bundle.header.context(),
        )
        .await?;
    bundle.decrypt(&key)
}

/// A parsed bundle. The header is not authenticated before `decrypt`.
pub struct Bundle<'a> {
    header: Header,
    wrapped: WrappedKey,
    nonce: XNonce,
    aad: &'a [u8],
    ciphertext: &'a [u8],
}

impl<'a> Bundle<'a> {
    /// Reads the header of a bundle.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut reader = Reader { bytes, pos: 0 };
        if reader.take(MAGIC.len())? != MAGIC {
            return Err(Error::NotABundle);
        }
        let version = reader.byte()?;
        if version != FORMAT_VERSION {
            return Err(Error::Version(version));
        }
        let cipher = reader.byte()?;
        if cipher != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::Cipher(cipher));
        }
        let header = Header {
            class: reader.text("class")?,
            key_id: reader.text("key ID")?,
            device: reader.text("device")?,
            command: reader.text("command")?,
            bundle: reader.text("bundle name")?,
        };
        let wrapped = WrappedKey(reader.field("wrapped key", MAX_WRAPPED_KEY_LEN)?.to_vec());
        let nonce = XNonce::try_from(reader.take(NONCE_LEN)?).map_err(|_| Error::Truncated)?;
        let (aad, ciphertext) = bytes.split_at(reader.pos);
        if ciphertext.len() < TAG_LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            header,
            wrapped,
            nonce,
            aad,
            ciphertext,
        })
    }

    /// The header as the bundle holds it.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The wrapped data key.
    pub fn wrapped_key(&self) -> &WrappedKey {
        &self.wrapped
    }

    /// Authenticates the bundle and decrypts its plaintext.
    pub fn decrypt(&self, key: &DataKey) -> Result<Zeroizing<Vec<u8>>, Error> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::Authentication)?;
        cipher
            .decrypt(
                &self.nonce,
                Payload {
                    msg: self.ciphertext,
                    aad: self.aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Authentication)
    }
}

fn put_field(
    out: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
    max: usize,
) -> Result<(), Error> {
    let len = u16::try_from(value.len())
        .ok()
        .filter(|&len| len != 0 && usize::from(len) <= max)
        .ok_or(Error::FieldLength {
            field,
            len: value.len(),
            max,
        })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(Error::Truncated)?;
        let part = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(part)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn field(&mut self, field: &'static str, max: usize) -> Result<&'a [u8], Error> {
        let len = self.take(2)?;
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        if len == 0 || len > max {
            return Err(Error::FieldLength { field, len, max });
        }
        self.take(len)
    }

    fn text(&mut self, field: &'static str) -> Result<String, Error> {
        let bytes = self.field(field, MAX_FIELD_LEN)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| Error::NotUtf8(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeKms, run};
    use crate::key::KmsError;

    const CONFIG_KEY: &str = "fake-key-running-config";
    const STATE_KEY: &str = "fake-key-state";
    const ANSWER: &[u8] = b"interface GigabitEthernet0/1\n ip address 192.0.2.1 255.255.255.0\n";

    fn header() -> Header {
        Header {
            class: "running-config".to_owned(),
            key_id: CONFIG_KEY.to_owned(),
            device: "router-a".to_owned(),
            command: "show running-config".to_owned(),
            bundle: new_bundle_name().expect("bundle name"),
        }
    }

    fn sealed(kms: &FakeKms, header: &Header) -> Vec<u8> {
        run(seal(kms, header, ANSWER)).expect("seal")
    }

    fn position(bytes: &[u8], part: &[u8]) -> usize {
        bytes
            .windows(part.len())
            .position(|window| window == part)
            .expect("part in bundle")
    }

    #[test]
    fn open_returns_the_answer() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let bytes = sealed(&kms, &header);
        let caller = kms.caller(&[CONFIG_KEY]);
        let answer = run(open(&caller, &header, &bytes)).expect("open");
        assert_eq!(answer.as_slice(), ANSWER);
    }

    #[test]
    fn parse_returns_the_header() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let bytes = sealed(&kms, &header);
        let bundle = Bundle::parse(&bytes).expect("parse");
        assert_eq!(bundle.header(), &header);
        assert!(!bundle.wrapped_key().0.is_empty());
    }

    #[test]
    fn open_refuses_a_caller_without_the_class() {
        let kms = FakeKms::new(&[CONFIG_KEY, STATE_KEY]);
        let header = header();
        let bytes = sealed(&kms, &header);
        let caller = kms.caller(&[STATE_KEY]);
        let result = run(open(&caller, &header, &bytes));
        assert!(matches!(result, Err(Error::Kms(KmsError::AccessDenied))));
    }

    #[test]
    fn open_refuses_a_bundle_of_another_device() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let bytes = sealed(&kms, &header);
        let expected = Header {
            device: "router-b".to_owned(),
            ..header
        };
        let caller = kms.caller(&[CONFIG_KEY]);
        let result = run(open(&caller, &expected, &bytes));
        assert!(matches!(result, Err(Error::HeaderMismatch)));
    }

    #[test]
    fn open_refuses_a_changed_device() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let mut bytes = sealed(&kms, &header);
        let at = position(&bytes, b"router-a");
        bytes[at + 7] = b'b';
        let expected = Header {
            device: "router-b".to_owned(),
            ..header
        };
        let caller = kms.caller(&[CONFIG_KEY]);
        let result = run(open(&caller, &expected, &bytes));
        assert!(matches!(result, Err(Error::Authentication)));
    }

    #[test]
    fn open_refuses_a_changed_bundle_name() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let mut bytes = sealed(&kms, &header);
        let at = position(&bytes, header.bundle.as_bytes());
        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        let changed = std::str::from_utf8(&bytes[at..at + header.bundle.len()])
            .expect("hex")
            .to_owned();
        let expected = Header {
            bundle: changed,
            ..header
        };
        let caller = kms.caller(&[CONFIG_KEY]);
        let result = run(open(&caller, &expected, &bytes));
        assert!(matches!(
            result,
            Err(Error::Kms(KmsError::InvalidCiphertext))
        ));
    }

    #[test]
    fn open_refuses_a_changed_ciphertext() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let mut bytes = sealed(&kms, &header);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let caller = kms.caller(&[CONFIG_KEY]);
        let result = run(open(&caller, &header, &bytes));
        assert!(matches!(result, Err(Error::Authentication)));
    }

    #[test]
    fn open_refuses_each_cut_bundle() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let bytes = sealed(&kms, &header);
        let caller = kms.caller(&[CONFIG_KEY]);
        for len in 0..bytes.len() {
            let result = run(open(&caller, &header, &bytes[..len]));
            assert!(result.is_err(), "a bundle cut to {len} bytes opened");
        }
    }

    #[test]
    fn parse_refuses_a_wrong_magic() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let mut bytes = sealed(&kms, &header());
        bytes[0] = b'X';
        assert!(matches!(Bundle::parse(&bytes), Err(Error::NotABundle)));
    }

    #[test]
    fn parse_refuses_an_unknown_version() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let mut bytes = sealed(&kms, &header());
        bytes[4] = 2;
        assert!(matches!(Bundle::parse(&bytes), Err(Error::Version(2))));
    }

    #[test]
    fn parse_refuses_an_unknown_cipher() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let mut bytes = sealed(&kms, &header());
        bytes[5] = 9;
        assert!(matches!(Bundle::parse(&bytes), Err(Error::Cipher(9))));
    }

    #[test]
    fn parse_refuses_a_field_longer_than_the_maximum() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let mut bytes = sealed(&kms, &header());
        bytes[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            Bundle::parse(&bytes),
            Err(Error::FieldLength { field: "class", .. })
        ));
    }

    #[test]
    fn seal_refuses_an_empty_device() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = Header {
            device: String::new(),
            ..header()
        };
        let result = run(seal(&kms, &header, ANSWER));
        assert!(matches!(
            result,
            Err(Error::FieldLength {
                field: "device",
                len: 0,
                ..
            })
        ));
    }

    #[test]
    fn seal_refuses_a_command_longer_than_the_maximum() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = Header {
            command: "x".repeat(MAX_FIELD_LEN + 1),
            ..header()
        };
        let result = run(seal(&kms, &header, ANSWER));
        assert!(matches!(
            result,
            Err(Error::FieldLength {
                field: "command",
                ..
            })
        ));
    }

    #[test]
    fn seal_refuses_an_unknown_key() {
        let kms = FakeKms::new(&[STATE_KEY]);
        let result = run(seal(&kms, &header(), ANSWER));
        assert!(matches!(result, Err(Error::Kms(KmsError::UnknownKey))));
    }

    #[test]
    fn seal_of_one_answer_differs_each_time() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        assert_ne!(sealed(&kms, &header), sealed(&kms, &header));
    }

    #[test]
    fn seal_of_an_empty_answer_opens() {
        let kms = FakeKms::new(&[CONFIG_KEY]);
        let header = header();
        let bytes = run(seal(&kms, &header, b"")).expect("seal");
        let caller = kms.caller(&[CONFIG_KEY]);
        let answer = run(open(&caller, &header, &bytes)).expect("open");
        assert!(answer.is_empty());
    }

    #[test]
    fn bundle_name_has_32_lowercase_hex_digits() {
        let name = new_bundle_name().expect("bundle name");
        assert_eq!(name.len(), 32);
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(name, new_bundle_name().expect("bundle name"));
    }

    #[test]
    fn data_key_debug_hides_the_bytes() {
        let key = DataKey::from_slice(&[7u8; crate::key::DATA_KEY_LEN]).expect("key");
        assert_eq!(format!("{key:?}"), "DataKey(..)");
    }

    #[test]
    fn data_key_refuses_a_wrong_length() {
        assert!(matches!(
            DataKey::from_slice(&[0u8; 16]),
            Err(KmsError::KeyLength(16))
        ));
    }
}
