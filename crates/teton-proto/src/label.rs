//! Device label: ID derivation and the QR URL (SPEC.md §3).

use aws_lc_rs::digest::{SHA256, digest};

use crate::crypto::{PUBLIC_KEY_LEN, validate_public_key};
use crate::{PROTOCOL_VERSION, b64};

/// Length of the device ID in hex characters (6 bytes of SHA-256(pk)).
pub const ID_LEN: usize = 12;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LabelError {
    #[error("URL has no #fragment")]
    MissingFragment,
    #[error("label is missing `{0}`")]
    MissingParam(&'static str),
    #[error("unsupported label version {0:?}")]
    UnsupportedVersion(String),
    #[error("label public key is not a valid P-256 key")]
    BadPublicKey,
    #[error("label ID does not match its public key")]
    IdMismatch,
}

impl LabelError {
    /// Stable error code shared with the JS configurator (test vectors).
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingFragment => "missing_fragment",
            Self::MissingParam(_) => "missing_param",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::BadPublicKey => "bad_public_key",
            Self::IdMismatch => "id_mismatch",
        }
    }
}

/// `hex(SHA-256(pk)[0..6])`, uppercase.
pub fn device_id(public_key: &[u8]) -> String {
    crate::hex(&digest(&SHA256, public_key).as_ref()[..ID_LEN / 2]).to_uppercase()
}

/// `4F2A9C11B03E` → `4F2A-9C11-B03E` for display.
pub fn format_id(id: &str) -> String {
    id.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c))
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub id: String,
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

impl Label {
    pub fn new(public_key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        Self {
            id: device_id(public_key),
            public_key: *public_key,
        }
    }

    /// `<base_url>#v=1&id=<id>&pk=<b64url(pk)>`
    pub fn url(&self, base_url: &str) -> String {
        format!(
            "{base_url}#v={PROTOCOL_VERSION}&id={}&pk={}",
            self.id,
            b64::encode(&self.public_key)
        )
    }

    /// Parses and validates a label URL. Unknown parameters are ignored.
    pub fn parse_url(url: &str) -> Result<Self, LabelError> {
        let (_, fragment) = url.split_once('#').ok_or(LabelError::MissingFragment)?;
        let param = |name: &'static str| {
            fragment
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v)
                .ok_or(LabelError::MissingParam(name))
        };
        let v = param("v")?;
        if v != PROTOCOL_VERSION.to_string() {
            return Err(LabelError::UnsupportedVersion(v.to_owned()));
        }
        let id = param("id")?;
        let public_key: [u8; PUBLIC_KEY_LEN] = b64::decode(param("pk")?)
            .ok()
            .and_then(|pk| pk.try_into().ok())
            .ok_or(LabelError::BadPublicKey)?;
        validate_public_key(&public_key).map_err(|_| LabelError::BadPublicKey)?;
        let label = Self::new(&public_key);
        if label.id != id {
            return Err(LabelError::IdMismatch);
        }
        Ok(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    const BASE: &str = "https://example.test/p/";

    #[test]
    fn round_trip() {
        let k = KeyPair::generate().unwrap();
        let label = Label::new(k.public_key());
        assert_eq!(label.id.len(), ID_LEN);
        assert_eq!(Label::parse_url(&label.url(BASE)).unwrap(), label);
    }

    #[test]
    fn rejects_bad_labels() {
        let label = Label::new(KeyPair::generate().unwrap().public_key());
        let url = label.url(BASE);
        let err = |u: &str| Label::parse_url(u).unwrap_err().code();
        assert_eq!(err(BASE), "missing_fragment");
        assert_eq!(err(&url.replace("v=1", "v=2")), "unsupported_version");
        assert_eq!(err(&url.replace("&id=", "&xx=")), "missing_param");
        assert_eq!(err(&url.replace(&label.id, "000000000000")), "id_mismatch");
        assert_eq!(err(&format!("{url}AA")), "bad_public_key");
    }

    #[test]
    fn formats_id() {
        assert_eq!(format_id("4F2A9C11B03E"), "4F2A-9C11-B03E");
    }
}
