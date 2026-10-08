//! Device identity: the long-term P-256 key and the label derived from it
//! (SPEC.md §3.1).

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;
use teton_proto::crypto::KeyPair;
use teton_proto::label::Label;
use teton_proto::{PROTOCOL_VERSION, b64};
use tracing::info;

pub const KEY_FILE: &str = "device_key.p8";
pub const LABEL_FILE: &str = "label.json";

pub struct Identity {
    pub key: KeyPair,
    pub label: Label,
    pub url: String,
}

/// Loads the device key from `dir`, creating it (mode 0600) on first run, and
/// (re)writes `label.json`. The key is never regenerated here.
pub fn load_or_create(dir: &Path, base_url: &str) -> Result<Identity> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let key_path = dir.join(KEY_FILE);
    let key = if key_path.exists() {
        KeyPair::from_pkcs8(&fs::read(&key_path)?)
            .with_context(|| format!("loading {}", key_path.display()))?
    } else {
        let key = KeyPair::generate()?;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .with_context(|| format!("creating {}", key_path.display()))?;
        f.write_all(&key.to_pkcs8()?)?;
        f.sync_all()?;
        info!(path = %key_path.display(), "generated new device key");
        key
    };
    let label = Label::new(key.public_key());
    let url = label.url(base_url);
    let doc = json!({
        "v": PROTOCOL_VERSION,
        "id": label.id,
        "pk": b64::encode(&label.public_key),
        "url": url,
    });
    fs::write(dir.join(LABEL_FILE), serde_json::to_vec_pretty(&doc)?)?;
    Ok(Identity { key, label, url })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_once_then_reloads() {
        let dir = std::env::temp_dir().join(format!("teton-id-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let a = load_or_create(&dir, "https://x.test/").unwrap();
        let mode = fs::metadata(dir.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let b = load_or_create(&dir, "https://x.test/").unwrap();
        assert_eq!(a.label, b.label);
        let doc: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(LABEL_FILE)).unwrap()).unwrap();
        assert_eq!(doc["url"], a.url.as_str());
        assert_eq!(Label::parse_url(&a.url).unwrap(), a.label);
        fs::remove_dir_all(&dir).unwrap();
    }
}
