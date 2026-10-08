//! Wi-Fi backends (SPEC.md §8): validation and NetworkManager mapping rules
//! shared by all backends, plus the backends themselves.

pub mod nm;

use teton_proto::msg::{FailReason, Internet, JoinRequest, Network, Security};

/// Profile name of the provisioned network, and of the in-flight candidate.
pub const PROFILE_ID: &str = "teton-provisioned";
pub const CANDIDATE_ID: &str = "teton-provisioned-candidate";

/// Progress reported while joining, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Associating,
    GotIp(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub ip: String,
    pub internet: Internet,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason:?}: {detail}")]
pub struct JoinFailure {
    pub reason: FailReason,
    /// Diagnostic detail for logs; never contains secrets.
    pub detail: String,
}

impl JoinFailure {
    pub fn new(reason: FailReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait WifiBackend {
    /// Up to 20 visible networks, strongest first, one entry per SSID.
    async fn scan(&self) -> anyhow::Result<Vec<Network>>;
    /// Joins `req`, reporting progress; on failure the previous state is restored.
    async fn join(
        &self,
        req: &JoinRequest,
        progress: tokio::sync::mpsc::UnboundedSender<Progress>,
    ) -> Result<Joined, JoinFailure>;
}

/// Input checks done before touching the radio (SPEC.md §6.3 `invalid_input`).
pub fn validate(req: &JoinRequest, sec: Security) -> Result<(), JoinFailure> {
    let invalid = |d: &str| Err(JoinFailure::new(FailReason::InvalidInput, d));
    if req.ssid.is_empty() || req.ssid.len() > 32 {
        return invalid("SSID must be 1-32 bytes");
    }
    if !sec.is_supported() {
        return Err(JoinFailure::new(
            FailReason::UnsupportedSecurity,
            format!("{sec:?}"),
        ));
    }
    match (sec, &req.psk) {
        (Security::Open, None) => Ok(()),
        (Security::Open, Some(_)) => invalid("password given for an open network"),
        (_, None) => invalid("password required"),
        (_, Some(psk)) => {
            let p = psk.expose();
            let passphrase =
                (8..=63).contains(&p.len()) && p.bytes().all(|b| (32..=126).contains(&b));
            let hex_key = p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit());
            if passphrase || hex_key {
                Ok(())
            } else {
                invalid("password must be 8-63 printable ASCII characters or 64 hex digits")
            }
        }
    }
}

// NM constants, from nm-dbus-interface.h (NetworkManager 1.46).
pub mod consts {
    pub const DEVICE_TYPE_WIFI: u32 = 2;

    pub const STATE_DISCONNECTED: u32 = 30;
    pub const STATE_PREPARE: u32 = 40;
    pub const STATE_CONFIG: u32 = 50;
    pub const STATE_NEED_AUTH: u32 = 60;
    pub const STATE_IP_CONFIG: u32 = 70;
    pub const STATE_ACTIVATED: u32 = 100;
    pub const STATE_DEACTIVATING: u32 = 110;
    pub const STATE_FAILED: u32 = 120;

    pub const REASON_IP_CONFIG_UNAVAILABLE: u32 = 5;
    pub const REASON_NO_SECRETS: u32 = 7;
    pub const REASON_SUPPLICANT_DISCONNECT: u32 = 8;
    pub const REASON_SUPPLICANT_FAILED: u32 = 10;
    pub const REASON_SUPPLICANT_TIMEOUT: u32 = 11;
    pub const REASON_DHCP_START_FAILED: u32 = 15;
    pub const REASON_DHCP_ERROR: u32 = 16;
    pub const REASON_DHCP_FAILED: u32 = 17;
    pub const REASON_SSID_NOT_FOUND: u32 = 53;

    pub const AP_FLAGS_PRIVACY: u32 = 0x1;
    pub const AP_SEC_KEY_MGMT_PSK: u32 = 0x100;
    pub const AP_SEC_KEY_MGMT_802_1X: u32 = 0x200;
    pub const AP_SEC_KEY_MGMT_SAE: u32 = 0x400;
    pub const AP_SEC_KEY_MGMT_OWE: u32 = 0x800;
    pub const AP_SEC_KEY_MGMT_OWE_TM: u32 = 0x1000;
    pub const AP_SEC_KEY_MGMT_EAP_SUITE_B_192: u32 = 0x2000;

    pub const CONNECTIVITY_NONE: u32 = 1;
    pub const CONNECTIVITY_PORTAL: u32 = 2;
    pub const CONNECTIVITY_LIMITED: u32 = 3;
    pub const CONNECTIVITY_FULL: u32 = 4;

    pub const ADD_CONNECTION2_IN_MEMORY: u32 = 0x2;
    pub const ADD_CONNECTION2_BLOCK_AUTOCONNECT: u32 = 0x20;
    pub const UPDATE2_TO_DISK: u32 = 0x1;
}

use consts::*;

/// How a scanned AP is secured: what the phone sees, and the NM `key-mgmt`
/// to join it with (`None` = no security section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApSecurity {
    pub sec: Security,
    pub key_mgmt: Option<&'static str>,
}

/// Classifies an AP from its `Flags`, `WpaFlags` and `RsnFlags`.
pub fn classify(flags: u32, wpa_flags: u32, rsn_flags: u32) -> ApSecurity {
    let km = wpa_flags | rsn_flags;
    let (sec, key_mgmt) = if km & (AP_SEC_KEY_MGMT_802_1X | AP_SEC_KEY_MGMT_EAP_SUITE_B_192) != 0 {
        (Security::Enterprise, None)
    } else if km & AP_SEC_KEY_MGMT_PSK != 0 && km & AP_SEC_KEY_MGMT_SAE != 0 {
        (Security::Wpa2Wpa3, Some("wpa-psk"))
    } else if km & AP_SEC_KEY_MGMT_SAE != 0 {
        (Security::Wpa3, Some("sae"))
    } else if km & AP_SEC_KEY_MGMT_PSK != 0 {
        (Security::Wpa2, Some("wpa-psk"))
    } else if km & (AP_SEC_KEY_MGMT_OWE | AP_SEC_KEY_MGMT_OWE_TM) != 0 {
        // Enhanced Open: no password for the user, encrypted on the air.
        (Security::Open, Some("owe"))
    } else if flags & AP_FLAGS_PRIVACY != 0 {
        (Security::Wep, None)
    } else {
        (Security::Open, None)
    };
    ApSecurity { sec, key_mgmt }
}

/// `key-mgmt` for a hidden network, whose security the phone states.
pub fn key_mgmt_for(sec: Security) -> Option<&'static str> {
    match sec {
        Security::Wpa2 | Security::Wpa2Wpa3 => Some("wpa-psk"),
        Security::Wpa3 => Some("sae"),
        _ => None,
    }
}

/// Maps an NM device state reason to the protocol failure reason (SPEC.md §6.3).
pub fn map_reason(reason: u32) -> FailReason {
    match reason {
        REASON_NO_SECRETS
        | REASON_SUPPLICANT_DISCONNECT
        | REASON_SUPPLICANT_FAILED
        | REASON_SUPPLICANT_TIMEOUT => FailReason::AuthFailed,
        REASON_SSID_NOT_FOUND => FailReason::SsidNotFound,
        REASON_IP_CONFIG_UNAVAILABLE
        | REASON_DHCP_START_FAILED
        | REASON_DHCP_ERROR
        | REASON_DHCP_FAILED => FailReason::DhcpFailed,
        _ => FailReason::Internal,
    }
}

pub fn map_connectivity(c: u32) -> Internet {
    match c {
        CONNECTIVITY_FULL => Internet::Full,
        CONNECTIVITY_LIMITED => Internet::Limited,
        CONNECTIVITY_PORTAL => Internet::Portal,
        CONNECTIVITY_NONE => Internet::NoInternet,
        _ => Internet::Unknown,
    }
}

/// Keeps the strongest entry per SSID, drops hidden ones, sorts by signal, caps at 20.
pub fn dedupe(mut aps: Vec<Network>) -> Vec<Network> {
    aps.retain(|n| !n.ssid.is_empty());
    aps.sort_by_key(|n| std::cmp::Reverse(n.signal));
    let mut seen = std::collections::HashSet::new();
    aps.retain(|n| seen.insert(n.ssid.clone()));
    aps.truncate(20);
    aps
}

#[cfg(test)]
mod tests {
    use super::*;
    use teton_proto::msg::Secret;

    fn req(ssid: &str, psk: Option<&str>) -> JoinRequest {
        JoinRequest {
            ssid: ssid.into(),
            psk: psk.map(|p| Secret::new(p.into())),
            sec: None,
            hidden: false,
        }
    }

    #[test]
    fn validation() {
        let ok = |r, s| validate(&r, s).is_ok();
        let reason = |r, s| validate(&r, s).unwrap_err().reason;
        assert!(ok(req("roy", Some("12345678")), Security::Wpa2));
        assert!(ok(req("roy", Some(&"a".repeat(63))), Security::Wpa3));
        assert!(ok(req("roy", Some(&"aB".repeat(32))), Security::Wpa2));
        assert!(ok(req("roy", None), Security::Open));
        assert_eq!(
            reason(req("roy", Some("short")), Security::Wpa2),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req("roy", Some(&"g".repeat(64))), Security::Wpa2),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req("roy", Some("pässwörd1")), Security::Wpa2),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req("roy", None), Security::Wpa2),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req("roy", Some("12345678")), Security::Open),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req("", None), Security::Open),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req(&"x".repeat(33), None), Security::Open),
            FailReason::InvalidInput
        );
        assert_eq!(
            reason(req("corp", Some("12345678")), Security::Enterprise),
            FailReason::UnsupportedSecurity
        );
        assert_eq!(
            reason(req("old", Some("12345678")), Security::Wep),
            FailReason::UnsupportedSecurity
        );
    }

    #[test]
    fn classification() {
        let c = |f, w, r| classify(f, w, r).sec;
        assert_eq!(c(0, 0, 0), Security::Open);
        assert_eq!(c(1, 0, 0), Security::Wep);
        assert_eq!(c(1, 0x10a, 0x188), Security::Wpa2); // WPA1+WPA2 PSK
        assert_eq!(c(1, 0, 0x588), Security::Wpa2Wpa3);
        assert_eq!(c(1, 0, 0x488), Security::Wpa3);
        assert_eq!(c(1, 0, 0x288), Security::Enterprise);
        assert_eq!(
            classify(0, 0, 0x888),
            ApSecurity {
                sec: Security::Open,
                key_mgmt: Some("owe")
            }
        );
        assert_eq!(classify(1, 0, 0x588).key_mgmt, Some("wpa-psk"));
        assert_eq!(classify(1, 0, 0x488).key_mgmt, Some("sae"));
    }

    #[test]
    fn reasons() {
        assert_eq!(map_reason(7), FailReason::AuthFailed);
        assert_eq!(map_reason(8), FailReason::AuthFailed);
        assert_eq!(map_reason(11), FailReason::AuthFailed);
        assert_eq!(map_reason(53), FailReason::SsidNotFound);
        assert_eq!(map_reason(5), FailReason::DhcpFailed);
        assert_eq!(map_reason(17), FailReason::DhcpFailed);
        assert_eq!(map_reason(9), FailReason::Internal);
        assert_eq!(map_connectivity(4), Internet::Full);
        assert_eq!(map_connectivity(0), Internet::Unknown);
    }

    #[test]
    fn dedupes_networks() {
        let n = |s: &str, sig| Network {
            ssid: s.into(),
            signal: sig,
            sec: Security::Open,
        };
        let out = dedupe(vec![n("a", 10), n("", 99), n("b", 50), n("a", 70)]);
        assert_eq!(out, vec![n("a", 70), n("b", 50)]);
        assert_eq!(
            dedupe((0..30).map(|i| n(&i.to_string(), i)).collect()).len(),
            20
        );
    }
}
