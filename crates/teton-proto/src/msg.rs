//! Wire messages (SPEC.md §4.2, §6.2). Every message is JSON with a `t` tag.
//!
//! Types are split by direction so each side can only parse what its peer
//! is allowed to send. Unknown fields are ignored for forward compatibility;
//! unknown message types are a protocol error.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::b64;

// ---------------------------------------------------------------- outer layer

/// Plaintext-layer messages, phone → device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PhoneOuter {
    Hello { v: u8 },
    Sealed(Sealed),
}

/// Plaintext-layer messages, device → phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DeviceOuter {
    Challenge {
        v: u8,
        id: String,
        #[serde(with = "b64")]
        n: Vec<u8>,
        mtu: u16,
    },
    Wait {
        retry_after: u32,
    },
    Error {
        code: ErrorCode,
    },
    Sealed(Sealed),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Phone ephemeral public key; present only in the first phone → device message.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64::option")]
    pub e: Option<Vec<u8>>,
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedVersion,
    Protocol,
}

// ---------------------------------------------------------------- sealed layer

/// Sealed messages, phone → device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PhoneMsg {
    Open,
    Scan,
    Join(JoinRequest),
    Ack,
}

/// Sealed messages, device → phone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DeviceMsg {
    Ready {
        state: DeviceState,
        retry_after: u32,
        version: String,
    },
    Networks {
        list: Vec<Network>,
    },
    Status(Status),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub ssid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<Secret>,
    /// Required only for hidden networks; otherwise taken from the device's scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sec: Option<Security>,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Unprovisioned,
    Recovery,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub ssid: String,
    /// 0–100, as reported by NetworkManager.
    pub signal: u8,
    pub sec: Security,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "wpa2")]
    Wpa2,
    #[serde(rename = "wpa3")]
    Wpa3,
    #[serde(rename = "wpa2/wpa3")]
    Wpa2Wpa3,
    #[serde(rename = "enterprise")]
    Enterprise,
    #[serde(rename = "wep")]
    Wep,
}

impl Security {
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Open | Self::Wpa2 | Self::Wpa3 | Self::Wpa2Wpa3)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub stage: Stage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internet: Option<Internet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<FailReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u32>,
}

impl Status {
    pub fn stage(stage: Stage) -> Self {
        Self {
            stage,
            ip: None,
            internet: None,
            reason: None,
            retry_after: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Accepted,
    Associating,
    Ip,
    Done,
    Failed,
    Locked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Internet {
    Full,
    Limited,
    Portal,
    #[serde(rename = "none")]
    NoInternet,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    InvalidInput,
    UnsupportedSecurity,
    SsidNotFound,
    AuthFailed,
    DhcpFailed,
    Timeout,
    Internal,
}

impl FailReason {
    /// Whether this failure reached the network's authentication and so
    /// counts toward the device-wide join lockout (SPEC.md §6.3, §7.1).
    pub fn counts_toward_lockout(self) -> bool {
        matches!(self, Self::AuthFailed | Self::Timeout)
    }
}

// ---------------------------------------------------------------- secrets

/// A credential that never appears in `Debug`/`Display` output and is wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted len={}>", self.0.chars().count())
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

// ---------------------------------------------------------------- encoding

/// Serializes a message to its compact JSON wire form.
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    serde_json::to_vec(msg).expect("message types always serialize")
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        assert_eq!(
            encode(&PhoneOuter::Hello { v: 1 }),
            br#"{"t":"hello","v":1}"#
        );
        assert_eq!(encode(&PhoneMsg::Open), br#"{"t":"open"}"#);
        assert_eq!(
            encode(&DeviceOuter::Sealed(Sealed {
                e: None,
                ct: vec![1, 2]
            })),
            br#"{"t":"sealed","ct":"AQI"}"#
        );
        let status = DeviceMsg::Status(Status {
            internet: Some(Internet::NoInternet),
            ..Status::stage(Stage::Done)
        });
        assert_eq!(
            encode(&status),
            br#"{"t":"status","stage":"done","internet":"none"}"#
        );
        assert_eq!(
            encode(&Network {
                ssid: "x".into(),
                signal: 5,
                sec: Security::Wpa2Wpa3
            }),
            br#"{"ssid":"x","signal":5,"sec":"wpa2/wpa3"}"#
        );
    }

    #[test]
    fn join_parsing() {
        let j: PhoneMsg =
            decode(br#"{"t":"join","ssid":"roy","psk":"hunter22","future":1}"#).unwrap();
        let PhoneMsg::Join(j) = j else { panic!() };
        assert_eq!(j.psk.as_ref().unwrap().expose(), "hunter22");
        assert!(!j.hidden);
        assert!(!format!("{j:?}").contains("hunter22"));
        assert!(format!("{j:?}").contains("<redacted len=8>"));
    }

    #[test]
    fn direction_is_enforced() {
        assert!(
            decode::<PhoneMsg>(br#"{"t":"ready","state":"manual","retry_after":0,"version":"x"}"#)
                .is_err()
        );
        assert!(
            decode::<PhoneOuter>(br#"{"t":"challenge","v":1,"id":"A","n":"AA","mtu":23}"#).is_err()
        );
        assert!(decode::<PhoneMsg>(br#"{"t":"bogus"}"#).is_err());
    }
}
