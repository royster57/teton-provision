//! NetworkManager backend over D-Bus (SPEC.md §8.1).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use teton_proto::msg::{FailReason, JoinRequest, Network};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, info, warn};
use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::consts::*;
use super::{
    ApSecurity, CANDIDATE_ID, JoinFailure, Joined, PROFILE_ID, Progress, WifiBackend, classify,
    dedupe, key_mgmt_for, map_connectivity, map_reason, validate,
};

const SCAN_WAIT: Duration = Duration::from_secs(8);

#[proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn get_device_by_ip_iface(&self, iface: &str) -> zbus::Result<OwnedObjectPath>;
    fn activate_connection(
        &self,
        connection: &ObjectPath<'_>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<OwnedObjectPath>;
    fn deactivate_connection(&self, active_connection: &ObjectPath<'_>) -> zbus::Result<()>;
    fn check_connectivity(&self) -> zbus::Result<u32>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager/Settings"
)]
trait Settings {
    fn list_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn add_connection2(
        &self,
        settings: HashMap<&str, HashMap<&str, Value<'_>>>,
        flags: u32,
        args: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<(OwnedObjectPath, HashMap<String, OwnedValue>)>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings.Connection",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Connection {
    fn get_settings(&self) -> zbus::Result<HashMap<String, HashMap<String, OwnedValue>>>;
    fn update2(
        &self,
        settings: HashMap<&str, HashMap<&str, Value<'_>>>,
        flags: u32,
        args: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<HashMap<String, OwnedValue>>;
    fn delete(&self) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Device {
    #[zbus(signal)]
    fn state_changed(&self, new_state: u32, old_state: u32, reason: u32) -> zbus::Result<()>;
    // Renamed: the property's change stream would clash with the StateChanged signal's.
    #[zbus(property, name = "State")]
    fn current_state(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn active_connection(&self) -> zbus::Result<OwnedObjectPath>;
    #[zbus(property)]
    fn ip4_config(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Wireless {
    fn request_scan(&self, options: HashMap<&str, Value<'_>>) -> zbus::Result<()>;
    fn get_all_access_points(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(property)]
    fn last_scan(&self) -> zbus::Result<i64>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.AccessPoint",
    default_service = "org.freedesktop.NetworkManager"
)]
trait AccessPoint {
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<Vec<u8>>;
    #[zbus(property)]
    fn strength(&self) -> zbus::Result<u8>;
    #[zbus(property)]
    fn flags(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn wpa_flags(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn rsn_flags(&self) -> zbus::Result<u32>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.Connection.Active",
    default_service = "org.freedesktop.NetworkManager"
)]
trait ActiveConnection {
    #[zbus(property)]
    fn connection(&self) -> zbus::Result<OwnedObjectPath>;
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
}

#[proxy(
    interface = "org.freedesktop.NetworkManager.IP4Config",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Ip4Config {
    #[zbus(property)]
    fn address_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;
}

/// A scanned network with what's needed to join it.
#[derive(Debug, Clone)]
pub struct ScannedAp {
    pub network: Network,
    pub security: ApSecurity,
}

pub struct NmWifi {
    conn: zbus::Connection,
    nm: NetworkManagerProxy<'static>,
    settings: SettingsProxy<'static>,
    device_path: OwnedObjectPath,
    pub iface: String,
    join_timeout: Duration,
}

fn is_root(p: &ObjectPath<'_>) -> bool {
    p.as_str() == "/"
}

impl NmWifi {
    /// Connects to NM and picks `iface`, or the first Wi-Fi device.
    pub async fn connect(iface: Option<&str>, join_timeout: Duration) -> Result<Self> {
        let conn = zbus::Connection::system()
            .await
            .context("connecting to the system bus")?;
        let nm = NetworkManagerProxy::new(&conn).await?;
        let settings = SettingsProxy::new(&conn).await?;
        let device_path = match iface {
            Some(i) => nm
                .get_device_by_ip_iface(i)
                .await
                .with_context(|| format!("no device {i}"))?,
            None => {
                let mut found = None;
                for p in nm.get_devices().await? {
                    if device(&conn, &p).await?.device_type().await? == DEVICE_TYPE_WIFI {
                        found = Some(p);
                        break;
                    }
                }
                found.ok_or_else(|| anyhow!("no Wi-Fi device managed by NetworkManager"))?
            }
        };
        let iface = device(&conn, &device_path).await?.interface().await?;
        info!(%iface, path = %device_path, "using Wi-Fi device");
        Ok(Self {
            conn,
            nm,
            settings,
            device_path,
            iface,
            join_timeout,
        })
    }

    async fn device(&self) -> Result<DeviceProxy<'static>> {
        device(&self.conn, &self.device_path).await
    }

    async fn wireless(&self) -> Result<WirelessProxy<'static>> {
        Ok(WirelessProxy::builder(&self.conn)
            .path(self.device_path.clone())?
            .build()
            .await?)
    }

    /// Requests a fresh scan (best effort) and returns all visible APs.
    pub async fn scan_aps(&self, fresh: bool) -> Result<Vec<ScannedAp>> {
        let wireless = self.wireless().await?;
        if fresh {
            let before = wireless.last_scan().await.unwrap_or(0);
            let mut changes = wireless.receive_last_scan_changed().await;
            match wireless.request_scan(HashMap::new()).await {
                Ok(()) => {
                    let deadline = Instant::now() + SCAN_WAIT;
                    while let Ok(Some(c)) = timeout_at(deadline, changes.next()).await {
                        if c.get().await.is_ok_and(|t| t != before) {
                            break;
                        }
                    }
                }
                // NM rate-limits scans and refuses them while activating; cached results are fine.
                Err(e) => debug!(error = %e, "scan request refused; using cached results"),
            }
        }
        let mut out = Vec::new();
        for path in wireless.get_all_access_points().await? {
            let ap = AccessPointProxy::builder(&self.conn)
                .path(path)?
                .build()
                .await?;
            // An AP can vanish between listing and reading; skip it.
            let Ok(ssid) = ap.ssid().await else { continue };
            let security = classify(
                ap.flags().await.unwrap_or(0),
                ap.wpa_flags().await.unwrap_or(0),
                ap.rsn_flags().await.unwrap_or(0),
            );
            out.push(ScannedAp {
                network: Network {
                    ssid: String::from_utf8_lossy(&ssid).into_owned(),
                    signal: ap.strength().await.unwrap_or(0),
                    sec: security.sec,
                },
                security,
            });
        }
        Ok(out)
    }

    /// Finds the security of `ssid` from cached results, rescanning once if absent.
    async fn lookup(&self, ssid: &str) -> Result<Option<ApSecurity>> {
        for fresh in [false, true] {
            let found = self
                .scan_aps(fresh)
                .await?
                .into_iter()
                .filter(|a| a.network.ssid == ssid)
                .max_by_key(|a| a.network.signal);
            if let Some(a) = found {
                return Ok(Some(a.security));
            }
        }
        Ok(None)
    }

    /// Connection profiles whose `connection.id` is `id`.
    pub async fn profiles_named(&self, id: &str) -> Result<Vec<OwnedObjectPath>> {
        let mut out = Vec::new();
        for path in self.settings.list_connections().await? {
            let Ok(c) = connection(&self.conn, &path).await else {
                continue;
            };
            let Ok(s) = c.get_settings().await else {
                continue;
            };
            let name = s
                .get("connection")
                .and_then(|c| c.get("id"))
                .and_then(|v| <&str>::try_from(v).ok().map(str::to_owned));
            if name.as_deref() == Some(id) {
                out.push(path);
            }
        }
        Ok(out)
    }

    pub async fn delete_profile(&self, path: &ObjectPath<'_>) -> Result<()> {
        connection(&self.conn, path).await?.delete().await?;
        Ok(())
    }

    /// The `connection.id` of the profile active on the Wi-Fi device, if any.
    pub async fn active_profile(&self) -> Result<Option<(String, OwnedObjectPath)>> {
        let ac = self.device().await?.active_connection().await?;
        if is_root(&ac) {
            return Ok(None);
        }
        let ac = ActiveConnectionProxy::builder(&self.conn)
            .path(ac)?
            .build()
            .await?;
        Ok(Some((ac.id().await?, ac.connection().await?)))
    }

    /// Raw NM device state (100 = activated).
    pub async fn device_state(&self) -> Result<u32> {
        Ok(self.device().await?.current_state().await?)
    }

    pub async fn connectivity(&self) -> teton_proto::msg::Internet {
        match self.nm.check_connectivity().await {
            Ok(c) => map_connectivity(c),
            Err(e) => {
                warn!(error = %e, "connectivity check failed");
                teton_proto::msg::Internet::Unknown
            }
        }
    }

    async fn ipv4_address(&self) -> Option<String> {
        let path = self.device().await.ok()?.ip4_config().await.ok()?;
        if is_root(&path) {
            return None;
        }
        let cfg = Ip4ConfigProxy::builder(&self.conn)
            .path(path)
            .ok()?
            .build()
            .await
            .ok()?;
        cfg.address_data().await.ok()?.into_iter().find_map(|a| {
            a.get("address")
                .and_then(|v| <&str>::try_from(v).ok().map(str::to_owned))
        })
    }

    async fn join_inner(
        &self,
        req: &JoinRequest,
        progress: &UnboundedSender<Progress>,
    ) -> Result<Joined, JoinFailure> {
        let internal = |e: anyhow::Error| JoinFailure::new(FailReason::Internal, format!("{e:#}"));

        let security = if req.hidden {
            let sec = req.sec.ok_or_else(|| {
                JoinFailure::new(FailReason::InvalidInput, "hidden network needs `sec`")
            })?;
            ApSecurity {
                sec,
                key_mgmt: key_mgmt_for(sec),
            }
        } else {
            self.lookup(&req.ssid)
                .await
                .map_err(internal)?
                .ok_or_else(|| JoinFailure::new(FailReason::SsidNotFound, "not in scan results"))?
        };
        validate(req, security.sec)?;

        // Remember what to restore if this attempt fails.
        let previous = self.profiles_named(PROFILE_ID).await.map_err(internal)?;
        let was_active = self.active_profile().await.map_err(internal)?;
        for stale in self.profiles_named(CANDIDATE_ID).await.map_err(internal)? {
            let _ = self.delete_profile(&stale).await;
        }

        let uuid = new_uuid();
        let (candidate, _) = self
            .settings
            .add_connection2(
                profile_settings(req, security, &uuid, CANDIDATE_ID, false),
                ADD_CONNECTION2_IN_MEMORY | ADD_CONNECTION2_BLOCK_AUTOCONNECT,
                HashMap::new(),
            )
            .await
            .map_err(|e| internal(e.into()))?;
        debug!(path = %candidate, "candidate profile added (in memory)");

        let result = self.activate_and_wait(&candidate, progress).await;
        match result {
            Ok(ip) => {
                // Persist under the final name, then drop the old profile.
                let c = connection(&self.conn, &candidate).await.map_err(internal)?;
                c.update2(
                    profile_settings(req, security, &uuid, PROFILE_ID, true),
                    UPDATE2_TO_DISK,
                    HashMap::new(),
                )
                .await
                .map_err(|e| internal(e.into()))?;
                for old in previous.iter().filter(|p| **p != candidate) {
                    if let Err(e) = self.delete_profile(old).await {
                        warn!(error = %e, "could not delete previous profile");
                    }
                }
                let internet = self.connectivity().await;
                info!(%ip, ?internet, "joined and persisted");
                Ok(Joined { ip, internet })
            }
            Err(failure) => {
                if let Err(e) = self.delete_profile(&candidate).await {
                    warn!(error = %e, "could not delete candidate profile");
                }
                if let Some((id, path)) = was_active.filter(|(id, _)| id == PROFILE_ID) {
                    info!(%id, "restoring previous network");
                    let _ = self
                        .nm
                        .activate_connection(
                            &path,
                            &self.device_path,
                            &ObjectPath::from_static_str_unchecked("/"),
                        )
                        .await;
                }
                Err(failure)
            }
        }
    }

    /// Activates `profile` and follows the device until it is up or fails.
    /// Returns the IPv4 address.
    async fn activate_and_wait(
        &self,
        profile: &ObjectPath<'_>,
        progress: &UnboundedSender<Progress>,
    ) -> Result<String, JoinFailure> {
        let internal = |e: zbus::Error| JoinFailure::new(FailReason::Internal, e.to_string());
        let device = self
            .device()
            .await
            .map_err(|e| JoinFailure::new(FailReason::Internal, e.to_string()))?;
        // Subscribe before activating so no transition is missed.
        let mut states = device.receive_state_changed().await.map_err(internal)?;
        let ac = self
            .nm
            .activate_connection(
                profile,
                &self.device_path,
                &ObjectPath::from_static_str_unchecked("/"),
            )
            .await
            .map_err(internal)?;
        let deadline = Instant::now() + self.join_timeout;

        let mut ours = false; // transitions before PREPARE belong to the previous connection
        let mut configured = false;
        let mut last_reason = 0;
        let outcome = loop {
            let signal = match timeout_at(deadline, states.next()).await {
                Err(_) => {
                    break Err(JoinFailure::new(
                        FailReason::Timeout,
                        format!(
                            "no result within {:?} (last reason {last_reason})",
                            self.join_timeout
                        ),
                    ));
                }
                Ok(None) => {
                    break Err(JoinFailure::new(
                        FailReason::Internal,
                        "NM signal stream ended",
                    ));
                }
                Ok(Some(s)) => s,
            };
            let Ok(args) = signal.args() else { continue };
            let (new, old, reason) = (args.new_state, args.old_state, args.reason);
            debug!(new, old, reason, "device state");
            if reason != 0 {
                last_reason = reason;
            }
            match new {
                STATE_PREPARE => ours = true,
                _ if !ours => {}
                STATE_CONFIG => {
                    if !configured {
                        configured = true;
                        let _ = progress.send(Progress::Associating);
                    }
                }
                // With the PSK stored in a system profile, NM only asks for
                // secrets again after the handshake failed: a wrong password.
                // Cancel now rather than wait for a desktop secret agent.
                STATE_NEED_AUTH if configured => {
                    break Err(JoinFailure::new(
                        FailReason::AuthFailed,
                        format!("handshake failed (reason {reason})"),
                    ));
                }
                STATE_ACTIVATED => match self.ipv4_address().await {
                    Some(ip) => break Ok(ip),
                    None => {
                        break Err(JoinFailure::new(
                            FailReason::DhcpFailed,
                            "activated without an IPv4 address",
                        ));
                    }
                },
                STATE_FAILED => {
                    break Err(JoinFailure::new(
                        map_reason(reason),
                        format!("NM failed (reason {reason})"),
                    ));
                }
                STATE_DISCONNECTED | STATE_DEACTIVATING if configured => {
                    break Err(JoinFailure::new(
                        map_reason(reason),
                        format!("disconnected (reason {reason})"),
                    ));
                }
                _ => {}
            }
        };
        match &outcome {
            Ok(ip) => {
                let _ = progress.send(Progress::GotIp(ip.clone()));
            }
            Err(f) => {
                info!(reason = ?f.reason, detail = %f.detail, "join failed; deactivating");
                let _ = self.nm.deactivate_connection(&ac).await;
            }
        }
        outcome
    }
}

impl WifiBackend for NmWifi {
    async fn scan(&self) -> Result<Vec<Network>> {
        Ok(dedupe(
            self.scan_aps(true)
                .await?
                .into_iter()
                .map(|a| a.network)
                .collect(),
        ))
    }

    async fn join(
        &self,
        req: &JoinRequest,
        progress: UnboundedSender<Progress>,
    ) -> Result<Joined, JoinFailure> {
        self.join_inner(req, &progress).await
    }
}

async fn device(conn: &zbus::Connection, path: &ObjectPath<'_>) -> Result<DeviceProxy<'static>> {
    Ok(DeviceProxy::builder(conn)
        .path(path.to_owned())?
        .build()
        .await?)
}

async fn connection(
    conn: &zbus::Connection,
    path: &ObjectPath<'_>,
) -> Result<ConnectionProxy<'static>> {
    Ok(ConnectionProxy::builder(conn)
        .path(path.to_owned())?
        .build()
        .await?)
}

/// The full NM settings for a provisioned profile. Secrets are system-owned
/// (`psk-flags = 0`) so the device reconnects at boot without a user session.
fn profile_settings<'a>(
    req: &'a JoinRequest,
    security: ApSecurity,
    uuid: &'a str,
    id: &'a str,
    autoconnect: bool,
) -> HashMap<&'static str, HashMap<&'static str, Value<'a>>> {
    let mut s = HashMap::new();
    s.insert(
        "connection",
        HashMap::from([
            ("id", Value::from(id)),
            ("uuid", Value::from(uuid)),
            ("type", Value::from("802-11-wireless")),
            ("autoconnect", Value::from(autoconnect)),
        ]),
    );
    let mut wifi = HashMap::from([
        ("ssid", Value::from(req.ssid.as_bytes())),
        ("mode", Value::from("infrastructure")),
        ("hidden", Value::from(req.hidden)),
    ]);
    if let Some(km) = security.key_mgmt {
        let mut sec = HashMap::from([("key-mgmt", Value::from(km))]);
        if let Some(psk) = &req.psk {
            sec.insert("psk", Value::from(psk.expose()));
            sec.insert("psk-flags", Value::from(0u32));
        }
        s.insert("802-11-wireless-security", sec);
        wifi.insert("security", Value::from("802-11-wireless-security"));
    }
    s.insert("802-11-wireless", wifi);
    // IPv4 is required: ACTIVATED then implies a DHCP lease.
    s.insert(
        "ipv4",
        HashMap::from([
            ("method", Value::from("auto")),
            ("may-fail", Value::from(false)),
        ]),
    );
    s.insert("ipv6", HashMap::from([("method", Value::from("auto"))]));
    s
}

fn new_uuid() -> String {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).expect("system RNG");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = teton_proto::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
