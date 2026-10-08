//! Scripted Wi-Fi backend for tests, CI and demos that must not touch the
//! machine's network (SPEC.md §8). Every network accepts the password
//! [`PASSWORD`]; `Lab-NoDHCP` authenticates but never hands out an address.

use std::sync::Mutex;
use std::time::Duration;

use teton_proto::msg::{FailReason, Internet, JoinRequest, Network, Security};
use tokio::sync::mpsc::UnboundedSender;

use super::{JoinFailure, Joined, NetStatus, Progress, WifiBackend, dedupe, validate};

pub const PASSWORD: &str = "correct horse";
const STEP: Duration = Duration::from_millis(700);

pub struct SimWifi {
    networks: Vec<Network>,
    state: Mutex<NetStatus>,
}

impl Default for SimWifi {
    fn default() -> Self {
        let n = |ssid: &str, signal, sec| Network {
            ssid: ssid.into(),
            signal,
            sec,
        };
        Self {
            networks: vec![
                n("roy", 82, Security::Wpa2),
                n("Teton-Lab", 64, Security::Wpa3),
                n("Hospital-Corp", 58, Security::Enterprise),
                n("Lab-NoDHCP", 47, Security::Wpa2Wpa3),
                n("Guest", 40, Security::Open),
            ],
            state: Mutex::new(NetStatus {
                provisioned: false,
                online: false,
            }),
        }
    }
}

impl SimWifi {
    /// Twenty long-named networks, like a real scan in a building: the
    /// `networks` reply then spans several full-size BLE chunks.
    pub fn crowded() -> Self {
        let mut sim = Self::default();
        sim.networks.extend((0..15).map(|i| Network {
            ssid: format!("Neighbour-Network-With-A-Long-Name-{i:02}"),
            signal: 30 - i,
            sec: Security::Wpa2,
        }));
        sim
    }

    /// Simulates the provisioned network going away or coming back.
    pub fn set_online(&self, online: bool) {
        self.state.lock().expect("lock").online = online;
    }
}

impl WifiBackend for SimWifi {
    async fn scan(&self) -> anyhow::Result<Vec<Network>> {
        tokio::time::sleep(STEP).await;
        Ok(dedupe(self.networks.clone()))
    }

    async fn join(
        &self,
        req: &JoinRequest,
        progress: UnboundedSender<Progress>,
    ) -> Result<Joined, JoinFailure> {
        let sec = match (
            req.hidden,
            self.networks.iter().find(|n| n.ssid == req.ssid),
        ) {
            (true, _) => req.sec.ok_or_else(|| {
                JoinFailure::new(FailReason::InvalidInput, "hidden network needs `sec`")
            })?,
            (false, Some(n)) => n.sec,
            (false, None) => return Err(JoinFailure::new(FailReason::SsidNotFound, "simulated")),
        };
        validate(req, sec)?;
        tokio::time::sleep(STEP).await;
        let _ = progress.send(Progress::Associating);
        tokio::time::sleep(STEP).await;
        let accepted =
            sec == Security::Open || req.psk.as_ref().is_some_and(|p| p.expose() == PASSWORD);
        if !accepted {
            return Err(JoinFailure::new(
                FailReason::AuthFailed,
                "simulated wrong password",
            ));
        }
        if req.ssid == "Lab-NoDHCP" {
            tokio::time::sleep(STEP * 3).await;
            return Err(JoinFailure::new(
                FailReason::DhcpFailed,
                "simulated DHCP timeout",
            ));
        }
        let ip = "10.0.0.42".to_string();
        let _ = progress.send(Progress::GotIp(ip.clone()));
        *self.state.lock().expect("lock") = NetStatus {
            provisioned: true,
            online: true,
        };
        Ok(Joined {
            ip,
            internet: Internet::Full,
        })
    }

    async fn status(&self) -> anyhow::Result<NetStatus> {
        Ok(*self.state.lock().expect("lock"))
    }
}
