//! Device state machine (SPEC.md §7): when to advertise, one session at a
//! time, chunking between the radio and the session, and the device-wide
//! limits that outlive any one session.

use std::future::{Future, pending};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bluer::Address;
use teton_proto::crypto::KeyPair;
use teton_proto::frame::{Reassembler, chunk};
use teton_proto::msg::{self, DeviceOuter, DeviceState, ErrorCode};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::{Instant, MissedTickBehavior, interval};
use tracing::{debug, info, warn};

use crate::ble::Inbound;
use crate::lockout::{ConnectionBackoff, JoinLockout};
use crate::session::{self, EndReason, SessionCtx, SessionEnd, SessionOut};
use crate::wifi::WifiBackend;

/// The BLE operations the device needs; implemented by
/// [`crate::ble::Peripheral`] and by an in-memory radio in tests.
pub trait Radio: Send + 'static {
    fn set_advertising(&mut self, on: bool) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn notify(&self, chunk: Vec<u8>) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn disconnect(&self, addr: Address) -> impl Future<Output = anyhow::Result<()>> + Send;
}

#[derive(Debug, Clone)]
pub struct Timers {
    pub recovery_after: Duration,
    pub idle_timeout: Duration,
    pub ack_timeout: Duration,
    pub manual_window: Duration,
    pub poll_interval: Duration,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            recovery_after: Duration::from_secs(600),
            idle_timeout: Duration::from_secs(120),
            ack_timeout: Duration::from_secs(10),
            manual_window: Duration::from_secs(600),
            poll_interval: Duration::from_secs(5),
        }
    }
}

/// What the device knows about its network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No provisioned profile: advertise.
    Unprovisioned,
    /// Provisioned and online, or offline for less than `recovery_after`.
    Provisioned,
    /// Provisioned but offline too long: advertise while NM keeps retrying.
    Recovery,
}

#[derive(Debug)]
pub enum Control {
    /// `teton-device reprovision`: advertise for `manual_window`.
    Reprovision,
    Shutdown,
}

struct Active {
    owner: Address,
    mtu: u16,
    reassembler: Reassembler,
    /// `None` once the phone disconnected; the session then winds down.
    to_session: Option<UnboundedSender<Vec<u8>>>,
    from_session: UnboundedReceiver<SessionOut>,
}

pub struct Device<W, R> {
    key: Arc<KeyPair>,
    id: String,
    wifi: Arc<W>,
    radio: R,
    timers: Timers,
    lockout: Arc<Mutex<JoinLockout>>,
    backoff: ConnectionBackoff,
    mode: Mode,
    manual_until: Option<Instant>,
    offline_since: Option<Instant>,
    session: Option<Active>,
    advertising: Option<bool>,
}

enum Event {
    Radio(Option<Inbound>),
    Session(SessionOut),
    Poll,
    Control(Option<Control>),
}

impl<W: WifiBackend, R: Radio> Device<W, R> {
    pub fn new(key: Arc<KeyPair>, id: String, wifi: Arc<W>, radio: R, timers: Timers) -> Self {
        Self {
            key,
            id,
            wifi,
            radio,
            timers,
            lockout: Arc::default(),
            backoff: ConnectionBackoff::default(),
            mode: Mode::Unprovisioned,
            manual_until: None,
            offline_since: None,
            session: None,
            advertising: None,
        }
    }

    pub async fn run(
        mut self,
        mut radio_events: UnboundedReceiver<Inbound>,
        mut control: UnboundedReceiver<Control>,
    ) -> anyhow::Result<()> {
        let mut poll = interval(self.timers.poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            let event = tokio::select! {
                e = radio_events.recv() => Event::Radio(e),
                o = next_out(&mut self.session) => Event::Session(o),
                _ = poll.tick() => Event::Poll,
                c = control.recv() => Event::Control(c),
            };
            match event {
                Event::Radio(Some(e)) => self.on_radio(e).await,
                Event::Session(o) => self.on_session(o).await,
                Event::Poll => self.refresh_mode().await,
                Event::Control(Some(Control::Reprovision)) => {
                    info!(window = ?self.timers.manual_window, "manual re-provisioning window opened");
                    self.manual_until = Some(Instant::now() + self.timers.manual_window);
                }
                Event::Radio(None) | Event::Control(Some(Control::Shutdown) | None) => break,
            }
            self.update_advertising().await;
        }
        info!("shutting down");
        let _ = self.radio.set_advertising(false).await;
        Ok(())
    }

    fn wants_advertising(&self) -> bool {
        let manual = self.manual_until.is_some_and(|t| t > Instant::now());
        self.session.is_none() && (self.mode != Mode::Provisioned || manual)
    }

    async fn update_advertising(&mut self) {
        let want = self.wants_advertising();
        if self.advertising != Some(want) {
            match self.radio.set_advertising(want).await {
                Ok(()) => self.advertising = Some(want),
                Err(e) => warn!(error = %e, "could not change advertising"),
            }
        }
    }

    fn phone_state(&self) -> DeviceState {
        match self.mode {
            Mode::Unprovisioned => DeviceState::Unprovisioned,
            Mode::Recovery => DeviceState::Recovery,
            Mode::Provisioned => DeviceState::Manual,
        }
    }

    async fn refresh_mode(&mut self) {
        if self.manual_until.is_some_and(|t| t <= Instant::now()) {
            info!("manual re-provisioning window closed");
            self.manual_until = None;
        }
        let status = match self.wifi.status().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "could not read network status");
                return;
            }
        };
        let now = Instant::now();
        let mode = if !status.provisioned {
            Mode::Unprovisioned
        } else if status.online {
            self.offline_since = None;
            Mode::Provisioned
        } else if now - *self.offline_since.get_or_insert(now) >= self.timers.recovery_after {
            Mode::Recovery
        } else {
            Mode::Provisioned
        };
        if mode != self.mode {
            info!(from = ?self.mode, to = ?mode, "device mode changed");
            self.mode = mode;
        }
    }

    async fn on_radio(&mut self, event: Inbound) {
        match event {
            Inbound::Subscribed => debug!("phone subscribed to notifications"),
            Inbound::Disconnected(addr) => {
                if let Some(a) = self.session.as_mut().filter(|a| a.owner == addr) {
                    info!(%addr, "phone disconnected");
                    a.to_session = None; // the session sees its input close and ends
                }
            }
            Inbound::Write { from, mtu, chunk } => self.on_write(from, mtu, chunk).await,
        }
    }

    async fn on_write(&mut self, from: Address, mtu: u16, data: Vec<u8>) {
        match &self.session {
            Some(a) if a.owner != from => {
                warn!(%from, "second phone while a session is active; disconnecting it");
                let _ = self.radio.disconnect(from).await;
                return;
            }
            Some(_) => {}
            None => self.start_session(from, mtu),
        }
        let a = self.session.as_mut().expect("session just ensured");
        let Some(tx) = &a.to_session else {
            return; // session winding down; ignore the rest of this phone's input
        };
        a.mtu = mtu;
        match a.reassembler.push(&data) {
            Ok(Some(m)) => {
                let _ = tx.send(m);
            }
            Ok(None) => {}
            Err(e) => {
                // Keep the session slot until its task reports the end, so a
                // join in progress can never overlap a new session.
                warn!(error = %e, "framing error; ending session");
                let owner = a.owner;
                self.send(&msg::encode(&DeviceOuter::Error {
                    code: ErrorCode::Protocol,
                }))
                .await;
                if let Some(a) = self.session.as_mut() {
                    a.to_session = None;
                }
                let _ = self.radio.disconnect(owner).await;
            }
        }
    }

    fn start_session(&mut self, owner: Address, mtu: u16) {
        let (to_tx, to_rx) = unbounded_channel();
        let (out_tx, out_rx) = unbounded_channel();
        let ctx = SessionCtx {
            key: self.key.clone(),
            id: self.id.clone(),
            wifi: self.wifi.clone(),
            lockout: self.lockout.clone(),
            state: self.phone_state(),
            refuse_for: self.backoff.remaining(Instant::now()),
            idle_timeout: self.timers.idle_timeout,
            ack_timeout: self.timers.ack_timeout,
            mtu,
        };
        info!(%owner, mtu, "session started");
        tokio::spawn(session::run(ctx, to_rx, out_tx));
        self.session = Some(Active {
            owner,
            mtu,
            reassembler: Reassembler::new(),
            to_session: Some(to_tx),
            from_session: out_rx,
        });
    }

    async fn on_session(&mut self, out: SessionOut) {
        match out {
            SessionOut::Send(m) => self.send(&m).await,
            SessionOut::End(end) => self.end_session(end).await,
        }
    }

    /// Chunks a message to the session's MTU and notifies it.
    async fn send(&self, m: &[u8]) {
        let Some(a) = &self.session else { return };
        let chunks = match chunk(m, usize::from(a.mtu.max(23)) - 3) {
            Ok(c) => c,
            Err(e) => return warn!(error = %e, "cannot chunk outgoing message"),
        };
        for c in chunks {
            if let Err(e) = self.radio.notify(c).await {
                return warn!(error = %e, "notify failed");
            }
        }
    }

    async fn end_session(&mut self, end: SessionEnd) {
        let Some(a) = self.session.take() else { return };
        if a.to_session.is_some() {
            let _ = self.radio.disconnect(a.owner).await;
        }
        if end.reason == EndReason::DecryptFailures {
            self.backoff.record_failure(Instant::now());
        } else if end.verified {
            self.backoff.reset();
        }
        if end.reason == EndReason::Provisioned {
            self.mode = Mode::Provisioned;
            self.offline_since = None;
            self.manual_until = None;
        }
    }
}

async fn next_out(session: &mut Option<Active>) -> SessionOut {
    match session {
        Some(a) => match a.from_session.recv().await {
            Some(o) => o,
            // The task always ends with `End`; treat a vanished task the same way.
            None => SessionOut::End(SessionEnd {
                reason: EndReason::PhoneGone,
                verified: false,
            }),
        },
        None => pending().await,
    }
}
