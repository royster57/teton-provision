//! One provisioning session with one phone (SPEC.md §6).
//!
//! Runs as its own task: whole messages in, whole messages out. Chunking,
//! BLE and the device-wide state machine are the caller's job.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use teton_proto::PROTOCOL_VERSION;
use teton_proto::crypto::{Channel, KeyPair, NONCE_LEN};
use teton_proto::msg::{
    self, DeviceMsg, DeviceOuter, DeviceState, ErrorCode, JoinRequest, PhoneMsg, PhoneOuter,
    Sealed, Stage, Status,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::{Instant, timeout};
use tracing::{info, warn};

use crate::lockout::{JoinLockout, ceil_secs};
use crate::wifi::{Progress, WifiBackend};

/// Decryption failures tolerated in one session before it is ended.
pub const MAX_DECRYPT_FAILURES: u32 = 3;

pub struct SessionCtx<W> {
    pub key: Arc<KeyPair>,
    pub id: String,
    pub wifi: Arc<W>,
    pub lockout: Arc<Mutex<JoinLockout>>,
    /// Reported to the phone in `ready`.
    pub state: DeviceState,
    /// Connection backoff still to run; non-zero means `hello` gets `wait`.
    pub refuse_for: Duration,
    pub idle_timeout: Duration,
    pub ack_timeout: Duration,
    /// ATT MTU seen on the first write, reported in `challenge`.
    pub mtu: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// Joined a network (whether or not the phone acknowledged).
    Provisioned,
    /// Connection backoff was active; `hello` got `wait`.
    Refused,
    IdleTimeout,
    Protocol,
    DecryptFailures,
    /// The phone disconnected.
    PhoneGone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEnd {
    pub reason: EndReason,
    /// The phone completed the key exchange (it holds the label).
    pub verified: bool,
}

#[derive(Debug)]
pub enum SessionOut {
    Send(Vec<u8>),
    /// Always the last item; everything before it has been queued.
    End(SessionEnd),
}

enum Recv {
    Msg(Vec<u8>),
    Idle,
    Gone,
}

struct Session<W> {
    ctx: SessionCtx<W>,
    inbound: UnboundedReceiver<Vec<u8>>,
    out: UnboundedSender<SessionOut>,
    channel: Option<Channel>,
    decrypt_failures: u32,
    verified: bool,
}

/// Runs a session to completion. `inbound` closing means the phone left.
pub async fn run<W: WifiBackend>(
    ctx: SessionCtx<W>,
    inbound: UnboundedReceiver<Vec<u8>>,
    out: UnboundedSender<SessionOut>,
) {
    let mut s = Session {
        ctx,
        inbound,
        out,
        channel: None,
        decrypt_failures: 0,
        verified: false,
    };
    let reason = s.drive().await;
    info!(?reason, verified = s.verified, "session ended");
    let _ = s.out.send(SessionOut::End(SessionEnd {
        reason,
        verified: s.verified,
    }));
}

impl<W: WifiBackend> Session<W> {
    async fn recv(&mut self, wait: Duration) -> Recv {
        match timeout(wait, self.inbound.recv()).await {
            Ok(Some(m)) => Recv::Msg(m),
            Ok(None) => Recv::Gone,
            Err(_) => Recv::Idle,
        }
    }

    fn send_plain(&self, m: &DeviceOuter) {
        let _ = self.out.send(SessionOut::Send(msg::encode(m)));
    }

    fn send_sealed(&mut self, m: &DeviceMsg) {
        let channel = self
            .channel
            .as_mut()
            .expect("sealed send before key exchange");
        match channel.seal(&msg::encode(m)) {
            Ok(ct) => self.send_plain(&DeviceOuter::Sealed(Sealed { e: None, ct })),
            Err(e) => warn!(error = %e, "seal failed"),
        }
    }

    fn status(&mut self, s: Status) {
        self.send_sealed(&DeviceMsg::Status(s));
    }

    fn protocol_error(&self, what: &str) -> EndReason {
        warn!(what, "protocol error");
        self.send_plain(&DeviceOuter::Error {
            code: ErrorCode::Protocol,
        });
        EndReason::Protocol
    }

    /// Counts a message that failed to decrypt; true once the session must end.
    fn decrypt_failed(&mut self) -> bool {
        self.decrypt_failures += 1;
        warn!(count = self.decrypt_failures, "message failed to decrypt");
        if self.decrypt_failures >= MAX_DECRYPT_FAILURES {
            self.send_plain(&DeviceOuter::Error {
                code: ErrorCode::Protocol,
            });
            return true;
        }
        false
    }

    async fn drive(&mut self) -> EndReason {
        let idle = self.ctx.idle_timeout;

        // hello → challenge (or wait / error)
        let first = match self.recv(idle).await {
            Recv::Msg(m) => m,
            Recv::Idle => return EndReason::IdleTimeout,
            Recv::Gone => return EndReason::PhoneGone,
        };
        match msg::decode::<PhoneOuter>(&first) {
            Ok(PhoneOuter::Hello { v }) if v == PROTOCOL_VERSION => {}
            Ok(PhoneOuter::Hello { v }) => {
                warn!(v, "unsupported protocol version");
                self.send_plain(&DeviceOuter::Error {
                    code: ErrorCode::UnsupportedVersion,
                });
                return EndReason::Protocol;
            }
            _ => return self.protocol_error("expected hello"),
        }
        if !self.ctx.refuse_for.is_zero() {
            let retry_after = ceil_secs(self.ctx.refuse_for);
            info!(retry_after, "refusing session: connection backoff active");
            self.send_plain(&DeviceOuter::Wait { retry_after });
            return EndReason::Refused;
        }
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).expect("system RNG");
        self.send_plain(&DeviceOuter::Challenge {
            v: PROTOCOL_VERSION,
            id: self.ctx.id.clone(),
            n: nonce.to_vec(),
            mtu: self.ctx.mtu,
        });

        // first sealed message carries the phone's ephemeral key and must be `open`
        loop {
            let m = match self.recv(idle).await {
                Recv::Msg(m) => m,
                Recv::Idle => return EndReason::IdleTimeout,
                Recv::Gone => return EndReason::PhoneGone,
            };
            let Ok(PhoneOuter::Sealed(Sealed { e: Some(e), ct })) = msg::decode(&m) else {
                return self.protocol_error("expected sealed open with ephemeral key");
            };
            let opened = Channel::accept(&self.ctx.key, &self.ctx.id, &nonce, &e)
                .and_then(|mut ch| ch.open(&ct).map(|pt| (ch, pt)));
            match opened {
                Ok((ch, pt)) => {
                    if !matches!(msg::decode::<PhoneMsg>(&pt), Ok(PhoneMsg::Open)) {
                        return self.protocol_error("expected open");
                    }
                    self.channel = Some(ch);
                    break;
                }
                Err(_) if self.decrypt_failed() => return EndReason::DecryptFailures,
                Err(_) => {}
            }
        }
        self.verified = true;
        let retry_after = ceil_secs(
            self.ctx
                .lockout
                .lock()
                .expect("lock")
                .remaining(Instant::now()),
        );
        info!(retry_after, "phone verified the device; session open");
        self.send_sealed(&DeviceMsg::Ready {
            state: self.ctx.state,
            retry_after,
            version: env!("CARGO_PKG_VERSION").into(),
        });

        // scan / join / ack
        let mut joined = false;
        loop {
            let wait = if joined { self.ctx.ack_timeout } else { idle };
            let m = match self.recv(wait).await {
                Recv::Msg(m) => m,
                Recv::Idle | Recv::Gone if joined => return EndReason::Provisioned,
                Recv::Idle => return EndReason::IdleTimeout,
                Recv::Gone => return EndReason::PhoneGone,
            };
            let ct = match msg::decode::<PhoneOuter>(&m) {
                Ok(PhoneOuter::Sealed(Sealed { e: None, ct })) => ct,
                _ => return self.protocol_error("expected sealed message"),
            };
            let pt = match self.channel.as_mut().expect("open").open(&ct) {
                Ok(pt) => pt,
                Err(_) if self.decrypt_failed() => return EndReason::DecryptFailures,
                Err(_) => continue,
            };
            match msg::decode::<PhoneMsg>(&pt) {
                Ok(PhoneMsg::Scan) if !joined => {
                    let list = self.ctx.wifi.scan().await.unwrap_or_else(|e| {
                        warn!(error = %e, "scan failed");
                        Vec::new()
                    });
                    info!(networks = list.len(), "scan");
                    self.send_sealed(&DeviceMsg::Networks { list });
                }
                Ok(PhoneMsg::Join(req)) if !joined => joined = self.join(req).await,
                Ok(PhoneMsg::Ack) if joined => return EndReason::Provisioned,
                _ => return self.protocol_error("unexpected message"),
            }
        }
    }

    /// Runs one join attempt under the device-wide lockout. True on success.
    async fn join(&mut self, req: JoinRequest) -> bool {
        let remaining = self
            .ctx
            .lockout
            .lock()
            .expect("lock")
            .remaining(Instant::now());
        if !remaining.is_zero() {
            info!(
                retry_after = ceil_secs(remaining),
                "join refused: lockout active"
            );
            self.status(Status {
                retry_after: Some(ceil_secs(remaining)),
                ..Status::stage(Stage::Locked)
            });
            return false;
        }
        info!(ssid = %req.ssid, psk = ?req.psk, sec = ?req.sec, hidden = req.hidden, "join requested");
        self.status(Status::stage(Stage::Accepted));

        let (ptx, mut prx) = unbounded_channel();
        let wifi = self.ctx.wifi.clone();
        let attempt = wifi.join(&req, ptx);
        tokio::pin!(attempt);
        let result = loop {
            tokio::select! {
                r = &mut attempt => break r,
                Some(p) = prx.recv() => self.progress(p),
            }
        };
        while let Ok(p) = prx.try_recv() {
            self.progress(p);
        }

        let mut lockout = self.ctx.lockout.lock().expect("lock");
        match result {
            Ok(j) => {
                lockout.record_success();
                drop(lockout);
                info!(ip = %j.ip, internet = ?j.internet, "join succeeded");
                self.status(Status {
                    ip: Some(j.ip),
                    internet: Some(j.internet),
                    ..Status::stage(Stage::Done)
                });
                true
            }
            Err(f) => {
                let now = Instant::now();
                if f.reason.counts_toward_lockout() {
                    lockout.record_failure(now);
                }
                let retry = ceil_secs(lockout.remaining(now));
                drop(lockout);
                info!(reason = ?f.reason, detail = %f.detail, retry_after = retry, "join failed");
                self.status(Status {
                    reason: Some(f.reason),
                    retry_after: (retry > 0).then_some(retry),
                    ..Status::stage(Stage::Failed)
                });
                false
            }
        }
    }

    fn progress(&mut self, p: Progress) {
        match p {
            Progress::Associating => self.status(Status::stage(Stage::Associating)),
            Progress::GotIp(ip) => self.status(Status {
                ip: Some(ip),
                ..Status::stage(Stage::Ip)
            }),
        }
    }
}
