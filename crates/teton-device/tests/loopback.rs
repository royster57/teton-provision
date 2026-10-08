//! Loopback tests (SPEC.md §11): a test phone built from `teton-proto` drives
//! the real device state machine and session code through an in-memory radio,
//! with simulated Wi-Fi and a paused clock.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bluer::Address;
use teton_device::ble::Inbound;
use teton_device::device::{Control, Device, Radio, Timers};
use teton_device::wifi::sim::{PASSWORD, SimWifi};
use teton_proto::PROTOCOL_VERSION;
use teton_proto::crypto::{Channel, KeyPair, PUBLIC_KEY_LEN};
use teton_proto::frame::{Reassembler, chunk};
use teton_proto::label::device_id;
use teton_proto::msg::{self, *};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::{advance, sleep, timeout};

// ------------------------------------------------------------------ radio

#[derive(Default)]
struct RadioLog {
    advertising: Vec<bool>,
    disconnects: Vec<Address>,
}

struct TestRadio {
    log: Arc<Mutex<RadioLog>>,
    notes: UnboundedSender<Vec<u8>>,
    events: UnboundedSender<Inbound>,
}

impl Radio for TestRadio {
    async fn set_advertising(&mut self, on: bool) -> anyhow::Result<()> {
        self.log.lock().unwrap().advertising.push(on);
        Ok(())
    }

    async fn notify(&self, chunk: Vec<u8>) -> anyhow::Result<()> {
        // Real stacks truncate attribute values beyond 512 bytes (found in M6).
        assert!(
            chunk.len() <= 512,
            "{}-byte notification would be truncated",
            chunk.len()
        );
        let _ = self.notes.send(chunk);
        Ok(())
    }

    async fn disconnect(&self, addr: Address) -> anyhow::Result<()> {
        self.log.lock().unwrap().disconnects.push(addr);
        // BlueZ reports the disconnect back, as on real hardware.
        let _ = self.events.send(Inbound::Disconnected(addr));
        Ok(())
    }
}

// ------------------------------------------------------------------ harness

struct Harness {
    wifi: Arc<SimWifi>,
    log: Arc<Mutex<RadioLog>>,
    events: UnboundedSender<Inbound>,
    notes: UnboundedReceiver<Vec<u8>>,
    control: UnboundedSender<Control>,
    device_public: [u8; PUBLIC_KEY_LEN],
    id: String,
}

fn timers() -> Timers {
    Timers {
        recovery_after: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(120),
        ack_timeout: Duration::from_secs(10),
        manual_window: Duration::from_secs(300),
        poll_interval: Duration::from_secs(5),
    }
}

async fn start() -> Harness {
    start_with(SimWifi::default()).await
}

async fn start_with(wifi: SimWifi) -> Harness {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("info")
        .try_init();
    let key = KeyPair::generate().unwrap();
    let device_public = *key.public_key();
    let id = device_id(&device_public);
    let wifi = Arc::new(wifi);
    let log = Arc::new(Mutex::new(RadioLog::default()));
    let (events_tx, events_rx) = unbounded_channel();
    let (notes_tx, notes_rx) = unbounded_channel();
    let (control_tx, control_rx) = unbounded_channel();
    let radio = TestRadio {
        log: log.clone(),
        notes: notes_tx,
        events: events_tx.clone(),
    };
    let device = Device::new(Arc::new(key), id.clone(), wifi.clone(), radio, timers());
    tokio::spawn(device.run(events_rx, control_rx));
    let h = Harness {
        wifi,
        log,
        events: events_tx,
        notes: notes_rx,
        control: control_tx,
        device_public,
        id,
    };
    settle().await;
    h
}

/// Lets the device task process everything queued.
async fn settle() {
    sleep(Duration::from_millis(10)).await;
}

impl Harness {
    fn advertising(&self) -> bool {
        *self
            .log
            .lock()
            .unwrap()
            .advertising
            .last()
            .expect("advertising decided")
    }

    fn disconnected(&self, phone: &Phone) -> bool {
        self.log.lock().unwrap().disconnects.contains(&phone.addr)
    }

    fn phone(&self, n: u8, mtu: u16) -> Phone {
        Phone {
            addr: Address::new([0x02, 0, 0, 0, 0, n]),
            mtu,
            chunk_len: 20,
            reassembler: Reassembler::new(),
            channel: None,
            events: self.events.clone(),
        }
    }
}

// ------------------------------------------------------------------ phone

struct Phone {
    addr: Address,
    mtu: u16,
    chunk_len: usize,
    reassembler: Reassembler,
    channel: Option<Channel>,
    events: UnboundedSender<Inbound>,
}

impl Phone {
    fn write(&self, message: &[u8]) {
        for c in chunk(message, self.chunk_len).unwrap() {
            self.write_chunk(c);
        }
    }

    fn write_chunk(&self, c: Vec<u8>) {
        let ev = Inbound::Write {
            from: self.addr,
            mtu: self.mtu,
            chunk: c,
        };
        self.events.send(ev).unwrap();
    }

    fn leave(&self) {
        self.events.send(Inbound::Disconnected(self.addr)).unwrap();
    }

    async fn recv_outer(&mut self, h: &mut Harness) -> DeviceOuter {
        loop {
            let c = timeout(Duration::from_secs(600), h.notes.recv())
                .await
                .expect("device answered")
                .expect("radio open");
            if let Some(m) = self.reassembler.push(&c).unwrap() {
                return msg::decode(&m).unwrap();
            }
        }
    }

    /// Expects no message within `wait`.
    async fn silent(&mut self, h: &mut Harness, wait: Duration) {
        assert!(
            timeout(wait, h.notes.recv()).await.is_err(),
            "unexpected message"
        );
    }

    async fn hello(&mut self, h: &mut Harness) -> DeviceOuter {
        self.write(&msg::encode(&PhoneOuter::Hello {
            v: PROTOCOL_VERSION,
        }));
        self.recv_outer(h).await
    }

    /// hello → challenge → open → ready, against `device_public`.
    async fn handshake_with(&mut self, h: &mut Harness, device_public: &[u8]) -> DeviceMsg {
        let DeviceOuter::Challenge { id, n, mtu, .. } = self.hello(h).await else {
            panic!("expected challenge")
        };
        assert_eq!(id, h.id);
        assert_eq!(mtu, self.mtu);
        self.chunk_len = usize::from(mtu - 3).min(512);
        let eph = KeyPair::generate().unwrap();
        let mut channel = Channel::initiate(&eph, device_public, &id, &n).unwrap();
        let ct = channel.seal(&msg::encode(&PhoneMsg::Open)).unwrap();
        self.write(&msg::encode(&PhoneOuter::Sealed(Sealed {
            e: Some(eph.public_key().to_vec()),
            ct,
        })));
        self.channel = Some(channel);
        self.recv_msg(h).await
    }

    async fn handshake(&mut self, h: &mut Harness) -> DeviceMsg {
        let pk = h.device_public;
        self.handshake_with(h, &pk).await
    }

    fn seal(&mut self, m: &PhoneMsg) -> Vec<u8> {
        let ct = self
            .channel
            .as_mut()
            .unwrap()
            .seal(&msg::encode(m))
            .unwrap();
        msg::encode(&PhoneOuter::Sealed(Sealed { e: None, ct }))
    }

    fn send(&mut self, m: &PhoneMsg) {
        let bytes = self.seal(m);
        self.write(&bytes);
    }

    async fn recv_msg(&mut self, h: &mut Harness) -> DeviceMsg {
        match self.recv_outer(h).await {
            DeviceOuter::Sealed(Sealed { ct, .. }) => {
                msg::decode(&self.channel.as_mut().unwrap().open(&ct).unwrap()).unwrap()
            }
            other => panic!("expected sealed message, got {other:?}"),
        }
    }

    /// Sends `join` and returns every status up to the final one.
    async fn join(&mut self, h: &mut Harness, ssid: &str, psk: Option<&str>) -> Vec<Status> {
        self.send(&PhoneMsg::Join(JoinRequest {
            ssid: ssid.into(),
            psk: psk.map(|p| Secret::new(p.into())),
            sec: None,
            hidden: false,
        }));
        let mut out = vec![];
        loop {
            let DeviceMsg::Status(s) = self.recv_msg(h).await else {
                panic!("expected status")
            };
            let last = matches!(s.stage, Stage::Done | Stage::Failed | Stage::Locked);
            out.push(s);
            if last {
                return out;
            }
        }
    }

    async fn join_final(&mut self, h: &mut Harness, ssid: &str, psk: Option<&str>) -> Status {
        self.join(h, ssid, psk).await.pop().unwrap()
    }
}

fn ready_state(m: &DeviceMsg) -> (DeviceState, u32) {
    match m {
        DeviceMsg::Ready {
            state, retry_after, ..
        } => (*state, *retry_after),
        other => panic!("expected ready, got {other:?}"),
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test(start_paused = true)]
async fn happy_path_provisions_and_stops_advertising() {
    let mut h = start().await;
    assert!(h.advertising(), "unprovisioned device advertises");

    let mut p = h.phone(1, 23); // minimum MTU: every message is multi-chunk
    let ready = p.handshake(&mut h).await;
    assert_eq!(ready_state(&ready), (DeviceState::Unprovisioned, 0));
    assert!(!h.advertising(), "advertising paused during a session");

    p.send(&PhoneMsg::Scan);
    let DeviceMsg::Networks { list } = p.recv_msg(&mut h).await else {
        panic!()
    };
    assert_eq!(list[0].ssid, "roy");
    assert!(list.iter().any(|n| n.sec == Security::Enterprise));

    let statuses = p.join(&mut h, "roy", Some(PASSWORD)).await;
    let stages: Vec<_> = statuses.iter().map(|s| s.stage).collect();
    assert_eq!(
        stages,
        [Stage::Accepted, Stage::Associating, Stage::Ip, Stage::Done]
    );
    let done = statuses.last().unwrap();
    assert_eq!(done.ip.as_deref(), Some("10.0.0.42"));
    assert_eq!(done.internet, Some(Internet::Full));

    p.send(&PhoneMsg::Ack);
    settle().await;
    assert!(h.disconnected(&p), "device disconnects after ack");
    assert!(!h.advertising(), "provisioned device stays quiet");
}

#[tokio::test(start_paused = true)]
async fn large_replies_fit_the_att_value_limit() {
    // Regression (M6): at MTU 517 the device sent 514-byte notifications,
    // which BlueZ/Chrome truncate to 512, corrupting multi-chunk messages.
    let mut h = start_with(SimWifi::crowded()).await;
    let mut p = h.phone(1, 517);
    p.handshake(&mut h).await;
    p.send(&PhoneMsg::Scan);
    let DeviceMsg::Networks { list } = p.recv_msg(&mut h).await else {
        panic!()
    };
    assert_eq!(list.len(), 20);
}

#[tokio::test(start_paused = true)]
async fn lockout_is_device_wide_and_survives_reconnecting() {
    let mut h = start().await;
    let mut a = h.phone(1, 517);
    a.handshake(&mut h).await;
    for expected in [None, None, Some(30)] {
        let s = a.join_final(&mut h, "roy", Some("wrong password")).await;
        assert_eq!(
            (s.stage, s.reason),
            (Stage::Failed, Some(FailReason::AuthFailed))
        );
        assert_eq!(s.retry_after, expected);
    }
    let s = a.join_final(&mut h, "roy", Some(PASSWORD)).await;
    assert_eq!(s.stage, Stage::Locked, "even the right password waits");

    // A fresh connection does not reset the lockout, and `ready` reports it.
    a.leave();
    settle().await;
    let mut b = h.phone(2, 517);
    let (_, retry) = ready_state(&b.handshake(&mut h).await);
    assert!((1..=30).contains(&retry), "ready.retry_after = {retry}");
    let s = b.join_final(&mut h, "roy", Some(PASSWORD)).await;
    assert_eq!(s.stage, Stage::Locked);

    advance(Duration::from_secs(30)).await;
    let s = b.join_final(&mut h, "roy", Some("wrong again")).await;
    assert_eq!((s.stage, s.retry_after), (Stage::Failed, Some(60)));
    advance(Duration::from_secs(60)).await;
    let s = b.join_final(&mut h, "roy", Some("still wrong")).await;
    assert_eq!((s.stage, s.retry_after), (Stage::Failed, Some(120)));
    advance(Duration::from_secs(120)).await;
    let s = b.join_final(&mut h, "roy", Some(PASSWORD)).await;
    assert_eq!(s.stage, Stage::Done, "success after the backoff");
}

#[tokio::test(start_paused = true)]
async fn only_auth_failures_count_toward_lockout() {
    let mut h = start().await;
    let mut p = h.phone(1, 517);
    p.handshake(&mut h).await;
    p.join_final(&mut h, "roy", Some("wrong pw 1")).await;
    p.join_final(&mut h, "roy", Some("wrong pw 2")).await;
    let s = p.join_final(&mut h, "Nowhere", Some(PASSWORD)).await;
    assert_eq!(
        (s.reason, s.retry_after),
        (Some(FailReason::SsidNotFound), None)
    );
    let s = p.join_final(&mut h, "roy", Some("short")).await;
    assert_eq!(
        (s.reason, s.retry_after),
        (Some(FailReason::InvalidInput), None)
    );
    let s = p.join_final(&mut h, "Hospital-Corp", Some(PASSWORD)).await;
    assert_eq!(s.reason, Some(FailReason::UnsupportedSecurity));
    let s = p.join_final(&mut h, "Lab-NoDHCP", Some(PASSWORD)).await;
    assert_eq!(
        (s.reason, s.retry_after),
        (Some(FailReason::DhcpFailed), None)
    );
    let s = p.join_final(&mut h, "roy", Some("wrong pw 3")).await;
    assert_eq!(s.retry_after, Some(30), "third auth failure locks");
}

#[tokio::test(start_paused = true)]
async fn impostor_label_ends_session_and_backs_off_new_connections() {
    let mut h = start().await;
    let impostor = KeyPair::generate().unwrap();
    let mut p = h.phone(1, 517);
    let DeviceOuter::Challenge { id, n, .. } = p.hello(&mut h).await else {
        panic!()
    };
    p.chunk_len = 514;
    for _ in 0..3 {
        let eph = KeyPair::generate().unwrap();
        let mut ch = Channel::initiate(&eph, impostor.public_key(), &id, &n).unwrap();
        let ct = ch.seal(&msg::encode(&PhoneMsg::Open)).unwrap();
        p.write(&msg::encode(&PhoneOuter::Sealed(Sealed {
            e: Some(eph.public_key().to_vec()),
            ct,
        })));
    }
    assert_eq!(
        p.recv_outer(&mut h).await,
        DeviceOuter::Error {
            code: ErrorCode::Protocol
        }
    );
    settle().await;
    assert!(h.disconnected(&p));

    let mut q = h.phone(2, 517);
    assert_eq!(q.hello(&mut h).await, DeviceOuter::Wait { retry_after: 5 });
    advance(Duration::from_secs(5)).await;
    let mut r = h.phone(3, 517);
    assert_eq!(
        ready_state(&r.handshake(&mut h).await).0,
        DeviceState::Unprovisioned
    );
}

#[tokio::test(start_paused = true)]
async fn replayed_and_reordered_messages_are_rejected() {
    let mut h = start().await;
    let mut a = h.phone(1, 517);
    a.handshake(&mut h).await;
    let recorded = a.seal(&PhoneMsg::Scan);
    a.leave();
    settle().await;

    let mut b = h.phone(2, 517);
    b.handshake(&mut h).await;
    b.write(&recorded); // from another session: different keys
    b.silent(&mut h, Duration::from_secs(1)).await;

    let first = b.seal(&PhoneMsg::Scan);
    let second = b.seal(&PhoneMsg::Scan);
    b.write(&second); // skips a counter value
    b.silent(&mut h, Duration::from_secs(1)).await;
    b.write(&first);
    assert!(matches!(
        b.recv_msg(&mut h).await,
        DeviceMsg::Networks { .. }
    ));
    b.write(&second); // now in order
    assert!(matches!(
        b.recv_msg(&mut h).await,
        DeviceMsg::Networks { .. }
    ));
    b.write(&first); // replay within the session (third decryption failure)
    assert_eq!(
        b.recv_outer(&mut h).await,
        DeviceOuter::Error {
            code: ErrorCode::Protocol
        }
    );
}

#[tokio::test(start_paused = true)]
async fn protocol_violations_end_the_session() {
    let mut h = start().await;

    let mut p = h.phone(1, 517);
    p.write(&msg::encode(&PhoneOuter::Hello { v: 9 }));
    assert_eq!(
        p.recv_outer(&mut h).await,
        DeviceOuter::Error {
            code: ErrorCode::UnsupportedVersion
        }
    );
    settle().await;

    // join before open: the first sealed message must be `open`
    let mut q = h.phone(2, 517);
    let DeviceOuter::Challenge { id, n, .. } = q.hello(&mut h).await else {
        panic!()
    };
    let eph = KeyPair::generate().unwrap();
    let mut ch = Channel::initiate(&eph, &h.device_public, &id, &n).unwrap();
    let join = PhoneMsg::Join(JoinRequest {
        ssid: "roy".into(),
        psk: None,
        sec: None,
        hidden: false,
    });
    let ct = ch.seal(&msg::encode(&join)).unwrap();
    q.write(&msg::encode(&PhoneOuter::Sealed(Sealed {
        e: Some(eph.public_key().to_vec()),
        ct,
    })));
    assert_eq!(
        q.recv_outer(&mut h).await,
        DeviceOuter::Error {
            code: ErrorCode::Protocol
        }
    );
    settle().await;

    // broken framing
    let r = h.phone(3, 517);
    r.write_chunk(vec![0x05, b'{']);
    let mut r = r;
    assert_eq!(
        r.recv_outer(&mut h).await,
        DeviceOuter::Error {
            code: ErrorCode::Protocol
        }
    );
    settle().await;
    assert!(h.disconnected(&r));
}

#[tokio::test(start_paused = true)]
async fn second_phone_is_disconnected_while_first_continues() {
    let mut h = start().await;
    let mut a = h.phone(1, 517);
    a.handshake(&mut h).await;
    let b = h.phone(2, 517);
    b.write(&msg::encode(&PhoneOuter::Hello { v: 1 }));
    settle().await;
    assert!(h.disconnected(&b));
    assert!(!h.disconnected(&a));
    a.send(&PhoneMsg::Scan);
    assert!(matches!(
        a.recv_msg(&mut h).await,
        DeviceMsg::Networks { .. }
    ));
}

#[tokio::test(start_paused = true)]
async fn idle_and_ack_timeouts() {
    let mut h = start().await;
    let mut p = h.phone(1, 517);
    p.handshake(&mut h).await;
    sleep(Duration::from_secs(119)).await;
    assert!(!h.disconnected(&p));
    sleep(Duration::from_secs(2)).await;
    assert!(h.disconnected(&p), "idle session dropped after 120 s");
    assert!(h.advertising(), "advertising resumes");

    let mut q = h.phone(2, 517);
    q.handshake(&mut h).await;
    assert_eq!(
        q.join_final(&mut h, "roy", Some(PASSWORD)).await.stage,
        Stage::Done
    );
    sleep(Duration::from_secs(11)).await; // never acks
    assert!(h.disconnected(&q));
    assert!(!h.advertising(), "provisioned even without ack");
}

#[tokio::test(start_paused = true)]
async fn phone_leaving_mid_join_still_provisions() {
    let mut h = start().await;
    let mut p = h.phone(1, 517);
    p.handshake(&mut h).await;
    p.send(&PhoneMsg::Join(JoinRequest {
        ssid: "roy".into(),
        psk: Some(Secret::new(PASSWORD.into())),
        sec: None,
        hidden: false,
    }));
    settle().await;
    p.leave();
    sleep(Duration::from_secs(5)).await;
    assert!(!h.advertising());
    let st = teton_device::wifi::WifiBackend::status(&*h.wifi)
        .await
        .unwrap();
    assert!(st.online && st.provisioned);
}

#[tokio::test(start_paused = true)]
async fn recovery_mode_after_prolonged_outage() {
    let mut h = start().await;
    let mut p = h.phone(1, 517);
    p.handshake(&mut h).await;
    p.join_final(&mut h, "roy", Some(PASSWORD)).await;
    p.send(&PhoneMsg::Ack);
    settle().await;
    assert!(!h.advertising());

    h.wifi.set_online(false);
    sleep(Duration::from_secs(40)).await;
    assert!(!h.advertising(), "short outages are left to NetworkManager");
    sleep(Duration::from_secs(30)).await;
    assert!(h.advertising(), "recovery after recovery_after (60 s)");
    let mut q = h.phone(2, 517);
    assert_eq!(
        ready_state(&q.handshake(&mut h).await).0,
        DeviceState::Recovery
    );
    q.leave();

    h.wifi.set_online(true);
    sleep(Duration::from_secs(6)).await;
    assert!(!h.advertising(), "back online: advertising stops");
}

#[tokio::test(start_paused = true)]
async fn reprovision_opens_a_manual_window() {
    let mut h = start().await;
    let mut p = h.phone(1, 517);
    p.handshake(&mut h).await;
    p.join_final(&mut h, "roy", Some(PASSWORD)).await;
    p.send(&PhoneMsg::Ack);
    settle().await;
    assert!(!h.advertising());

    h.control.send(Control::Reprovision).unwrap();
    settle().await;
    assert!(h.advertising());
    let mut q = h.phone(2, 517);
    assert_eq!(
        ready_state(&q.handshake(&mut h).await).0,
        DeviceState::Manual
    );
    q.leave();
    // The window is checked on each status poll, so it closes within one poll interval.
    sleep(Duration::from_secs(300) + timers().poll_interval).await;
    assert!(!h.advertising(), "window closes");
}
