# teton-provision — Specification

Status: **draft for review** · 2026-10-08

Provision a "Teton Device" (an Ubuntu 24.04 laptop) with Wi-Fi credentials from an
Android phone over BLE, with no internet, no shared network, no plaintext credentials
over the air, and a flow a facilities technician can complete.

This document is the contract for implementation. Rationale for each decision is
summarised inline; the long-form reasoning goes into `docs/ARCHITECTURE.md`.

---

## 1. Decisions at a glance

| # | Area | Decision |
|---|------|----------|
| 1 | Channel | BLE GATT. Device = peripheral, phone = central. |
| 2 | Trust & crypto | Device static P-256 key; public key on a QR label. Phone: ephemeral ECDH → HKDF-SHA256 → AES-256-GCM, directional keys. No BLE pairing. |
| 3 | Configurator | Vanilla-JS PWA on GitHub Pages, offline via service worker. Web Bluetooth + WebCrypto + BarcodeDetector, zero dependencies. |
| 4 | Wi-Fi join | NetworkManager over D-Bus (zbus). In-memory candidate profile, persisted only on success; rollback on failure. Open / WPA2-PSK / WPA3-SAE. |
| 5 | Lifecycle | Advertise only when unprovisioned, in recovery, or manually triggered. One session at a time. Device-wide join backoff. Dedicated `teton-prov` user, polkit, hardened systemd unit. |
| 6 | Stack | Rust workspace (bluer, zbus, aws-lc-rs, tokio). One GATT service, two characteristics as a message pipe. `.deb` via cargo-deb. |
| 7 | Evidence | Airplane-mode phone, `btmon` capture with automated plaintext search, before/after network state, screen recording incl. failure paths. `--wifi=simulated` for CI and reviewers. |
| 8 | Scale | Provisioned-devices list with room field + CSV export in the app; everything else in the writeup. |

### 1.1 Changes from the discussion (please review)

These came out of working through the details:

1. **No `BUSY` message.** BlueZ delivers notifications to *every* subscribed central, so
   the device cannot send a reply to only the second phone. Instead, the device
   **stops advertising while a session is active** and **disconnects any additional
   central** that connects. Phone-side message: *"Device not found. It may be busy
   with another phone, or out of range."*
2. **Device ID is derived from the public key**: the first 6 bytes of SHA-256(pk), as
   12 uppercase hex characters. The phone recomputes it, so a label whose `id` and `pk`
   don't match is rejected.
3. **Two keys, one per direction, and counter-based nonces** instead of random IVs.
   Replaying or reordering messages within a session is rejected without extra state.
4. **The candidate NM profile is kept in memory** (`AddConnection2` with the in-memory
   flag) and written to disk only after success, so a crash during an attempt never
   leaves a broken profile saved.
5. **The daemon can only open Unix sockets** (`RestrictAddressFamilies=AF_UNIX`). It
   talks only over D-Bus, so the process that parses radio input can't open network
   connections.
6. **One binary, `teton-device`**, with subcommands (`run`, `label`, `reset`,
   `reprovision`). The crate is renamed to match.
7. **The device reports its negotiated ATT MTU** in the challenge message, because
   Web Bluetooth doesn't expose MTU to JS.

---

## 2. Repository layout

```
teton-provision/
├── Cargo.toml                    workspace
├── rust-toolchain.toml           pinned stable
├── crates/
│   ├── teton-proto/              pure: crypto, framing, messages, label URL. No I/O, no async.
│   └── teton-device/             daemon + CLI: BLE, NM, session, lockout, label
├── configurator/                 PWA (served at https://royster57.github.io/teton-provision/)
│   ├── index.html  app.js  ui.js  ble.js  crypto.js  protocol.js  scanner.js  history.js
│   ├── sw.js  manifest.webmanifest  icons/
├── packaging/
│   ├── teton-provisiond.service
│   ├── 50-teton-provision.rules  (polkit)
│   ├── teton-provision.conf      (D-Bus system policy)
│   └── debian/ postinst postrm
├── scripts/  demo-prep  demo-restore  demo-run.sh  verify-capture
├── tests/    test-vectors.json  crypto.test.mjs  framing.test.mjs  label.test.mjs
├── docs/     ARCHITECTURE.md  evidence/
├── .github/workflows/  ci.yml  pages.yml  release.yml
└── README.md  SPEC.md
```

---

## 3. Device identity and label

### 3.1 Key material

| File (in `/var/lib/teton-provision/`) | Mode | Content |
|---|---|---|
| `device_key.p8` | 0600 `teton-prov` | P-256 private key, PKCS#8 DER |
| `label.json` | 0644 | `{"v":1,"id":"…","pk":"…","url":"…"}` |
| `label.png` | 0644 | QR of `url`, with a 4-module white border, plus the ID as text underneath |

- Created on first `run` if missing. **Never regenerated** by `reset`. Only
  `reset --new-identity` (dev) replaces it.
- `pk` = base64url, unpadded, of the 65-byte uncompressed SEC1 point.
- `id` = uppercase hex of `SHA-256(pk_raw)[0..6]` → 12 characters, displayed as
  `4F2A-9C11-B03E`.

### 3.2 Label URL

```
https://royster57.github.io/teton-provision/#v=1&id=4F2A9C11B03E&pk=<87 chars>
```

- Parameters go in the fragment, so they're never sent to a server.
- The configurator validates: `v == 1`, `pk` decodes to 65 bytes starting with `0x04`
  and imports as a P-256 key, and `id == hex(SHA-256(pk)[0..6])`.
- The base URL is configurable at build/run time (`--label-base-url`) for forks.

### 3.3 `teton-device label`

Prints the QR to the terminal as Unicode half-blocks, **dark modules on an explicit
white background** with a 4-module border (so it scans on dark terminal themes),
followed by the ID and the path to `label.png`. Readable by any user.

---

## 4. BLE interface

| Item | Value |
|---|---|
| Service UUID | `a08f8d5d-8e67-44f2-89d9-59299eab3f49` |
| `rx` (phone → device) | `4b11a607-2abe-4fc6-9b03-e62677c327fe`, write (with response) |
| `tx` (device → phone) | `d5c6dde2-10f8-435c-90cb-c1e003a5550c`, notify |
| Advertising data | flags + 128-bit service UUID |
| Scan response | complete local name `Teton-<id>` (18 characters) |
| Pairing / bonding | none. The characteristics need no BLE encryption; encryption is in the application layer. |

- Advertising is on only in the `UNPROVISIONED`, `RECOVERY` and `MANUAL` device
  states (§7), and **paused while a session is active**.
- Phone filter: `requestDevice({filters:[{name:"Teton-<id>"}], optionalServices:[SERVICE]})`.
- *Check early on hardware:* the name is found through the scan response, and BlueZ
  5.72 puts `LocalName` there when the advertising data is full.

### 4.1 Framing

Each GATT write or notification carries **one chunk**:

```
byte 0     : bit 7 = FINAL, bits 0–6 = chunk index within the message, mod 128
bytes 1..  : payload
```

- Message = concatenation of chunk payloads in index order up to the FINAL chunk.
- Maximum message size **4096 bytes**. Chunk index must start at 0 and increase by 1,
  wrapping 127 → 0 (with 20-byte chunks a 4096-byte message needs 216 chunks).
  Any violation causes a protocol error and the session ends.
- Chunk size: the device uses `MTU − 3`. The phone uses 20 bytes until it receives
  `mtu` in the challenge, then `min(mtu − 3, 512)`.
- No interleaving: each direction has at most one message in flight.

### 4.2 Message envelope

Every message is UTF-8 JSON with a `t` (type) field.

**Plaintext messages** (no secrets in them):

| Direction | Message | Meaning |
|---|---|---|
| P→D | `{"t":"hello","v":1}` | Start a session |
| D→P | `{"t":"challenge","v":1,"id":"…","n":"<b64url 16B>","mtu":517}` | New random nonce for this connection |
| D→P | `{"t":"wait","retry_after":20}` | Connection refused; decryption-failure backoff active (§7.3) |
| D→P | `{"t":"error","code":"unsupported_version"\|"protocol"}` | Sent, then the device disconnects |

**Sealed messages** (all after `challenge`):

```json
{"t":"sealed","e":"<b64url 65B, first P→D sealed message only>","ct":"<b64url ciphertext‖tag>"}
```

---

## 5. Cryptography

All primitives come from `aws-lc-rs` (device) and WebCrypto (phone).

```
D, d     device static P-256 key pair (D on the label)
E, e     phone ephemeral P-256 key pair, one per session
N        16-byte random nonce from the device, one per connection (challenge.n)

Z        = ECDH(e, D) = ECDH(d, E)            32-byte x-coordinate
info     = "teton-prov v1" ‖ id(12 ASCII) ‖ E(65) ‖ D(65)
OKM      = HKDF-SHA256(ikm=Z, salt=N, info, L=64)
K_pd     = OKM[0..32]    phone → device
K_dp     = OKM[32..64]   device → phone

seal     = AES-256-GCM(K_dir, iv = 0x00000000 ‖ u64_be(counter_dir), aad = "", plaintext)
```

- Each direction keeps its own counter, starting at 0 and increasing by 1 per sealed
  message. The receiver expects exactly the next counter value, and anything else
  fails to decrypt. BLE GATT delivers messages reliably and in order, so the counter is
  never sent.
- **Device authentication:** only the holder of `d` can derive `K_dp`. The phone treats
  the first sealed message that decrypts (`ready`) as proof it's talking to the real
  device, and shows "Device verified". **The phone sends `join` only after `ready`.**
- **Replay:** `N` is new for every connection, so recorded sealed messages from an
  earlier session can't be decrypted in a new one.
- **Authorization:** whoever has the label can provision the device. That's the same
  model as Matter's setup code.
- Session keys are dropped (`zeroize`) when the session ends. The PSK is held in
  `Zeroizing<String>`, and its `Debug`/`Display` print `<redacted len=N>`.
- `tests/test-vectors.json` fixes `d`, `e`, `N` and the plaintexts, and lists `Z`,
  `K_pd`, `K_dp` and the expected ciphertexts. Both the Rust and JS test suites must
  reproduce it byte for byte.

---

## 6. Session protocol

### 6.1 Sequence

```
Phone                                         Device
  │  connect, subscribe tx                       │  (advertising paused)
  │── hello ───────────────────────────────────▶ │
  │ ◀──────────────────────────────── challenge ─│  new N
  │── sealed{e=E}( open ) ─────────────────────▶ │  derive keys; decrypt OK → session OPEN
  │ ◀──────────────────────────── sealed(ready) ─│  phone: "Device verified ✓"
  │── sealed( scan ) ──────────────────────────▶ │  NM RequestScan (≤ 8 s)
  │ ◀───────────────────────── sealed(networks) ─│
  │── sealed( join{ssid,psk,sec?,hidden} ) ────▶ │
  │ ◀──────────── sealed(status: accepted) ──────│
  │ ◀──────────── sealed(status: associating) ───│
  │ ◀──────────── sealed(status: ip, ip=…) ──────│
  │ ◀──────────── sealed(status: done, internet=full) ─│
  │── sealed( ack ) ───────────────────────────▶ │  disconnect; state → ONLINE
```

On `status: failed`, the session stays `OPEN` and the phone may send `scan` or `join` again.

### 6.2 Inner messages (inside `sealed`)

| Dir | Message | Fields |
|---|---|---|
| P→D | `open` | — |
| D→P | `ready` | `state`: `unprovisioned`\|`recovery`\|`manual`; `retry_after`: seconds (0 if no lockout); `version` |
| P→D | `scan` | — |
| D→P | `networks` | `list`: up to 20 of `{ssid, signal: 0–100, sec: open\|wpa2\|wpa3\|wpa2/wpa3\|enterprise\|wep}`, deduplicated by SSID (strongest kept), hidden SSIDs omitted, sorted by signal |
| P→D | `join` | `ssid` (≤ 32 UTF-8 bytes), `psk` (8–63 characters, or 64 hex digits; absent for open), `sec` (needed only when `hidden`), `hidden`: bool |
| D→P | `status` | `stage` (below), plus `ip`, `internet`, `reason`, `retry_after` as applicable |
| P→D | `ack` | — |

`status.stage` values:

| stage | Extra fields | Phone shows |
|---|---|---|
| `accepted` | — | ✓ Credentials sent securely |
| `associating` | — | ⋯ Joining "roy" |
| `ip` | `ip` | ✓ Got IP address 192.168.1.42 |
| `done` | `ip`, `internet`: `full`\|`limited`\|`portal`\|`none`\|`unknown` | ✅ Device online / ⚠ Connected, but no internet. Contact IT |
| `failed` | `reason`, optional `retry_after` | see §6.3 |
| `locked` | `retry_after` | ⏳ Too many failed attempts. Try again in 0:45 |

### 6.3 Failure reasons

| `reason` | Cause (NM device state reason) | Counts toward lockout | Phone message |
|---|---|---|---|
| `invalid_input` | Validation failed before touching the radio | no | "That password can't be right: Wi-Fi passwords are 8–63 characters." |
| `unsupported_security` | enterprise / WEP | no | "This network type isn't supported yet. Choose another network or contact Teton." |
| `ssid_not_found` | `SSID_NOT_FOUND` | no | "The device can't see "X". Is it in range?" |
| `auth_failed` | `NO_SECRETS`, `SUPPLICANT_DISCONNECT`, `SUPPLICANT_TIMEOUT`, `SUPPLICANT_FAILED` | **yes** | "Wrong password for "X"." |
| `dhcp_failed` | `IP_CONFIG_UNAVAILABLE`, `DHCP_*` | no | "Joined "X" but didn't get an address. Contact IT (DHCP)." |
| `timeout` | 30 s without `ACTIVATED`, no specific reason | **yes** | "Couldn't connect to "X". Move closer or try again." |
| `internal` | anything else | no | "Something went wrong on the device. Try again." |

Reason numbers verified against `nm-dbus-interface.h` (NM 1.46) in M2; `auth_failed` via
`SUPPLICANT_DISCONNECT` (8) observed on hardware ~6 s after a wrong password.
Each phone message also shows a short code (e.g. `E-AUTH`) that can be quoted to support.

### 6.4 Session rules

- **One active session.** The first central to send `hello` owns the session. Any
  other central that connects while a session is active is disconnected immediately
  (`Device1.Disconnect`).
- **Idle timeout:** 120 s with no message received → keys dropped, phone disconnected.
- **Decryption failures:** 3 in one session → `error: protocol`, disconnect, and they
  count toward the connection backoff (§7.3).
- **Out-of-order types** (e.g. `join` before `open`) → `error: protocol`, disconnect.
- **After `done`:** wait up to 10 s for `ack`, then disconnect, stop advertising, and
  move to `ONLINE`.

---

## 7. Device state machine

```
               boot / restart
                    │
       profile "teton-provisioned" exists?
          no │                     │ yes
             ▼                     ▼
     UNPROVISIONED  ◀── reset   ONLINE ──── offline > recovery_after (600 s) ───▶ RECOVERY
     (advertising)                ▲  ▲                                            (advertising +
             │                    │  └──── old network back (NM autoconnect) ──── NM keeps retrying)
             │ session            │ done                                               │ session
             ▼                    │                                                    ▼
          SESSION ────────────────┘  failure / disconnect → back to previous state ◀───┘
   (advertising paused)
                                  MANUAL: `teton-device reprovision` (SIGUSR1) → advertise for 10 min
```

- `ONLINE` means the `teton-provisioned` profile is active on the Wi-Fi device.
  "Offline" means it isn't, as seen through NM state signals.
- In `RECOVERY`, NetworkManager keeps auto-reconnecting to the old profile on its own.
  If that succeeds, the device returns to `ONLINE` and stops advertising.

### 7.1 Join-attempt lockout (device-wide, in memory)

- `consecutive_failures` increases only for failures marked **yes** in §6.3.
- Before each `join`: if `consecutive_failures ≥ 3` and the backoff hasn't elapsed,
  reply `status: locked, retry_after`.
- Backoff after the 3rd failure: **30 s**, after the 4th: **60 s**, after the 5th and
  later: **120 s** (maximum).
- Reset to 0 on a successful join. Not persisted: a reboot takes about as long as the
  backoff (documented in the writeup).
- `ready.retry_after` carries any active lockout, so the phone shows the countdown
  before the technician types a password.

### 7.2 `reset` / `reprovision`

- `teton-device reset` (root): deletes NM profiles named `teton-provisioned*`, then
  restarts the service → `UNPROVISIONED`. `--new-identity` also deletes the key and
  label (dev only, with a warning).
- `teton-device reprovision` (root): sends `SIGUSR1` to the daemon → `MANUAL` for 10
  minutes. In production this would be a button held down.

### 7.3 Connection backoff (decryption failures, device-wide)

After each session ended by decryption failures, the device refuses the next `hello`
with `wait` for 5 s, then 10, 20 … up to 300 s. A session that reaches `ready` resets it.

### 7.4 Configurable timers (for demos and tests)

`--recovery-after` (600 s), `--join-timeout` (30 s), `--idle-timeout` (120 s),
`--manual-window` (600 s).

---

## 8. Wi-Fi backend

```rust
trait WifiBackend {
    async fn scan(&self) -> Result<Vec<Network>>;
    async fn join(&self, req: JoinRequest, progress: Sender<Stage>) -> Result<JoinOutcome, JoinFailure>;
    async fn is_online(&self) -> bool;
    fn state_changes(&self) -> impl Stream<Item = OnlineState>;
}
```

Two implementations: `NetworkManager` (real) and `Simulated` (scripted: e.g. password
`correct horse` succeeds, anything else is `auth_failed`; SSID `missing` is
`ssid_not_found`). Selected with `--wifi=nm|simulated`. Simulated mode prints a
prominent banner.

### 8.1 NetworkManager (zbus, hand-written proxies)

**Scan:** `Device.Wireless.RequestScan({})`. If NM refuses because a scan happened
recently, use the cached results. Wait for `LastScan` to change (≤ 8 s), then
`GetAllAccessPoints` and read `Ssid`, `Strength`, `Flags`, `WpaFlags`, `RsnFlags`.
Security classification from `RsnFlags`/`WpaFlags`: SAE only → `wpa3`; PSK and SAE →
`wpa2/wpa3`; PSK → `wpa2`; 802.1X → `enterprise`; privacy flag with no WPA → `wep`;
otherwise `open`.

**Join:**
1. Validate input (§6.3 `invalid_input`). Choose `key-mgmt` from the scan entry
   (`wpa-psk` for `wpa2` and `wpa2/wpa3`, `sae` for `wpa3`, none for `open`). For hidden
   networks use `join.sec`.
2. `Settings.AddConnection2(settings, flags=IN_MEMORY)` with id `teton-provisioned-candidate`,
   `autoconnect=false`, `permissions=[]` (system profile), `psk-flags=0`, ipv4/ipv6 `auto`.
3. `ActivateConnection(candidate, wifi_device, "/")`. Watch the device's `StateChanged`
   (new, old, reason) and the active connection's state. Send `associating` on entering
   `CONFIG`/`NEED_AUTH`, and `ip` once `Ip4Config` has an address.
4. **Success** (`ACTIVATED` + IPv4 address within the join timeout):
   `Update2(flags=TO_DISK)` with id `teton-provisioned` and `autoconnect=true`. Delete
   any previous `teton-provisioned` profile. Then `CheckConnectivity()` → `internet`.
5. **Failure:** delete the candidate. If a previous `teton-provisioned` profile existed
   and was active before, reactivate it. Map the reason (§6.3).

**Online tracking:** subscribe to the Wi-Fi device's `ActiveConnection` and state;
`ONLINE` means the active connection's id is `teton-provisioned`.

**Observed in M2 (NM 1.46, Ubuntu 24.04):**
- *Every* activation passes `CONFIG → NEED_AUTH (reason 0) → PREPARE` while NM loads the
  stored secrets, including for the user's own profiles. This is not a failure.
- A rejected password shows as `4way_handshake → disconnected`, then `NEED_AUTH` with
  reason `SUPPLICANT_DISCONNECT` (8). The device cancels the activation at that point
  (about 10 ms later), before NM asks a secret agent, so **no GNOME password dialog
  appears**. The state handling is the pure `JoinTracker`, with the recorded sequences as
  regression tests.
- On Ubuntu 24.04, NM saves system profiles **through netplan**: the profile is written to
  `/etc/netplan/90-NM-<uuid>.yaml` (root, 0600), and NM loads it from
  `/run/NetworkManager/system-connections/netplan-NM-<uuid>-<ssid>.nmconnection`.
  Deleting the profile through NM's D-Bus API removes both.

---

## 9. Process, permissions, packaging

### 9.1 Binary

`teton-device run [--foreground] [--wifi=nm|simulated] [--state-dir DIR] [--event-log FILE] [timers…]`
`teton-device label | reset [--new-identity] | reprovision`

- Logging: `tracing`. In foreground: readable output on stderr and the terminal QR.
  As a service: journald. `--event-log` writes JSON lines (one event per state
  change, message type and join stage) for evidence. Secrets never reach a log
  (enforced by the `Secret` type, §5).

### 9.2 systemd unit (`teton-provisiond.service`)

```ini
[Unit]
Description=Teton Wi-Fi provisioning over BLE
After=bluetooth.service NetworkManager.service
Wants=bluetooth.service

[Service]
User=teton-prov
ExecStart=/usr/bin/teton-device run
StateDirectory=teton-provision
StateDirectoryMode=0755
Restart=on-failure
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

`systemd-analyze security teton-provisiond` output goes into the evidence.

### 9.3 polkit (`/etc/polkit-1/rules.d/50-teton-provision.rules`)

Allow `teton-prov` exactly these actions:
`org.freedesktop.NetworkManager.settings.modify.system`,
`org.freedesktop.NetworkManager.network-control`,
`org.freedesktop.NetworkManager.wifi.scan`.
*Confirm in M2 which action `CheckConnectivity` needs.*

### 9.4 D-Bus policy (`/etc/dbus-1/system.d/teton-provision.conf`)

Allow user `teton-prov` to send to `org.bluez` (GattManager1, LEAdvertisingManager1,
Device1, Adapter1) and to receive the BlueZ callbacks into our exported objects.

### 9.5 `.deb` (cargo-deb)

Contents: `/usr/bin/teton-device`, the unit, the polkit rule, the D-Bus policy.
`postinst`: create system user `teton-prov` (no login), `daemon-reload`, enable and
start. `postrm purge`: remove the user and `/var/lib/teton-provision`. Runtime
dependencies: `bluez (>= 5.64)`, `network-manager (>= 1.40)`.
Build dependencies (from source): `libdbus-1-dev pkg-config cmake gcc`.

---

## 10. Configurator (PWA)

### 10.1 Screens

1. **Home**: [Scan device label], "Provisioned this session (n)" → list, install hint
   if not installed. If opened through a label URL, go straight to step 3.
2. **Scan**: rear camera + `BarcodeDetector({formats:["qr_code"]})`. Fallback text:
   "Or scan the label with your phone's camera app."
3. **Device**: "Teton device 4F2A-9C11-B03E" [Connect] → Chrome picker (one entry) →
   hello / challenge / open / ready → "Device verified ✓". If a lockout is active,
   show the countdown right away.
4. **Network**: list from `networks` (signal bars, lock icon, entries for unsupported
   types greyed out with an explanation), [Other network…] for hidden SSIDs, [Rescan].
   If a network is remembered from the batch: "Use roy again?" as the first choice.
5. **Password**: field with show/hide toggle, client-side length check, [Connect device].
6. **Progress**: the four stages, with checkmarks as they arrive.
7. **Result**: success → optional "Room / location" field → [Save & next device] /
   [Done]. Failure → message + code + [Try again] (keeps the session) or [Choose another
   network]. Locked → live countdown, [Try again] enabled when it reaches 0.

Errors on the phone's side: Bluetooth off / permission denied, device not found
(busy or out of range, §1.1), connection lost mid-session, invalid label, browser without
Web Bluetooth ("Open this page in Chrome").

### 10.2 State and storage

| Data | Where | Lifetime |
|---|---|---|
| Batch network `{ssid, psk, sec}` | JS memory only | until [Forget network] or the page closes |
| Provisioned list `{id, at, ssid, result, ip, room}` | `localStorage["teton.provisioned.v1"]` (try/catch) | until [Clear list] (with confirmation) |
| Session keys, ephemeral key | JS memory | one BLE session |

- The provisioned list **never contains a PSK**. `result` is
  `online|no_internet|failed`; failed attempts are recorded too.
- [Export CSV] downloads `teton-provisioned-YYYYMMDD-HHMM.csv` with columns
  `device_id,provisioned_at,ssid,result,ip,room`.

### 10.3 Offline and hosting

- `sw.js`: precache every asset under a versioned cache name, cache-first, and delete
  old caches on activate. `manifest.webmanifest` with standalone display and icons.
- `pages.yml` publishes `configurator/` to GitHub Pages on pushes to `main`.
- Dev loop: `python3 -m http.server -d configurator 8000` + `adb reverse tcp:8000 tcp:8000`
  → `http://localhost:8000` on the phone (localhost counts as a secure context).

---

## 11. Testing

| Layer | Tests |
|---|---|
| `teton-proto` (Rust) | Test vectors; framing with proptest (round trip for any message and MTU; rejection of bad index, missing FINAL, oversize); label URL parse and validation; message serde |
| Configurator (Node `--test`) | Same test vectors through `crypto.js`; framing; label parsing; CSV export escaping |
| `teton-device` session | **Loopback**: a test-only phone client from `teton-proto` drives the real session code over an in-memory chunk pipe, with `Simulated` Wi-Fi. Scenarios: happy path; wrong password ×3 → `locked` with 30/60/120 s (tokio paused clock); success resets the counter; `ssid_not_found` doesn't count; decryption failure ×3 → disconnect + `wait` backoff; replayed sealed message from a previous session rejected; skipped counter rejected; `join` before `open` rejected; idle timeout; `ack` timeout |
| NM mapping | Unit tests: reason code → `reason`; AP flags → `sec` |
| CI | `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `node --test`; `release.yml` builds the `.deb` on tags |

### 11.1 Hardware checklist (manual, with phone)

1. Advertisement visible and the name filter matches in Chrome (a free BLE scanner app
   such as nRF Connect helps with debugging).
2. Negotiated MTU reported; a large `networks` message is reassembled correctly.
3. Wrong password: phone message, lockout countdown, no GNOME dialog (or documented
   behaviour).
4. Successful join, profile persisted, reconnects after reboot.
5. Recovery mode with `--recovery-after 60s` (e.g. provision to a phone hotspot, then
   change its password).
6. Second phone or Chrome tab cannot join an active session.

---

## 12. Demo and evidence

`scripts/demo-prep`: save the list of Wi-Fi profiles with `autoconnect=yes` to
`~/.local/state/teton-demo/autoconnect.txt`, set them to `no`, disconnect
`wlp0s20f3`. `scripts/demo-restore`: re-enable exactly those profiles. Nothing is deleted.

`scripts/demo-run.sh` (run by you, since the laptop is offline until provisioning succeeds):

1. `demo-prep`; write "before" state (`nmcli general`, `nmcli -t device`, `ip route`) to `before.txt`.
2. `sudo btmon -w capture.btsnoop &`
3. `systemctl stop teton-provisiond`; `sudo -u teton-prov teton-device run --foreground --event-log events.jsonl`.
4. On Ctrl-C: "after" state + `ping -c3 <gateway>` + `nmcli networking connectivity check`
   to `after.txt`; stop btmon; run `verify-capture capture.btsnoop` (prompts for the
   PSK with no echo, searches the capture for the PSK and SSID as raw bytes and in
   their base64 forms, prints `NOT FOUND` / `FOUND`, and lists the sealed frames
   that were seen) → `verify.txt`.
5. Everything goes in `docs/evidence/<timestamp>/`.

Phone: airplane mode with only Bluetooth on (screenshot), screen recording of: scan →
verify → network list → wrong password ×3 → locked countdown → correct password →
progress → online → room entry → list → CSV export.

Afterwards (back online), I write `docs/evidence/README.md` from the collected
artifacts and you run `demo-restore`.

---

## 13. Documentation deliverables

- **README.md**: what it is, hardware requirements (Ubuntu 24.04 laptop with Wi-Fi
  managed by NM and a BLE 4.2+ adapter; Android phone with Chrome, or desktop Chrome
  with Web Bluetooth), install from `.deb`, build from source, run, install the
  configurator, simulated mode, troubleshooting, uninstall.
- **docs/ARCHITECTURE.md**: channel choice and trade-offs (SoftAP, DPP, optical,
  Improv's plaintext), threat model and crypto (incl. why not BLE pairing, PAKE, `ring`),
  data flow diagram, state machines, least-privilege design, known limitations
  (non-UTF-8 SSIDs, lockout not persisted, no Enterprise), and the 200-device section
  (8 points agreed in discussion).
- **docs/evidence/**: §12 artifacts plus `README.md`.

---

## 14. Implementation plan

| Milestone | Content | Done when |
|---|---|---|
| M0 | `rustup update`, `apt install libdbus-1-dev`, workspace scaffold, CI | `cargo test` + CI green on an empty skeleton |
| M1 | `teton-proto` + `configurator/crypto.js` + test vectors + framing | Rust and Node pass the same vectors |
| M2 | NM backend spike against real hardware: scan, join, rollback, reason mapping, GNOME agent check, polkit actions | Correct join and wrong-password outcomes observed on `roy` (only brief disconnects) |
| M3 | BLE: bluer GATT app + advertising, echo pipe | Phone (nRF Connect, then a Chrome test page) exchanges chunked messages |
| M4 | Session + device state machine + lockout + loopback tests | All §11 session scenarios pass |
| M5 | Configurator PWA, provisioned list, Pages deploy | Full flow with `--wifi=simulated` from the phone |
| M6 | End-to-end with real NM | §11.1 checklist done |
| M7 | Packaging: `.deb`, unit, polkit, D-Bus policy, hardening | Clean install on this laptop, service runs as `teton-prov` |
| M8 | Demo run + evidence | §12 folder complete |
| M9 | README, ARCHITECTURE.md, release | Ready to submit |

**Needs your go-ahead when we get there:** creating the public GitHub repo
`royster57/teton-provision` and enabling Pages (needed by M5 for the phone to load the
configurator over HTTPS; the `adb reverse` dev loop covers M3–M4).
