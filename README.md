# teton-provision

Wi-Fi provisioning for headless Linux devices over Bluetooth Low Energy. A technician
scans the device's QR label with an Android phone, picks the network, types the
password, and watches the device come online. There's no internet, cloud or shared network
involved, and the password never crosses the air unencrypted.

- **Demo:** [phone screen recording](docs/evidence/20261008T193026Z/phone-recording.mp4) (2 min), plus the [evidence](docs/evidence/README.md) for each constraint, including a Bluetooth capture that contains none of the passwords typed.
- **Design:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): why BLE, how credentials are protected, and what changes for 200 devices.
- **Specification:** [SPEC.md](SPEC.md): the protocol and implementation details.

| Part | What it is |
|---|---|
| `teton-provisiond` (`crates/teton-device`) | Rust daemon on the device. BLE peripheral (BlueZ), NetworkManager over D-Bus, a hardened systemd service running as an unprivileged user. Packaged as a `.deb`. |
| *Teton Setup* (`configurator/`) | Phone app: a dependency-free PWA, served at **https://royster57.github.io/teton-provision/** and installable for offline use. |
| `crates/teton-proto` | The shared protocol: P-256 ECDH, HKDF-SHA256, AES-256-GCM, framing, messages. Mirrored by `configurator/crypto.js` and checked byte for byte against shared test vectors. |

## Requirements

**Device (the machine being provisioned)**
- Ubuntu 24.04 with Wi-Fi managed by NetworkManager (the default on Ubuntu Desktop).
- A Bluetooth adapter that can act as a BLE peripheral; most laptop adapters can. Tested on an Intel AX201.
- `bluez` **5.72-0ubuntu5.6 or later**. Earlier 24.04 builds can't advertise on current kernels; see [Troubleshooting](#troubleshooting). The package enforces this.

**Configurator**
- An Android phone with Chrome. Web Bluetooth is not available in iOS Safari, and desktop Chrome on Linux has it disabled by default; only Android was tested.

**A Wi-Fi network** to join: WPA2/WPA3-Personal or open. Enterprise (802.1X) isn't supported yet.

## Quick start

### 1. Install the daemon on the device

```bash
sudo apt update && sudo apt install --only-upgrade bluez   # needs >= 5.72-0ubuntu5.6
wget https://github.com/royster57/teton-provision/releases/download/v0.1.0/teton-provisiond_0.1.0-1_amd64.deb
sudo apt install ./teton-provisiond_0.1.0-1_amd64.deb
```

This creates the system user `teton-prov` and starts `teton-provisiond`. On first start it
generates the device's key and label, and starts advertising because it isn't provisioned yet.

```bash
systemctl status teton-provisiond
```

### The device label

Each device has a QR label. It holds the device's ID and public key, which is how the phone
knows it's talking to the real device. On production hardware the label is a sticker
printed at the factory. On a test machine, the device shows its own label, in any of three
ways:

```bash
teton-device label                                  # 1. print the QR in this terminal (any user)
xdg-open /var/lib/teton-provision/label.png         # 2. open it as an image
xdg-open /var/lib/teton-provision/label.svg         # 3. a 50 mm printable sticker with the ID underneath
```

The terminal QR is about 30 lines tall, so make the window tall enough; it is drawn black on
white, so dark terminal themes are fine. The label only changes with
`teton-device reset --new-identity`.

### 2. Prepare the phone (once, while online)

Open **https://royster57.github.io/teton-provision/** in Chrome and choose **⋮ → Install app**.
From then on the app works offline; airplane mode with Bluetooth turned on is fine.

### 3. Provision

1. Show the [device label](#the-device-label) and scan it with the phone's **camera app**, or
   press **Scan device label** in the app.
2. Press **Connect** and pick the one device Chrome lists. The first time, allow "Nearby devices".
3. *Device verified* appears, then the networks the device can see. Pick one and enter the password.
4. Watch the progress: *Credentials sent securely → Joining → Got an address → Device online*.

Check on the device:

```bash
nmcli connection show --active          # teton-provisioned is active
journalctl -u teton-provisiond -e       # the session, with the password shown as <redacted len=N>
```

To provision again, either open a 10-minute window, which stands in for a hardware button:
```bash
sudo teton-device reprovision
```
or forget the network entirely:
```bash
sudo teton-device reset
```

## Try it without touching your network

Simulated Wi-Fi runs the real BLE protocol and the real phone app, but joins nothing. Every
simulated network accepts the password `correct horse`; `Lab-NoDHCP` simulates a DHCP failure.

```bash
sudo systemctl stop teton-provisiond                  # only one daemon may advertise the service
teton-device run --foreground --wifi simulated --state-dir /tmp/teton-sim
# ... scan the QR it prints, as above ...
sudo systemctl start teton-provisiond
```

## Recording a demo with evidence

`scripts/demo-run.sh` records an end-to-end run of the installed service into
`docs/evidence/<time>/`:
- before/after network state,
- a `btmon` capture of every Bluetooth packet,
- the device and NetworkManager logs,
- the systemd hardening report,
- the result of `scripts/verify-capture`, which reconstructs every protocol message from the capture and searches it for each password you typed on the phone.

```bash
scripts/demo-run.sh        # takes the laptop offline (demo-prep); asks for sudo once
scripts/demo-restore       # afterwards: re-enable autoconnect on your own Wi-Fi profiles
```

`scripts/demo-prep` turns off autoconnect on every saved Wi-Fi profile, so the laptop
starts genuinely unprovisioned and nothing reconnects behind your back. It records what it
changed, and `demo-restore` undoes exactly that. Each profile change goes through netplan
and takes about 1.5 s, so expect a minute or two.

## Commands

| Command | Does |
|---|---|
| `teton-device run [--foreground] [--wifi nm\|simulated] [--state-dir DIR] [--event-log FILE] [--recovery-after 10m] [--join-timeout 30s] [--idle-timeout 120s] [--manual-window 10m]` | The daemon (normally started by systemd) |
| `teton-device label` | Print the label QR for any user |
| `sudo teton-device reset [--new-identity]` | Forget the provisioned network; `--new-identity` also replaces the key, which invalidates the old label |
| `sudo teton-device reprovision` | Advertise for 10 minutes so an already provisioned device can be re-provisioned |

## Build from source

```bash
sudo apt install build-essential pkg-config cmake libdbus-1-dev
curl https://sh.rustup.rs -sSf | sh        # rust-toolchain.toml pins the version
cargo build --release                      # target/release/teton-device
cargo test --workspace                     # 50 tests, incl. 12 BLE loopback scenarios
npm test                                   # 19 tests for the configurator (Node 22+)
cargo install cargo-deb && cargo deb -p teton-device   # target/debian/*.deb
```

To develop the phone app locally, serve `configurator/` and forward it to the phone, since
Chrome only allows Web Bluetooth on HTTPS or `localhost`:
`python3 -m http.server -d configurator 8000` and `adb reverse tcp:8000 tcp:8000`, then open
`http://localhost:8000` on the phone.

## Repository layout

```
crates/teton-proto/     protocol: crypto, framing, messages, label (no I/O)
crates/teton-device/    daemon: BLE, NetworkManager, session, state machine, label rendering
  examples/             hardware probes used during development (nm_probe, ble_echo)
  tests/loopback.rs     device + session tests over an in-memory radio
configurator/           the phone app (PWA)
tests/                  shared test vectors + configurator tests
packaging/              systemd unit, polkit rule, maintainer scripts
scripts/                demo-prep, demo-run.sh, verify-capture, demo-restore, diag-advertising.sh
docs/                   ARCHITECTURE.md, evidence/
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Failed to register advertisement` / `Invalid Parameters (0x0d)` in `journalctl -u bluetooth` | Unpatched `bluez` on Ubuntu 24.04 sends a malformed command that current kernels reject (LP: #2164626). Upgrade to `5.72-0ubuntu5.6` or later, then `sudo systemctl restart bluetooth`. `sudo scripts/diag-advertising.sh` captures a trace if it persists. |
| The phone says *Device not found* | The device is already provisioned and stopped advertising (`sudo teton-device reprovision`), another phone is mid-session, or it's out of range. |
| *Could not verify the device* | The label doesn't belong to this device (e.g. after `reset --new-identity`); print the current one with `teton-device label`. |
| *Too many failed attempts* | Device-wide lockout after 3 wrong passwords: 30 s, then 60 s, then 120 s. Wait for the countdown. |
| *Connected, but no internet* | The device joined Wi-Fi and got an address, but NetworkManager's connectivity check failed (no upstream internet, or a captive portal). |
| A GNOME password dialog appears on a desktop test machine | NetworkManager's own reconnect asking the desktop for a password after the network's password changed. The daemon never triggers it, and a headless device has no desktop to ask. Press Cancel. |

## Uninstall

```bash
sudo apt purge teton-provisiond     # removes the service, the user and /var/lib/teton-provision (the device identity)
nmcli connection delete teton-provisioned   # if you want to forget the provisioned network too
```

## License

MIT, see [LICENSE](LICENSE).
