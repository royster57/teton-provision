# Evidence: end-to-end provisioning run

One recorded run of the installed package, provisioning this laptop (the "Teton device")
onto a real WPA2 home network from an Android phone in airplane mode. Produced by
[`scripts/demo-run.sh`](../../scripts/demo-run.sh); everything below is in
[`20261008T193026Z/`](20261008T193026Z/).

| | |
|---|---|
| **Device** | Laptop, Ubuntu 24.04.1, kernel 6.8.0-146, Intel AX201 (Wi-Fi + BT 5.2), BlueZ 5.72-0ubuntu5.6, NetworkManager 1.46 |
| **Software** | `teton-provisiond_0.1.0-1_amd64.deb`, running as the systemd service (user `teton-prov`, hardened unit) |
| **Configurator** | Android phone, Chrome, the *Teton Setup* PWA installed from GitHub Pages; **airplane mode with only Bluetooth on** |
| **Network** | Home Wi-Fi `roy`, WPA2-Personal |
| **Scenario** | Scan label → verify device → three wrong passwords → 30 s lockout → correct password → online |

Times in `device.log` are UTC; `networkmanager.log` is local time (UTC+3).

## Constraint 1: no internet, no shared network

- **Laptop before** ([`before.txt`](20261008T193026Z/before.txt)): `wlp0s20f3 wifi disconnected`,
  NetworkManager connectivity `none`, **no default route**. `demo-prep` had also turned off
  autoconnect for every saved Wi-Fi profile, so nothing could reconnect by itself.
- **Phone**: airplane mode with Bluetooth re-enabled; the airplane icon is in the status bar
  for the whole [screen recording](20261008T193026Z/phone-recording.mp4).
- The only link between the two was BLE.

## Constraint 2: a real network connection

From [`after.txt`](20261008T193026Z/after.txt):

```
wlp0s20f3  wifi  connected  teton-provisioned
default via 192.168.10.1 dev wlp0s20f3 proto dhcp src 192.168.10.6 metric 600
3 packets transmitted, 3 received, 0% packet loss            (ping 192.168.10.1)
NetworkManager connectivity check: full
```

The saved profile is a system profile (`connection.permissions: --`, `psk-flags: 0`), so it
reconnects at boot with nobody logged in; that was verified separately in M6 by rebooting.

## Constraint 3: no plaintext credentials over the air

[`capture.btsnoop`](20261008T193026Z/capture.btsnoop) is every Bluetooth packet of the
session, recorded with `btmon` on the laptop. The BLE link has no link-layer encryption,
so this is exactly what an eavesdropper would receive. Open it with `btmon -r capture.btsnoop`.

[`scripts/verify-capture`](../../scripts/verify-capture) reassembled HCI ACL → L2CAP →
ATT → chunk framing and listed every protocol message
([`verify.txt`](20261008T193026Z/verify.txt)):

| | Messages | Content |
|---|---|---|
| Plaintext | 2 | `hello` (v=1) and `challenge` (device ID, MTU 517, a fresh 16-byte nonce) |
| Sealed | 22 | AES-256-GCM ciphertext only: `open`, `ready`, the 20-network scan reply (965 bytes of ciphertext over 3 chunks), four `join`s, their status updates, `ack` |

It then searched the whole capture for **all four passwords typed on the phone** (the
three wrong ones also crossed the air): lengths 14, 14, 14 and 10, matching the
`psk=<redacted len=…>` lines in the device log. Each was searched as raw bytes, hex,
and base64 at every byte alignment:

```
password #1 (14 chars): raw / hex / base64 -> NOT FOUND
password #2 (14 chars): raw / hex / base64 -> NOT FOUND
password #3 (14 chars): raw / hex / base64 -> NOT FOUND
password #4 (10 chars): raw / hex / base64 -> NOT FOUND
SSID 'roy': raw bytes found 0 time(s)
RESULT: PASS
```

## Constraint 4: usable by a non-developer

The whole flow on the phone is: scan the label with the camera, tap **Connect**, pick the
one device Chrome offers, pick the network, type the password. Every failure shows a plain
sentence and a short code. The timeline from [`device.log`](20261008T193026Z/device.log):

| UTC | Phone | Device |
|---|---|---|
| 19:30:27 | | service restarted, advertising `Teton-DBCC11F80668` |
| 19:30:56 | Connect | session started (MTU 517); **phone verified the device** |
| 19:30:58 | network list (20 networks) | scan |
| 19:31:11 | wrong password #1 | `password rejected (reason 8)` after 4 s → *"Wrong password for "roy""* |
| 19:31:27 | wrong password #2 | rejected after 5 s |
| 19:31:41 | wrong password #3 | rejected after 4 s, **`retry_after=30`** → countdown on the phone |
| 19:32:24 | correct password (after the countdown) | `joined and persisted ip=192.168.10.6 internet=Full` in **2 s** |
| 19:32:26 | *Device online* | session ended: provisioned; advertising stays off |

The secrets never reached a log: the device logs `psk=Some(<redacted len=14>)`.

## Least privilege, observed

In [`networkmanager.log`](20261008T193026Z/networkmanager.log) every profile change was
made by **`uid=133` (`teton-prov`)**: an unprivileged user with no login session,
authorized for exactly three NetworkManager actions by the packaged polkit rule:

```
22:31:11 audit: op="connection-add"    name="teton-provisioned-candidate" uid=133 result="success"
22:31:15 4way_handshake -> disconnected; config -> need-auth (reason 'supplicant-disconnect')
22:31:15 audit: op="connection-delete" name="teton-provisioned-candidate" uid=133   (rollback)
   ... twice more ...
22:32:25 Activation: successful, device activated.
22:32:25 audit: op="connection-update" name="teton-provisioned" uid=133             (saved to disk)
```

[`security.txt`](20261008T193026Z/security.txt): `systemd-analyze security` rates the
service **0.4 SAFE**. It has no capabilities, a read-only filesystem, Unix sockets only, and a
private network namespace.

## Phone recording

[`phone-recording.mp4`](20261008T193026Z/phone-recording.mp4) (2:05, 6.7 MB) is the phone
screen for the whole run: scanning the label, the device picker, verification, the network
list, the three rejections and the countdown, *Device online*, and the "Done today" list.

## Notes on this run

- `demo-run.sh` should stop following the log by itself after provisioning. It didn't,
  because the service logged ANSI color codes into the journal, so it was stopped with
  Ctrl-C after the device reported success. Fixed afterwards (`97ddd28`), along with the
  plain-text journal output. `device.log` here has the color codes stripped;
  `device-journal.jsonl` still contains them.
- The profile section of `after.txt` used a field name `nmcli` doesn't accept. The
  addendum at its end was captured a few minutes later, while the same profile was still
  active (script fixed in `6ba3ac5`).
- `verify.txt` is from a second run of `verify-capture` on the same capture. In the first run
  one password was mistyped at the prompt (15 characters, while the device received 14),
  which would have made that search meaningless.
