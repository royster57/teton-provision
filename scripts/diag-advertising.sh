#!/usr/bin/env bash
# Captures why BLE advertising registration fails (M3 diagnostics).
# Usage: sudo scripts/diag-advertising.sh   → writes target/adv-diag.txt
set -u
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
out="$(dirname "$0")/../target/adv-diag.txt"
snoop=$(mktemp --suffix=.btsnoop)
mkdir -p "$(dirname "$out")"
{
  echo "== btmgmt advinfo";   timeout 5 btmgmt --index 0 advinfo
  # Capture to a file: `btmon -t` with redirected output crashes (buffer overflow).
  timeout 15 btmon -w "$snoop" > /dev/null 2>&1 &
  sleep 1
  echo "== bluetoothctl advertise on (via bluetoothd)"
  ( echo "advertise on"; sleep 2; echo "advertise off"; sleep 1; echo quit ) | timeout 8 bluetoothctl 2>&1 \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "advertis|fail" | head -5
  echo "== btmgmt add-adv (kernel directly, bypassing bluetoothd)"
  timeout 5 btmgmt --index 0 add-adv -c -g -u a08f8d5d-8e67-44f2-89d9-59299eab3f49 5
  sleep 1
  timeout 5 btmgmt --index 0 rm-adv 5
  sleep 1
  pkill -INT -f "btmon -w $snoop"
  wait
  echo "== trace"
  btmon -r "$snoop" 2>&1 | grep -vE "^\s*$" | grep -B2 -A14 -iE "advertis|Status: (Invalid|Unsupported|Unknown|Command Disallowed)" | head -200
} > "$out" 2>&1
rm -f "$snoop"
chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$out"
echo "wrote $out"
