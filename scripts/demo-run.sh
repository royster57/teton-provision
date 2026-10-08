#!/usr/bin/env bash
# Records an end-to-end provisioning demo of the installed service, with
# evidence for each constraint (SPEC.md §12), into docs/evidence/<UTC time>/.
#
#   scripts/demo-run.sh        (as your user; asks for sudo once)
#
# Steps: demo-prep (laptop offline, nothing autoconnects) -> restart the
# service (fresh session state) -> "before" snapshot -> btmon capture ->
# show the label QR and follow the device log until a phone provisions it
# (or Ctrl-C) -> "after" snapshot, logs, hardening report -> verify-capture.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
service=teton-provisiond
command -v teton-device > /dev/null || { echo "Install the .deb first (see README)." >&2; exit 1; }
systemctl is-enabled --quiet "$service" || { echo "$service is not installed/enabled." >&2; exit 1; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$repo/docs/evidence/$stamp"
mkdir -p "$out"
echo "Evidence will be written to ${out#"$repo"/}"
sudo -v # one password prompt for the whole run

snapshot() { # $1 = file
  {
    echo "# $(date -u +%FT%TZ)  $(uname -r)  $(lsb_release -ds 2>/dev/null)"
    echo; echo "## nmcli general";               nmcli general
    echo; echo "## devices";                     nmcli -f DEVICE,TYPE,STATE,CONNECTION device
    echo; echo "## active connections";          nmcli -f NAME,TYPE,DEVICE connection show --active
    echo; echo "## routes";                      ip route
    echo; echo "## teton-provisioned profile";   nmcli -f connection.id,connection.autoconnect,connection.permissions,802-11-wireless.ssid,802-11-wireless-security.key-mgmt,802-11-wireless-security.psk-flags connection show teton-provisioned 2>&1 || true
                                                 nmcli -f NAME,FILENAME connection show | grep -E "^(NAME|teton-provisioned) " || true
    echo; echo "## service";                     systemctl status "$service" --no-pager -n 0 | head -5 || true
  } > "$1"
}

echo; echo "== 1/5 Making this laptop an unprovisioned device"
"$repo/scripts/demo-prep"
sudo systemctl restart "$service"
start=$(date '+%F %T')
sleep 2
snapshot "$out/before.txt"

echo; echo "== 2/5 Capturing all Bluetooth traffic (btmon)"
sudo btmon -w "$out/capture.btsnoop" > /dev/null 2>&1 &
sleep 1

echo; echo "== 3/5 Device ready. Scan this label with the phone:"
teton-device label
echo "Following the device log; stops by itself once a phone provisions it (or press Ctrl-C)."
echo "------------------------------------------------------------------------"
trap 'echo "(stopped)"' INT
while IFS= read -r line; do
  printf '%s\n' "$line"
  case "$line" in *"session ended reason=Provisioned"*) break ;; esac
done < <(journalctl -fu "$service" --since "$start" -o cat --no-pager | sed -u 's/\x1b\[[0-9;]*m//g')
pkill -f "[j]ournalctl -fu $service --since $start" 2> /dev/null || true
trap - INT
echo "------------------------------------------------------------------------"
sleep 3 # let the connectivity state settle

echo; echo "== 4/5 Collecting evidence"
sudo pkill -INT -f "[b]tmon -w $out/capture.btsnoop" || true
sleep 1
sudo chown "$(id -u):$(id -g)" "$out/capture.btsnoop"
snapshot "$out/after.txt"
{
  gw=$(ip route show default | awk '/default/ { print $3; exit }')
  echo "## ping gateway ${gw:-<none>}"; [ -n "$gw" ] && ping -c 3 -W 2 "$gw" || true
  echo; echo "## NetworkManager connectivity check"; nmcli networking connectivity check
} >> "$out/after.txt" 2>&1
journalctl -u "$service" --since "$start" -o cat --no-pager | sed 's/\x1b\[[0-9;]*m//g' > "$out/device.log"
journalctl -u "$service" --since "$start" -o json --no-pager > "$out/device-journal.jsonl"
journalctl -u NetworkManager --since "$start" -o short-precise --no-pager > "$out/networkmanager.log"
systemd-analyze security "$service" --no-pager > "$out/security.txt" 2>&1 || true

echo; echo "== 5/5 Checking the capture for credentials"
ssid=$(nmcli -g 802-11-wireless.ssid connection show teton-provisioned 2> /dev/null || true)
"$repo/scripts/verify-capture" "$out/capture.btsnoop" ${ssid:+--ssid "$ssid"} | tee "$out/verify.txt"

cat << EOF

Done. Evidence in ${out#"$repo"/}:
  before.txt / after.txt   network state before and after (no route -> online)
  capture.btsnoop          every Bluetooth packet of the session (open with btmon -r)
  verify.txt               credential search + over-the-air message transcript
  device.log               the device's log; device-journal.jsonl is the same as JSON
  networkmanager.log       NetworkManager's view (handshake failures, activation)
  security.txt             systemd-analyze security for the service
Add the phone screen recording/screenshots to that folder, then run
scripts/demo-restore to give your other Wi-Fi profiles back their autoconnect.
EOF
