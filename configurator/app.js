// Teton Setup: screen flow for provisioning a device (SPEC.md §10).
// All device-provided text (SSIDs, IDs) is rendered with textContent only.

import { bluetoothAvailable, BleTransport } from "./ble.js";
import * as history from "./history.js";
import { formatId, LabelError, parseLabelUrl } from "./protocol.js";
import { scanQr, scannerAvailable } from "./scanner.js";
import { ProvisioningSession, SessionError } from "./session.js";

const $ = (id) => document.getElementById(id);

const REASONS = {
  invalid_input: ["E-INPUT", () => "That password can't be right: Wi-Fi passwords are 8–63 characters."],
  unsupported_security: ["E-UNSUPPORTED", () => "This network type isn't supported yet. Choose another network or contact Teton."],
  ssid_not_found: ["E-SSID", (n) => `The device can't see “${n}”. Is it in range?`],
  auth_failed: ["E-AUTH", (n) => `Wrong password for “${n}”.`],
  dhcp_failed: ["E-DHCP", (n) => `Joined “${n}” but didn't get an address. Contact IT (DHCP).`],
  timeout: ["E-TIMEOUT", (n) => `Couldn't connect to “${n}”. Move closer or try again.`],
  internal: ["E-INTERNAL", () => "Something went wrong on the device. Try again."],
};

const UNSUPPORTED_NOTE = {
  enterprise: "Enterprise (802.1X) Wi-Fi isn't supported yet",
  wep: "WEP is insecure and not supported",
};

// Per-device state; reset for every new label.
let dev = null;
// Network credentials reused across devices in this page session only. Never stored.
let remembered = null;
let deferredInstall = null;
let lastLabelUrl = null;
let scanAbort = null;
let countdownTimer = null;

function freshDevice(label) {
  return { label, transport: null, session: null, networks: [], target: null, finished: false, lastFailure: null, lockoutUntil: 0 };
}

// ------------------------------------------------------------------ screens

function show(name) {
  for (const s of document.querySelectorAll("[data-screen]")) s.hidden = s.dataset.screen !== name;
  window.scrollTo(0, 0);
  if (name !== "scan") scanAbort?.abort();
  if (name !== "result") clearInterval(countdownTimer);
}

function steps(listId, current) {
  const items = [...$(listId).children];
  const idx = items.findIndex((li) => li.dataset.step === current);
  items.forEach((li, i) => {
    li.classList.toggle("done", i < idx || current === "*");
    li.classList.toggle("active", i === idx);
  });
}

function refreshHistoryButton() {
  const n = history.load().length;
  $("history-count").textContent = String(n);
  $("history-btn").hidden = n === 0;
}

function problem(err) {
  const e = err instanceof SessionError || err instanceof LabelError ? err : new SessionError("E-APP", String(err?.message ?? err));
  $("problem-title").textContent = e.code === "E-BUSY" ? "Device is busy" : "Something went wrong";
  let detail = e.message;
  if (e.retryAfter) detail += ` Try again in ${e.retryAfter} seconds.`;
  $("problem-detail").textContent = detail;
  $("problem-code").textContent = e.code ? `Code ${e.code}` : "";
  $("problem-retry").hidden = !lastLabelUrl;
  disconnect();
  show("problem");
}

function disconnect() {
  if (!dev) return;
  dev.finished = true; // a disconnect from here on is expected
  dev.transport?.close();
  dev.transport = null;
  dev.session = null;
}

// ------------------------------------------------------------------ label → connect

async function openLabel(url) {
  lastLabelUrl = url;
  try {
    const label = await parseLabelUrl(url);
    dev = freshDevice(label);
    $("device-id").textContent = formatId(label.id);
    $("device-msg").textContent = "Press Connect, then pick this device in the list that appears.";
    $("verify-steps").hidden = true;
    $("connect-btn").disabled = false;
    show("device");
  } catch (e) {
    problem(e instanceof LabelError ? new SessionError(`E-LABEL`, e.message) : e);
  }
}

async function connect() {
  const d = dev;
  $("connect-btn").disabled = true;
  $("verify-steps").hidden = false;
  $("device-msg").textContent = "Pick the device in the list that appears.";
  steps("verify-steps", "connect");
  try {
    d.finished = false;
    d.transport = await BleTransport.connect(d.label.id);
    d.transport.onDisconnect = (err) => {
      if (!d.finished && dev === d) problem(err);
    };
    steps("verify-steps", "verify");
    d.session = new ProvisioningSession(d.transport, d.label);
    const ready = await d.session.start();
    steps("verify-steps", "*");
    if (ready.retry_after > 0) d.lockoutUntil = Date.now() + ready.retry_after * 1000;
    await loadNetworks();
  } catch (e) {
    if (dev === d) problem(e);
  }
}

// ------------------------------------------------------------------ networks

function bars(signal) {
  const span = document.createElement("span");
  span.className = "bars";
  span.setAttribute("aria-label", `signal ${signal}%`);
  const on = signal >= 75 ? 4 : signal >= 50 ? 3 : signal >= 25 ? 2 : 1;
  for (let i = 0; i < 4; i++) {
    const bar = document.createElement("i");
    if (i < on) bar.className = "on";
    span.append(bar);
  }
  return span;
}

function renderNetworks() {
  const list = $("network-list");
  list.replaceChildren();
  for (const n of dev.networks) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = n.ssid;
    if (UNSUPPORTED_NOTE[n.sec]) {
      btn.disabled = true;
      const note = document.createElement("span");
      note.className = "note";
      note.textContent = UNSUPPORTED_NOTE[n.sec];
      name.append(note);
    }
    const lock = document.createElement("span");
    lock.className = "lock";
    lock.textContent = n.sec === "open" ? "open" : "🔒";
    btn.append(name, lock, bars(n.signal));
    btn.addEventListener("click", () => chooseNetwork(n));
    li.append(btn);
    list.append(li);
  }
  $("networks-hint").hidden = dev.networks.length === 0;
  const visible = remembered && dev.networks.some((n) => n.ssid === remembered.ssid);
  $("reuse-btn").hidden = !visible;
  if (visible) $("reuse-btn").textContent = `Use “${remembered.ssid}” again`;
}

async function loadNetworks() {
  show("networks");
  $("networks-loading").hidden = false;
  $("network-list").replaceChildren();
  $("rescan-btn").disabled = true;
  try {
    dev.networks = await dev.session.scan();
    $("networks-loading").textContent = dev.networks.length ? "" : "The device can't see any networks. Try Rescan, or Other network for a hidden one.";
    $("networks-loading").hidden = dev.networks.length > 0;
    renderNetworks();
  } catch (e) {
    problem(e);
  } finally {
    $("rescan-btn").disabled = false;
  }
}

function chooseNetwork(n) {
  dev.target = { ssid: n.ssid, sec: n.sec, hidden: false };
  if (n.sec === "open") return join({ ssid: n.ssid, hidden: false });
  passwordScreen(false);
}

function passwordScreen(hiddenNetwork) {
  $("pw-title").textContent = hiddenNetwork ? "Other network" : dev.target.ssid;
  $("hidden-fields").hidden = !hiddenNetwork;
  $("psk-field").hidden = false;
  $("psk-input").value = "";
  $("pw-error").textContent = "";
  $("psk-input").type = "password";
  $("psk-toggle").textContent = "Show";
  if (hiddenNetwork) {
    dev.target = { ssid: "", sec: "wpa2", hidden: true };
    $("ssid-input").value = "";
    $("sec-input").value = "wpa2";
  }
  show("password");
  (hiddenNetwork ? $("ssid-input") : $("psk-input")).focus();
}

function submitPassword(ev) {
  ev.preventDefault();
  const t = dev.target;
  const ssid = t.hidden ? $("ssid-input").value.trim() : t.ssid;
  const sec = t.hidden ? $("sec-input").value : t.sec;
  const psk = $("psk-input").value;
  const err = (m) => ($("pw-error").textContent = m);
  if (t.hidden && !ssid) return err("Enter the network name.");
  if (new TextEncoder().encode(ssid).length > 32) return err("Network names are at most 32 bytes.");
  if (sec !== "open") {
    const hex = /^[0-9a-fA-F]{64}$/.test(psk);
    if (!hex && (psk.length < 8 || psk.length > 63)) return err("Wi-Fi passwords are 8–63 characters.");
  }
  const creds = { ssid, hidden: t.hidden };
  if (sec !== "open") creds.psk = psk;
  if (t.hidden) creds.sec = sec;
  join(creds);
}

// ------------------------------------------------------------------ join

async function join(creds) {
  const d = dev;
  if (d.lockoutUntil > Date.now()) return lockedScreen(creds.ssid);
  show("progress");
  for (const el of document.querySelectorAll("#join-steps .ssid")) el.textContent = `“${creds.ssid}”`;
  steps("join-steps", "accepted");
  d.joinAttempted = true;
  let final;
  try {
    final = await d.session.join(creds, (s) => {
      const next = { accepted: "associating", associating: "ip", ip: "done" }[s.stage];
      if (next) steps("join-steps", next);
    });
  } catch (e) {
    return dev === d && problem(e);
  }
  if (dev !== d) return;
  d.lastCreds = creds;
  if (final.stage === "done") return succeeded(creds, final);
  if (final.retry_after) d.lockoutUntil = Date.now() + final.retry_after * 1000;
  if (final.stage === "locked") return lockedScreen(creds.ssid);
  failed(creds, final);
}

async function succeeded(creds, status) {
  const d = dev;
  remembered = creds; // memory only, for the next device
  d.success = { ssid: creds.ssid, ip: status.ip, internet: status.internet };
  d.finished = true;
  try {
    await d.session.ack(); // the device then disconnects and stops advertising
  } catch {
    // provisioning already succeeded; the device times out the ack on its own
  }
  d.transport?.close();
  const online = status.internet === "full";
  $("result-icon").className = `result-icon ${online ? "ok" : "warn"}`;
  $("result-title").textContent = online ? "Device online" : "Connected, but no internet";
  $("result-detail").textContent = online
    ? `Connected to “${creds.ssid}” (${status.ip}).`
    : `The device joined “${creds.ssid}” (${status.ip}) but can't reach the internet. Contact IT.`;
  $("result-code").textContent = online ? "" : `Code E-NO-INTERNET (${status.internet})`;
  $("success-actions").hidden = false;
  $("failure-actions").hidden = true;
  $("room-input").value = "";
  show("result");
}

function failed(creds, status) {
  const [code, text] = REASONS[status.reason] ?? REASONS.internal;
  dev.lastFailure = code;
  if (status.reason === "auth_failed" && remembered?.ssid === creds.ssid) remembered = null;
  $("result-icon").className = "result-icon fail";
  $("result-title").textContent = "Not connected";
  $("result-detail").textContent = text(creds.ssid);
  $("result-code").textContent = `Code ${code}`;
  $("success-actions").hidden = true;
  $("failure-actions").hidden = false;
  $("retry-btn").disabled = false;
  show("result");
  if (dev.lockoutUntil > Date.now()) startCountdown();
}

function lockedScreen(ssid) {
  $("result-icon").className = "result-icon wait";
  $("result-title").textContent = "Too many failed attempts";
  $("result-code").textContent = "Code E-LOCKED";
  $("success-actions").hidden = true;
  $("failure-actions").hidden = false;
  dev.lastFailure ??= "E-LOCKED";
  show("result");
  startCountdown(ssid);
}

function startCountdown(ssid) {
  clearInterval(countdownTimer);
  const tick = () => {
    const left = Math.max(0, Math.ceil((dev.lockoutUntil - Date.now()) / 1000));
    const mmss = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    if (ssid) $("result-detail").textContent = left ? `Try again in ${mmss}.` : "You can try again now.";
    $("retry-btn").disabled = left > 0;
    $("retry-btn").textContent = left ? `Try again in ${mmss}` : "Try again";
    if (!left) clearInterval(countdownTimer);
  };
  tick();
  countdownTimer = setInterval(tick, 1000);
}

function retry() {
  const t = dev.target;
  if (!t || (t.sec === "open" && !t.hidden)) return join({ ssid: t.ssid, hidden: false });
  passwordScreen(t.hidden);
}

// ------------------------------------------------------------------ finish

function record(extra = {}) {
  if (!dev) return;
  if (dev.success) {
    history.add({
      device_id: formatId(dev.label.id),
      ssid: dev.success.ssid,
      result: dev.success.internet === "full" ? "online" : "no_internet",
      ip: dev.success.ip,
      room: $("room-input").value.trim(),
      ...extra,
    });
  } else if (dev.joinAttempted) {
    history.add({ device_id: formatId(dev.label.id), ssid: dev.lastCreds?.ssid ?? "", result: `failed (${dev.lastFailure ?? "E-?"})`, ip: "", room: "" });
  }
  refreshHistoryButton();
}

function finish(next) {
  record();
  disconnect();
  dev = null;
  if (next) startScan();
  else show("home");
}

// ------------------------------------------------------------------ scan / history / install

async function startScan() {
  if (!scannerAvailable()) {
    show("home");
    $("compat-warning").hidden = false;
    $("compat-warning").textContent = "This phone can't scan from inside the app. Open the label with the camera app instead.";
    return;
  }
  show("scan");
  scanAbort = new AbortController();
  try {
    const text = await scanQr($("scan-video"), scanAbort.signal);
    await openLabel(text);
  } catch (e) {
    if (e.name === "AbortError") return;
    if (e.name === "NotAllowedError") return problem(new SessionError("E-CAMERA", "Camera permission was denied. Allow the camera, or use the phone's camera app."));
    problem(e);
  }
}

function renderHistory() {
  const list = history.load();
  const ul = $("history-list");
  ul.replaceChildren();
  for (const r of [...list].reverse()) {
    const li = document.createElement("li");
    const id = document.createElement("span");
    id.className = "id";
    id.textContent = r.device_id;
    const status = document.createElement("span");
    status.className = r.result === "online" ? "status-online" : r.result.startsWith("failed") ? "status-failed" : "";
    status.textContent = r.result;
    const meta = document.createElement("span");
    meta.className = "meta";
    const time = new Date(r.provisioned_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    meta.textContent = [time, r.ssid, r.room].filter(Boolean).join(" · ");
    li.append(id, status, meta);
    ul.append(li);
  }
  $("history-empty").hidden = list.length > 0;
  show("history");
}

function exportCsv() {
  const blob = new Blob([history.toCsv(history.load())], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = history.csvFilename();
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

function wire() {
  $("scan-btn").addEventListener("click", startScan);
  $("scan-cancel").addEventListener("click", () => show("home"));
  $("connect-btn").addEventListener("click", connect);
  $("rescan-btn").addEventListener("click", loadNetworks);
  $("other-btn").addEventListener("click", () => passwordScreen(true));
  $("reuse-btn").addEventListener("click", () => {
    dev.target = { ssid: remembered.ssid, sec: remembered.sec ?? null, hidden: remembered.hidden };
    join(remembered);
  });
  $("sec-input").addEventListener("change", () => ($("psk-field").hidden = $("sec-input").value === "open"));
  $("psk-toggle").addEventListener("click", () => {
    const shown = $("psk-input").type === "text";
    $("psk-input").type = shown ? "password" : "text";
    $("psk-toggle").textContent = shown ? "Show" : "Hide";
    $("psk-toggle").setAttribute("aria-pressed", String(!shown));
  });
  $("pw-form").addEventListener("submit", submitPassword);
  $("retry-btn").addEventListener("click", retry);
  $("next-btn").addEventListener("click", () => finish(true));
  $("done-btn").addEventListener("click", () => finish(false));
  $("problem-retry").addEventListener("click", () => lastLabelUrl && openLabel(lastLabelUrl));
  $("history-btn").addEventListener("click", renderHistory);
  $("export-btn").addEventListener("click", exportCsv);
  $("clear-btn").addEventListener("click", () => {
    if (confirm("Clear the list of devices done today?")) {
      history.clear();
      refreshHistoryButton();
      renderHistory();
    }
  });
  for (const b of document.querySelectorAll("[data-action]")) {
    b.addEventListener("click", () => {
      const a = b.dataset.action;
      if (a === "home") finish(false);
      else if (a === "abandon") finish(false);
      else if (a === "networks") dev?.session ? (show("networks"), renderNetworks()) : finish(false);
    });
  }
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredInstall = e;
    $("install-hint").hidden = false;
  });
  $("install-btn").addEventListener("click", async () => {
    $("install-hint").hidden = true;
    await deferredInstall?.prompt();
    deferredInstall = null;
  });
}

function boot() {
  wire();
  refreshHistoryButton();
  if (!bluetoothAvailable()) {
    $("compat-warning").hidden = false;
    $("compat-warning").textContent = "This browser can't use Bluetooth. Open this page in Chrome on Android.";
  }
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(() => {});
  // Opened from a label via the camera app: the label is in the #fragment.
  if (location.hash.includes("id=")) {
    const url = location.href;
    // Drop the fragment so a reload doesn't reopen this device.
    window.history.replaceState(null, "", location.pathname);
    openLabel(url);
  } else {
    show("home");
  }
}

boot();
