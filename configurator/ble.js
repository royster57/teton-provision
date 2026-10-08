// Web Bluetooth transport: the device's rx/tx characteristics as a chunked
// message pipe (SPEC.md §4).

import { chunk, GATT, Reassembler } from "./protocol.js";
import { SessionError } from "./session.js";

const CONNECT_TIMEOUT_MS = 20_000;

function withTimeout(ms, fn) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), ms);
  });
  return Promise.race([fn(), timeout]).finally(() => clearTimeout(timer));
}

export function bluetoothAvailable() {
  return typeof navigator !== "undefined" && "bluetooth" in navigator;
}

export class BleTransport {
  #device;
  #rx;
  #tx;
  #chunkLen = 20; // safe for the minimum ATT MTU until the device reports its MTU
  #reassembler = new Reassembler();
  #queue = [];
  #waiters = [];
  #closed = null;
  onDisconnect = () => {};

  /**
   * Shows Chrome's device picker filtered to exactly this device and
   * connects. Must be called from a user gesture.
   */
  static async connect(id) {
    if (!bluetoothAvailable()) {
      throw new SessionError("E-NO-BT", "This browser can't use Bluetooth. Open this page in Chrome.");
    }
    let device;
    try {
      device = await navigator.bluetooth.requestDevice({
        filters: [{ name: `Teton-${id}` }],
        optionalServices: [GATT.SERVICE],
      });
    } catch (e) {
      if (e.name === "NotFoundError") {
        throw new SessionError(
          "E-NOT-FOUND",
          "Device not found. If it's already set up, press its setup button first to change its network. " +
            "Otherwise it may be busy with another phone, or out of range.",
        );
      }
      if (e.name === "NotAllowedError" || e.name === "SecurityError") {
        throw new SessionError("E-BT-PERMISSION", "Bluetooth permission was denied. Allow \"Nearby devices\" for Chrome.");
      }
      throw new SessionError("E-BT-OFF", "Bluetooth is off or unavailable. Turn it on and try again.");
    }
    const t = new BleTransport();
    await t.#open(device);
    return t;
  }

  async #open(device) {
    this.#device = device;
    device.addEventListener("gattserverdisconnected", () => this.#fail("E-LOST", "Connection to the device was lost."));
    try {
      // gatt.connect() has no timeout of its own: picking a device Chrome remembers but
      // that is no longer advertising (e.g. already provisioned) would wait indefinitely.
      await withTimeout(CONNECT_TIMEOUT_MS, async () => {
        const server = await device.gatt.connect();
        const service = await server.getPrimaryService(GATT.SERVICE);
        this.#rx = await service.getCharacteristic(GATT.RX);
        this.#tx = await service.getCharacteristic(GATT.TX);
        this.#tx.addEventListener("characteristicvaluechanged", (ev) => this.#onNotify(ev.target.value));
        await this.#tx.startNotifications();
      });
    } catch {
      this.close();
      throw new SessionError(
        "E-CONNECT",
        "Couldn't connect to the device. If it's already set up, press its setup button first; otherwise move closer and try again.",
      );
    }
  }

  #onNotify(view) {
    const bytes = new Uint8Array(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
    let msg;
    try {
      msg = this.#reassembler.push(bytes);
    } catch {
      return this.#fail("E-PROTOCOL", "Received a garbled message from the device.");
    }
    if (!msg) return;
    const waiter = this.#waiters.shift();
    if (waiter) waiter.resolve(msg);
    else this.#queue.push(msg);
  }

  #fail(code, message) {
    if (this.#closed) return;
    this.#closed = new SessionError(code, message);
    for (const w of this.#waiters.splice(0)) w.reject(this.#closed);
    this.onDisconnect(this.#closed);
  }

  setChunkLen(n) {
    this.#chunkLen = Math.max(20, n);
  }

  async send(message) {
    if (this.#closed) throw this.#closed;
    for (const c of chunk(message, this.#chunkLen)) {
      await this.#rx.writeValueWithResponse(c);
    }
  }

  /** Next complete message from the device. */
  next(timeoutMs) {
    if (this.#queue.length) return Promise.resolve(this.#queue.shift());
    if (this.#closed) return Promise.reject(this.#closed);
    return new Promise((resolve, reject) => {
      const w = { resolve, reject };
      const timer = setTimeout(() => {
        this.#waiters = this.#waiters.filter((x) => x !== w);
        reject(new SessionError("E-TIMEOUT", "The device stopped responding."));
      }, timeoutMs);
      w.resolve = (m) => (clearTimeout(timer), resolve(m));
      w.reject = (e) => (clearTimeout(timer), reject(e));
      this.#waiters.push(w);
    });
  }

  /** Disconnects without reporting it as a failure. */
  close() {
    this.#closed ??= new SessionError("E-CLOSED", "Disconnected.");
    try {
      this.#device?.gatt?.disconnect();
    } catch {
      // already disconnected
    }
  }
}
