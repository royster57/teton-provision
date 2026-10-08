// Provisioning session, phone side (SPEC.md §6). Transport-agnostic: anything
// with send(bytes), next(timeoutMs) and setChunkLen(n) works, which lets tests
// replay the Rust test vectors without Bluetooth.

import { Channel } from "./crypto.js";
import { b64urlDecode, b64urlEncode, decodeMessage, encodeMessage, PROTOCOL_VERSION } from "./protocol.js";

const REPLY_TIMEOUT_MS = 15_000;
const SCAN_TIMEOUT_MS = 30_000;
// NM may take its full join timeout plus DHCP and the connectivity check.
const JOIN_STEP_TIMEOUT_MS = 90_000;

/** Errors carry a short code that technicians can quote to support. */
export class SessionError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export class ProvisioningSession {
  #transport;
  #label;
  #ephemeral;
  #channel = null;

  /**
   * @param transport  {send(Uint8Array), next(timeoutMs) → Uint8Array, setChunkLen(n)}
   * @param label      {id, publicKey} from parseLabelUrl
   * @param options    {ephemeral} to inject a key pair (test vectors only)
   */
  constructor(transport, label, { ephemeral } = {}) {
    this.#transport = transport;
    this.#label = label;
    this.#ephemeral = ephemeral;
  }

  async #recvOuter(timeoutMs = REPLY_TIMEOUT_MS) {
    const msg = decodeMessage(await this.#transport.next(timeoutMs));
    if (msg.t === "error") {
      const code = msg.code === "unsupported_version" ? "E-VERSION" : "E-PROTOCOL";
      throw new SessionError(code, `Device reported error: ${msg.code}`);
    }
    if (msg.t === "wait") {
      throw new SessionError("E-BUSY", "Device is refusing new connections for now.", {
        retryAfter: msg.retry_after,
      });
    }
    return msg;
  }

  async #recv(timeoutMs) {
    const outer = await this.#recvOuter(timeoutMs);
    if (outer.t !== "sealed") throw new SessionError("E-PROTOCOL", `Unexpected "${outer.t}"`);
    let plaintext;
    try {
      plaintext = await this.#channel.open(b64urlDecode(outer.ct));
    } catch {
      throw new SessionError("E-PROTOCOL", "A message from the device failed to decrypt.");
    }
    return decodeMessage(plaintext);
  }

  async #send(inner, ephemeralPublic) {
    const ct = await this.#channel.seal(encodeMessage(inner));
    const outer = { t: "sealed" };
    if (ephemeralPublic) outer.e = b64urlEncode(ephemeralPublic);
    outer.ct = b64urlEncode(ct);
    await this.#transport.send(encodeMessage(outer));
  }

  /**
   * hello → challenge → open → ready. Resolves to the `ready` message:
   * {state, retry_after, version}. Only the real device can produce it.
   */
  async start() {
    await this.#transport.send(encodeMessage({ t: "hello", v: PROTOCOL_VERSION }));
    const challenge = await this.#recvOuter();
    if (challenge.t !== "challenge") throw new SessionError("E-PROTOCOL", "Expected a challenge.");
    if (challenge.id !== this.#label.id) {
      throw new SessionError("E-LABEL", "This device does not match the scanned label.");
    }
    this.#transport.setChunkLen(Math.min(challenge.mtu - 3, 512));
    const { channel, ephemeralPublic } = await Channel.initiate(
      this.#label.publicKey,
      this.#label.id,
      b64urlDecode(challenge.n),
      this.#ephemeral,
    );
    this.#channel = channel;
    await this.#send({ t: "open" }, ephemeralPublic);
    let ready;
    try {
      ready = await this.#recv();
    } catch (e) {
      // A device without the label's private key cannot answer.
      if (e.code === "E-PROTOCOL") {
        throw new SessionError("E-VERIFY", "Could not verify the device. Is this the right label?");
      }
      throw e;
    }
    if (ready.t !== "ready") throw new SessionError("E-PROTOCOL", "Expected ready.");
    return ready;
  }

  /** Networks visible to the device, strongest first. */
  async scan() {
    await this.#send({ t: "scan" });
    const reply = await this.#recv(SCAN_TIMEOUT_MS);
    if (reply.t !== "networks") throw new SessionError("E-PROTOCOL", "Expected networks.");
    return reply.list;
  }

  /**
   * Sends credentials and reports each status to onStatus until the final
   * one (done, failed or locked), which it resolves to.
   */
  async join({ ssid, psk, sec, hidden = false }, onStatus = () => {}) {
    const req = { t: "join", ssid };
    if (psk) req.psk = psk;
    if (sec) req.sec = sec;
    req.hidden = hidden;
    await this.#send(req);
    for (;;) {
      const status = await this.#recv(JOIN_STEP_TIMEOUT_MS);
      if (status.t !== "status") throw new SessionError("E-PROTOCOL", "Expected status.");
      onStatus(status);
      if (["done", "failed", "locked"].includes(status.stage)) return status;
    }
  }

  async ack() {
    await this.#send({ t: "ack" });
  }
}
