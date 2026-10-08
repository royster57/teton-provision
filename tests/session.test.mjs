import { test } from "node:test";
import assert from "node:assert/strict";
import { b64urlDecode, b64urlEncode, encodeMessage, hex } from "../configurator/protocol.js";
import { ProvisioningSession } from "../configurator/session.js";
import { unhex, vectors } from "./helpers.mjs";

const v = vectors.session;
const label = { id: v.device_id, publicKey: unhex(v.device_public) };

async function vectorEphemeral() {
  const pub = unhex(v.ephemeral_public);
  const jwk = {
    kty: "EC", crv: "P-256",
    x: b64urlEncode(pub.subarray(1, 33)), y: b64urlEncode(pub.subarray(33)),
    d: b64urlEncode(unhex(v.ephemeral_private)),
  };
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  return { privateKey, publicRaw: pub };
}

/** Plays the device side of the vector transcript, checking every phone message. */
class VectorDevice {
  queue = [];
  chunkLen = null;
  step = 0;

  constructor({ challengeId = v.device_id, script } = {}) {
    this.challengeId = challengeId;
    this.script = script;
  }

  reply(obj) {
    this.queue.push(encodeMessage(obj));
  }

  sealedReply(i) {
    this.reply({ t: "sealed", ct: b64urlEncode(unhex(v.device_to_phone[i].ciphertext)) });
  }

  async send(bytes) {
    const msg = JSON.parse(new TextDecoder().decode(bytes));
    if (this.script) return this.script(msg, this);
    const p2d = v.phone_to_device;
    switch (this.step++) {
      case 0:
        assert.deepEqual(msg, { t: "hello", v: 1 });
        return this.reply({ t: "challenge", v: 1, id: this.challengeId, n: b64urlEncode(unhex(v.nonce)), mtu: 185 });
      case 1:
        assert.equal(hex(b64urlDecode(msg.e)), v.ephemeral_public);
        assert.equal(hex(b64urlDecode(msg.ct)), p2d[0].ciphertext, "open");
        return this.sealedReply(0); // ready
      case 2:
        assert.equal(msg.e, undefined, "ephemeral key only in the first sealed message");
        assert.equal(hex(b64urlDecode(msg.ct)), p2d[1].ciphertext, "scan");
        return this.sealedReply(1); // networks
      case 3:
        assert.equal(hex(b64urlDecode(msg.ct)), p2d[2].ciphertext, "join JSON must match Rust byte for byte");
        this.sealedReply(2); // accepted
        return this.sealedReply(3); // done
      case 4:
        assert.equal(hex(b64urlDecode(msg.ct)), p2d[3].ciphertext, "ack");
        return;
      default:
        assert.fail("unexpected message");
    }
  }

  async next() {
    const m = this.queue.shift();
    if (!m) throw new Error("device has nothing to say");
    return m;
  }

  setChunkLen(n) {
    this.chunkLen = n;
  }
}

test("full session reproduces the Rust transcript", async () => {
  const device = new VectorDevice();
  const session = new ProvisioningSession(device, label, { ephemeral: await vectorEphemeral() });
  const ready = await session.start();
  assert.deepEqual(ready, { t: "ready", state: "unprovisioned", retry_after: 0, version: "0.1.0" });
  assert.equal(device.chunkLen, 182, "chunk length follows the device's MTU");
  const list = await session.scan();
  assert.equal(list[0].ssid, "roy");
  const seen = [];
  const final = await session.join({ ssid: "roy", psk: "correct horse" }, (s) => seen.push(s.stage));
  assert.deepEqual(seen, ["accepted", "done"]);
  assert.deepEqual(final, { t: "status", stage: "done", ip: "192.168.1.42", internet: "full" });
  await session.ack();
  assert.equal(device.step, 5);
});

test("rejects a device whose challenge ID differs from the label", async () => {
  const device = new VectorDevice({ challengeId: "000000000000" });
  const session = new ProvisioningSession(device, label);
  await assert.rejects(session.start(), (e) => e.code === "E-LABEL");
});

test("an impostor that cannot decrypt fails verification", async () => {
  const device = new VectorDevice({
    script(msg, d) {
      if (msg.t === "hello") {
        return d.reply({ t: "challenge", v: 1, id: v.device_id, n: b64urlEncode(unhex(v.nonce)), mtu: 23 });
      }
      d.reply({ t: "sealed", ct: b64urlEncode(new Uint8Array(40)) }); // forged "ready"
    },
  });
  const session = new ProvisioningSession(device, label);
  await assert.rejects(session.start(), (e) => e.code === "E-VERIFY");
});

test("device wait and error messages surface as coded errors", async () => {
  const waiting = new VectorDevice({ script: (_, d) => d.reply({ t: "wait", retry_after: 20 }) });
  await assert.rejects(new ProvisioningSession(waiting, label).start(), (e) => e.code === "E-BUSY" && e.retryAfter === 20);
  const old = new VectorDevice({ script: (_, d) => d.reply({ t: "error", code: "unsupported_version" }) });
  await assert.rejects(new ProvisioningSession(old, label).start(), (e) => e.code === "E-VERSION");
});
