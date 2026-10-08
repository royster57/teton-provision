import { test } from "node:test";
import assert from "node:assert/strict";
import { agree, Channel, deriveKeyMaterial, hkdfInfo } from "../configurator/crypto.js";
import { b64urlEncode, decodeMessage, hex } from "../configurator/protocol.js";
import { unhex, vectors } from "./helpers.mjs";

const v = vectors.session;
const subtle = globalThis.crypto.subtle;

// WebCrypto cannot import a raw EC scalar, so the vector key goes in as a JWK.
async function importScalar(scalarHex, publicHex) {
  const pub = unhex(publicHex);
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: b64urlEncode(pub.subarray(1, 33)),
    y: b64urlEncode(pub.subarray(33)),
    d: b64urlEncode(unhex(scalarHex)),
  };
  return subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

const importAes = (h) => subtle.importKey("raw", unhex(h), "AES-GCM", false, ["encrypt", "decrypt"]);

test("ECDH shared secret matches", async () => {
  const eph = await importScalar(v.ephemeral_private, v.ephemeral_public);
  assert.equal(hex(await agree(eph, unhex(v.device_public))), v.shared_secret);
  const dev = await importScalar(v.device_private, v.device_public);
  assert.equal(hex(await agree(dev, unhex(v.ephemeral_public))), v.shared_secret);
});

test("HKDF info and session keys match", async () => {
  const info = hkdfInfo(v.device_id, unhex(v.ephemeral_public), unhex(v.device_public));
  assert.equal(hex(info), v.hkdf_info);
  const okm = await deriveKeyMaterial(
    unhex(v.shared_secret), unhex(v.nonce), v.device_id,
    unhex(v.ephemeral_public), unhex(v.device_public),
  );
  assert.equal(hex(okm.subarray(0, 32)), v.k_pd);
  assert.equal(hex(okm.subarray(32)), v.k_dp);
});

test("phone channel seals and opens the vector transcript", async () => {
  const privateKey = await importScalar(v.ephemeral_private, v.ephemeral_public);
  const { channel, ephemeralPublic } = await Channel.initiate(
    unhex(v.device_public), v.device_id, unhex(v.nonce),
    { privateKey, publicRaw: unhex(v.ephemeral_public) },
  );
  assert.equal(hex(ephemeralPublic), v.ephemeral_public);
  const enc = new TextEncoder();
  for (const m of v.phone_to_device) {
    assert.equal(hex(await channel.seal(enc.encode(m.plaintext))), m.ciphertext);
  }
  for (const m of v.device_to_phone) {
    const pt = await channel.open(unhex(m.ciphertext));
    assert.equal(new TextDecoder().decode(pt), m.plaintext);
    decodeMessage(pt);
  }
});

test("device-direction ciphertexts decrypt with K_pd (device view)", async () => {
  const device = new Channel(await importAes(v.k_dp), await importAes(v.k_pd));
  for (const m of v.phone_to_device) {
    const pt = await device.open(unhex(m.ciphertext));
    assert.equal(new TextDecoder().decode(pt), m.plaintext);
  }
});

test("replayed, reordered and tampered messages are rejected", async () => {
  const device = new Channel(await importAes(v.k_dp), await importAes(v.k_pd));
  const [first, second] = v.phone_to_device.map((m) => unhex(m.ciphertext));
  await assert.rejects(device.open(second), /decryption failed/);
  const tampered = first.slice();
  tampered[3] ^= 1;
  await assert.rejects(device.open(tampered), /decryption failed/);
  await device.open(first);
  await assert.rejects(device.open(first), /decryption failed/);
  await device.open(second);
});

test("fresh ephemeral sessions interoperate", async () => {
  const devicePublic = unhex(v.device_public);
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const { channel, ephemeralPublic } = await Channel.initiate(devicePublic, v.device_id, nonce);
  const dev = await importScalar(v.device_private, v.device_public);
  const okm = await deriveKeyMaterial(
    await agree(dev, ephemeralPublic), nonce, v.device_id, ephemeralPublic, devicePublic,
  );
  const device = new Channel(
    await subtle.importKey("raw", okm.slice(32), "AES-GCM", false, ["encrypt", "decrypt"]),
    await subtle.importKey("raw", okm.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]),
  );
  const pt = new TextEncoder().encode('{"t":"open"}');
  assert.deepEqual(await device.open(await channel.seal(pt)), pt);
  assert.deepEqual(await channel.open(await device.seal(pt)), pt);
});
