// Session key agreement and sealing (SPEC.md §5), on WebCrypto only.
//
//   Z    = ECDH-P256(e, D)
//   OKM  = HKDF-SHA256(ikm=Z, salt=N, info="teton-prov v1" ‖ id ‖ E ‖ D, L=64)
//   K_pd = OKM[0..32] (phone → device), K_dp = OKM[32..64] (device → phone)
//   seal = AES-256-GCM(K, iv = 0^4 ‖ u64_be(counter), no AAD)

import { concat } from "./protocol.js";

const subtle = globalThis.crypto.subtle;
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const INFO_LABEL = new TextEncoder().encode("teton-prov v1");

export const NONCE_LEN = 16;

export function hkdfInfo(id, ephemeralPublic, devicePublic) {
  return concat(INFO_LABEL, new TextEncoder().encode(id), ephemeralPublic, devicePublic);
}

/** Generates the phone's ephemeral key pair; resolves to {privateKey, publicRaw}. */
export async function generateEphemeral() {
  const pair = await subtle.generateKey(ECDH, false, ["deriveBits"]);
  return {
    privateKey: pair.privateKey,
    publicRaw: new Uint8Array(await subtle.exportKey("raw", pair.publicKey)),
  };
}

/** Raw ECDH shared secret (32-byte x-coordinate). */
export async function agree(privateKey, peerPublicRaw) {
  const peer = await subtle.importKey("raw", peerPublicRaw, ECDH, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256));
}

/** The 64 bytes K_pd ‖ K_dp. */
export async function deriveKeyMaterial(sharedSecret, nonce, id, ephemeralPublic, devicePublic) {
  if (nonce.length !== NONCE_LEN) throw new Error("nonce must be 16 bytes");
  const ikm = await subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const info = hkdfInfo(id, ephemeralPublic, devicePublic);
  const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: nonce, info }, ikm, 512);
  return new Uint8Array(bits);
}

class Direction {
  counter = 0n;

  constructor(key) {
    this.key = key;
  }

  iv() {
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setBigUint64(4, this.counter);
    return iv;
  }
}

/** Phone side of an established session. */
export class Channel {
  #send;
  #recv;

  constructor(sendKey, recvKey) {
    this.#send = new Direction(sendKey);
    this.#recv = new Direction(recvKey);
  }

  /** Builds the phone's channel from K_pd ‖ K_dp; wipes the key material. */
  static async fromKeyMaterial(okm) {
    const imp = (raw) => subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    const [kPd, kDp] = await Promise.all([imp(okm.slice(0, 32)), imp(okm.slice(32, 64))]);
    okm.fill(0);
    return new Channel(kPd, kDp);
  }

  /**
   * Starts a session against a device whose label public key is devicePublic.
   * Resolves to {channel, ephemeralPublic}; ephemeralPublic goes in the first
   * sealed message. `ephemeral` is injectable for test vectors.
   */
  static async initiate(devicePublic, id, nonce, ephemeral) {
    const eph = ephemeral ?? (await generateEphemeral());
    const z = await agree(eph.privateKey, devicePublic);
    const okm = await deriveKeyMaterial(z, nonce, id, eph.publicRaw, devicePublic);
    z.fill(0);
    return { channel: await Channel.fromKeyMaterial(okm), ephemeralPublic: eph.publicRaw };
  }

  async seal(plaintext) {
    const d = this.#send;
    const ct = await subtle.encrypt({ name: "AES-GCM", iv: d.iv() }, d.key, plaintext);
    d.counter += 1n;
    return new Uint8Array(ct);
  }

  /** Opens the next message; the counter advances only on success. */
  async open(ciphertext) {
    const d = this.#recv;
    let pt;
    try {
      pt = await subtle.decrypt({ name: "AES-GCM", iv: d.iv() }, d.key, ciphertext);
    } catch {
      throw new Error("decryption failed");
    }
    d.counter += 1n;
    return new Uint8Array(pt);
  }
}
