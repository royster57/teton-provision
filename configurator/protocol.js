// Teton provisioning protocol v1: encoding helpers, framing and label parsing
// (SPEC.md §3, §4). Runs in the browser and in Node (tests).

export const PROTOCOL_VERSION = 1;

export const GATT = Object.freeze({
  SERVICE: "a08f8d5d-8e67-44f2-89d9-59299eab3f49",
  RX: "4b11a607-2abe-4fc6-9b03-e62677c327fe", // phone → device, write
  TX: "d5c6dde2-10f8-435c-90cb-c1e003a5550c", // device → phone, notify
});

export const PUBLIC_KEY_LEN = 65;
export const ID_LEN = 12;
export const MAX_MESSAGE_LEN = 4096;

const FINAL = 0x80;
const INDEX_MASK = 0x7f;

// ------------------------------------------------------------------ encoding

export function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder("utf-8", { fatal: true });

export function encodeMessage(obj) {
  return utf8.encode(JSON.stringify(obj));
}

export function decodeMessage(bytes) {
  const msg = JSON.parse(fromUtf8.decode(bytes));
  if (typeof msg !== "object" || msg === null || typeof msg.t !== "string") {
    throw new Error("message without type");
  }
  return msg;
}

// ------------------------------------------------------------------ framing

export class FrameError extends Error {}

/** Splits a message into chunks of at most maxChunkLen bytes (header included). */
export function chunk(msg, maxChunkLen) {
  if (maxChunkLen < 2) throw new FrameError("chunk size must be at least 2 bytes");
  if (msg.length > MAX_MESSAGE_LEN) throw new FrameError("message too large");
  const payload = maxChunkLen - 1;
  const count = Math.max(1, Math.ceil(msg.length / payload));
  const chunks = [];
  for (let i = 0; i < count; i++) {
    const part = msg.subarray(i * payload, (i + 1) * payload);
    const c = new Uint8Array(part.length + 1);
    c[0] = (i % 128) | (i === count - 1 ? FINAL : 0);
    c.set(part, 1);
    chunks.push(c);
  }
  return chunks;
}

/** Reassembles chunks; push() returns the message on its final chunk, else null. */
export class Reassembler {
  #parts = [];
  #len = 0;
  #next = 0;

  push(chunk) {
    try {
      return this.#push(chunk);
    } catch (e) {
      this.#parts = [];
      this.#len = 0;
      this.#next = 0;
      throw e;
    }
  }

  #push(chunk) {
    if (chunk.length === 0) throw new FrameError("empty chunk");
    const index = chunk[0] & INDEX_MASK;
    if (index !== this.#next) {
      throw new FrameError(`chunk index ${index}, expected ${this.#next}`);
    }
    const payload = chunk.subarray(1);
    if (this.#len + payload.length > MAX_MESSAGE_LEN) throw new FrameError("message too large");
    this.#parts.push(payload.slice());
    this.#len += payload.length;
    if (chunk[0] & FINAL) {
      const msg = concat(...this.#parts);
      this.#parts = [];
      this.#len = 0;
      this.#next = 0;
      return msg;
    }
    this.#next = (this.#next + 1) & INDEX_MASK;
    return null;
  }
}

// ------------------------------------------------------------------ label

export class LabelError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/** hex(SHA-256(pk)[0..6]), uppercase. */
export async function deviceId(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  return hex(digest.subarray(0, ID_LEN / 2)).toUpperCase();
}

/** 4F2A9C11B03E → 4F2A-9C11-B03E */
export function formatId(id) {
  return id.match(/.{1,4}/g)?.join("-") ?? "";
}

/**
 * Parses and validates a label URL: version, a P-256 public key that is on
 * the curve, and an ID that matches the key. Resolves to {id, publicKey}.
 */
export async function parseLabelUrl(url) {
  const hashAt = url.indexOf("#");
  if (hashAt < 0) throw new LabelError("missing_fragment", "Not a Teton device label.");
  const params = new Map();
  for (const kv of url.slice(hashAt + 1).split("&")) {
    const eq = kv.indexOf("=");
    if (eq > 0 && !params.has(kv.slice(0, eq))) params.set(kv.slice(0, eq), kv.slice(eq + 1));
  }
  const param = (name) => {
    if (!params.has(name)) throw new LabelError("missing_param", `Label is missing "${name}".`);
    return params.get(name);
  };
  if (param("v") !== String(PROTOCOL_VERSION)) {
    throw new LabelError("unsupported_version", "This label needs a newer version of the app.");
  }
  const id = param("id");
  const pk = param("pk");
  let publicKey;
  try {
    publicKey = b64urlDecode(pk);
  } catch {
    throw new LabelError("bad_public_key", "The label is damaged or not a Teton label.");
  }
  if (publicKey.length !== PUBLIC_KEY_LEN || publicKey[0] !== 0x04) {
    throw new LabelError("bad_public_key", "The label is damaged or not a Teton label.");
  }
  try {
    // Import rejects points that are not on the curve.
    await crypto.subtle.importKey("raw", publicKey, { name: "ECDH", namedCurve: "P-256" }, true, []);
  } catch {
    throw new LabelError("bad_public_key", "The label is damaged or not a Teton label.");
  }
  if ((await deviceId(publicKey)) !== id) {
    throw new LabelError("id_mismatch", "The label is damaged or misprinted (ID does not match).");
  }
  return { id, publicKey };
}
