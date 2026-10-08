import { test } from "node:test";
import assert from "node:assert/strict";
import { chunk, FrameError, hex, MAX_MESSAGE_LEN, Reassembler } from "../configurator/protocol.js";
import { unhex, vectors } from "./helpers.mjs";

test("chunking matches vectors and reassembles", () => {
  for (const f of vectors.framing) {
    const msg = new TextEncoder().encode(f.message);
    const chunks = chunk(msg, f.max_chunk_len);
    assert.deepEqual(chunks.map(hex), f.chunks);
    const r = new Reassembler();
    const out = f.chunks.map((c) => r.push(unhex(c))).filter(Boolean);
    assert.deepEqual(out, [msg]);
  }
});

test("round trip over many sizes", () => {
  for (const len of [0, 1, 18, 19, 20, 500, MAX_MESSAGE_LEN]) {
    for (const max of [2, 20, 244, 514]) {
      const msg = crypto.getRandomValues(new Uint8Array(len));
      const r = new Reassembler();
      const out = chunk(msg, max).map((c) => r.push(c)).filter(Boolean);
      assert.deepEqual(out, [msg], `len=${len} max=${max}`);
    }
  }
});

test("rejects out-of-order, empty and oversize input; error resets state", () => {
  const r = new Reassembler();
  assert.throws(() => r.push(Uint8Array.of(0x05, 1)), FrameError);
  assert.deepEqual(r.push(Uint8Array.of(0x80, 9)), Uint8Array.of(9));
  assert.throws(() => r.push(new Uint8Array()), FrameError);
  assert.throws(() => chunk(new Uint8Array(MAX_MESSAGE_LEN + 1), 20), FrameError);
  assert.throws(() => chunk(Uint8Array.of(1), 1), FrameError);
});
