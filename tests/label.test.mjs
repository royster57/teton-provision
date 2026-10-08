import { test } from "node:test";
import assert from "node:assert/strict";
import { formatId, hex, parseLabelUrl } from "../configurator/protocol.js";
import { vectors } from "./helpers.mjs";

test("parses the vector label", async () => {
  const { id, publicKey } = await parseLabelUrl(vectors.label.url);
  assert.equal(id, vectors.session.device_id);
  assert.equal(hex(publicKey), vectors.session.device_public);
  assert.equal(formatId(id), vectors.label.display_id);
});

test("rejects invalid labels with the shared error codes", async () => {
  for (const bad of vectors.invalid_labels) {
    await assert.rejects(parseLabelUrl(bad.url), (e) => e.code === bad.error, bad.url);
  }
});

test("rejects a point that is not on the curve", async () => {
  const pk = vectors.label.url.split("pk=")[1];
  const flipped = pk.slice(0, -2) + (pk.at(-2) === "A" ? "B" : "A") + pk.at(-1);
  await assert.rejects(parseLabelUrl(vectors.label.url.replace(pk, flipped)), (e) => e.code === "bad_public_key");
});
