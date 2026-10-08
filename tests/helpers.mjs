import { readFileSync } from "node:fs";

export const vectors = JSON.parse(
  readFileSync(new URL("./test-vectors.json", import.meta.url), "utf8"),
);

export function unhex(s) {
  return Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
}
