import { test } from "node:test";
import assert from "node:assert/strict";
import * as history from "../configurator/history.js";

test("CSV escapes quotes, commas, newlines and spreadsheet formulas", () => {
  const csv = history.toCsv([
    { device_id: "4F2A-9C11-B03E", provisioned_at: "2026-10-08T10:00:00.000Z", ssid: 'Ward "B", 2nd', result: "online", ip: "10.0.0.5", room: "=HYPERLINK(\"x\")" },
    { device_id: "AAAA-BBBB-CCCC", provisioned_at: "2026-10-08T10:05:00.000Z", ssid: "line\nbreak", result: "failed (E-AUTH)", ip: "", room: "-5" },
  ]);
  const lines = csv.split("\r\n");
  assert.equal(lines[0], "device_id,provisioned_at,ssid,result,ip,room");
  assert.equal(lines[1], '4F2A-9C11-B03E,2026-10-08T10:00:00.000Z,"Ward ""B"", 2nd",online,10.0.0.5,"\'=HYPERLINK(""x"")"');
  assert.ok(csv.includes('"line\nbreak"'));
  assert.ok(csv.includes(",'-5\r\n"));
  assert.ok(csv.endsWith("\r\n"));
});

test("stores records and survives broken storage", () => {
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, val) => store.set(k, val),
  };
  history.clear();
  history.add({ device_id: "X", ssid: "roy", result: "online", ip: "1.2.3.4", room: "" });
  assert.equal(history.load().length, 1);
  assert.ok(!JSON.stringify(history.load()).includes("psk"));
  store.set("teton.provisioned.v1", "{not json");
  assert.deepEqual(history.load(), []);
  globalThis.localStorage = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } };
  assert.deepEqual(history.load(), []);
  assert.doesNotThrow(() => history.add({ device_id: "Y" }));
  delete globalThis.localStorage;
});

test("filename is timestamped", () => {
  assert.equal(history.csvFilename(new Date(2026, 9, 8, 9, 5)), "teton-provisioned-20261008-0905.csv");
});
