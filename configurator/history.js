// "Provisioned this session" list (SPEC.md §10.2). Stored in localStorage so
// it survives a reload; it never contains a Wi-Fi password.

const KEY = "teton.provisioned.v1";
const COLUMNS = ["device_id", "provisioned_at", "ssid", "result", "ip", "room"];

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null; // blocked storage (private mode, policy)
  }
}

export function load() {
  try {
    const list = JSON.parse(storage()?.getItem(KEY) ?? "[]");
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function save(list) {
  try {
    storage()?.setItem(KEY, JSON.stringify(list));
  } catch {
    // storage full or blocked: the list still lives in memory for this page
  }
}

/** Adds {device_id, ssid, result, ip, room}; returns the new list. */
export function add(record) {
  const entry = { provisioned_at: new Date().toISOString(), ...record };
  const list = [...load(), entry];
  save(list);
  return list;
}

export function clear() {
  save([]);
}

function csvField(value) {
  let s = String(value ?? "");
  // Spreadsheets execute cells starting with these characters as formulas.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(list) {
  const rows = [COLUMNS, ...list.map((r) => COLUMNS.map((c) => r[c]))];
  return rows.map((row) => row.map(csvField).join(",")).join("\r\n") + "\r\n";
}

export function csvFilename(now = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `teton-provisioned-${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}.csv`;
}
