// Offline support: precache the whole app, serve it cache-first.
// VERSION is replaced with the commit SHA when deployed (.github/workflows/pages.yml).

const VERSION = "dev";
const CACHE = `teton-setup-${VERSION}`;
const ASSETS = [
  "./",
  "index.html",
  "style.css",
  "app.js",
  "ble.js",
  "crypto.js",
  "history.js",
  "protocol.js",
  "scanner.js",
  "session.js",
  "manifest.webmanifest",
  "icons/icon.svg",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "icons/icon-maskable-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("teton-setup-") && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return;
  event.respondWith(
    (async () => {
      const hit = await caches.match(req, { ignoreSearch: true });
      if (hit) return hit;
      // Label links open the app's root URL with a #fragment; serve the cached page.
      if (req.mode === "navigate") {
        const page = await caches.match("./");
        if (page) return page;
      }
      return fetch(req);
    })(),
  );
});
