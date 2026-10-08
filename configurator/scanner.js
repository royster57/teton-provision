// Label scanning with the rear camera and Chrome's built-in BarcodeDetector.

export function scannerAvailable() {
  return "BarcodeDetector" in globalThis && !!navigator.mediaDevices?.getUserMedia;
}

/**
 * Streams the camera into `video` until a QR code is read. Resolves to its
 * text; `signal` (AbortSignal) stops scanning.
 */
export async function scanQr(video, signal) {
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: "environment" } },
    audio: false,
  });
  const stop = () => stream.getTracks().forEach((t) => t.stop());
  signal?.addEventListener("abort", stop);
  try {
    video.srcObject = stream;
    await video.play();
    while (!signal?.aborted) {
      const codes = await detector.detect(video).catch(() => []);
      if (codes.length) return codes[0].rawValue;
      await new Promise((r) => setTimeout(r, 150));
    }
    throw new DOMException("Scan cancelled", "AbortError");
  } finally {
    stop();
    video.srcObject = null;
  }
}
