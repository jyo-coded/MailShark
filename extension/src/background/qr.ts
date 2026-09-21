// QR-code decoding for image attachments ("quishing"). Images are decoded to pixels offscreen and
// scanned with jsQR; nothing is displayed or uploaded.
import jsQR from 'jsqr';
import type { QrDecoder } from '../../../engine/src/types';

const MAX_SIDE = 1600;

async function toImageData(bytes: Uint8Array, mime: string): Promise<ImageData | null> {
  if (typeof createImageBitmap !== 'function') return null;
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const bitmap = await createImageBitmap(new Blob([copy.buffer], { type: mime }));
  try {
    const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
    const w = Math.max(1, Math.round(bitmap.width * scale));
    const h = Math.max(1, Math.round(bitmap.height * scale));
    if (w < 21 || h < 21) return null;
    if (typeof OffscreenCanvas !== 'undefined') {
      const canvas = new OffscreenCanvas(w, h);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return null;
      ctx.drawImage(bitmap, 0, 0, w, h);
      return ctx.getImageData(0, 0, w, h);
    }
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return null;
    ctx.drawImage(bitmap, 0, 0, w, h);
    return ctx.getImageData(0, 0, w, h);
  } finally {
    bitmap.close();
  }
}

export const qrDecoder: QrDecoder = async (bytes, mime) => {
  try {
    const img = await toImageData(bytes, mime);
    if (!img) return null;
    const hit = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
    return hit?.data?.trim() || null;
  } catch {
    return null;
  }
};
