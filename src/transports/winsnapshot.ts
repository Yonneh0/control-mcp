import koffi from 'koffi';
import { ControlError } from '../errors.js';
import { deflateSync } from 'node:zlib';

export interface WindowShot {
  width: number;
  height: number;
  step: number;
  bgra: Buffer;
}

let api: Record<string, any> | null = null;

// user32 and gdi32 are loaded on first use so importing this module never touches the FFI layer.
function ensureLoaded(): Record<string, any> {
  if (!api) {
    const u = koffi.load('user32.dll');
    const g = koffi.load('gdi32.dll');
    api = {
      GetWindowRect: u.func('int32 GetWindowRect(void*, void*)'),
      PrintWindow: u.func('bool PrintWindow(void*, void*, uint32_t)'),
      // gdi32.dll on this build does NOT export GetDC/ReleaseDC — binding them throws
      // "Cannot find function 'GetDC'". CreateCompatibleDC(NULL) is the verified path.
      CreateCompatibleDC: g.func('void* CreateCompatibleDC(void*)'),
      CreateCompatibleBitmap: g.func('void* CreateCompatibleBitmap(void*, int32_t, int32_t)'),
      SelectObject: g.func('void* SelectObject(void*, void*)'),
      DeleteObject: g.func('int32 DeleteObject(void*)'),
      DeleteDC: g.func('int32 DeleteDC(void*)'),
      // Real GDI signature has exactly 7 parameters (hdc, hbmp, uStartScan, cScanLines,
      // lpvBits, lpbi, uUsage); an 8-parameter declaration makes koffi reject the call.
      GetDIBits: g.func('int32 GetDIBits(void*, void*, uint32_t, uint32_t, void*, void*, uint32_t)'),
    };
  }
  return api;
}

export function captureWindow(hwnd: number): WindowShot {
  if (!Number.isInteger(hwnd) || hwnd < 1 || hwnd > 0xffffffff) {
    throw new ControlError('BAD_ARGS', 'invalid window handle: hwnd must be an integer in 1..0xffffffff', { hwnd }, 'Re-enumerate windows and pass a live handle.');
  }
  const a = ensureLoaded();
  const rect = Buffer.alloc(16);
  if (!a.GetWindowRect(hwnd, rect)) {
    throw new ControlError('REMOTE_ERROR', 'GetWindowRect failed: the window handle is stale or the window was destroyed', { hwnd }, 'Re-enumerate windows and retry with a current handle.');
  }
  const x = rect.readInt32LE(0);
  const y = rect.readInt32LE(4);
  const width = rect.readInt32LE(8) - x;
  const height = rect.readInt32LE(12) - y;
  if (width <= 0 || height <= 0) {
    throw new ControlError('REMOTE_ERROR', 'window has zero size: the window is likely minimized or hidden', { hwnd, width, height }, 'Restore or unhide the window, then retry the capture.');
  }
  let memDc: bigint | number = 0;
  let bmp: bigint | number = 0;
  let oldBmp: bigint | number = 0;
  try {
    // This gdi32 build has no GetDC/ReleaseDC, so there is no screen DC to derive from
    // or release; CreateCompatibleDC(NULL) returns a display-compatible memory DC (verified).
    memDc = a.CreateCompatibleDC(null);
    if (!memDc) throw new ControlError('REMOTE_ERROR', 'CreateCompatibleDC(NULL) failed: no display DC is available to this process', { hwnd }, 'Run the capture from an interactive desktop session (not a detached service) and retry.');
    bmp = a.CreateCompatibleBitmap(memDc, width, height);
    if (!bmp) throw new ControlError('REMOTE_ERROR', 'CreateCompatibleBitmap failed: GDI could not allocate the capture surface', { hwnd, width, height }, 'Shrink the window or free GDI resources, then retry.');
    oldBmp = a.SelectObject(memDc, bmp);
    // PW_RENDERFULLCONTENT (2) first: DWM-composited windows (incl. mstsc AxHost) need it;
    // plain 0 is the fallback for legacy windows that refuse the flag.
    if (!a.PrintWindow(hwnd, memDc, 2) && !a.PrintWindow(hwnd, memDc, 0)) {
      throw new ControlError('REMOTE_ERROR', 'PrintWindow failed with both PW_RENDERFULLCONTENT and the plain flag: the window refuses to render its contents', { hwnd }, 'Make sure the window is visible and not cloaked (e.g. a UAC secure-desktop dialog cannot be captured).');
    }
    // BITMAPINFOHEADER, built by hand: planes and bit count share the dword at offset 12.
    // Negative height gives top-down rows so buffer row 0 is the window's top edge.
    const bmi = Buffer.alloc(40);
    bmi.writeUInt32LE(40, 0);
    bmi.writeUInt32LE(width, 4);
    bmi.writeInt32LE(-height, 8);
    bmi.writeUInt16LE(1, 12);
    bmi.writeUInt16LE(32, 14);
    const bgra = Buffer.alloc(width * height * 4);
    // GDI signature: (hdc, hbmp, uStartScan, cScanLines, lpvBits, lpbi, uUsage).
    if (!a.GetDIBits(memDc, bmp, 0, height, bgra, bmi, 0)) {
      throw new ControlError('REMOTE_ERROR', 'GetDIBits failed: GDI could not read the bitmap bits from the memory DC', { hwnd, width, height }, 'Check that the target window still exists and retry; if it persists, verify the 32bpp BITMAPINFOHEADER path.');
    }
    return { width, height, step: 4, bgra };
  } finally {
    // Verified cleanup order: DeleteObject(bmp) FIRST while bmp is still selected into
    // memDc (deleting after un-selecting leaks it), then restore the previous bitmap,
    // then destroy the DC. There is no screen DC to release on this gdi32 build.
    if (bmp) a.DeleteObject(bmp);
    if (memDc && oldBmp) a.SelectObject(memDc, oldBmp);
    if (memDc) a.DeleteDC(memDc);
  }
}

let crcTable: Uint32Array | null = null;

function crc32(buf: Buffer): number {
  if (!crcTable) {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c;
    }
    crcTable = t;
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const typeBuf = Buffer.from(type, 'ascii');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

export function bgraToPng(shot: WindowShot): Buffer {
  const { width, height, step, bgra } = shot;
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
    throw new ControlError('BAD_ARGS', 'invalid dimensions: width and height must be > 0 (a 0x0 PNG is invalid)', { width, height }, 'Capture a window with a non-zero client area first; captureWindow rejects zero-size windows for the same reason.');
  }
  if (!Number.isInteger(step) || step < 4) throw new ControlError('BAD_ARGS', 'invalid step: need at least 4 bytes per pixel (BGRA)', { step }, 'Pass a 32bpp BGRA buffer as produced by captureWindow.');
  if (bgra.length < height * width * step) {
    throw new ControlError('BAD_ARGS', 'pixel buffer too short: bgra is smaller than height * width * step', { need: height * width * step, got: bgra.length }, 'Pass a full-frame buffer, not a partial or clipped one.');
  }
  const raw = Buffer.alloc(height * (width * 4 + 1));
  let at = 0;
  for (let y = 0; y < height; y++) {
    raw[at++] = 0;
    const row = bgra.subarray(y * width * step, y * width * step + width * step);
    for (let i = 0; i < width; i++) {
      raw[at++] = row[i * step + 2];
      raw[at++] = row[i * step + 1];
      raw[at++] = row[i * step];
      // GDI leaves the BGRA alpha byte at 0x00 (measured max alpha = 0 on real
      // PrintWindow captures), so force 0xFF: alpha 0 makes the PNG fully
      // transparent and invisible in every viewer.
      raw[at++] = 0xff;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

export function captureWindowPng(hwnd: number): Buffer {
  return bgraToPng(captureWindow(hwnd));
}
