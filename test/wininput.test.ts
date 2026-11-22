import { describe, it, expect } from 'vitest';
import { VK, packLParam, unpackPoint, hotkey, typeText } from '../src/transports/wininput.js';
import { bgraToPng, type WindowShot } from '../src/transports/winsnapshot.js';
import { ControlError } from '../src/errors.js';
import { inflateSync } from 'node:zlib';

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

const VK_EXPECT: Record<string, number> = {
  ENTER: 0x0d, ESC: 0x1b, TAB: 0x09, BACKSPACE: 0x08, SPACE: 0x20,
  LEFT: 0x25, UP: 0x26, RIGHT: 0x27, DOWN: 0x28, HOME: 0x24, END: 0x23,
  PAGEUP: 0x21, PAGEDOWN: 0x22,
  F1: 0x70, F2: 0x71, F3: 0x72, F4: 0x73, F5: 0x74, F6: 0x75,
  F7: 0x76, F8: 0x77, F9: 0x78, F10: 0x79, F11: 0x7a, F12: 0x7b,
  CTRL: 0x11, ALT: 0x12, SHIFT: 0x10, WIN: 0x5b,
  DELETE: 0x2e, INSERT: 0x2d,
  // Letters and digits are keyed by the character itself; their VK code is the
  // ASCII/UTF-16 char code. Spelled out here so the exact-table check below stays
  // a real check on the generated entries rather than a restatement of the loop.
  A: 0x41, B: 0x42, C: 0x43, D: 0x44, E: 0x45, F: 0x46, G: 0x47, H: 0x48,
  I: 0x49, J: 0x4a, K: 0x4b, L: 0x4c, M: 0x4d, N: 0x4e, O: 0x4f, P: 0x50,
  Q: 0x51, R: 0x52, S: 0x53, T: 0x54, U: 0x55, V: 0x56, W: 0x57, X: 0x58,
  Y: 0x59, Z: 0x5a,
  '0': 0x30, '1': 0x31, '2': 0x32, '3': 0x33, '4': 0x34,
  '5': 0x35, '6': 0x36, '7': 0x37, '8': 0x38, '9': 0x39,
};

// The refusal helper: the guard must fire before any FFI call, so these stay headless.
function refusing(fn: () => void): ControlError {
  try {
    fn();
  } catch (caught) {
    if (caught instanceof ControlError) return caught;
    throw caught;
  }
  throw new Error('expected a ControlError');
}

function parseChunk(png: Buffer, at: number): { type: string; data: Buffer; crc: number; next: number } {
  const len = png.readUInt32BE(at);
  return {
    type: png.toString('ascii', at + 4, at + 8),
    data: png.subarray(at + 8, at + 8 + len),
    crc: png.readUInt32BE(at + 8 + len),
    next: at + 12 + len,
  };
}

function crc32(buf: Buffer): number {
  let table: Uint32Array | null = null;
  if (!table) {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c;
    }
    table = t;
  }
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

describe('packLParam / unpackPoint', () => {
  it('packs y in the high word and x in the low word', () => {
    expect(packLParam(300, 400)).toBe(((400 << 16) | 300) | 0);
    expect(packLParam(0x1234, 0x5678)).toBe(((0x5678 << 16) | 0x1234) | 0);
    expect(packLParam(0, 0)).toBe(0);
  });

  it('masks coordinates wider than 16 bits', () => {
    expect(packLParam(0x12345, 0x67890)).toBe(packLParam(0x2345, 0x7890));
  });

  it('round-trips through the signed int32', () => {
    for (const [x, y] of [[0, 0], [1, 1], [300, 400], [65535, 65535], [0, 65535], [65535, 0]]) {
      expect(unpackPoint(packLParam(x, y))).toEqual({ x, y });
    }
    expect(unpackPoint(-1)).toEqual({ x: 65535, y: 65535 });
  });
});

describe('VK', () => {
  it('is exactly the agreed table', () => {
    expect(Object.fromEntries(Object.entries(VK))).toEqual(VK_EXPECT);
  });

  it('carries unique codes in the vk range', () => {
    const codes = Object.values(VK);
    expect(new Set(codes).size).toBe(codes.length);
    expect(codes.every((c) => c >= 0 && c <= 0xffff)).toBe(true);
  });

  it('names letters and digits by the character itself so Ctrl+A is expressible', () => {
    // The regression this guards: with no A-Z / 0-9 entries a caller could not name
    // Ctrl+C at all, only send a bare vk number. Derived here independently of the
    // module's own generation loop.
    for (let c = 0x41; c <= 0x5a; c++) expect(VK[String.fromCharCode(c)]).toBe(c);
    for (let d = 0x30; d <= 0x39; d++) expect(VK[String.fromCharCode(d)]).toBe(d);
    expect(VK.A).toBe(0x41);
    expect(VK.C).toBe(0x43);
    expect(VK['7']).toBe(0x37);
  });
});

describe('argument validation', () => {
  it('refuses an empty text before touching the FFI layer', () => {
    const err = refusing(() => typeText(0x1234, ''));
    expect(err.code).toBe('BAD_ARGS');
    expect(err.name).toBe('ControlError');
  });

  it('refuses a window handle of zero', () => {
    const err = refusing(() => hotkey(0, ['ctrl'], 0x41));
    expect(err.code).toBe('BAD_ARGS');
  });

  it('refuses an out-of-range vk code', () => {
    const err = refusing(() => hotkey(0x1234, ['ctrl'], 0x10000));
    expect(err.code).toBe('BAD_ARGS');
  });

  it('refuses an unknown modifier handed over from JavaScript', () => {
    const mods = ['ctrl', 'meta'] as unknown as Array<'ctrl' | 'alt' | 'shift' | 'win'>;
    const err = refusing(() => hotkey(0x1234, mods, 0x41));
    expect(err.code).toBe('BAD_ARGS');
  });
});

describe('bgraToPng', () => {
  const shot: WindowShot = {
    width: 2,
    height: 1,
    step: 4,
    bgra: Buffer.from([0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff]),
  };
  const png = bgraToPng(shot);

  it('starts with the PNG signature', () => {
    expect([...png.subarray(0, 8)]).toEqual(PNG_SIG);
  });

  it('writes an IHDR that describes a 2x1 RGBA image', () => {
    const ihdr = parseChunk(png, 8);
    expect(ihdr.type).toBe('IHDR');
    expect(ihdr.data).toHaveLength(13);
    expect(ihdr.data.readUInt32BE(0)).toBe(2);
    expect(ihdr.data.readUInt32BE(4)).toBe(1);
    expect(ihdr.data[8]).toBe(8);
    expect(ihdr.data[9]).toBe(6);
    expect(ihdr.data[10]).toBe(0);
    expect(ihdr.data[11]).toBe(0);
    expect(ihdr.data[12]).toBe(0);
    expect(ihdr.crc).toBe(crc32(Buffer.concat([Buffer.from('IHDR', 'ascii'), ihdr.data])));
  });

  it('inflates IDAT to filter bytes and BGRA swapped to RGBA', () => {
    const ihdr = parseChunk(png, 8);
    const idat = parseChunk(png, ihdr.next);
    expect(idat.type).toBe('IDAT');
    expect(idat.crc).toBe(crc32(Buffer.concat([Buffer.from('IDAT', 'ascii'), idat.data])));
    const raw = inflateSync(idat.data);
    expect(raw).toHaveLength(9);
    expect(raw[0]).toBe(0);
    expect([...raw.subarray(1, 5)]).toEqual([0x00, 0x00, 0xff, 0xff]);
    expect([...raw.subarray(5, 9)]).toEqual([0x00, 0xff, 0x00, 0xff]);
  });

  it('ends with an empty IEND at the exact end of the buffer', () => {
    const ihdr = parseChunk(png, 8);
    const idat = parseChunk(png, ihdr.next);
    const iend = parseChunk(png, idat.next);
    expect(iend.type).toBe('IEND');
    expect(iend.data).toHaveLength(0);
    expect(iend.next).toBe(png.length);
  });

  it('keeps every pixel of a 3x2 image at its position', () => {
    const w = 3;
    const h = 2;
    const step = 5;
    const bgra = Buffer.alloc(h * w * step);
    for (let i = 0; i < w * h; i++) {
      bgra[i * step] = (i * 13) & 0xff;
      bgra[i * step + 1] = (i * 47 + 91) & 0xff;
      bgra[i * step + 2] = (i * 101 + 7) & 0xff;
      bgra[i * step + 3] = 0xff;
    }
    const image = bgraToPng({ width: w, height: h, step, bgra });
    let at = 8;
    let pixels: Buffer | null = null;
    while (at < image.length) {
      const c = parseChunk(image, at);
      expect(c.crc).toBe(crc32(Buffer.concat([Buffer.from(c.type, 'ascii'), c.data])));
      if (c.type === 'IDAT') {
        const raw = inflateSync(c.data);
        pixels = Buffer.alloc(w * h * 4);
        for (let y = 0; y < h; y++) {
          expect(raw[y * (w * 4 + 1)]).toBe(0);
          raw.copy(pixels, y * w * 4, y * (w * 4 + 1) + 1, y * (w * 4 + 1) + 1 + w * 4);
        }
      }
      at = c.next;
    }
    if (pixels === null) throw new Error('no IDAT chunk found');
    for (let i = 0; i < w * h; i++) {
      expect([...pixels.subarray(i * 4, i * 4 + 4)]).toEqual([
        bgra[i * step + 2],
        bgra[i * step + 1],
        bgra[i * step],
        0xff,
      ]);
    }
  });
});
