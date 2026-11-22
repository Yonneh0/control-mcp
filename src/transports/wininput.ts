import koffi from 'koffi';
import { ControlError } from '../errors.js';

export interface WindowInfo {
  hwnd: number;
  title: string;
  className: string;
  x: number;
  y: number;
  width: number;
  height: number;
  visible: boolean;
  enabled: boolean;
  pid: number;
}

export const VK: Record<string, number> = {
  ENTER: 0x0d,
  ESC: 0x1b,
  TAB: 0x09,
  BACKSPACE: 0x08,
  SPACE: 0x20,
  LEFT: 0x25,
  UP: 0x26,
  RIGHT: 0x27,
  DOWN: 0x28,
  HOME: 0x24,
  END: 0x23,
  PAGEUP: 0x21,
  PAGEDOWN: 0x22,
  F1: 0x70,
  F2: 0x71,
  F3: 0x72,
  F4: 0x73,
  F5: 0x74,
  F6: 0x75,
  F7: 0x76,
  F8: 0x77,
  F9: 0x78,
  F10: 0x79,
  F11: 0x7a,
  F12: 0x7b,
  CTRL: 0x11,
  ALT: 0x12,
  SHIFT: 0x10,
  WIN: 0x5b,
  DELETE: 0x2e,
  INSERT: 0x2d,
};

// Letters and digits have no mnemonic name of their own, so they are keyed by the
// character itself: the VK code of A-Z is 0x41-0x5A and of 0-9 is 0x30-0x39, which
// is exactly their char code. Without these entries a caller cannot name Ctrl+A or
// Ctrl+C at all — only send a raw number. Generated instead of spelled out so the
// table can never drift from the documented code points.
for (let c = 0x41; c <= 0x5a; c++) VK[String.fromCharCode(c)] = c;
for (let d = 0x30; d <= 0x39; d++) VK[String.fromCharCode(d)] = d;

const WM_KEYDOWN = 0x0100;
const WM_KEYUP = 0x0101;
const WM_CHAR = 0x0102;
const WM_MOUSEMOVE = 0x0200;
const WM_MOUSEWHEEL = 0x020a;

const BUTTONS: Record<string, { down: number; up: number; flag: number }> = {
  left: { down: 0x0201, up: 0x0202, flag: 0x0001 },
  right: { down: 0x0204, up: 0x0205, flag: 0x0002 },
  middle: { down: 0x0207, up: 0x0208, flag: 0x0010 },
};

const MODS: Record<string, number> = {
  ctrl: VK.CTRL,
  alt: VK.ALT,
  shift: VK.SHIFT,
  win: VK.WIN,
};

// Every message this module posts, by name. A rejected send is reported by name
// because one click or hotkey is a sequence of posts and "message 0x201 was
// refused" is only actionable as "WM_LBUTTONDOWN was refused".
const MSG_NAMES: Record<number, string> = {
  [WM_KEYDOWN]: 'WM_KEYDOWN',
  [WM_KEYUP]: 'WM_KEYUP',
  [WM_CHAR]: 'WM_CHAR',
  [WM_MOUSEMOVE]: 'WM_MOUSEMOVE',
  [WM_MOUSEWHEEL]: 'WM_MOUSEWHEEL',
  [BUTTONS.left.down]: 'WM_LBUTTONDOWN',
  [BUTTONS.left.up]: 'WM_LBUTTONUP',
  [BUTTONS.right.down]: 'WM_RBUTTONDOWN',
  [BUTTONS.right.up]: 'WM_RBUTTONUP',
  [BUTTONS.middle.down]: 'WM_MBUTTONDOWN',
  [BUTTONS.middle.up]: 'WM_MBUTTONUP',
};

function msgName(msg: number): string {
  return MSG_NAMES[msg] ?? `message 0x${msg.toString(16)}`;
}

export function packLParam(x: number, y: number): number {
  return (((y & 0xffff) << 16) | (x & 0xffff)) | 0;
}

export function unpackPoint(packed: number): { x: number; y: number } {
  const v = packed | 0;
  return { x: v & 0xffff, y: (v >> 16) & 0xffff };
}

function needHwnd(hwnd: number): void {
  if (!Number.isInteger(hwnd) || hwnd < 1 || hwnd > 0xffffffff) {
    throw new ControlError(
      'BAD_ARGS',
      `invalid window handle: got ${hwnd}, expected a nonzero 32-bit window handle (1 to 4294967295)`,
      { hwnd },
      'Take the handle from the window-list/enumeration call (rdp_connect records the RDP window; findAllWindows/listWindows return the rest) and pass it through unchanged — never construct or reuse one by hand.',
    );
  }
}

function needPoint(x: number, y: number): void {
  if (!Number.isInteger(x) || !Number.isInteger(y) || x < 0 || x > 0xffff || y < 0 || y > 0xffff) {
    throw new ControlError(
      'BAD_ARGS',
      `coordinate out of range: got x=${x} y=${y}, expected whole numbers from 0 to 65535`,
      { x, y },
      'Coordinates are relative to the window\'s client area, not the screen; read the window position and size from the window-list call and subtract its x/y, or click at the client-area offset the target control reports.',
    );
  }
}

function needVk(vk: number): void {
  if (!Number.isInteger(vk) || vk < 0 || vk > 0xffff) {
    throw new ControlError(
      'BAD_ARGS',
      `invalid virtual key code: got ${vk}, expected a whole number from 0 to 65535`,
      { vk },
      'Pass a VK name from the key table (letters A-Z and digits 0-9 are named by the character) or a numeric vk code; use the text-input tool for characters and the key tool only for control keys.',
    );
  }
}

let api: Record<string, any> | null = null;

// user32 is loaded on first use so importing this module never touches the FFI layer.
function ensureLoaded(): Record<string, any> {
  if (!api) {
    const u = koffi.load('user32.dll');
    api = {
      // EnumProc is registered before the EnumWindows prototype is parsed, so
      // the callback parameter resolves in the prototype string.
      EnumCb: koffi.pointer(koffi.proto('EnumProc', 'bool', ['void*', 'intptr_t'])),
      EnumWindows: u.func('bool EnumWindows(EnumProc*, intptr_t)'),
      GetWindowTextW: u.func('int32 GetWindowTextW(void*, void*, int32_t)'),
      GetClassNameW: u.func('int32 GetClassNameW(void*, void*, int32_t)'),
      GetWindowRect: u.func('int32 GetWindowRect(void*, void*)'),
      IsWindowVisible: u.func('bool IsWindowVisible(void*)'),
      IsWindowEnabled: u.func('bool IsWindowEnabled(void*)'),
      GetWindowThreadProcessId: u.func('uint32_t GetWindowThreadProcessId(void*, void*)'),
      FindWindowW: u.func('void* FindWindowW(void*, void*)'),
      ShowWindow: u.func('bool ShowWindow(void*, int32_t)'),
      BringWindowToTop: u.func('bool BringWindowToTop(void*)'),
      SetForegroundWindow: u.func('bool SetForegroundWindow(void*)'),
      // WPARAM/LPARAM are pointer-sized, not 32-bit: declare them uintptr_t/intptr_t
      // so koffi packs the full value on an x64 stack instead of truncating.
      PostMessageW: u.func('bool PostMessageW(void*, uintptr_t, uintptr_t, intptr_t)'),
    };
  }
  return api;
}

// Returns the PostMessageW BOOL. FALSE means the target window refused the message,
// so it is raised rather than swallowed: reporting a click that never arrived is
// worse than a failure, and the tool result must not claim success.
function post(hwnd: number, msg: number, w: number, l: number): boolean {
  const name = msgName(msg);
  const ok = ensureLoaded().PostMessageW(hwnd, msg, w, l);
  if (ok !== true) {
    throw new ControlError(
      'REMOTE_ERROR',
      `PostMessageW(${name}) returned FALSE for hwnd ${hwnd}: the window may be minimized, on a locked workstation, or ignores window messages`,
      { hwnd, message: name },
      'Restore and unlock the window (or re-run rdp_connect to get a live handle), then retry; if the target truly ignores window messages, drive it through the RDP input path instead.',
    );
  }
  return true;
}

export function listWindows(opts: { includeInvisible?: boolean } = {}): WindowInfo[] {
  const a = ensureLoaded();
  const seen: WindowInfo[] = [];
  const cb = koffi.register((hwndArg: bigint, userData: bigint) => {
    const hwnd = Number(hwndArg);
    if (!hwnd) return true;
    const visible = a.IsWindowVisible(hwnd);
    if (!visible && opts.includeInvisible !== true) return true;
    const enabled = a.IsWindowEnabled(hwnd);
    const titleBuf = Buffer.alloc(2048);
    const classBuf = Buffer.alloc(512);
    const rect = Buffer.alloc(16);
    const pidBuf = Buffer.alloc(4);
    if (!a.GetWindowRect(hwnd, rect)) return true;
    const titleLen = a.GetWindowTextW(hwnd, titleBuf, 1024);
    const classLen = a.GetClassNameW(hwnd, classBuf, 256);
    a.GetWindowThreadProcessId(hwnd, pidBuf);
    const x = rect.readInt32LE(0);
    const y = rect.readInt32LE(4);
    seen.push({
      hwnd,
      title: titleLen > 1 ? titleBuf.toString('utf16le', 0, (titleLen - 1) * 2) : '',
      className: classLen > 1 ? classBuf.toString('utf16le', 0, (classLen - 1) * 2) : '',
      x,
      y,
      width: rect.readInt32LE(8) - x,
      height: rect.readInt32LE(12) - y,
      visible: visible === true,
      enabled: enabled === true,
      pid: pidBuf.readUInt32LE(0),
    });
    return true;
  }, a.EnumCb);
  try {
    a.EnumWindows(cb, 0n);
  } finally {
    koffi.unregister(cb);
  }
  return seen;
}

export function findWindow(opts: { title?: string; className?: string }): number | null {
  const title = opts.title;
  const className = opts.className;
  if (title === undefined && className === undefined) {
    throw new ControlError('BAD_ARGS', 'no window criterion given');
  }
  const a = ensureLoaded();
  const titleArg = title === undefined ? null : Buffer.from(title + '\0', 'utf16le');
  const classArg = className === undefined ? null : Buffer.from(className + '\0', 'utf16le');
  const hwnd = a.FindWindowW(titleArg, classArg);
  if (hwnd) return Number(hwnd);
  // No silent single-criterion fallback: acting on a window that matches only
  // half of what the caller asked for is how input reaches the wrong app.
  // findAllWindows + explicit choice is the documented escape hatch.
  return null;
}

export function findAllWindows(opts: { title?: string; className?: string }): number[] {
  const title = opts.title;
  const className = opts.className;
  if (title === undefined && className === undefined) {
    throw new ControlError('BAD_ARGS', 'no window criterion given');
  }
  return listWindows({ includeInvisible: false })
    .filter((w) => (title === undefined || w.title === title) && (className === undefined || w.className === className))
    .map((w) => w.hwnd);
}

export function foreground(hwnd: number): boolean {
  needHwnd(hwnd);
  const a = ensureLoaded();
  a.ShowWindow(hwnd, 9);
  a.BringWindowToTop(hwnd);
  return a.SetForegroundWindow(hwnd);
}

export function mouseMove(hwnd: number, x: number, y: number): void {
  needHwnd(hwnd);
  needPoint(x, y);
  post(hwnd, WM_MOUSEMOVE, 0, packLParam(x, y));
}

export function mouseClick(hwnd: number, x: number, y: number, button = 'left', doubleClick = false): void {
  needHwnd(hwnd);
  needPoint(x, y);
  const b = BUTTONS[button];
  if (!b) throw new ControlError('BAD_ARGS', 'unknown button', { button });
  const l = packLParam(x, y);
  post(hwnd, WM_MOUSEMOVE, 0, l);
  post(hwnd, b.down, b.flag, l);
  post(hwnd, b.up, b.flag, l);
  if (button === 'left' && doubleClick) {
    post(hwnd, b.down, b.flag, l);
    post(hwnd, b.up, b.flag, l);
  }
}

export function mouseDrag(hwnd: number, x1: number, y1: number, x2: number, y2: number, button = 'left'): void {
  needHwnd(hwnd);
  needPoint(x1, y1);
  needPoint(x2, y2);
  const b = BUTTONS[button];
  if (!b) throw new ControlError('BAD_ARGS', 'unknown button', { button });
  post(hwnd, b.down, b.flag, packLParam(x1, y1));
  for (let i = 1; i <= 8; i++) {
    const x = x1 + Math.round(((x2 - x1) * i) / 8);
    const y = y1 + Math.round(((y2 - y1) * i) / 8);
    post(hwnd, WM_MOUSEMOVE, b.flag, packLParam(x, y));
  }
  post(hwnd, b.up, b.flag, packLParam(x2, y2));
}

// One wheel "click" is WHEEL_DELTA (120) units, carried in the HIGH WORD of wParam.
// The bound below keeps notches * 120 inside the signed 16-bit HIWORD: past that the
// delta has no valid encoding at all, and a JS int32 shift would silently wrap it
// (the old code wrapped at |notches| >= 274 and sent a wrong, sometimes opposite,
// scroll distance).
const WHEEL_DELTA = 120;
const WHEEL_MAX_NOTCHES = 250;

export function mouseWheel(hwnd: number, x: number, y: number, notches: number): void {
  needHwnd(hwnd);
  needPoint(x, y);
  if (!Number.isInteger(notches)) {
    throw new ControlError(
      'BAD_ARGS',
      `notches must be an integer: got ${notches}`,
      { notches },
      'Pass a whole number of wheel clicks — positive scrolls down, negative scrolls up; split a fractional amount into separate calls.',
    );
  }
  if (notches < -WHEEL_MAX_NOTCHES || notches > WHEEL_MAX_NOTCHES) {
    throw new ControlError(
      'BAD_ARGS',
      `notches must be between -${WHEEL_MAX_NOTCHES} and ${WHEEL_MAX_NOTCHES}: got ${notches}`,
      { notches, min: -WHEEL_MAX_NOTCHES, max: WHEEL_MAX_NOTCHES },
      `Issue several wheel calls of at most ${WHEEL_MAX_NOTCHES} notches each, or drag the scrollbar with mouseDrag instead of requesting one enormous wheel step.`,
    );
  }
  // Multiply, then widen to the HIWORD position, then drop to the unsigned 32-bit
  // wParam the API truncates to: within the clamp above the product is exact in
  // JS doubles, and >>> 0 is the same two-complement truncation Win32 performs,
  // so a negative delta reaches the app as the signed -notches*120 it asked for.
  const delta = notches * WHEEL_DELTA;
  const wParam = (delta * 0x10000) >>> 0;
  post(hwnd, WM_MOUSEWHEEL, wParam, packLParam(x, y));
}

export function keyDown(hwnd: number, vk: number): void {
  needHwnd(hwnd);
  needVk(vk);
  post(hwnd, WM_KEYDOWN, vk, 0);
}

export function keyUp(hwnd: number, vk: number): void {
  needHwnd(hwnd);
  needVk(vk);
  post(hwnd, WM_KEYUP, vk, 0);
}

export function keyPress(hwnd: number, vk: number): void {
  keyDown(hwnd, vk);
  keyUp(hwnd, vk);
}

export function typeText(hwnd: number, text: string): void {
  needHwnd(hwnd);
  if (text.length === 0) throw new ControlError('BAD_ARGS', 'empty text');
  // One WM_CHAR per code point, not per UTF-16 code unit: iterating by index would
  // deliver every astral character (emoji, Musical Symbols, CJK ext B) as two broken
  // lone surrogates that no control accepts.
  for (const ch of text) post(hwnd, WM_CHAR, ch.codePointAt(0)!, 0);
}

export function hotkey(hwnd: number, modifiers: Array<'ctrl' | 'alt' | 'shift' | 'win'>, vk: number): void {
  needHwnd(hwnd);
  needVk(vk);
  for (const m of modifiers) {
    if (!Object.hasOwn(MODS, m)) throw new ControlError('BAD_ARGS', 'unknown modifier', { modifier: m });
  }
  for (const m of modifiers) post(hwnd, WM_KEYDOWN, MODS[m], 0);
  post(hwnd, WM_KEYDOWN, vk, 0);
  post(hwnd, WM_KEYUP, vk, 0);
  for (let i = modifiers.length - 1; i >= 0; i--) post(hwnd, WM_KEYUP, MODS[modifiers[i]], 0);
}
