import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname, posix, win32 } from 'node:path';
import { ControlError } from '../errors.js';
import { resolveAdbBin, type AdbBinResolution } from './adbPath.js';

// One shared hint for every adb-missing path, so an operator is told exactly how
// to fix it rather than only that adb "is not installed".
const ADB_INSTALL_HINT =
  'install Android platform-tools and put it on PATH, or set CONTROL_MCP_ADB_PATH to the adb binary; run adb_status to see which path control-mcp resolved';

export interface AdbDevice {
  serial: string;
  state: string;
  model?: string;
}

export interface AdbProbe {
  available: boolean;
  version?: string;
  error?: string;
}

interface AdbExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
  signal: string | null;
  truncated: boolean;
  durationMs: number;
  // True when the adb binary itself could not be spawned (ENOENT). Callers map
  // this to CAPABILITY_UNAVAILABLE instead of reporting a null exit code, so a
  // missing binary is never confused with a command that ran and failed.
  missing?: boolean;
}

interface SpawnOut {
  stdout: Buffer;
  stderr: Buffer;
  code: number | null;
  signal: string | null;
  // True only when a chunk past the stdout/stderr caps was actually dropped.
  truncated: boolean;
  // Code of the captured spawn error (e.g. 'ENOENT' when adb is missing),
  // when one occurred; lets callers branch on it instead of only sniffing
  // stderr text.
  spawnErrorCode?: string;
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47];
// The device `input text` argument: only these characters can ever reach it,
// spaces are encoded as %s, and a leading '-' is refused (`input text -h` would
// be parsed as an option). Because spaces never survive the %s encoding, no
// option-like fragment (`--help`) and no shell metacharacter can become a
// separate word — anything outside this class is refused outright rather than
// quoted, so a payload like `'; rm -rf /sdcard` can neither inject nor type.
const INPUT_SAFE = /^(?!-)[A-Za-z0-9 ._-]+$/;
// Caps on captured child output; dropping a chunk past a cap sets `truncated`.
const STDOUT_CAP = 8 * 1024 * 1024;
const STDERR_CAP = 1 * 1024 * 1024;
// Grace after SIGTERM before escalating to SIGKILL and settling anyway.
const KILL_GRACE_MS = 1000;

// ---------------------------------------------------------------------------
// Device-side quoting.
//
// spawnAdb/spawnWait take an argv ARRAY, so nothing here ever passes through
// the HOST shell (cmd.exe / sh): host-side injection is not possible. The
// injection surface is the DEVICE — `adb -s X shell <cmd>` hands <cmd> verbatim
// to the device's /system/bin/sh, which word-splits and expands it. So every
// caller-supplied string that lands inside one <cmd> must be quoted FOR THAT
// SHELL, and the quoting must never be hand-rolled at the call site.
//
// quoteShellArg is the single form used for that. Single quotes are the only
// POSIX form in which every other character ($ ` \ ; & | < > ( ) newline *) is
// literal. A single quote cannot appear inside single quotes, so it is spelled
// out as '\'': close quote, escaped quote, reopen quote.
// ---------------------------------------------------------------------------
export function quoteShellArg(value: string): string {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

// Resolved adb binary, cached after the first probe so we do not re-stat the
// SDK on every call. Call sites pass the sentinel 'adb' as argv[0]; the two
// spawn helpers below swap it for the resolved path. resolveAdbBin already
// returns the bare 'adb' when nothing is found, so PATH resolution is preserved.
let cachedAdbBin: AdbBinResolution | null = null;
function adbBin(): AdbBinResolution {
  if (!cachedAdbBin) cachedAdbBin = resolveAdbBin();
  return cachedAdbBin;
}
// Exposed for adb_status: the concrete binary + how it was found + what was probed.
export function adbBinInfo(): AdbBinResolution {
  return adbBin();
}
// Test seam: force a re-resolve after changing env in a unit test.
export function resetAdbBinCache(): void {
  cachedAdbBin = null;
}

function asError(err: unknown): Error {
  if (err instanceof Error) return err;
  return new Error(String(err));
}

function errCodeOf(err: Error): string {
  const code = (err as { code?: unknown }).code;
  return typeof code === 'string' ? code : '';
}

function isTimeoutError(err: Error): boolean {
  const code = errCodeOf(err);
  return code === 'ETIMESPAWNED' || code === 'ETIMEDOUT' || /timed out/i.test(err.message);
}

function decodeText(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString();
}

// Only argv arrays with typed options: payloads never pass through cmd.exe.
// A timeout kills the child with SIGTERM; if it ignores SIGTERM we escalate to
// SIGKILL after a short grace and settle anyway, so the call always finishes.
// Partial output is kept rather than lost, and `truncated` reports whether any
// output beyond the caps below was actually dropped.
function spawnAdb(argv: string[], timeoutMs: number): Promise<{ out: SpawnOut; durationMs: number }> {
  const started = Date.now();
  return new Promise((resolve) => {
    const cmd = argv[0] === 'adb' ? adbBin().bin : argv[0];
    const child = spawn(cmd, argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
    const chunksOut: Buffer[] = [];
    const chunksErr: Buffer[] = [];
    let stdoutLen = 0;
    let stderrLen = 0;
    let stdoutTruncated = false;
    let stderrTruncated = false;
    let settled = false;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | undefined;
    child.stdout.on('data', (d: Buffer) => {
      if (stdoutLen < STDOUT_CAP) {
        chunksOut.push(d);
        stdoutLen += d.length;
      } else {
        stdoutTruncated = true;
      }
    });
    child.stderr.on('data', (d: Buffer) => {
      if (stderrLen < STDERR_CAP) {
        chunksErr.push(d);
        stderrLen += d.length;
      } else {
        stderrTruncated = true;
      }
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => {
        // adb ignored SIGTERM: force-kill and settle with the timed-out/signal
        // result even if 'close' never fires; finish() clears this timer.
        child.kill('SIGKILL');
        finish(null, 'SIGKILL');
      }, KILL_GRACE_MS);
    }, timeoutMs);
    let spawnError: Error | null = null;
    const finish = (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      // Claim SIGTERM only when the kill actually landed on a live child; a
      // natural exit just before the timer must report its real code.
      const killedByUs = timedOut && signal === 'SIGTERM';
      resolve({
        out: {
          stdout: Buffer.concat(chunksOut),
          stderr: spawnError ? Buffer.concat([...chunksErr, Buffer.from(`\n${spawnError.message}`)]) : Buffer.concat(chunksErr),
          code,
          signal: killedByUs ? 'SIGTERM' : signal,
          truncated: stdoutTruncated || stderrTruncated,
          // Expose the captured spawn error code (e.g. 'ENOENT') so callers
          // can branch on it instead of only sniffing stderr text.
          spawnErrorCode: spawnError ? errCodeOf(spawnError) || undefined : undefined,
        },
        durationMs: Date.now() - started,
      });
    };
    child.once('error', (err) => {
      spawnError = err;
      finish(null, null);
    });
    child.once('close', () => finish(child.exitCode, child.signalCode));
  });
}

function asAdbError(err: Error, op: string): ControlError {
  if (errCodeOf(err) === 'ENOENT') {
    return new ControlError('CAPABILITY_UNAVAILABLE', `adb not installed: ${op}`, { op }, ADB_INSTALL_HINT);
  }
  if (isTimeoutError(err)) {
    return new ControlError('TIMEOUT', `${op} timed out`, { op });
  }
  return new ControlError('REMOTE_ERROR', `${op} failed: ${err.message}`, { op });
}

// Shared handling for code === null: the child never exited cleanly (a spawn
// failure such as ENOENT, or a kill). Prefer the captured spawn error code and
// fall back to the stderr sniff only when no code was captured, so missing-adb
// detection does not depend on the string match alone.
function noExitCodeError(op: string, serial: string, out: SpawnOut): ControlError {
  const why = decodeText(out.stderr).trim();
  const missing =
    out.spawnErrorCode === 'ENOENT' ||
    (out.spawnErrorCode === undefined && why.includes('ENOENT'));
  return new ControlError(
    missing ? 'CAPABILITY_UNAVAILABLE' : 'REMOTE_ERROR',
    `${op} did not complete: ${why || 'adb process died without an exit code'}`,
    { serial, op },
    missing ? ADB_INSTALL_HINT : undefined,
  );
}

function needSerial(serial: string): string {
  if (typeof serial !== 'string') {
    throw new ControlError('BAD_ARGS', 'adb serial must be a string', { received: typeof serial });
  }
  const trimmed = serial.trim();
  if (trimmed === '') throw new ControlError('BAD_ARGS', 'empty adb serial');
  // A leading '-' would let callers smuggle adb flags such as --killserver
  // through the serial slot of `adb -s <serial> ...`.
  if (trimmed.startsWith('-')) {
    throw new ControlError('BAD_ARGS', 'adb serial must not start with "-" (flags such as --killserver are refused)', { serial: trimmed });
  }
  return trimmed;
}

export async function adbAvailable(timeoutMs = 5000): Promise<AdbProbe> {
  const { out } = await spawnAdb(['adb', 'version'], timeoutMs);
  if (out.code !== 0) {
    const reason = decodeText(out.stderr).trim();
    return { available: false, error: `adb version failed: ${reason || 'no version output'}` };
  }
  const version = decodeText(out.stdout).trim();
  return { available: true, version: version === '' ? undefined : version };
}

export async function listDevices(timeoutMs = 15000): Promise<AdbDevice[]> {
  const { out } = await spawnAdb(['adb', 'devices', '-l'], timeoutMs);
  const devices: AdbDevice[] = [];
  for (const rawLine of decodeText(out.stdout).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const first = parts[0];
    if (first === 'List' || first === 'Session' || first === 'adb') continue;
    const device: AdbDevice = { serial: first, state: parts[1] };
    const model = /model:\s*([A-Za-z0-9._-]+)/.exec(line);
    if (model) device.model = model[1];
    devices.push(device);
  }
  return devices;
}

export async function adbExec(
  serial: string,
  command: string,
  timeoutMs = 15000,
): Promise<AdbExecResult> {
  serial = needSerial(serial);
  const started = Date.now();
  const { out, durationMs } = await spawnAdb(['adb', '-s', serial, 'shell', command], timeoutMs);
  return {
    stdout: decodeText(out.stdout),
    stderr: decodeText(out.stderr),
    code: out.code,
    signal: out.signal,
    truncated: out.truncated,
    durationMs,
    missing: out.code === null && out.spawnErrorCode === 'ENOENT',
  };
}

export async function screencapPng(serial: string, timeoutMs = 15000): Promise<Buffer> {
  serial = needSerial(serial);
  const { out } = await spawnAdb(['adb', '-s', serial, 'exec-out', 'screencap', '-p'], timeoutMs);
  // code === null means adb never exited (spawn failure such as ENOENT, or a
  // kill); report that honestly instead of falling through to "no image data".
  if (out.code === null) {
    throw noExitCodeError('screencap', serial, out);
  }
  if (out.code !== 0) {
    throw new ControlError('REMOTE_ERROR', `screencap failed: exit ${out.code} ${decodeText(out.stderr).trim()}`, { serial });
  }
  const bytes = Buffer.from(out.stdout);
  if (bytes.length < 4) {
    throw new ControlError('REMOTE_ERROR', `screencap returned no image data (${bytes.length} bytes)`, { serial });
  }
  const head = [bytes[0], bytes[1], bytes[2], bytes[3]];
  if (head[0] !== PNG_SIGNATURE[0] || head[1] !== PNG_SIGNATURE[1] || head[2] !== PNG_SIGNATURE[2] || head[3] !== PNG_SIGNATURE[3]) {
    throw new ControlError(
      'REMOTE_ERROR',
      'screencap output is not a PNG stream',
      { serial, head: head.join(',') },
    );
  }
  // A capture killed mid-stream or clipped by the size cap still starts with
  // the signature; require the trailing IEND chunk so we never hand back an
  // unopenable file as success.
  if (out.signal !== null || !hasIendTail(bytes)) {
    const capNote = out.truncated ? ' (local output cap reached; stdout/stderr were clipped)' : '';
    throw new ControlError('REMOTE_ERROR', `screencap output is truncated (no IEND chunk); the capture did not complete${capNote}`, { serial, bytes: bytes.length, truncated: out.truncated });
  }
  return bytes;
}

function hasIendTail(bytes: Buffer): boolean {
  // IEND = length(00000000) 'IEND' CRC(ae426082); check the last 12 bytes.
  if (bytes.length < 12) return false;
  const t = bytes.subarray(bytes.length - 12);
  return t.readUInt32BE(0) === 0 && t[4] === 0x49 && t[5] === 0x45 && t[6] === 0x4e && t[7] === 0x44 && t.readUInt32BE(8) === 0xae426082;
}

function needCoordinates(name: string, values: number[]): void {
  // Mirror the public schema bound: 0..65535.
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 65535) {
      throw new ControlError('BAD_ARGS', `invalid ${name} coordinate: ${value} is outside the allowed range 0..65535`, { value });
    }
  }
}

function needDuration(durationMs: number): void {
  // Mirror the public adb_swipe schema bound (1..60000). An unbounded value is
  // not a typo we can honour: the device keeps swiping long after the local adb
  // client has been killed at timeoutMs, so the refusal belongs here.
  if (!Number.isSafeInteger(durationMs) || durationMs < 1 || durationMs > 60000) {
    throw new ControlError('BAD_ARGS', `invalid swipe duration: ${durationMs} is outside the allowed range 1..60000`, { durationMs });
  }
}

export async function inputTap(
  serial: string,
  x: number,
  y: number,
  timeoutMs = 15000,
): Promise<void> {
  serial = needSerial(serial);
  needCoordinates('tap', [x, y]);
  await runInput(serial, `input tap ${x} ${y}`, 'input tap', timeoutMs);
}

export async function inputSwipe(
  serial: string,
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  durationMs: number,
  timeoutMs = 15000,
): Promise<void> {
  serial = needSerial(serial);
  needCoordinates('swipe', [x1, y1, x2, y2]);
  needDuration(durationMs);
  await runInput(
    serial,
    `input swipe ${x1} ${y1} ${x2} ${y2} ${durationMs}`,
    'input swipe',
    timeoutMs,
  );
}

export async function inputText(serial: string, text: string, timeoutMs = 15000): Promise<void> {
  serial = needSerial(serial);
  if (text === '') throw new ControlError('BAD_ARGS', 'empty input text');
  if (!INPUT_SAFE.test(text)) {
    throw new ControlError(
      'BAD_ARGS',
      'input text must stay within [A-Za-z0-9 ._-]; control characters are refused',
      { text },
      'special characters cannot be typed by `input text` safely: send them with adb_key (e.g. delete, tab) or omit them',
    );
  }
  await runInput(serial, `input text ${text.replace(/ /g, '%s')}`, 'input text', timeoutMs);
}

async function runInput(serial: string, shell: string, op: string, timeoutMs: number): Promise<void> {
  const { out } = await spawnAdb(['adb', '-s', serial, 'shell', shell], timeoutMs);
  // code === null means the child never exited cleanly (spawn failure or kill);
  // that is a failure, not a success.
  if (out.code === null) {
    throw noExitCodeError(op, serial, out);
  }
  if (out.code !== 0) {
    throw asAdbError(new Error(`${op} rejected: exit ${out.code} ${decodeText(out.stderr).trim()}`.trim()), op);
  }
}

export async function adminRoot(serial: string, timeoutMs = 15000): Promise<{ ok: boolean; output: string }> {
  serial = needSerial(serial);
  const { out } = await spawnAdb(['adb', '-s', serial, 'root'], timeoutMs);
  const output = `${decodeText(out.stdout)}\n${decodeText(out.stderr)}`.trim();
  if (out.code === null || out.code !== 0) {
    return { ok: false, output: output || 'adb root failed' };
  }
  return { ok: true, output };
}

// ===========================================================================
// UI hierarchy, selector targeting, files, apps, settings, media, presets.
//
// Design note (learned on a real Galaxy S21): a generic `am start VIEW` with a
// MIME type is hijackable — any installed app that registered the type (Termux
// had claimed audio/* here) intercepts it and nothing happens. Every action
// below therefore uses an EXPLICIT component or a real system service
// (uiautomator, media_session dispatch, svc/settings, monkey launcher), and
// screen interactions target parsed UI nodes instead of guessed coordinates.
// ===========================================================================

export interface UiBounds {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

export interface UiNode {
  text: string;
  desc: string;
  resourceId: string;
  className: string;
  package: string;
  clickable: boolean;
  enabled: boolean;
  scrollable: boolean;
  bounds: UiBounds;
  centerX: number;
  centerY: number;
  depth: number;
}

export interface UiTarget {
  text?: string;
  desc?: string;
  id?: string;
  className?: string;
  // Match by substring (default, case-insensitive) instead of exact equality.
  contains?: boolean;
  // Disambiguate among several matches by position in the tree (0-based).
  index?: number;
}

const XML_UNESCAPE: Record<string, string> = {
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&apos;': "'",
  '&amp;': '&',
};

function unescapeXml(s: string): string {
  return s.replace(/&lt;|&gt;|&quot;|&apos;|&amp;/g, (m) => XML_UNESCAPE[m] ?? m);
}

function parseBounds(raw: string): UiBounds | null {
  const m = /^\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]$/.exec(raw);
  if (!m) return null;
  return { x1: +m[1], y1: +m[2], x2: +m[3], y2: +m[4] };
}

// Pure parser over a `uiautomator dump` XML string -> flat nodes with tree
// depth. Attribute values are XML-escaped by the dumper, so the first '>' is
// always the tag end and parsing needs no full XML library.
export function parseUiHierarchy(xml: string): UiNode[] {
  const nodes: UiNode[] = [];
  const attr = (tag: string, name: string): string => {
    const mm = new RegExp(`\\b${name}="([^"]*)"`).exec(tag);
    return mm ? unescapeXml(mm[1]) : '';
  };
  let i = 0;
  let depth = 0;
  while (i < xml.length) {
    const lt = xml.indexOf('<', i);
    if (lt < 0) break;
    if (xml.startsWith('</node>', lt)) {
      depth = Math.max(0, depth - 1);
      i = lt + 7;
      continue;
    }
    if (xml.startsWith('<node', lt)) {
      const close = xml.indexOf('>', lt);
      if (close < 0) break;
      const tag = xml.slice(lt, close + 1);
      const selfClosed = tag.endsWith('/>');
      const bounds = parseBounds(attr(tag, 'bounds'));
      if (bounds) {
        nodes.push({
          text: attr(tag, 'text'),
          desc: attr(tag, 'content-desc'),
          resourceId: attr(tag, 'resource-id'),
          className: attr(tag, 'class'),
          package: attr(tag, 'package'),
          clickable: attr(tag, 'clickable') === 'true',
          enabled: attr(tag, 'enabled') !== 'false',
          scrollable: attr(tag, 'scrollable') === 'true',
          bounds,
          centerX: Math.round((bounds.x1 + bounds.x2) / 2),
          centerY: Math.round((bounds.y1 + bounds.y2) / 2),
          depth,
        });
      }
      if (!selfClosed) depth++;
      i = close + 1;
      continue;
    }
    i = lt + 1;
  }
  return nodes;
}

function matchesTarget(n: UiNode, t: UiTarget): boolean {
  const cmp = (hay: string, needle?: string): boolean => {
    if (needle === undefined) return true;
    return t.contains ? hay.toLowerCase().includes(needle.toLowerCase()) : hay.toLowerCase() === needle.toLowerCase();
  };
  if (t.text !== undefined && !cmp(n.text, t.text)) return false;
  if (t.desc !== undefined && !cmp(n.desc, t.desc)) return false;
  if (t.id !== undefined && !cmp(n.resourceId, t.id)) return false;
  if (t.className !== undefined && !cmp(n.className, t.className)) return false;
  // At least one discriminator must be supplied or nothing matches.
  return t.text !== undefined || t.desc !== undefined || t.id !== undefined || t.className !== undefined;
}

export function findUiNodes(nodes: UiNode[], t: UiTarget): UiNode[] {
  return nodes.filter((n) => matchesTarget(n, t));
}

// The remote dump path carries a nonce so concurrent dumps never clobber each
// other's file; it is always removed afterwards.
let dumpNonce = 0;
export async function dumpUi(serial: string, timeoutMs = 20000): Promise<UiNode[]> {
  serial = needSerial(serial);
  const path = `/sdcard/dsh_ui_${process.pid}_${dumpNonce++}.xml`;
  // Clear this process's stale dumps first: a dump killed on timeout never
  // reached its trailing `rm`, and the litter would accumulate.
  const r = await adbExec(serial, `rm -f /sdcard/dsh_ui_${process.pid}_*.xml; rm -f ${path}; uiautomator dump ${path}; cat ${path} 2>/dev/null; rm -f ${path}`, timeoutMs);
  const start = r.stdout.indexOf('<?xml');
  if (start < 0) {
    throw new ControlError(
      'REMOTE_ERROR',
      `uiautomator produced no hierarchy: ${(r.stdout + ' ' + r.stderr).trim().slice(0, 200) || 'empty'}`,
      { serial },
      'the UI may still be animating or a secure screen blocks capture — wait and retry, or use adb_screencap to see the state',
    );
  }
  const nodes = parseUiHierarchy(r.stdout.slice(start));
  if (nodes.length === 0) {
    throw new ControlError('REMOTE_ERROR', 'uiautomator hierarchy parsed to zero nodes', { serial });
  }
  return nodes;
}

const KEY_CODES: Record<string, number> = {
  home: 3,
  back: 4,
  enter: 66,
  search: 84,
  menu: 82,
  power: 26,
  delete: 67,
  forward_del: 112,
  recents: 187,
  volume_up: 24,
  volume_down: 25,
  volume_mute: 164,
  camera: 27,
  tab: 61,
  escape: 111,
  dpad_up: 19,
  dpad_down: 20,
  dpad_left: 21,
  dpad_right: 22,
  dpad_center: 23,
  media_play: 126,
  media_pause: 121,
  media_play_pause: 85,
  media_next: 87,
  media_previous: 88,
  media_stop: 86,
  media_rewind: 89,
  media_fast_forward: 90,
  brightness_up: 221,
  brightness_down: 220,
  sleep: 223,
  wakeup: 224,
  lock: 276, // KEYCODE_SOFT_SLEEP — the conventional screen-lock key on essentially all devices
};

export function resolveKeyCode(name: string): number | null {
  // A non-string (a JSON body with the wrong shape, a null) is not a key name:
  // answer null so the caller reports "unknown key" with the list of known keys
  // instead of taking down the call with a TypeError on .trim().
  if (typeof name !== 'string') return null;
  const lower = name.trim().toLowerCase();
  // Own-property lookup only: KEY_CODES is an object literal, so an inherited
  // name ('toString', 'constructor', 'valueOf') would otherwise be returned as
  // the key CODE — a function, not a number — instead of answered with null.
  if (Object.prototype.hasOwnProperty.call(KEY_CODES, lower)) return KEY_CODES[lower];
  if (/^\d+$/.test(lower)) return parseInt(lower, 10);
  return null;
}

export function knownKeyNames(): string[] {
  return Object.keys(KEY_CODES);
}

export async function inputKey(serial: string, keyCode: number, timeoutMs = 15000): Promise<void> {
  serial = needSerial(serial);
  if (!Number.isSafeInteger(keyCode) || keyCode < 0 || keyCode > 1000) {
    throw new ControlError('BAD_ARGS', `invalid key code: ${keyCode} (allowed 0..1000)`, { keyCode });
  }
  await runInput(serial, `input keyevent ${keyCode}`, 'input keyevent', timeoutMs);
}

// Tap the centre of a node (from dumpUi/findUiNodes). Kept separate from
// inputTap so selector taps and raw taps are both auditable.
export async function tapNode(serial: string, node: UiNode, timeoutMs = 15000): Promise<void> {
  await inputTap(serial, node.centerX, node.centerY, timeoutMs);
}

// Browser-mcp "fill" equivalent: focus a field by tapping it, then type.
// Honest limitation: `input text` APPENDS to the focused field; it cannot
// reliably select-all across OEM keyboards, so callers wanting a clean value
// should clear the field first (e.g. via adb_key dpad/backspace) or use a
// field that starts empty. This never silently claims a replace it did not do.
export async function setTextField(
  serial: string,
  node: UiNode,
  text: string,
  timeoutMs = 15000,
): Promise<void> {
  if (text === '') throw new ControlError('BAD_ARGS', 'empty field text');
  if (!INPUT_SAFE.test(text)) {
    throw new ControlError(
      'BAD_ARGS',
      'field text must stay within [A-Za-z0-9 ._-]; use adb_key for special characters',
      { text },
      'characters outside [A-Za-z0-9 ._-] cannot be typed into the field: use adb_key for them or strip them from the value',
    );
  }
  await inputTap(serial, node.centerX, node.centerY, timeoutMs);
  await runInput(serial, `input text ${text.replace(/ /g, '%s')}`, 'input text', timeoutMs);
}

const PKG_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;
function needPackage(pkg: string): string {
  const t = pkg.trim();
  if (!PKG_RE.test(t)) {
    throw new ControlError('BAD_ARGS', `invalid package name: "${t}" (expected form like com.example.app)`, { pkg: t });
  }
  return t;
}

export async function currentApp(serial: string, timeoutMs = 15000): Promise<{ focus: string; package: string | null; activity: string | null }> {
  serial = needSerial(serial);
  // Grep BOTH keys without -m1: when mCurrentFocus is null (a transition, or no
  // focused window) -m1 would stop on the null line and lose the real app in
  // mFocusedApp. We read both and prefer mCurrentFocus, else mFocusedApp.
  const r = await adbExec(serial, `dumpsys window 2>/dev/null | grep -E 'mCurrentFocus|mFocusedApp'`, timeoutMs);
  const lines = (r.stdout || '').split('\n').map((l) => l.trim()).filter(Boolean);
  const focusLine = lines.find((l) => l.includes('mCurrentFocus')) ?? '';
  const altLine = lines.find((l) => l.includes('mFocusedApp')) ?? '';
  // u\d+ (not u0): secondary/headless users run as u10, u11, … and u0-only
  // silently missed their foreground app.
  const pick = /u\d+\s+([^\s/{}]+)\/([^\s{},]+)/;
  const m = pick.exec(focusLine) ?? pick.exec(altLine);
  return {
    focus: focusLine || altLine,
    package: m ? m[1] : null,
    activity: m ? m[2] : null,
  };
}

// Launch a package's main/launcher activity via monkey (the robust way that
// does not need the exact activity name and cannot be MIME-hijacked).
export async function launchApp(serial: string, pkg: string, timeoutMs = 15000): Promise<{ ok: boolean; output: string }> {
  serial = needSerial(serial);
  const p = needPackage(pkg);
  const r = await adbExec(serial, `monkey -p ${p} -c android.intent.category.LAUNCHER 1`, timeoutMs);
  const output = (r.stdout + '\n' + r.stderr).trim();
  const ok = r.code === 0 && /Events injected: 1/.test(output) && !/No activities found/.test(output);
  return { ok, output };
}

// Browser-mcp "goto" equivalent, made hijack-resistant: only http(s) is
// accepted, and an optional explicit browser package pins the handler so a
// rogue MIME registration cannot swallow the link.
export async function openUrl(serial: string, url: string, browserPackage?: string, timeoutMs = 15000): Promise<{ ok: boolean; command: string; output: string }> {
  serial = needSerial(serial);
  if (typeof url !== 'string') {
    throw new ControlError('BAD_ARGS', 'url must be a string', { received: typeof url });
  }
  // A URL lands inside the device command as ONE quoted word, so a single quote
  // would end the quoting form. It is refused rather than escaped: a URL that
  // contains a single quote is never what the operator meant to open.
  if (url.includes("'")) throw new ControlError('BAD_ARGS', 'url must not contain a single quote', { url: url.slice(0, 60) });
  // Whitespace and control bytes are not valid URL bytes: they cannot be
  // percent-decoding (an encoded space is %20) and would reach `am` as literal
  // data in the intent URI, so they are refused here rather than quoted around.
  if (/[\s\x00-\x1f\x7f]/.test(url)) {
    throw new ControlError(
      'BAD_ARGS',
      'url must not contain whitespace or control characters',
      { url: url.slice(0, 60) },
      'percent-encode a space as %20 and strip control characters — a raw newline or space is not part of a URL',
    );
  }
  if (!/^https?:\/\//i.test(url)) {
    throw new ControlError('BAD_ARGS', 'only http(s) URLs are accepted by adb_open_url', { url: url.slice(0, 60) });
  }
  // Quoted for the DEVICE shell: & ? = # $ ( ) ` | are data here, not syntax.
  // quoteShellArg keeps the whole URL a single word on the device's `am`.
  let cmd = `am start -a android.intent.action.VIEW -d ${quoteShellArg(url)}`;
  if (browserPackage) cmd += ` -p ${needPackage(browserPackage)}`;
  const r = await adbExec(serial, cmd, timeoutMs);
  const output = (r.stdout + '\n' + r.stderr).trim();
  const ok = r.code === 0 && !/Error: /i.test(output) && !/does not match/i.test(output);
  return { ok, command: cmd, output };
}

// ---- filesystem ----------------------------------------------------------

export interface FileEntry {
  name: string;
  type: 'dir' | 'link' | 'file';
  size: number;
  mode: string;
  mtime: string;
}

// Parse `ls -l` output (toybox format): "drwxr-xr-x 2 u0_a0 group 4096 2026-11-22 18:10 name".
export function parseLsLines(out: string): FileEntry[] {
  const entries: FileEntry[] = [];
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line || /^total /.test(line)) continue;
    const m = /^([\-dlpsbc])(\S{9})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})\s+(.+)$/.exec(line);
    if (!m) continue;
    const kind = m[1];
    entries.push({
      name: m[8].replace(/ -> .*$/, ''),
      type: kind === 'd' ? 'dir' : kind === 'l' ? 'link' : 'file',
      size: parseInt(m[5], 10),
      mode: kind + m[2],
      mtime: `${m[6]} ${m[7]}`,
    });
  }
  return entries;
}

function needRemotePath(p: string, label: string): string {
  if (typeof p !== 'string' || p.trim() === '') throw new ControlError('BAD_ARGS', `${label} must be a non-empty path`, {});
  const t = p.trim();
  if (!t.startsWith('/')) throw new ControlError('BAD_ARGS', `${label} must be an absolute device path`, { path: t });
  return t;
}

// A local path is written by the adb child (pull) or read from (push), so a
// RELATIVE one resolves against the server's own working directory — landing
// outside whatever the operator meant, with no allowlist to catch it. Absolute
// is the only meaningful guard, and it has to hold inside the transport, not
// only at one tool boundary. Both path dialects are accepted because the two
// disagree on their own host: win32.isAbsolute('/srv/x') is true while
// posix.isAbsolute('C:\\x') is false. This rejects relative paths only; it
// never claims a path is writable, readable, or safe beyond that.
export function isAbsoluteLocalPath(p: string): boolean {
  if (typeof p !== 'string' || p.trim() === '') return false;
  const t = p.trim();
  return win32.isAbsolute(t) || posix.isAbsolute(t);
}

function needLocalPath(p: string, label: string): string {
  if (typeof p !== 'string' || p.trim() === '') {
    throw new ControlError('BAD_ARGS', `${label} must be a non-empty absolute path`, {});
  }
  const t = p.trim();
  if (!isAbsoluteLocalPath(t)) {
    throw new ControlError(
      'BAD_ARGS',
      `${label} must be an absolute local path: "${t}" would resolve against the server's working directory`,
      { [label]: t },
      `pass a full path for ${label} (e.g. C:\\out\\shot.png or /tmp/shot.png)`,
    );
  }
  return t;
}

export async function listDir(serial: string, remotePath: string, timeoutMs = 15000): Promise<FileEntry[]> {
  serial = needSerial(serial);
  const rp = needRemotePath(remotePath, 'remotePath');
  // One quoting form for every caller path: a device path may legitimately
  // contain spaces, and must not be able to end its own quote.
  const q = quoteShellArg(rp);
  const r = await adbExec(serial, `ls -l ${q}`, timeoutMs);
  if (r.code !== 0 || /No such file|Permission denied|Is a directory/.test(r.stdout + r.stderr)) {
    // Fall back to treating a single path as a file.
    const single = await adbExec(serial, `ls -ld ${q}`, timeoutMs);
    if (single.code !== 0) {
      throw new ControlError('REMOTE_ERROR', `ls ${rp} failed: ${(r.stderr || single.stderr || r.stdout).trim().slice(0, 200)}`, { serial, remotePath: rp });
    }
    return parseLsLines(single.stdout);
  }
  return parseLsLines(r.stdout);
}

// adb pull / push stream the file themselves (we only observe exit status), so
// unlike shell commands these never load a binary into memory.
function spawnWait(argv: string[], timeoutMs: number): Promise<{ code: number | null; signal: string | null; stderr: string; timedOut: boolean }> {
  return new Promise((resolve) => {
    const cmd = argv[0] === 'adb' ? adbBin().bin : argv[0];
    const child = spawn(cmd, argv.slice(1), { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderrLen = 0;
    let err = '';
    let timedOut = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;
    child.stderr.on('data', (d: Buffer) => {
      if (stderrLen < STDERR_CAP) {
        err += d.toString();
        stderrLen += d.length;
      }
    });
    const finish = (code: number | null, signal: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      resolve({ code, signal, stderr: err, timedOut });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => {
        child.kill('SIGKILL');
        finish(null, 'SIGKILL');
      }, KILL_GRACE_MS);
    }, timeoutMs);
    child.once('error', (e) => {
      err += `\n${e.message}`;
      finish(null, null);
    });
    child.once('close', () => finish(child.exitCode, child.signalCode));
  });
}

export async function pullFile(serial: string, remotePath: string, localPath: string, timeoutMs = 60000): Promise<{ bytes: number; localPath: string }> {
  serial = needSerial(serial);
  const rp = needRemotePath(remotePath, 'remotePath');
  // Validated before mkdir/spawn so a bad destination never creates a directory
  // nor moves bytes.
  const lp = needLocalPath(localPath, 'localPath');
  mkdirSync(dirname(lp), { recursive: true });
  const res = await spawnWait(['adb', '-s', serial, 'pull', rp, lp], timeoutMs);
  if (res.code !== 0 || res.timedOut) {
    throw new ControlError(res.timedOut ? 'TIMEOUT' : 'REMOTE_ERROR', `pull ${rp} failed: ${res.stderr.trim().slice(0, 200) || 'adb pull exit ' + res.code}`, { serial, remotePath: rp });
  }
  if (!existsSync(lp)) throw new ControlError('REMOTE_ERROR', `pull reported success but ${lp} is absent`, { serial, localPath: lp });
  // adb pull of a directory lands a directory; stat of that is meaningless as a
  // "bytes pulled" figure, so only a regular file counts as success here.
  const st = statSync(lp);
  if (!st.isFile()) throw new ControlError('REMOTE_ERROR', `pull reported success but ${lp} is not a regular file (a directory pull lands a directory)`, { serial, localPath: lp });
  return { bytes: st.size, localPath: lp };
}

export async function pushFile(serial: string, localPath: string, remotePath: string, timeoutMs = 60000): Promise<{ bytes: number }> {
  serial = needSerial(serial);
  const rp = needRemotePath(remotePath, 'remotePath');
  const lp = needLocalPath(localPath, 'localPath');
  if (!existsSync(lp)) throw new ControlError('BAD_ARGS', `local file does not exist: ${lp}`, { localPath: lp });
  const res = await spawnWait(['adb', '-s', serial, 'push', lp, rp], timeoutMs);
  if (res.code !== 0 || res.timedOut) {
    throw new ControlError(res.timedOut ? 'TIMEOUT' : 'REMOTE_ERROR', `push -> ${rp} failed: ${res.stderr.trim().slice(0, 200) || 'adb push exit ' + res.code}`, { serial, remotePath: rp });
  }
  return { bytes: statSync(lp).size };
}

// ---- app inventory -------------------------------------------------------

export type AppsScope = 'all' | 'system' | 'third_party';
export async function listApps(serial: string, scope: AppsScope = 'all', timeoutMs = 15000): Promise<string[]> {
  serial = needSerial(serial);
  const flag = scope === 'third_party' ? ' -3' : scope === 'system' ? ' -s' : '';
  const r = await adbExec(serial, `pm list packages${flag}`, timeoutMs);
  const pkgs: string[] = [];
  for (const raw of r.stdout.split(/\r?\n/)) {
    const m = /^package:(.+)$/.exec(raw.trim());
    if (m) pkgs.push(m[1]);
  }
  return pkgs;
}

// ---- settings ------------------------------------------------------------

export type SettingsNs = 'system' | 'secure' | 'global';

// The namespace is interpolated into the device command unquoted (it is a fixed
// word of `settings <verb> <ns> ...`), so the type has to be enforced at runtime
// too: TypeScript's SettingsNs is erased at the boundary, and any caller that
// is not the zod-validated tool (another module, a test, a future wiring) could
// otherwise put `global; rm -rf /sdcard` in that slot and have the DEVICE shell
// run it.
function needNs(ns: SettingsNs): SettingsNs {
  const t = typeof ns === 'string' ? ns.trim() : '';
  if (t !== 'system' && t !== 'secure' && t !== 'global') {
    throw new ControlError('BAD_ARGS', `invalid settings namespace: ${JSON.stringify(ns)} (allowed system|secure|global)`, { ns: t }, 'namespace must be exactly system, secure or global');
  }
  return t as SettingsNs;
}

function needKey(key: string): string {
  const t = key.trim();
  if (!/^[A-Za-z0-9_.:]+$/.test(t)) throw new ControlError('BAD_ARGS', `invalid settings key: "${t}"`, { key: t });
  return t;
}

export async function getSetting(serial: string, ns: SettingsNs, key: string, timeoutMs = 15000): Promise<string | null> {
  serial = needSerial(serial);
  const n = needNs(ns);
  const r = await adbExec(serial, `settings get ${n} ${needKey(key)}`, timeoutMs);
  const v = r.stdout.trim();
  if (r.code !== 0) throw new ControlError('REMOTE_ERROR', `settings get failed: ${r.stderr.trim().slice(0, 200)}`, { serial, ns: n, key });
  return v === '' || v === 'null' ? null : v;
}

export async function putSetting(serial: string, ns: SettingsNs, key: string, value: string, timeoutMs = 15000): Promise<{ written: string; readBack: string | null }> {
  serial = needSerial(serial);
  const n = needNs(ns);
  const k = needKey(key);
  // The value is arbitrary operator text: quote it for the device shell so
  // quotes, $( ), ; and newlines are written as data, then read the truth back.
  const r = await adbExec(serial, `settings put ${n} ${k} ${quoteShellArg(String(value))}`, timeoutMs);
  if (r.code !== 0) throw new ControlError('REMOTE_ERROR', `settings put failed: ${r.stderr.trim().slice(0, 200)}`, { serial, ns: n, key: k });
  // Read back the truth rather than trusting the write exit code.
  const readBack = await getSetting(serial, n, k, timeoutMs);
  return { written: String(value), readBack };
}

// ---- media ---------------------------------------------------------------

const MEDIA_DISPATCH: Record<string, string> = {
  play: 'play',
  pause: 'pause',
  'play-pause': 'play-pause',
  next: 'next',
  previous: 'previous',
  stop: 'stop',
  rewind: 'rewind',
  'fast-forward': 'fast-forward',
};
// Volume is global stream control, not a media_session verb: `cmd media_session
// dispatch volume_up` is not accepted, so these go straight to a keyevent.
const MEDIA_VOLUME_KEY: Record<string, number> = {
  volume_up: 24,
  volume_down: 25,
  mute: 164,
};

export interface NowPlaying {
  active: boolean;
  state?: string;
  title?: string;
  artist?: string;
  package?: string;
}

// Parse the active-session block out of `dumpsys media_session`. Formats vary
// across OEMs, so this is deliberately best-effort and reports what it finds.
export function parseNowPlaying(out: string): NowPlaying {
  const hasActive = /PlaybackState[^}]*state=(?:PLAYING|STATE_PLAYING|3)\b/i.test(out);
  const stateM = /PlaybackState[^}]*state=([A-Za-z0-9_]+|[-]?\d+)/i.exec(out);
  const titleM = /(?:description=|title=)([^;\n}]+)/i.exec(out);
  const artistM = /artist=([^;\n}]+)/i.exec(out);
  const pkgM = /packages=([A-Za-z][A-Za-z0-9_.]+)/.exec(out);
  const np: NowPlaying = { active: hasActive };
  if (stateM) np.state = stateM[1];
  if (titleM) np.title = titleM[1].trim();
  if (artistM) np.artist = artistM[1].trim();
  if (pkgM) np.package = pkgM[1];
  return np;
}

export async function nowPlaying(serial: string, timeoutMs = 15000): Promise<NowPlaying> {
  serial = needSerial(serial);
  const r = await adbExec(serial, `dumpsys media_session 2>/dev/null`, timeoutMs);
  return parseNowPlaying(r.stdout);
}

// Browser-mcp "play/pause/skip" equivalent for the device's active media
// session, via `cmd media_session dispatch` (routes to the live session rather
// than a global keyevent that any app could ignore).
export async function mediaControl(serial: string, action: string, timeoutMs = 15000): Promise<{ dispatched: string; via: 'media_session' | 'keyevent'; output: string; nowPlaying: NowPlaying }> {
  serial = needSerial(serial);
  const lower = action.trim().toLowerCase();
  const allowed = [...Object.keys(MEDIA_DISPATCH), ...Object.keys(MEDIA_VOLUME_KEY)];
  if (!allowed.includes(lower)) {
    throw new ControlError('BAD_ARGS', `unknown media action "${action}"`, { action, allowed });
  }

  let via: 'media_session' | 'keyevent';
  let dispatched: string;
  let output = '';

  if (MEDIA_VOLUME_KEY[lower] !== undefined) {
    await inputKey(serial, MEDIA_VOLUME_KEY[lower], timeoutMs);
    via = 'keyevent';
    dispatched = lower;
  } else {
    const mapped = MEDIA_DISPATCH[lower];
    const r = await adbExec(serial, `cmd media_session dispatch ${mapped}`, timeoutMs);
    output = (r.stdout + '\n' + r.stderr).trim();
    const broken = r.code !== 0 || /Can't find|No such|Error|Exception/i.test(r.stdout + r.stderr);
    if (broken) {
      const code = resolveKeyCode(`media_${lower.replace(/-/g, '_')}`);
      if (code === null) {
        throw new ControlError('REMOTE_ERROR', `media_session dispatch failed and no keyevent fallback for "${action}": ${output.slice(0, 120)}`, { serial, action });
      }
      await inputKey(serial, code, timeoutMs);
      via = 'keyevent';
    } else {
      via = 'media_session';
    }
    dispatched = mapped;
  }

  const np = await nowPlaying(serial, timeoutMs);
  return { dispatched, via, output, nowPlaying: np };
}

// ---- screen recording (bounded clip) -------------------------------------

export async function recordScreen(
  serial: string,
  localPath: string,
  durationMs: number,
  bitRateMbps: number,
  timeoutMs: number,
): Promise<{ bytes: number; localPath: string; durationMs: number; note: string }> {
  serial = needSerial(serial);
  if (!Number.isSafeInteger(durationMs) || durationMs < 500 || durationMs > 180000) {
    throw new ControlError('BAD_ARGS', 'screenrecord durationMs must be 500..180000 (screenrecord caps at 180s per run)', { durationMs });
  }
  if (!Number.isSafeInteger(bitRateMbps) || bitRateMbps < 1 || bitRateMbps > 60) {
    throw new ControlError('BAD_ARGS', 'bitRateMbps must be 1..60', { bitRateMbps });
  }
  const seconds = Math.max(1, Math.round(durationMs / 1000));
  // Validate the local destination BEFORE any device work: a relative path must
  // not cost a screenrecord run whose result then has nowhere honest to go.
  const lp = needLocalPath(localPath, 'localPath');
  const remote = `/sdcard/dsh_rec_${process.pid}_${dumpNonce++}.mp4`;
  // Android's screenrecord wants a plain integer for --time-limit (seconds) and
  // bits-per-second for --bit-rate; the `s`/`M` suffixes are rejected by the
  // toybox parser on real devices.
  const shell = `screenrecord --time-limit ${seconds} --bit-rate ${bitRateMbps * 1_000_000} ${remote}`;
  const r = await adbExec(serial, shell, timeoutMs);
  if (r.code !== 0) {
    await adbExec(serial, `rm -f ${remote}`, 10000).catch(() => undefined);
    // A null code means the process was killed (no exit code observed) — the
    // clip is likely truncated, so it must not be reported as a complete
    // recording. Only a clean exit 0 is a success.
    if (r.code === null) throw new ControlError('REMOTE_ERROR', 'screenrecord produced no exit code (process killed or timed out); the clip may be truncated', { serial, seconds });
    throw new ControlError('REMOTE_ERROR', `screenrecord failed: ${(r.stderr || r.stdout).trim().slice(0, 200) || 'exit ' + r.code}`, { serial, seconds });
  }
  const pulled = await pullFile(serial, remote, lp, timeoutMs);
  await adbExec(serial, `rm -f ${remote}`, 10000).catch(() => undefined);
  if (pulled.bytes === 0) {
    throw new ControlError('REMOTE_ERROR', 'screenrecord produced an empty clip', { serial });
  }
  return { bytes: pulled.bytes, localPath: lp, durationMs: seconds * 1000, note: 'silent video (screenrecord does not capture audio on Android); for live streaming use a dedicated scrcpy bridge' };
}

// ---- UI presets ----------------------------------------------------------
// Common one-shot device actions, so operators need not memorise key codes,
// `cmd statusbar` incantations, or the camera-flip dance. camera_front bakes in
// the selector-driven flip discovered on a real Galaxy S21 and verifies the
// result by re-reading the hierarchy rather than assuming the tap landed.
export const UI_PRESETS = [
  'home',
  'back',
  'recents',
  'notification_shade',
  'quick_settings',
  'collapse_shade',
  'camera_rear',
  'camera_front',
] as const;
export type UiPreset = (typeof UI_PRESETS)[number];

export interface PresetResult {
  ok: boolean;
  action: UiPreset;
  detail: string;
  observed?: string;
}

export async function runUiPreset(serial: string, name: UiPreset, timeoutMs = 20000): Promise<PresetResult> {
  serial = needSerial(serial);
  switch (name) {
    case 'home':
      await inputKey(serial, 3, timeoutMs);
      return { ok: true, action: name, detail: 'sent HOME' };
    case 'back':
      await inputKey(serial, 4, timeoutMs);
      return { ok: true, action: name, detail: 'sent BACK' };
    case 'recents':
      await inputKey(serial, 187, timeoutMs);
      return { ok: true, action: name, detail: 'opened recents' };
    case 'notification_shade': {
      const r = await adbExec(serial, 'cmd statusbar expand-notifications', timeoutMs);
      return { ok: r.code === 0, action: name, detail: (r.stdout + r.stderr).trim().slice(0, 160) || 'expanded notification shade' };
    }
    case 'quick_settings': {
      const r = await adbExec(serial, 'cmd statusbar expand-settings', timeoutMs);
      return { ok: r.code === 0, action: name, detail: (r.stdout + r.stderr).trim().slice(0, 160) || 'expanded quick settings' };
    }
    case 'collapse_shade': {
      const r = await adbExec(serial, 'cmd statusbar collapse', timeoutMs);
      return { ok: r.code === 0, action: name, detail: (r.stdout + r.stderr).trim().slice(0, 160) || 'collapsed shade' };
    }
    case 'camera_rear': {
      const r = await adbExec(serial, 'am start -a android.media.action.STILL_IMAGE_CAMERA -f 0x10000000', timeoutMs);
      const output = (r.stdout + r.stderr).trim();
      return { ok: r.code === 0 && !/Error: /i.test(output), action: name, detail: output.slice(0, 160) };
    }
    case 'camera_front': {
      await adbExec(serial, 'am start -a android.media.action.STILL_IMAGE_CAMERA -f 0x10000000; sleep 2', timeoutMs);
      const nodes = await dumpUi(serial, timeoutMs);
      const frontSwitch = findUiNodes(nodes, { desc: 'Switch to front camera', contains: false });
      let flipped = false;
      if (frontSwitch.length > 0) {
        await tapNode(serial, frontSwitch[0], timeoutMs);
        flipped = true;
      }
      // Verify by re-reading rather than assuming the tap landed.
      const after = await dumpUi(serial, timeoutMs);
      const nowFront = findUiNodes(after, { desc: 'Switch to rear camera', contains: false }).length > 0;
      return {
        ok: nowFront,
        action: name,
        detail: flipped ? 'tapped switch-to-front' : 'no front-switch control found (camera may already be front or still loading)',
        observed: nowFront ? 'front camera active' : 'could not confirm front camera from hierarchy',
      };
    }
    default: {
      // The switch is exhaustive over UiPreset today, so a value reaching here
      // came from outside the enum. Falling off the end would resolve the call
      // to `undefined` (which the tool then dereferences as r.ok); refuse it
      // with the list of what is actually supported instead.
      throw new ControlError('BAD_ARGS', `unknown UI preset: ${JSON.stringify(name)}`, { preset: name }, `known presets: ${UI_PRESETS.join(', ')}`);
    }
  }
}

// ---- device state snapshot (battery / power / settings / storage) ---------
//
// A compact health/power snapshot so the operator does not have to run several
// `dumpsys` / `settings` reads by hand. Honesty rules as ever: every field is
// either read from the device or null — a dumpsys format a parser does not
// recognize yields null, never a guess. The sections are gathered independently
// so one unreadable dump does not cost the other reads; sections whose read did
// not complete are listed in `failed` with their fields left null.

export interface BatteryState {
  level: number | null;
  status: string | null;
  plugged: string | null;
  temperatureC: number | null;
}

export interface PowerState {
  wakefulness: string | null;
  screenOn: boolean | null;
  doze: string | null;
}

// BatteryManager.BATTERY_STATUS_* and BATTERY_PLUGGED_* codes.
const BATTERY_STATUS: Record<number, string> = {
  1: 'unknown',
  2: 'charging',
  3: 'discharging',
  4: 'not-charging',
  5: 'full',
};
const BATTERY_PLUGGED: Record<number, string> = {
  0: 'none',
  1: 'ac',
  2: 'usb',
  4: 'wireless',
};

// An exact `key: <integer>` line in a dumpsys battery block. The "AC powered:
// true" style boolean lines are deliberately NOT mapped — they are redundant
// with `plugged:` and treating them as it would be interpretation, not a read.
function batteryNumber(out: string, key: string): number | null {
  const m = new RegExp(`^[ \\t]*${key}:[ \\t]*(-?\\d+)[ \\t]*$`, 'm').exec(out);
  return m ? parseInt(m[1], 10) : null;
}

export function parseBatteryDump(out: string): BatteryState {
  const rawLevel = batteryNumber(out, 'level');
  // Clamp into the documented 0..100 range; out-of-range numbers are still
  // clamped, a missing or non-numeric line is null, never an invented value.
  const level = rawLevel === null ? null : Math.max(0, Math.min(100, rawLevel));
  const rawStatus = batteryNumber(out, 'status');
  // An unrecognized status code is surfaced verbatim as its number rather than
  // folded into 'unknown', so the operator sees it is not a mapped value.
  const status = rawStatus === null ? null : BATTERY_STATUS[rawStatus] ?? String(rawStatus);
  const rawPlugged = batteryNumber(out, 'plugged');
  const plugged = rawPlugged === null ? null : BATTERY_PLUGGED[rawPlugged] ?? 'other';
  const rawTemp = batteryNumber(out, 'temperature');
  // EXTRA_TEMPERATURE is in tenths of a degree Celsius.
  const temperatureC = rawTemp === null ? null : rawTemp / 10;
  return { level, status, plugged, temperatureC };
}

// Parse a `dumpsys power` block. Formats differ across OEM releases, so each
// field is probed alone and stays null when the dump does not carry it.
export function parsePowerDump(out: string): PowerState {
  // The lookbehind keeps near-neighbours (mWakefulnessChanging,
  // mQcomScreenOn) from matching the key we actually want.
  const wake = /(?<![A-Za-z0-9_$])mWakefulness=(\S+)/.exec(out);
  let screenOn: boolean | null = null;
  const screenFlag = /(?<![A-Za-z0-9_$])mScreenOn=(true|false)/.exec(out);
  const displayPower = /Display Power:\s*state=([A-Za-z]+)/.exec(out);
  if (screenFlag) {
    screenOn = screenFlag[1] === 'true';
  } else if (displayPower) {
    const v = displayPower[1].toUpperCase();
    // Only ON/OFF is a boolean screen state; other values this field takes
    // (DOZING, INTERACTIVE, DIM, …) are not mapped onto a guess.
    if (v === 'ON') screenOn = true;
    else if (v === 'OFF') screenOn = false;
  }
  const dozeLine = /^[ \t]*(?:Doze mode|Doze|mDozeState)[ \t]*[:=][ \t]*(\S.*)$/m.exec(out);
  const doze = dozeLine ? dozeLine[1].replace(/[;{}].*$/, '').trim().slice(0, 60) || null : null;
  return { wakefulness: wake ? wake[1] : null, screenOn, doze };
}

const DF_SUFFIX: Record<string, number> = {
  K: 1024,
  M: 1024 * 1024,
  G: 1024 * 1024 * 1024,
};

// Parse `df /data` (toybox/busybox with a Mounted-on column): find the row
// whose last column is exactly /data and convert its 4th column (Available) to
// MB. Toybox df defaults to 1K-blocks, so an unsuffixed number means KiB;
// suffixed values (human-readable df, e.g. "5.2G") are powers of 1024 bytes.
// `dumpsys diskstats` would be an alternative source but its label wording
// varies too much across OEMs to trust a regex against it, so df is the only
// path here. No /data row, or an unparsable Available column, is null — not 0.
export function parseDataFreeMb(out: string, assumeTarget = false): number | null {
  const availOf = (tok: string): number | null => {
    const m = /^(\d+(?:\.\d+)?)([KMG])?$/i.exec(tok);
    if (!m) return null;
    return Math.round(parseFloat(m[1]) * (m[2] ? DF_SUFFIX[m[2].toUpperCase()] : 1024) / 1e6);
  };
  let singleAvail: number | null = null; // Available of the (only) non-/data data row
  let dataRows = 0;
  for (const raw of out.split(/\r?\n/)) {
    const cols = raw.trim().split(/\s+/).filter(Boolean);
    // df row: Filesystem <size> <used> <available> <use%> <mounted-on>
    if (cols.length < 6) continue;
    const avail = availOf(cols[3]);
    if (avail === null) continue; // header row or unparsable size → not a data row
    dataRows++;
    // An explicit /data mount wins outright.
    if (cols[cols.length - 1] === '/data') return avail;
    singleAvail = avail;
  }
  // No /data label. Only trust a lone row when the caller asked for a specific
  // path (`df /data` prints the one filesystem that HOLDS /data, though its
  // mount column may be labeled oddly — a real S21 reports it as a /storage/...
  // path). Without assumeTarget a single non-/data row is just one filesystem in
  // a full listing, so it is NOT treated as /data.
  if (assumeTarget && dataRows === 1 && singleAvail !== null) return singleAvail;
  return null;
}

export interface DeviceState {
  serial: string;
  battery: BatteryState;
  power: PowerState;
  airplaneModeOn: boolean | null;
  screenBrightness: number | null;
  screenBrightnessMode: string | null;
  dataFreeMb: number | null;
  // Section names ('battery','power','airplane','brightness','brightnessMode',
  // 'data') whose read did not complete. The fields stay null because they were
  // never observed, not because the device reported them absent.
  failed: string[];
  collectedAt: string;
}

export async function deviceState(serial: string, timeoutMs = 15000): Promise<DeviceState> {
  serial = needSerial(serial);
  const failed: string[] = [];
  // Set if any adb shell probe could not spawn the binary at all (ENOENT): the
  // whole snapshot is then pointless, so it is reported as a missing capability.
  let adbMissing = false;
  const state: DeviceState = {
    serial,
    battery: { level: null, status: null, plugged: null, temperatureC: null },
    power: { wakefulness: null, screenOn: null, doze: null },
    airplaneModeOn: null,
    screenBrightness: null,
    screenBrightnessMode: null,
    dataFreeMb: null,
    failed,
    collectedAt: new Date().toISOString(),
  };
  // One probe per section, each guarded on its own: a dead dumpsys service or
  // a missing settings key must not cost the operator the other reads. The
  // probes run concurrently so the whole snapshot still fits inside timeoutMs.
  // A non-zero exit counts as a failure (no usable dump), recorded in failed[].
  const batteryProbe = adbExec(serial, 'dumpsys battery', timeoutMs)
    .then((r) => {
      if (r.missing) adbMissing = true;
      if (r.code !== 0) throw new Error(`dumpsys battery exit ${r.code ?? 'no exit code'}`);
      state.battery = parseBatteryDump(r.stdout);
    })
    .catch(() => {
      failed.push('battery');
    });
  const powerProbe = adbExec(serial, 'dumpsys power', timeoutMs)
    .then((r) => {
      if (r.missing) adbMissing = true;
      if (r.code !== 0) throw new Error(`dumpsys power exit ${r.code ?? 'no exit code'}`);
      state.power = parsePowerDump(r.stdout);
    })
    .catch(() => {
      failed.push('power');
    });
  const airplaneProbe = getSetting(serial, 'global', 'airplane_mode_on', timeoutMs)
    .then((v) => {
      if (v === '1') state.airplaneModeOn = true;
      else if (v === '0') state.airplaneModeOn = false;
      // null or an unexpected value: leave airplaneModeOn null — unset is not off.
    })
    .catch(() => {
      failed.push('airplane');
    });
  const brightnessProbe = getSetting(serial, 'system', 'screen_brightness', timeoutMs)
    .then((v) => {
      if (v !== null && /^\d+$/.test(v)) state.screenBrightness = parseInt(v, 10);
    })
    .catch(() => {
      failed.push('brightness');
    });
  const brightnessModeProbe = getSetting(serial, 'system', 'screen_brightness_mode', timeoutMs)
    .then((v) => {
      state.screenBrightnessMode = v;
    })
    .catch(() => {
      failed.push('brightnessMode');
    });
  const dataProbe = adbExec(serial, 'df /data', timeoutMs)
    .then((r) => {
      if (r.missing) adbMissing = true;
      if (r.code !== 0) throw new Error(`df /data exit ${r.code ?? 'no exit code'}`);
      state.dataFreeMb = parseDataFreeMb(r.stdout, true);
    })
    .catch(() => {
      failed.push('data');
    });
  await Promise.all([batteryProbe, powerProbe, airplaneProbe, brightnessProbe, brightnessModeProbe, dataProbe]);
  if (adbMissing) {
    throw new ControlError('CAPABILITY_UNAVAILABLE', 'adb not installed: cannot read device state', { serial }, ADB_INSTALL_HINT);
  }
  return state;
}
