import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import { ControlError } from '../errors.js';

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
const INPUT_SAFE = /^[A-Za-z0-9 ._-]+$/;
// Caps on captured child output; dropping a chunk past a cap sets `truncated`.
const STDOUT_CAP = 8 * 1024 * 1024;
const STDERR_CAP = 1 * 1024 * 1024;
// Grace after SIGTERM before escalating to SIGKILL and settling anyway.
const KILL_GRACE_MS = 1000;

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
    const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
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
    return new ControlError('CAPABILITY_UNAVAILABLE', `adb not installed: ${op}`, { op });
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
  if (!Number.isSafeInteger(durationMs) || durationMs < 1) {
    throw new ControlError('BAD_ARGS', 'invalid swipe duration', { durationMs });
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
  const r = await adbExec(serial, `rm -f ${path}; uiautomator dump ${path}; cat ${path} 2>/dev/null; rm -f ${path}`, timeoutMs);
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
  media_fast_forward: 71,
  brightness_up: 241,
  brightness_down: 242,
  lock: 276,
};

export function resolveKeyCode(name: string): number | null {
  const lower = name.trim().toLowerCase();
  if (KEY_CODES[lower] !== undefined) return KEY_CODES[lower];
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
  const r = await adbExec(serial, `dumpsys window 2>/dev/null | grep -m1 -E 'mCurrentFocus|mFocusedApp'`, timeoutMs);
  const line = (r.stdout || '').trim();
  // mCurrentFocus=Window{7f1a2b3 u0 com.foo.bar/com.foo.bar.MainActivity}
  const m = /u0\s+([^\s/{}]+)\/([^\s{},]+)/.exec(line);
  return {
    focus: line,
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
  if (url.includes("'")) throw new ControlError('BAD_ARGS', 'url must not contain a single quote', {});
  if (!/^https?:\/\//i.test(url)) {
    throw new ControlError('BAD_ARGS', 'only http(s) URLs are accepted by adb_open_url', { url: url.slice(0, 60) });
  }
  let cmd = `am start -a android.intent.action.VIEW -d '${url}'`;
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

export async function listDir(serial: string, remotePath: string, timeoutMs = 15000): Promise<FileEntry[]> {
  serial = needSerial(serial);
  const rp = needRemotePath(remotePath, 'remotePath');
  const r = await adbExec(serial, `ls -l '${rp.replace(/'/g, "'\\''")}'`, timeoutMs);
  if (r.code !== 0 || /No such file|Permission denied|Is a directory/.test(r.stdout + r.stderr)) {
    // Fall back to treating a single path as a file.
    const single = await adbExec(serial, `ls -ld '${rp.replace(/'/g, "'\\''")}'`, timeoutMs);
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
    const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'ignore', 'pipe'] });
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
  if (!localPath || localPath.trim() === '') throw new ControlError('BAD_ARGS', 'localPath must be a non-empty absolute path', {});
  mkdirSync(dirname(localPath), { recursive: true });
  const res = await spawnWait(['adb', '-s', serial, 'pull', rp, localPath], timeoutMs);
  if (res.code !== 0 || res.timedOut) {
    throw new ControlError(res.timedOut ? 'TIMEOUT' : 'REMOTE_ERROR', `pull ${rp} failed: ${res.stderr.trim().slice(0, 200) || 'adb pull exit ' + res.code}`, { serial, remotePath: rp });
  }
  if (!existsSync(localPath)) throw new ControlError('REMOTE_ERROR', `pull reported success but ${localPath} is absent`, { serial, localPath });
  return { bytes: statSync(localPath).size, localPath };
}

export async function pushFile(serial: string, localPath: string, remotePath: string, timeoutMs = 60000): Promise<{ bytes: number }> {
  serial = needSerial(serial);
  const rp = needRemotePath(remotePath, 'remotePath');
  if (!existsSync(localPath)) throw new ControlError('BAD_ARGS', `local file does not exist: ${localPath}`, { localPath });
  const res = await spawnWait(['adb', '-s', serial, 'push', localPath, rp], timeoutMs);
  if (res.code !== 0 || res.timedOut) {
    throw new ControlError(res.timedOut ? 'TIMEOUT' : 'REMOTE_ERROR', `push -> ${rp} failed: ${res.stderr.trim().slice(0, 200) || 'adb push exit ' + res.code}`, { serial, remotePath: rp });
  }
  return { bytes: statSync(localPath).size };
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
function needKey(key: string): string {
  const t = key.trim();
  if (!/^[A-Za-z0-9_.:]+$/.test(t)) throw new ControlError('BAD_ARGS', `invalid settings key: "${t}"`, { key: t });
  return t;
}

export async function getSetting(serial: string, ns: SettingsNs, key: string, timeoutMs = 15000): Promise<string | null> {
  serial = needSerial(serial);
  const r = await adbExec(serial, `settings get ${ns} ${needKey(key)}`, timeoutMs);
  const v = r.stdout.trim();
  if (r.code !== 0) throw new ControlError('REMOTE_ERROR', `settings get failed: ${r.stderr.trim().slice(0, 200)}`, { serial, ns, key });
  return v === '' || v === 'null' ? null : v;
}

export async function putSetting(serial: string, ns: SettingsNs, key: string, value: string, timeoutMs = 15000): Promise<{ written: string; readBack: string | null }> {
  serial = needSerial(serial);
  const k = needKey(key);
  const quoted = `'${String(value).replace(/'/g, "'\\''")}'`;
  const r = await adbExec(serial, `settings put ${ns} ${k} ${quoted}`, timeoutMs);
  if (r.code !== 0) throw new ControlError('REMOTE_ERROR', `settings put failed: ${r.stderr.trim().slice(0, 200)}`, { serial, ns, key: k });
  // Read back the truth rather than trusting the write exit code.
  const readBack = await getSetting(serial, ns, k, timeoutMs);
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
  volume_up: 'volume_up',
  volume_down: 'volume_down',
  mute: 'volume_mute',
};

export interface NowPlaying {
  active: boolean;
  state?: string;
  title?: string;
  artist?: string;
  package?: string;
  raw?: string;
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
  const mapped = MEDIA_DISPATCH[lower];
  if (!mapped) {
    throw new ControlError('BAD_ARGS', `unknown media action "${action}"`, { action, allowed: Object.keys(MEDIA_DISPATCH) });
  }
  let via: 'media_session' | 'keyevent' = 'media_session';
  let r = await adbExec(serial, `cmd media_session dispatch ${mapped}`, timeoutMs);
  const looksBroken = r.code !== 0 || /Can't find|No such|Error|Exception/i.test(r.stdout + r.stderr);
  if (looksBroken) {
    via = 'keyevent';
    const codeName = `media_${lower.replace(/-/g, '_')}`;
    const code = resolveKeyCode(codeName);
    if (code === null) {
      throw new ControlError('REMOTE_ERROR', `media_session dispatch failed and no keyevent fallback for "${action}": ${r.stderr.trim().slice(0, 120)}`, { serial, action });
    }
    await inputKey(serial, code, timeoutMs);
  }
  const np = await nowPlaying(serial, timeoutMs);
  return { dispatched: mapped, via, output: (r.stdout + '\n' + r.stderr).trim(), nowPlaying: np };
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
  const remote = `/sdcard/dsh_rec_${process.pid}_${dumpNonce++}.mp4`;
  // Android's screenrecord wants a plain integer for --time-limit (seconds) and
  // bits-per-second for --bit-rate; the `s`/`M` suffixes are rejected by the
  // toybox parser on real devices.
  const shell = `screenrecord --time-limit ${seconds} --bit-rate ${bitRateMbps * 1_000_000} ${remote}`;
  const r = await adbExec(serial, shell, timeoutMs);
  if (r.code !== 0 && r.code !== null) {
    await adbExec(serial, `rm -f ${remote}`, 10000).catch(() => undefined);
    throw new ControlError('REMOTE_ERROR', `screenrecord failed: ${(r.stderr || r.stdout).trim().slice(0, 200) || 'exit ' + r.code}`, { serial, seconds });
  }
  const pulled = await pullFile(serial, remote, localPath, timeoutMs);
  await adbExec(serial, `rm -f ${remote}`, 10000).catch(() => undefined);
  if (pulled.bytes === 0) {
    throw new ControlError('REMOTE_ERROR', 'screenrecord produced an empty clip', { serial });
  }
  return { bytes: pulled.bytes, localPath, durationMs: seconds * 1000, note: 'silent video (screenrecord does not capture audio on Android); for live streaming use a dedicated scrcpy bridge' };
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
  }
}
