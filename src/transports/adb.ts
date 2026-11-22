import { spawn } from 'node:child_process';
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
