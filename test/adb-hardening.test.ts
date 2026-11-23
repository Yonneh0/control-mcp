// ===========================================================================
// Input + quoting hardening for src/transports/adb.ts.
//
// Why this suite asserts on argv: spawnAdb/spawnWait take an argv ARRAY, so
// nothing in adb.ts ever passes through the HOST shell (cmd.exe / sh). The
// injection surface is the DEVICE: `adb -s <serial> shell <cmd>` hands <cmd>
// verbatim to the device's /system/bin/sh. So every test here stubs
// node:child_process (no adb binary, no device is ever touched), captures the
// exact argv handed to spawn, and re-parses the device-side command string with
// a minimal POSIX tokenizer to prove a caller-supplied payload cannot become a
// separate word, an option, or a second command.
//
// Anything only observable against real hardware (whether the device `input`
// tool turns %s back into a space, whether dumpsys formats match, whether a
// PTY rewrites LF as CRLF) is labelled unverified in the report, never asserted.
// ===========================================================================

import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  dumpUi,
  getSetting,
  inputKey,
  inputSwipe,
  inputTap,
  inputText,
  launchApp,
  listApps,
  listDir,
  mediaControl,
  openUrl,
  putSetting,
  pullFile,
  pushFile,
  recordScreen,
  resolveKeyCode,
  runUiPreset,
  screencapPng,
  setTextField,
  type AppsScope,
  type SettingsNs,
  type UiNode,
  type UiPreset,
} from '../src/transports/adb.js';

// --- stubbed child_process ---------------------------------------------------

interface Script {
  stdout?: string | Buffer;
  stderr?: string | Buffer;
  code?: number | null;
  signal?: string | null;
  spawnError?: { message: string; code?: string };
  // Side effect standing in for the adb child itself (e.g. `adb pull` writing
  // the local file). Receives the argv slice passed to spawn.
  onCall?: (args: string[]) => void;
}

const h = vi.hoisted(() => ({
  calls: [] as { cmd: string; args: string[] }[],
  script: {} as any,
}));

vi.mock('node:child_process', () => {
  type Fn = (...args: any[]) => void;
  // Tiny emitter: enough for stdout/stderr 'data' and child 'error'/'close'.
  const make = () => {
    const map = new Map<string, Fn[]>();
    return {
      on(name: string, fn: Fn) {
        map.set(name, [...(map.get(name) ?? []), fn]);
      },
      once(name: string, fn: Fn) {
        const wrapped: Fn = (...a) => {
          map.set(name, (map.get(name) ?? []).filter((x) => x !== wrapped));
          fn(...a);
        };
        map.set(name, [...(map.get(name) ?? []), wrapped]);
      },
      emit(name: string, ...args: any[]) {
        for (const fn of [...(map.get(name) ?? [])]) fn(...args);
      },
    };
  };
  const spawn = (cmd: string, args: string[] = [], _opts: unknown = {}): any => {
    const child: any = make();
    const out = make();
    const err = make();
    child.stdout = out;
    child.stderr = err;
    child.exitCode = null;
    child.signalCode = null;
    child.kill = () => true;
    h.calls.push({ cmd, args });
    const script: Script = h.script ?? {};
    // Deferred so the caller has attached its listeners first.
    setImmediate(() => {
      try {
        script.onCall?.(args);
      } catch (e) {
        err.emit('data', Buffer.from(`onCall failed: ${(e as Error).message}`));
      }
      if (script.spawnError) {
        const e: any = new Error(script.spawnError.message);
        if (script.spawnError.code) e.code = script.spawnError.code;
        child.emit('error', e);
        return;
      }
      if (script.stdout !== undefined) {
        out.emit('data', Buffer.isBuffer(script.stdout) ? script.stdout : Buffer.from(String(script.stdout)));
      }
      if (script.stderr !== undefined) {
        err.emit('data', Buffer.isBuffer(script.stderr) ? script.stderr : Buffer.from(String(script.stderr)));
      }
      child.exitCode = script.code === undefined ? 0 : script.code;
      child.signalCode = script.signal ?? null;
      child.emit('close');
    });
    return child;
  };
  return { spawn };
});

beforeEach(() => {
  h.calls.length = 0;
  h.script = { code: 0 };
});

// --- assertion helpers -------------------------------------------------------

/** Every device-side shell string handed to `adb ... shell <cmd>`. */
function shellStrings(): string[] {
  return h.calls.filter((c) => c.args.includes('shell')).map((c) => c.args[c.args.indexOf('shell') + 1] ?? '');
}

function lastShell(): string {
  const s = shellStrings();
  if (s.length === 0) throw new Error('no adb shell call was made');
  return s[s.length - 1];
}

/** The rejection value of a call expected to fail, or a thrown test error. */
async function rejection(fn: () => Promise<unknown>): Promise<any> {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected the call to reject, but it resolved');
}

/** `label -> CODE` for each case, so a failing loop prints every case. */
async function codesOf(cases: Record<string, () => Promise<unknown>>): Promise<string[]> {
  const out: string[] = [];
  for (const [label, fn] of Object.entries(cases)) {
    let code = 'RESOLVED';
    try {
      await fn();
    } catch (e: any) {
      code = String(e?.code ?? e?.name ?? 'THREW');
    }
    out.push(`${JSON.stringify(label)} -> ${code}`);
  }
  return out;
}

const allBad = (cases: Record<string, unknown>): string[] => Object.keys(cases).map((k) => `${JSON.stringify(k)} -> BAD_ARGS`);

/**
 * Minimal POSIX-sh word splitter, used to prove quoting is correct.
 * Handles 'single quotes', "double quotes" with \" \\ escapes, and backslash
 * escapes outside quotes — including the `'\''` idiom (close quote, escaped
 * quote, reopen quote) that quoteShellArg produces. Reports the metacharacters
 * that appear UNQUOTED (; & | < > ( ) and the expansion chars $ and backtick),
 * i.e. exactly the set that could turn a payload into a new word or a second
 * command on the device. Globs (* ? [ ]) are deliberately not flagged, because
 * dumpUi's own `rm -f <glob>` cleanup relies on one.
 */
function splitShell(cmd: string): { words: string[]; metachars: string[] } {
  const words: string[] = [];
  const metachars: string[] = [];
  let cur = '';
  let started = false;
  let i = 0;
  const flush = () => {
    if (started) {
      words.push(cur);
      cur = '';
      started = false;
    }
  };
  while (i < cmd.length) {
    const c = cmd[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      flush();
      i++;
      continue;
    }
    if (c === "'") {
      started = true;
      i++;
      while (i < cmd.length && cmd[i] !== "'") cur += cmd[i++];
      i++; // closing quote (or end of input)
      continue;
    }
    if (c === '"') {
      started = true;
      i++;
      while (i < cmd.length && cmd[i] !== '"') {
        if (cmd[i] === '\\' && i + 1 < cmd.length) {
          cur += cmd[i + 1];
          i += 2;
          continue;
        }
        cur += cmd[i++];
      }
      i++;
      continue;
    }
    if (c === '\\') {
      started = true;
      cur += cmd[i + 1] ?? '';
      i += 2;
      continue;
    }
    if (';&|<>()$`'.includes(c)) {
      metachars.push(c);
      flush();
      i++;
      continue;
    }
    started = true;
    cur += c;
    i++;
  }
  flush();
  return { words, metachars };
}

/** Assert a built device command tokenises to exactly `expected`, nothing unquoted. */
function expectShell(cmd: string, expected: string[]): void {
  const { words, metachars } = splitShell(cmd);
  expect({ words, metachars, cmd }).toEqual({ words: expected, metachars: [], cmd });
}

function uiNode(centerX: number, centerY: number): UiNode {
  return {
    text: '',
    desc: '',
    resourceId: '',
    className: 'android.widget.EditText',
    package: 'com.example',
    clickable: true,
    enabled: true,
    scrollable: false,
    bounds: { x1: centerX - 10, y1: centerY - 10, x2: centerX + 10, y2: centerY + 10 },
    centerX,
    centerY,
    depth: 0,
  };
}

const PNG_HEAD = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_IEND = Buffer.concat([Buffer.from([0, 0, 0, 0]), Buffer.from('IEND'), Buffer.from([0xae, 0x42, 0x60, 0x82])]);
const PNG = Buffer.concat([PNG_HEAD, Buffer.from('ihdr-body'), PNG_IEND]);

// --- host-side argv safety ---------------------------------------------------

describe('host-side argv (no host shell is ever involved)', () => {
  it('passes adb as argv, never as `sh -c <string>`', async () => {
    await inputTap('SER', 10, 20);
    expect(h.calls).toHaveLength(1);
    const [call] = h.calls;
    expect(typeof call.cmd).toBe('string');
    expect(['sh', 'bash', 'cmd.exe', 'cmd']).not.toContain(call.cmd);
    expect(call.args).toEqual(['-s', 'SER', 'shell', 'input tap 10 20']);
    // The whole device command stays in ONE argv element.
    expect(call.args.filter((a) => a.includes('input'))).toHaveLength(1);
  });

  it('screencap goes through exec-out with separate argv (no device shell at all)', async () => {
    h.script = { code: 0, stdout: PNG };
    const png = await screencapPng('SER');
    expect(Buffer.compare(png, PNG)).toBe(0);
    expect(h.calls[0].args).toEqual(['-s', 'SER', 'exec-out', 'screencap', '-p']);
  });

  it('refuses serials that could smuggle adb flags, before any spawn', async () => {
    const cases = {
      '': () => inputTap('', 1, 1),
      '   ': () => screencapPng('   '),
      '--killserver': () => screencapPng('--killserver'),
      '-s': () => inputKey('-s', 3),
      '-t foo': () => listDir('-t foo', '/sdcard'),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });
});

// --- input text -------------------------------------------------------------

describe('inputText / setTextField (device `input text`)', () => {
  const injections: Record<string, string> = {
    quote: "it's",
    semicolon: "'; rm -rf /sdcard #",
    subshell: 'a$(id)b',
    backtick: 'a`id`b',
    pipe: 'a|b',
    andand: 'a&&b',
    redirect: 'a>b',
    newline: 'a\nb',
    crlf: 'a\r\nb',
    tab: 'a\tb',
    percent: 'a%sb',
    dollar: 'a$HOME',
    paren: 'a(b)',
    glob: 'a*',
    unicode: 'héllo',
    leadingDash: '-l',
    empty: '',
  };

  it('rejects every character outside [A-Za-z0-9 ._-] (and a leading -) without spawning', async () => {
    const cases: Record<string, () => Promise<unknown>> = {};
    for (const [k, v] of Object.entries(injections)) cases[k] = () => inputText('SER', v);
    expect(await codesOf(cases)).toEqual(Object.keys(injections).map((k) => `${JSON.stringify(k)} -> BAD_ARGS`));
    expect(h.calls).toHaveLength(0);
  });

  it('the accepted charset is passed through with each space encoded as %s', async () => {
    await inputText('SER', 'hello world 42_x-1');
    expect(shellStrings()).toEqual(['input text hello%sworld%s42_x-1']);
  });

  it('an option-looking fragment can never become a separate word (spaces never survive)', async () => {
    await inputText('SER', 'a --help --root');
    const built = lastShell();
    expect(built).toBe('input text a%s--help%s--root');
    expectShell(built, ['input', 'text', 'a%s--help%s--root']);
  });

  it('setTextField validates the text BEFORE tapping, so a payload never reaches the device', async () => {
    const bad = await rejection(() => setTextField('SER', uiNode(5, 7), "'; rm -rf /sdcard"));
    expect(String(bad?.code)).toBe('BAD_ARGS');
    expect(h.calls).toHaveLength(0);
  });

  it('setTextField happy path is tap then typed text with %s for spaces', async () => {
    await setTextField('SER', uiNode(5, 7), 'a b');
    expect(shellStrings()).toEqual(['input tap 5 7', 'input text a%sb']);
  });

  it('node coordinates are bounds-checked on the way to the shell', async () => {
    // A hostile uiautomator hierarchy could carry anything in centerX/centerY.
    const e = await rejection(() => setTextField('SER', uiNode(1e9, 7), 'a'));
    expect(String(e?.code)).toBe('BAD_ARGS');
    expect(h.calls).toHaveLength(0);
  });
});

// --- launchApp / openUrl ----------------------------------------------------

describe('launchApp (package name into monkey)', () => {
  it('rejects package names that are not exactly com.example.form', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      'com.example.app; rm -rf /': () => launchApp('SER', 'com.example.app; rm -rf /'),
      'com.example.app && curl evil': () => launchApp('SER', 'com.example.app && curl evil'),
      "com.example'": () => launchApp('SER', "com.example'"),
      'com.example app': () => launchApp('SER', 'com.example app'),
      '$(id)': () => launchApp('SER', '$(id)'),
      com: () => launchApp('SER', 'com'),
      empty: () => launchApp('SER', ''),
      'com.example.app -p foo': () => launchApp('SER', 'com.example.app -p foo'),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('a valid package produces a fixed monkey command line', async () => {
    h.script = { code: 0, stdout: 'Events injected: 1' };
    const r = await launchApp('SER', 'com.example.app');
    expect(r.ok).toBe(true);
    expectShell(lastShell(), ['monkey', '-p', 'com.example.app', '-c', 'android.intent.category.LAUNCHER', '1']);
  });
});

describe('openUrl (URL into `am start -d`)', () => {
  it('quotes a real query string so & ? = # stay one word', async () => {
    const r = await openUrl('SER', 'https://example.com/s?q=a&x=1#frag');
    expect(r.command).toBe(`am start -a android.intent.action.VIEW -d 'https://example.com/s?q=a&x=1#frag'`);
    expectShell(r.command, ['am', 'start', '-a', 'android.intent.action.VIEW', '-d', 'https://example.com/s?q=a&x=1#frag']);
  });

  it('rejects a URL carrying a single quote (it would break the quoting form)', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      embedded: () => openUrl('SER', "http://example.com/a'b"),
      breakout: () => openUrl('SER', "http://x/' ; rm -rf /sdcard ; '"),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('rejects whitespace and control characters in a URL (they are not valid URL bytes)', async () => {
    const cases: Record<string, () => Promise<unknown>> = {};
    for (const [label, url] of Object.entries({
      newline: 'http://example.com/\nrm -rf /sdcard',
      cr: 'http://example.com/a\rb',
      space: 'http://example.com/a b',
      tab: 'http://example.com/a\tb',
      leadingSpace: ' http://example.com/',
      trailingSpace: 'http://example.com/ ',
      nul: 'http://example.com/a\x00b',
    })) {
      cases[label] = () => openUrl('SER', url);
    }
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('shell metacharacters inside a URL cannot escape the quoting', async () => {
    for (const url of [
      'http://example.com/$(id)',
      'http://example.com/`id`',
      'http://example.com/a;b',
      'http://example.com/a|b',
      'http://example.com/a&&b',
      'http://example.com/a>b<c',
      'http://example.com/a(b)c',
      'http://example.com/a\\b',
      'http://example.com/*',
    ]) {
      const r = await openUrl('SER', url);
      expectShell(r.command, ['am', 'start', '-a', 'android.intent.action.VIEW', '-d', url]);
    }
  });

  it('only http(s) is accepted and browserPackage is validated', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      'file:///etc/passwd': () => openUrl('SER', 'file:///etc/passwd'),
      'javascript:alert(1)': () => openUrl('SER', 'javascript:alert(1)'),
      'content://sms': () => openUrl('SER', 'content://sms/inbox'),
      'package:com.example': () => openUrl('SER', 'package:com.example'),
      'browserPackage payload': () => openUrl('SER', 'https://example.com', 'com.example; id'),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });
});

// --- settings ---------------------------------------------------------------

describe('getSetting / putSetting', () => {
  it('rejects a namespace outside system|secure|global before touching the device', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      'global; id': () => getSetting('SER', 'global; id' as SettingsNs, 'k'),
      "sys'tem": () => getSetting('SER', "sys'tem" as SettingsNs, 'k'),
      'global newline payload': () => putSetting('SER', 'global\nrm -rf /sdcard' as SettingsNs, 'k', 'v'),
      GLOBAL: () => getSetting('SER', 'GLOBAL' as SettingsNs, 'k'),
      empty: () => putSetting('SER', '' as SettingsNs, 'k', 'v'),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('reads a validated namespace+key as a fixed command', async () => {
    h.script = { code: 0, stdout: '255\n' };
    expect(await getSetting('SER', 'system', 'screen_brightness')).toBe('255');
    expectShell(lastShell(), ['settings', 'get', 'system', 'screen_brightness']);
  });

  it('quotes a settings value so quotes, $( ), ; and newlines stay literal', async () => {
    const value = "it's a $(id) test; `whoami` | tail -n1 > /sdcard/x \nend";
    const r = await putSetting('SER', 'global', 'demo_key', value);
    expect(r.written).toBe(value);
    const puts = shellStrings().filter((s) => s.startsWith('settings put'));
    expect(puts).toHaveLength(1);
    expectShell(puts[0], ['settings', 'put', 'global', 'demo_key', value]);
    // The read-back is its own measured call, keyed by the key (never the value).
    const gets = shellStrings().filter((s) => s.startsWith('settings get'));
    expect(gets).toHaveLength(1);
    expectShell(gets[0], ['settings', 'get', 'global', 'demo_key']);
  });

  it('rejects keys outside [A-Za-z0-9_.:] for both verbs', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      'get;id': () => getSetting('SER', 'global', 'k;id'),
      "get quote": () => getSetting('SER', 'global', "k'"),
      'put subshell': () => putSetting('SER', 'global', '$(id)', 'v'),
      'put space': () => putSetting('SER', 'global', 'a b', 'v'),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });
});

// --- device paths -----------------------------------------------------------

describe('listDir remote-path quoting', () => {
  it('quotes the device path so a payload cannot break out of the ls argument', async () => {
    for (const p of [
      "/sdcard/a';rm -rf '/x",
      '/sdcard/a$(id)b',
      '/sdcard/a`id`b',
      '/sdcard/name with spaces',
      '/sdcard/a;b|c&&d',
      '/sdcard/*',
    ]) {
      h.calls.length = 0;
      await listDir('SER', p);
      expect(shellStrings()).toHaveLength(1);
      expectShell(lastShell(), ['ls', '-l', p]);
    }
  });

  it('refuses a relative device path (no cwd-dependent ls)', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      sdcard: () => listDir('SER', 'sdcard'),
      dot: () => listDir('SER', '.'),
      'dotdot': () => listDir('SER', '..'),
      '../../etc/hosts': () => listDir('SER', '../../etc/hosts'),
      empty: () => listDir('SER', ''),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });
});

describe('pullFile / pushFile local-path guards', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-adb-test-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('refuses a relative localPath (the write would land in the server cwd)', async () => {
    const cases: Record<string, () => Promise<unknown>> = {};
    for (const p of ['out.bin', './out.bin', '../out.bin', join('sub', 'out.bin')]) {
      cases[p] = () => pullFile('SER', '/sdcard/x.bin', p);
    }
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('refuses a relative push source with the same absolute-path refusal', async () => {
    const e = await rejection(() => pushFile('SER', 'in.bin', '/sdcard/in.bin'));
    expect(String(e?.code)).toBe('BAD_ARGS');
    expect(String(e?.message)).toMatch(/absolute/i);
    expect(h.calls).toHaveLength(0);
  });

  it('refuses an empty localPath', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      empty: () => pullFile('SER', '/sdcard/x', ''),
      spaces: () => pullFile('SER', '/sdcard/x', '   '),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('classifies absolute-looking local paths without touching the filesystem', async () => {
    const adb: any = await import('../src/transports/adb.js');
    expect(typeof adb.isAbsoluteLocalPath).toBe('function');
    const accepted = [join(dir, 'x.bin'), 'C:\\Temp\\x.png', 'C:/Temp/x.png', '/home/op/x.png', '\\\\nas\\share\\x.png'];
    const rejected = ['x.bin', './x.bin', '../x.bin', 'C:x.bin', '', '   ', 'sub/x.bin'];
    expect(accepted.filter((p) => !adb.isAbsoluteLocalPath(p))).toEqual([]);
    expect(rejected.filter((p) => adb.isAbsoluteLocalPath(p))).toEqual([]);
    expect(h.calls).toHaveLength(0);
  });

  it('accepts an absolute localPath and measures the pulled file', async () => {
    const local = join(dir, 'pulled.bin');
    h.script = { code: 0, onCall: (args: string[]) => writeFileSync(args[4], Buffer.alloc(5, 7)) };
    const r = await pullFile('SER', '/sdcard/x.bin', local);
    expect(r.bytes).toBe(5);
    expect(r.localPath).toBe(local);
    expect(h.calls[0].args).toEqual(['-s', 'SER', 'pull', '/sdcard/x.bin', local]);
  });

  it('does not claim success when the pull left nothing behind', async () => {
    const local = join(dir, 'never-written.bin');
    const e = await rejection(() => pullFile('SER', '/sdcard/x.bin', local));
    expect(String(e?.code)).toBe('REMOTE_ERROR');
    expect(String(e?.message)).toMatch(/absent/);
  });

  it('push sends an absolute local file and reports its measured size', async () => {
    const local = join(dir, 'push.bin');
    writeFileSync(local, 'abcd');
    const r = await pushFile('SER', local, '/sdcard/push.bin');
    expect(r.bytes).toBe(4);
    expect(h.calls[0].args).toEqual(['-s', 'SER', 'push', local, '/sdcard/push.bin']);
  });
});

// --- screencap integrity ----------------------------------------------------

describe('screencapPng output integrity', () => {
  it('rejects a stream with no IEND instead of handing back an unopenable file', async () => {
    h.script = { code: 0, stdout: Buffer.concat([PNG_HEAD, Buffer.from('truncated')]) };
    const e = await rejection(() => screencapPng('SER'));
    expect(String(e?.code)).toBe('REMOTE_ERROR');
    expect(String(e?.message)).toMatch(/IEND/);
  });

  it('rejects non-PNG output naming the observed header bytes', async () => {
    h.script = { code: 0, stdout: Buffer.from('not a png at all....') };
    const e = await rejection(() => screencapPng('SER'));
    expect(String(e?.message)).toMatch(/not a PNG/);
  });

  it('rejects an empty capture', async () => {
    h.script = { code: 0, stdout: Buffer.from([0x89, 0x50]) };
    const e = await rejection(() => screencapPng('SER'));
    expect(String(e?.message)).toMatch(/no image data/);
  });

  it('a killed capture (signal set) is reported as truncated, not as success', async () => {
    h.script = { code: 0, signal: 'SIGKILL', stdout: PNG };
    const e = await rejection(() => screencapPng('SER'));
    expect(String(e?.message)).toMatch(/truncated/);
  });

  it('a missing adb binary is CAPABILITY_UNAVAILABLE, never "no image data"', async () => {
    h.script = { spawnError: { message: 'spawn adb ENOENT', code: 'ENOENT' } };
    const e = await rejection(() => screencapPng('SER'));
    expect(String(e?.code)).toBe('CAPABILITY_UNAVAILABLE');
  });
});

// --- recordScreen -----------------------------------------------------------

describe('recordScreen bounds and command line', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-adb-rec-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('bounds durationMs, bitRateMbps and the local path before any device work', async () => {
    const local = join(dir, 'clip.mp4');
    const cases: Record<string, () => Promise<unknown>> = {
      'duration 0': () => recordScreen('SER', local, 0, 4, 30000),
      'duration 499': () => recordScreen('SER', local, 499, 4, 30000),
      'duration 180001': () => recordScreen('SER', local, 180001, 4, 30000),
      'duration 1.5': () => recordScreen('SER', local, 1500.5, 4, 30000),
      'bitrate 0': () => recordScreen('SER', local, 5000, 0, 30000),
      'bitrate 61': () => recordScreen('SER', local, 5000, 61, 30000),
      'relative out': () => recordScreen('SER', 'clip.mp4', 5000, 4, 30000),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('builds the screenrecord line from validated integers only', async () => {
    const local = join(dir, 'clip.mp4');
    h.script = {
      code: 0,
      onCall: (args: string[]) => {
        if (args.includes('pull')) writeFileSync(args[4], Buffer.alloc(7, 9));
      },
    };
    const r = await recordScreen('SER', local, 5000, 4, 30000);
    expect(r.bytes).toBe(7);
    expect(r.durationMs).toBe(5000);
    const rec = shellStrings()[0];
    expect(rec).toMatch(/^screenrecord --time-limit 5 --bit-rate 4000000 \/sdcard\/dsh_rec_\d+_\d+\.mp4$/);
    expectShell(rec, ['screenrecord', '--time-limit', '5', '--bit-rate', '4000000', rec.split(' ').pop() as string]);
    // The temp clip is removed afterwards, and its name came from the pid, not the caller.
    expect(shellStrings().some((s) => /^rm -f \/sdcard\/dsh_rec_\d+_\d+\.mp4$/.test(s))).toBe(true);
  });
});

// --- keys, taps, swipes -----------------------------------------------------

describe('resolveKeyCode / inputKey', () => {
  it('returns null for non-string input instead of throwing a TypeError', () => {
    const results: string[] = [];
    for (const bad of [undefined, null, 123, {}, [], true, 'x'.charCodeAt(0) === 120 ? Symbol('k') : 0]) {
      let out = 'THREW';
      try {
        const r = resolveKeyCode(bad as any);
        out = r === null ? 'null' : `got:${String(r)}`;
      } catch {
        out = 'THREW';
      }
      results.push(out);
    }
    expect(results).toEqual(results.map(() => 'null'));
  });

  it('never answers from the object prototype (toString is not a key name)', () => {
    const results: string[] = [];
    for (const inherited of ['toString', 'constructor', 'valueOf', 'hasOwnProperty', '__proto__']) {
      let out = 'THREW';
      try {
        const r = resolveKeyCode(inherited);
        out = r === null ? 'null' : `got:${typeof r}`;
      } catch {
        out = 'THREW';
      }
      results.push(out);
    }
    expect(results).toEqual(results.map(() => 'null'));
  });

  it('resolves names case-insensitively and digit strings only', () => {
    expect(resolveKeyCode('  HOME ')).toBe(3);
    expect(resolveKeyCode('27')).toBe(27);
    expect(resolveKeyCode('007')).toBe(7);
    expect(resolveKeyCode('1e3')).toBeNull();
    expect(resolveKeyCode('-5')).toBeNull();
    expect(resolveKeyCode('')).toBeNull();
  });

  it('bounds the key code before the device shell sees it', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      '1001': () => inputKey('SER', 1001),
      '-1': () => inputKey('SER', -1),
      '1.5': () => inputKey('SER', 1.5),
      NaN: () => inputKey('SER', NaN),
      '1e21': () => inputKey('SER', 1e21),
      string: () => inputKey('SER', '3; id' as any),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
    await inputKey('SER', 3);
    expectShell(lastShell(), ['input', 'keyevent', '3']);
  });
});

describe('inputTap / inputSwipe bounds', () => {
  it('refuses out-of-range coordinates without spawning', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      'x 65536': () => inputTap('SER', 65536, 1),
      'y -1': () => inputTap('SER', 1, -1),
      'x 1.5': () => inputTap('SER', 1.5, 1),
      'x NaN': () => inputTap('SER', NaN, 1),
      'x string': () => inputTap('SER', '1;id' as any, 1),
      'swipe x2 huge': () => inputSwipe('SER', 1, 2, 3, 1e9, 300),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('bounds the swipe duration like the public schema (no unbounded device-side swipe)', async () => {
    const e = await rejection(() => inputSwipe('SER', 1, 2, 3, 4, 1_000_000_000_000));
    expect(String(e?.code)).toBe('BAD_ARGS');
    expect(h.calls).toHaveLength(0);
    await inputSwipe('SER', 1, 2, 3, 4, 60000);
    expectShell(lastShell(), ['input', 'swipe', '1', '2', '3', '4', '60000']);
  });
});

// --- enum-valued entry points ----------------------------------------------

describe('enum-valued entry points refuse values outside their enum', () => {
  it('runUiPreset rejects an unknown preset instead of resolving to undefined', async () => {
    const e = await rejection(() => runUiPreset('SER', 'not_a_preset' as UiPreset));
    expect(String(e?.code)).toBe('BAD_ARGS');
    expect(h.calls).toHaveLength(0);
  });

  it('runUiPreset home is a plain keyevent', async () => {
    const r = await runUiPreset('SER', 'home');
    expect(r.ok).toBe(true);
    expectShell(lastShell(), ['input', 'keyevent', '3']);
  });

  it('mediaControl rejects an unknown action', async () => {
    const cases: Record<string, () => Promise<unknown>> = {
      payload: () => mediaControl('SER', 'x;id'),
      empty: () => mediaControl('SER', ''),
      'PLAY payload': () => mediaControl('SER', 'PLAY; rm -rf /sdcard'),
    };
    expect(await codesOf(cases)).toEqual(allBad(cases));
    expect(h.calls).toHaveLength(0);
  });

  it('listApps maps only known scopes to a flag', async () => {
    h.script = { code: 0, stdout: '' };
    expect(await listApps('SER', 'third_party; id' as AppsScope)).toEqual([]);
    expectShell(lastShell(), ['pm', 'list', 'packages']);
    await listApps('SER', 'third_party');
    expectShell(lastShell(), ['pm', 'list', 'packages', '-3']);
  });
});

// --- dumpUi path derivation -------------------------------------------------

describe('dumpUi remote path is derived, never caller-controlled', () => {
  it('uses only pid/nonce for the dump file', async () => {
    h.script = {
      code: 0,
      stdout: `<?xml version='1.0'?>\n<hierarchy><node text="ok" bounds="[0,0][2,2]" class="X" /></hierarchy>`,
    };
    expect(await dumpUi('SER')).toHaveLength(1);
    const cmd = lastShell();
    expect(cmd).toMatch(
      /^rm -f \/sdcard\/dsh_ui_\d+_\*\.xml; rm -f \/sdcard\/dsh_ui_\d+_\d+\.xml; uiautomator dump \/sdcard\/dsh_ui_\d+_\d+\.xml; cat \/sdcard\/dsh_ui_\d+_\d+\.xml 2>\/dev\/null; rm -f \/sdcard\/dsh_ui_\d+_\d+\.xml$/,
    );
  });
});

// --- quoting helper + dumpsys parser edges ---------------------------------

describe('quoteShellArg (single documented POSIX quoting form)', () => {
  it('is exported and round-trips every dangerous character as one word', async () => {
    const adb: any = await import('../src/transports/adb.js');
    expect(typeof adb.quoteShellArg).toBe('function');
    for (const payload of [
      "it's",
      "'; rm -rf /sdcard #",
      '$(id)`whoami`',
      'a|b&c<d>e(f)g',
      'multi\nline\tvalue',
      'back\\slash and "double quotes"',
      '',
    ]) {
      const quoted = adb.quoteShellArg(payload);
      expect(splitShell(quoted).words).toEqual([payload]);
      expect(splitShell(quoted).metachars).toEqual([]);
    }
  });
});

describe('dumpsys parser edges', () => {
  const adbP = () => import('../src/transports/adb.js');

  it('reads a battery dump whose lines end with CRLF (PTY line endings)', async () => {
    const adb: any = await adbP();
    const crlf = 'Current Battery Service state:\r\n  AC powered: true\r\n  status: 2\r\n  plugged: 1\r\n  level: 87\r\n  temperature: 291\r\n';
    expect(adb.parseBatteryDump(crlf)).toEqual({ level: 87, status: 'charging', plugged: 'ac', temperatureC: 29.1 });
  });

  it('does not carry a trailing CR into the doze value', async () => {
    const adb: any = await adbP();
    expect(adb.parsePowerDump('  mWakefulness=Dozing\r\nDoze: dozing\r\n')).toEqual({ wakefulness: 'Dozing', screenOn: null, doze: 'dozing' });
  });

  it('handles absurd magnitudes and unicode without throwing or inventing values', async () => {
    const adb: any = await adbP();
    expect(adb.parseBatteryDump('  level: 99999999999999999999\r\n  temperature: -400')).toMatchObject({ level: 100, temperatureC: -40 });
    // Arabic-Indic digits are not ASCII digits: not a reading, so null.
    expect(adb.parseBatteryDump('  level: ١٠').level).toBeNull();
    expect(adb.parseDataFreeMb('/dev/block/dm-50 1 1 9999999999G 100% /data', true)).toBeGreaterThan(0);
    expect(adb.parsePowerDump('  mWakefulness=Awake ')).toMatchObject({ wakefulness: 'Awake' });
  });
});
