import { describe, it, expect } from 'vitest';
import { SshTransport, errCodeFromSsh, sentinelFor, wrapShellCommand, parseShellResult, stripAnsi } from '../src/transports/ssh.js';
import { ControlError } from '../src/errors.js';
import type { ErrCode } from '../src/errors.js';
import type { HostConfig } from '../src/config/schema.js';

// The sentinel framing is now pure, exported helpers (sentinelFor /
// wrapShellCommand / parseShellResult), so the cross-talk safety that used to
// need a live host is unit-testable; the live half still skips without a host.
const U = 'sh-never-opened';

describe('errCodeFromSsh', () => {
  const CODES: ErrCode[] = ['AUTH_FAILED', 'HOST_UNREACHABLE', 'SESSION_GONE', 'REMOTE_ERROR', 'BAD_ARGS'];

  it.each(CODES)('passes through a ControlError $code unchanged', (code) => {
    expect(errCodeFromSsh(new ControlError(code, 'raised by the transport'))).toBe(code);
  });

  it('calls anything that is not a ControlError internal', () => {
    expect(errCodeFromSsh(new Error('socket hang up'))).toBe('INTERNAL');
    expect(errCodeFromSsh('a bare string')).toBe('INTERNAL');
    expect(errCodeFromSsh(undefined)).toBe('INTERNAL');
  });
});

describe('sentinel framing (per-command marker)', () => {
  it('gives every command in a session a UNIQUE marker (the recovery guarantee)', () => {
    // With a per-session marker (the old design) two commands shared one string,
    // so a late marker could not be told from the next command's — the reason a
    // timeout used to poison the session. A distinct seq is what prevents it.
    expect(sentinelFor('sh-1', 1)).not.toBe(sentinelFor('sh-1', 2));
    expect(sentinelFor('sh-1', 1)).toBe('CTL_MCP_sh-1_1_END');
    expect(sentinelFor('sh/we#ird', 9)).toBe('CTL_MCP_shweird_9_END'); // sanitised, shell/regex-safe
  });

  it('wraps the command so the shell prints the marker with its exit code', () => {
    const w = wrapShellCommand('ls -l', sentinelFor('sh-1', 3));
    expect(w.startsWith('{\nls -l\n')).toBe(true);
    expect(w).toContain('"$?"');
    expect(w).toContain('CTL_MCP_sh-1_3_END');
    expect(w.endsWith('2>/dev/null\n')).toBe(true);
  });

  // Issue #1: the marker line used to sit on the tty directly behind the
  // command, so anything reading stdin (nested ssh, read, bare wc) CONSUMED it —
  // the command then finished with the marker never printed and the reader saw a
  // false TIMEOUT over an idle prompt. The command group now runs with stdin off
  // the tty (`} < /dev/null`), so the marker line can never be eaten. Fails on
  // the old `command\n{ printf … }` framing: that line had no stdin redirect.
  it('runs the command with stdin redirected so it CANNOT eat the marker line (issue #1)', () => {
    const w = wrapShellCommand('ssh root@other id', sentinelFor('sh-1', 7));
    expect(w).toContain('} < /dev/null\n');
    // Braces (live shell, cwd/env persist), never a subshell.
    expect(w.startsWith('{\n')).toBe(true);
    // Closing brace alone on its line: a command ending in `&` still parses.
    expect(wrapShellCommand('sleep 1 &', 'M')).toContain('sleep 1 &\n} < /dev/null\n');
    // The marker line follows the redirected group, outside it.
    const markerAt = w.indexOf('{ printf');
    const redirAt = w.indexOf('} < /dev/null');
    expect(redirAt).toBeGreaterThan(-1);
    expect(markerAt).toBeGreaterThan(redirAt);
  });

  // What bash now emits for the issue's repro class: the group runs with stdin
  // at EOF, `read` gets EOF (honest exit 1), and the marker still prints — where
  // before, `read` had eaten the marker line and no amount of waiting resolved.
  it('parses a marker after a stdin-eating command that exited cleanly', () => {
    const marker = sentinelFor('sh-2', 9);
    const buffer =
      `{\r\nread x\r\n} < /dev/null\r\nroot@um780:~# { printf '\\n${marker}%s\\n' "$?" 2>/dev/null; } 2>/dev/null\r\n` +
      `\r\n${marker}1\r\nroot@um780:~# `;
    const res = parseShellResult(buffer, marker);
    expect(res?.exit).toBe('1'); // read's honest EOF exit, not a fabricated 0
  });

  it('resolves only on THIS command marker, not a stale one from a prior command', () => {
    const stale = sentinelFor('sh-1', 4); // an earlier command that finished late
    const active = sentinelFor('sh-1', 5);
    // The old per-session code matched the FIRST marker in the buffer — the stale
    // one — and would have wrongly returned exit 0 as the answer for command 5.
    const onlyStale = `a\r\n${stale}0\r\nb is still running`;
    expect(parseShellResult(onlyStale, active)).toBeNull();
    // Once the ACTIVE marker completes, its own exit code is reported.
    const done = `a\r\n${stale}0\r\nb\r\n${active}7\r\n`;
    const res = parseShellResult(done, active);
    expect(res?.exit).toBe('7');
  });

  it('does not resolve on the echoed wrapper fragment (%s, not digits)', () => {
    const active = sentinelFor('sh-1', 6);
    const echoFragment = `x\r\n{ printf '\\n${active}%s\\n' "$?" 2>/dev/null || echo ${active}?; } 2>/dev/null\r\n`;
    expect(parseShellResult(echoFragment, active)).toBeNull();
  });

  it('cuts the echoed wrapper line out of the reported output', () => {
    const marker = sentinelFor('sh-1', 5);
    const echo = `{ printf '\\n${marker}%s\\n' "$?" 2>/dev/null || echo ${marker}?; } 2>/dev/null`;
    const buffer = `hello\r\n${echo}\r\n${marker}0\r\n`;
    const res = parseShellResult(buffer, marker);
    expect(res?.exit).toBe('0');
    expect(res?.output).toBe('hello\r\n'); // wrapper echo excluded
  });

  // cmd.exe (the Windows OpenSSH default shell) is where the reported failure
  // lived: the POSIX printf sentinel is echoed back verbatim and never runs, so
  // a completed command's marker never appeared and the waiter hung. The
  // platform-aware wrapper uses `echo <marker>%errorlevel%`, which cmd DOES run.
  it('cmd.exe: observes the marker and strips the %errorlevel% wrapper line', () => {
    const marker = sentinelFor('sh-2', 1);
    const buffer =
      `C:\\Users\\y>echo hi\r\nhi\r\n` +
      `C:\\Users\\y>echo ${marker}%errorlevel%\r\n` + // echoed back: literal %errorlevel%, must NOT match
      `${marker}0\r\n`; // cmd ran it: marker + exit code -> this is what was never seen before
    const res = parseShellResult(buffer, marker, 'windows');
    expect(res?.exit).toBe('0');
    expect(res?.output).toContain('hi');
    expect(res?.output).not.toContain('%errorlevel%');
  });

  it('cmd.exe: reports a nonzero errorlevel honestly (not forced to 0)', () => {
    const marker = sentinelFor('sh-2', 2);
    const buffer = `C:\\>nope\r\n'nope' is not recognized\r\nC:\\>echo ${marker}%errorlevel%\r\n${marker}9009\r\n`;
    expect(parseShellResult(buffer, marker, 'windows')?.exit).toBe('9009');
  });

  it('cmd.exe: before the exit line completes, still returns null (no false match)', () => {
    const marker = sentinelFor('sh-2', 3);
    const buffer = `C:\\Users\\y>echo hi\r\nhi\r\nC:\\Users\\y>echo ${marker}%errorlevel%\r\n`;
    expect(parseShellResult(buffer, marker, 'windows')).toBeNull();
  });

  it('observes the marker even when a cursor-control code follows the digits (the real msi bytes)', () => {
    const marker = sentinelFor('sh-2', 4);
    // Real msi capture: the prompt emits ANSI cursor moves, so the exit digits
    // are followed by ESC[… , not `\r\n` — the old requirement never matched.
    const buffer = `yonneh@MSI C:\\>echo ${marker}%errorlevel%\r\n${marker}0\x1b[10;1Hyonneh@MSI C:\\>`;
    const res = parseShellResult(buffer, marker, 'windows');
    expect(res?.exit).toBe('0');
  });

  it('does not accept a number until a non-digit proves it complete (chunk-safe)', () => {
    const marker = sentinelFor('sh-2', 5);
    expect(parseShellResult(`x\n${marker}1`, marker)).toBeNull(); // buffer ends mid-number
    expect(parseShellResult(`x\n${marker}12\r\n`, marker)?.exit).toBe('12');
  });

  it('stripAnsi removes control codes but keeps text, CR and LF', () => {
    expect(stripAnsi('a\x1b[?25lb\x1b[7;1Hc\r\nd')).toBe('abc\r\nd');
  });
});

describe('session bookkeeping with no connection made', () => {
  const transport = new SshTransport();

  it('lists no sessions and knows no session object', () => {
    expect(transport.listSessions()).toEqual([]);
    expect(transport.getSession(U)).toBeUndefined();
  });

  it('refuses to run a command in a session it never opened', async () => {
    await expect(() => transport.runInShell(U, 'pwd')).rejects.toThrow(/No such shell session/);
  });

  it('says that closing a session it never opened did nothing', async () => {
    expect(await transport.closeShell(U)).toBe(false);
  });
});

// The live half of the protocol needs a real host, so the probe decides whether
// anything below is attempted; ok with an auth error means "the socket answered
// but we could not log in", which is not a usable shell.
// The target comes from the environment so no real address/credential is committed;
// the default is an unreachable documentation address, so the live cases skip
// unless you set CONTROL_MCP_TEST_HOST (plus optional USER/KEY) on your own machine.
const LIVE = {
  name: process.env.CONTROL_MCP_TEST_HOST ?? '192.0.2.10',
  address: process.env.CONTROL_MCP_TEST_HOST ?? '192.0.2.10',
};
const liveHost: HostConfig = {
  name: LIVE.name,
  address: LIVE.address,
  os: 'linux',
  ssh: {
    port: 22,
    user: process.env.CONTROL_MCP_TEST_USER ?? 'root',
    privateKeyPath: process.env.CONTROL_MCP_TEST_KEY ?? '~/.ssh/id_ed25519',
  },
  alternateAddresses: [],
  capabilities: { rdp: false },
};

describe('the sentinel protocol against a live host', async () => {
  const transport = new SshTransport();
  const gate = await transport.probe(liveHost, liveHost.address);
  const live = gate.ok && !gate.error;

  it('never turns a dead connection into a thrown error, and says why', () => {
    expect(typeof gate.ok).toBe('boolean');
    expect(gate.ok || gate.error !== undefined).toBe(true);
  });

  it.skipIf(!live)('runs echo hello and reports the exit as zero', async () => {
    const result = await transport.exec(liveHost, liveHost.address, 'echo hello', { timeoutMs: 8000 });
    expect(result.stdout).toContain('hello');
    expect(result.code).toBe(0);
    // ssh2's close event hands the exit code only, so a clean exit leaves this
    // field absent rather than the declared null.
    expect(result.signal ?? null).toBeNull();
    expect(result.truncated).toBe(false);
    expect(result.durationMs >= 0).toBe(true);
    expect(result.stderr.includes('timeout')).toBe(false);
  });

  it.skipIf(!live)('keeps one shell across two commands and reports both exits', async () => {
    const session = await transport.openShell(liveHost, liveHost.address);
    const moved = await transport.runInShell(session.id, 'cd /tmp', 4000);
    const asked = await transport.runInShell(session.id, 'pwd', 4000);
    // The second call was accepted, which is the same-session proof: an
    // unanswered first command would have been refused with BAD_ARGS instead.
    expect(moved.closed).toBe(false);
    expect(asked.closed).toBe(false);
    expect(transport.getSession(session.id)).toBeDefined();
    // A shell that understood the POSIX wrapper answers with the exit label;
    // one that did not (cmd.exe) answers with the timeout notice instead.
    const labelled = /\[exit (0|\?)\]/.test(asked.output);
    if (labelled) {
      expect(moved.output).toContain('[exit 0]');
      expect(asked.output).toMatch(/^\s*\/tmp\s*$/m);
    } else {
      expect(asked.output).toContain('sentinel not seen');
    }
    await transport.closeShell(session.id);
    // A closed session is dropped from the map, so the next call is refused
    // immediately rather than after another safety-gate round trip.
    await expect(() => transport.runInShell(session.id, 'pwd')).rejects.toThrow(/No such shell session/);
  });
});
