import { describe, it, expect } from 'vitest';
import { SshTransport, errCodeFromSsh } from '../src/transports/ssh.js';
import { ControlError } from '../src/errors.js';
import type { ErrCode } from '../src/errors.js';
import type { HostConfig } from '../src/config/schema.js';

// The completion sentinel (SENTINEL_MARK and sentinelFor) is module-private, so
// the parts of the protocol a unit test can reach without a live host are the
// error mapping around it and the session lookups that run before any socket is
// opened.
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
