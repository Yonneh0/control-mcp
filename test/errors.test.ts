import { describe, it, expect } from 'vitest';
import { toolError } from '../src/errors.js';
import type { ErrCode } from '../src/errors.js';

const CODES: Array<{ code: ErrCode; message: string }> = [
  { code: 'AUTH_FAILED', message: 'the presented key was refused by the host' },
  { code: 'HOST_UNREACHABLE', message: 'no interface answered for 10.0.0.7' },
  { code: 'CAPABILITY_UNAVAILABLE', message: 'this host has no scripted-RDP path' },
  { code: 'TRANSPORT_SEVERED_RISK', message: 'this command stops the service carrying our transport' },
  { code: 'TIMEOUT', message: 'the command did not finish within its budget' },
  { code: 'SESSION_GONE', message: 'the shell session was closed by the peer' },
  { code: 'BAD_ARGS', message: 'the host name given is not configured' },
  { code: 'REMOTE_ERROR', message: 'the remote command exited non-zero' },
  { code: 'INTERNAL', message: 'an internal invariant failed' },
];

describe('toolError', () => {
  it.each(CODES)('refuses $code with one text block and matching structuredContent', (row) => {
    const result = toolError(row.code, row.message);
    expect(result.isError).toBe(true);
    expect(result.content.length).toBe(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text.startsWith(`[${row.code}] ${row.message}`)).toBe(true);
    expect(result.structuredContent.code).toBe(row.code);
    expect(result.structuredContent.message).toBe(row.message);
    // No detail argument means no detail key: a client rendering structuredContent
    // must not have to filter an empty object out of every refusal.
    expect(result.structuredContent.detail).toBeUndefined();
  });

  // Self-learning contract: EVERY error carries an actionable next step, both in
  // the visible text line (so single-block clients recover) and structuredContent.
  it.each(CODES)('every $code error carries a non-empty hint in text and structuredContent', (row) => {
    const result = toolError(row.code, row.message);
    expect(typeof result.structuredContent.hint).toBe('string');
    expect((result.structuredContent.hint as string).length).toBeGreaterThan(20);
    expect(result.content[0].text.includes(result.structuredContent.hint as string)).toBe(true);
    expect(result.content[0].text.includes('\n→ ')).toBe(true);
  });

  it('lets a call site override the default hint', () => {
    const custom = 'retry with host=n100; that is the only Windows host configured';
    const result = toolError('BAD_ARGS', 'unknown host "n10"', { host: 'n10' }, custom);
    expect(result.structuredContent.hint).toBe(custom);
    expect(result.content[0].text.endsWith(`\n→ ${custom}`)).toBe(true);
  });

  // A message that carries bracketed context must not confuse the code prefix,
  // which is the whole point of the text line and structuredContent pairing.
  it('keeps the code prefix distinguishable when the message itself is bracketed', () => {
    const message = '[press-room] TCP/3389 closed';
    const result = toolError('CAPABILITY_UNAVAILABLE', message);
    expect(result.content[0].text.startsWith(`[CAPABILITY_UNAVAILABLE] ${message}\n→ `)).toBe(true);
    expect(result.structuredContent.message).toBe(message);
  });

  it('passes a detail object through to structuredContent unchanged', () => {
    const detail = { command: 'Stop-Service sshd', transport: 'ssh', pid: 4123, selfSevering: true };
    const result = toolError('TRANSPORT_SEVERED_RISK', 'stopping sshd would end our own transport', detail);
    expect(result.isError).toBe(true);
    expect(result.content[0].text.startsWith('[TRANSPORT_SEVERED_RISK] stopping sshd would end our own transport')).toBe(true);
    expect(result.structuredContent.code).toBe('TRANSPORT_SEVERED_RISK');
    expect(result.structuredContent.detail).toEqual(detail);
    // structuredContent has to survive a JSON round-trip on the wire.
    expect(JSON.parse(JSON.stringify(result.structuredContent.detail))).toEqual(detail);
  });

  it('keeps a detail that only carries nested values', () => {
    const detail = { probe: { tcp: false, ssh: true }, attempts: [1, 2, 3] };
    const result = toolError('HOST_UNREACHABLE', 'neither interface answered', detail);
    expect(result.structuredContent.detail).toEqual(detail);
    expect(result.content[0].text.startsWith('[HOST_UNREACHABLE] ')).toBe(true);
  });
});
