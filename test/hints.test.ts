import { describe, it, expect } from 'vitest';
import { DEFAULT_HINTS, execOutcomeHint } from '../src/hints.js';
import { toolError } from '../src/errors.js';
import type { ErrCode } from '../src/errors.js';

// The compile-time half of the self-learning contract. Indexing every member of
// ErrCode as a key here means a new code cannot join the union without either a
// hint in the table or a failing typecheck on this literal — the promise is that
// no error ever ships without a next step, so the union itself is the test input.
const EVERY_CODE: Record<ErrCode, true> = {
  AUTH_FAILED: true,
  HOST_UNREACHABLE: true,
  CAPABILITY_UNAVAILABLE: true,
  TRANSPORT_SEVERED_RISK: true,
  TIMEOUT: true,
  SESSION_GONE: true,
  BAD_ARGS: true,
  REMOTE_ERROR: true,
  INTERNAL: true,
};

const CODE_NAMES = Object.keys(EVERY_CODE) as ErrCode[];
const CODES: Array<{ code: ErrCode }> = CODE_NAMES.map((code) => ({ code }));

// A hint is only worth sending if it names something the caller can act on: a
// tool to re-probe with, a knob to turn, or the narrower next step for the codes
// where no single tool fits (read stdout/stderr after a remote failure, retry
// once on an internal one). Deliberately not exact wording — the table may be
// reworded, the anchor must stay.
const RECOVERY_CONCEPTS = [
  'host_status',
  'host_list',
  'shell_open',
  'shell_list',
  'tools/list',
  'wol_wake',
  'arp_table',
  'config',
  'timeoutMs',
  'override',
  'overwrite',
  'stdout',
  'stderr',
  'retry',
  'exit',
];

// Boilerplate we would rather have no hint than receive: filler that sounds
// helpful and tells a model nothing it can do.
const PLACEHOLDERS = ['todo', 'tbd', 'coming soon', 'not implemented', 'see docs', 'unknown error'];

describe('DEFAULT_HINTS', () => {
  // Runtime mirror of the type-level check: the table has exactly the codes the
  // union has, so a hint added for a code that no longer exists is caught too.
  it('covers every ErrCode and nothing else', () => {
    expect(Object.keys(DEFAULT_HINTS).sort()).toEqual([...CODE_NAMES].sort());
  });

  it.each(CODES)('$code has a hint long enough to be a sentence, not a label', (row) => {
    const hint = DEFAULT_HINTS[row.code];
    expect(typeof hint).toBe('string');
    expect(hint.trim().length).toBeGreaterThan(20);
  });

  // Restating the code is the most convincing form of boilerplate: it parses as
  // guidance and carries no information the [CODE] prefix did not already carry.
  it.each(CODES)('$code is not answered with its own name', (row) => {
    const hint = DEFAULT_HINTS[row.code];
    expect(hint).not.toBe(row.code);
    expect(hint.toLowerCase()).not.toBe(row.code.toLowerCase());
    expect(hint.toLowerCase()).not.toBe(row.code.toLowerCase().replace(/_/g, ' '));
  });

  it.each(CODES)('$code points at something the caller can act on', (row) => {
    const hint = DEFAULT_HINTS[row.code];
    expect(RECOVERY_CONCEPTS.some((concept) => hint.includes(concept))).toBe(true);
    expect(PLACEHOLDERS.some((filler) => hint.toLowerCase().includes(filler))).toBe(false);
  });

  // Nine identical sentences would satisfy every length check above while
  // proving nothing was learned about the individual failure.
  it('gives each code its own guidance rather than one shared fallback', () => {
    const values = Object.values(DEFAULT_HINTS);
    expect(new Set(values).size).toBe(values.length);
  });
});

describe('execOutcomeHint', () => {
  // A bare "killed by SIGTERM" teaches a model nothing about which knob to turn;
  // the signal and timeoutMs have to arrive together.
  it('names the signal and timeoutMs when a command was killed on its budget', () => {
    const hint = execOutcomeHint('SIGTERM', null) as string;
    expect(typeof hint).toBe('string');
    expect(hint.includes('SIGTERM')).toBe(true);
    expect(hint.includes('timeoutMs')).toBe(true);
  });

  // Some platforms report both; the signal is the part that explains the kill.
  it('still names the signal when an exit code comes back with it', () => {
    const hint = execOutcomeHint('SIGKILL', 137) as string;
    expect(hint.includes('SIGKILL')).toBe(true);
    expect(hint.includes('timeoutMs')).toBe(true);
  });

  // A non-zero code is the target program talking, not the transport failing;
  // conflating the two sends a caller to re-probe the network.
  it('marks a non-zero code as the target program exit and quotes the number', () => {
    const hint = execOutcomeHint(null, 5) as string;
    expect(typeof hint).toBe('string');
    expect(hint.includes('exit')).toBe(true);
    expect(hint.includes('5')).toBe(true);
  });

  // Success must stay silent: guidance on a clean exit trains the caller to
  // distrust the channel, and a half-known outcome is not a failure to explain.
  it('returns null for a clean exit and for an outcome with neither signal nor code', () => {
    expect(execOutcomeHint(null, 0)).toBeNull();
    expect(execOutcomeHint(null, null)).toBeNull();
  });
});

describe('toolError falls back to DEFAULT_HINTS', () => {
  it.each(CODES)('$code carries its table entry when the call site passes no hint', (row) => {
    const result = toolError(row.code, 'the call failed');
    expect(result.structuredContent.hint).toBe(DEFAULT_HINTS[row.code]);
    // The text line is the copy single-block clients actually see, and the
    // newline marker is what separates the diagnosis from the recovery step.
    expect(result.content[0].text.includes(`\n→ ${DEFAULT_HINTS[row.code]}`)).toBe(true);
    expect(result.content[0].text.startsWith(`[${row.code}] `)).toBe(true);
  });

  it('lets the call site replace the table entry with a more specific hint', () => {
    const code: ErrCode = 'HOST_UNREACHABLE';
    const custom = 'host "n100" is only declared with an alternate address; retry with host=press-room-01';
    const result = toolError(code, 'no interface answered for 10.0.0.7', { address: '10.0.0.7' }, custom);
    expect(result.structuredContent.hint).toBe(custom);
    expect(result.content[0].text.endsWith(`\n→ ${custom}`)).toBe(true);
    expect(result.content[0].text.includes(DEFAULT_HINTS[code])).toBe(false);
  });

  // Detail and the safety-net hint are independent: a call site that takes the
  // trouble to attach a detail object must not have to write guidance as well.
  it('keeps the fallback hint alongside a detail object', () => {
    const code: ErrCode = 'TIMEOUT';
    const detail = { command: 'Get-Process', timeoutMs: 30000, host: 'n100' };
    const result = toolError(code, 'the command did not finish within its budget', detail);
    expect(result.structuredContent.detail).toEqual(detail);
    expect(result.structuredContent.hint).toBe(DEFAULT_HINTS[code]);
    expect(result.structuredContent.hint).toContain('timeoutMs');
  });
});
