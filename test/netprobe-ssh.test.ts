import { describe, it, expect } from 'vitest';
import { classifySshState } from '../src/transports/netprobe.js';

// The bug this pins: a just-booted Windows box answers ICMP and opens RDP before
// sshd binds :22, so the TCP connect gets ECONNREFUSED. That is proof the host is
// ALIVE — it must classify as 'refused', not 'down'. Treating it as down is what
// made an operator (and this agent) conclude "msi is off" and reach for WoL.
describe('classifySshState', () => {
  it('a refused port on a pinging host is REFUSED, not down (host is up)', () => {
    expect(classifySshState(true, { ok: false, error: 'connect ECONNREFUSED 10.255.0.11:22' })).toBe('refused');
  });

  it('ready when the probe connects', () => {
    expect(classifySshState(true, { ok: true })).toBe('ready');
  });

  it('auth when the daemon answered but the credential was rejected', () => {
    expect(classifySshState(true, { ok: false, error: 'All configured authentication methods failed' })).toBe('auth');
    expect(classifySshState(true, { ok: false, error: 'no matching key' })).toBe('auth');
  });

  it('filtered when a pinging host times out or resets on the port', () => {
    expect(classifySshState(true, { ok: false, error: 'connect ETIMEDOUT' })).toBe('filtered');
    expect(classifySshState(true, { ok: false, error: 'Timed out while waiting for handshake' })).toBe('filtered');
    expect(classifySshState(true, { ok: false, error: 'connect ECONNRESET' })).toBe('filtered');
  });

  it('down when nothing answered ping, regardless of the probe', () => {
    expect(classifySshState(false, { ok: false, error: 'connect ECONNREFUSED 10.255.0.11:22' })).toBe('down');
    expect(classifySshState(false, null)).toBe('down');
  });

  it('down when the host is up but no probe was run', () => {
    expect(classifySshState(true, null)).toBe('down');
  });

  it('unknown errors surface as error', () => {
    expect(classifySshState(true, { ok: false, error: 'socket hang up weirdly' })).toBe('error');
  });
});
