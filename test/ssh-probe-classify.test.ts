import { describe, it, expect } from 'vitest';
import { probeResultFromError } from '../src/transports/ssh.js';

// Pins two honesty rules of the SSH probe result mapping (ssh.ts probe()).
describe('probeResultFromError', () => {
  it('an authentication failure is NEVER ok:true (never reported as "ready")', () => {
    // Old bug: probe() returned { ok: true, error: 'auth' } on auth failure, and
    // classifySshState mapped ok:true straight to 'ready' — so a host listening
    // with the WRONG credential was reported as "ssh: READY — service listening
    // AND authenticating", a credential we never resolved. Must be ok:false.
    const r = probeResultFromError('All configured authentication methods failed', true);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/authentication/i);
  });

  it('a handshake reset AFTER the port opened is a listening verdict (tcpOpen true)', () => {
    const r = probeResultFromError('read ECONNRESET', true);
    expect(r.ok).toBe(false);
    expect(r.tcpOpen).toBe(true);
    expect(r.error).toMatch(/handshake incomplete/i);
  });

  it('a TCP-level failure (port not open) keeps the raw error and tcpOpen false', () => {
    const r = probeResultFromError('connect ECONNREFUSED', false);
    expect(r.ok).toBe(false);
    expect(r.tcpOpen).toBe(false);
    expect(r.error).toContain('ECONNREFUSED');
  });
});
