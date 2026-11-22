import { describe, it, expect } from 'vitest';
import { classifyRdp, pickInterface } from '../src/capability.js';
import type { RdpProbeInput, RdpUnreason, InterfacePick } from '../src/capability.js';

// The decision table. `code` is the machine-readable reason; `reason` is prose
// for the operator, so these tests assert the code and only the facts the prose
// is required to carry.
const REFUSALS: Array<{ why: string; input: RdpProbeInput; code: RdpUnreason }> = [
  {
    why: 'declared false outranks every probe',
    input: { declared: false, tcpOpen: false, sshAlive: false },
    code: 'not-declared',
  },
  {
    why: 'declared false outranks a listener that is even open',
    input: { declared: false, tcpOpen: true, sshAlive: true, blankPasswordAccount: true, limitBlankPasswordUse: 1, nlaRequired: true },
    code: 'not-declared',
  },
  {
    why: 'nothing answered on either interface',
    input: { declared: true, tcpOpen: false, sshAlive: false },
    code: 'host-unreachable',
  },
  {
    // A host that is down is not a policy problem, so the blank-password signal
    // must not outrank it.
    why: 'host-unreachable outranks the blank-password signal',
    input: { declared: true, tcpOpen: false, sshAlive: false, blankPasswordAccount: true, limitBlankPasswordUse: 1, nlaRequired: true },
    code: 'host-unreachable',
  },
  {
    why: 'ssh answered but the listener is closed',
    input: { declared: true, tcpOpen: false, sshAlive: true },
    code: 'rdp-port-closed',
  },
  {
    why: 'a closed listener outranks the blank-password signal',
    input: { declared: true, tcpOpen: false, sshAlive: true, blankPasswordAccount: true, limitBlankPasswordUse: 1, nlaRequired: true },
    code: 'rdp-port-closed',
  },
  {
    why: 'the blank password was detected without reading the registry',
    input: { declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true },
    code: 'blank-password-policy',
  },
  {
    why: 'the n100 shape: open listener, live ssh, blank account, limit enforced, NLA required',
    input: { declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true, limitBlankPasswordUse: 1, nlaRequired: true },
    code: 'blank-password-policy',
  },
  {
    // The blank-password refusal is checked first; a limit value of 0 only means
    // policy is not enforced, which is not the same as the account being blank.
    why: 'a blank account refuses even with LimitBlankPasswordUse=0',
    input: { declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true, limitBlankPasswordUse: 0, nlaRequired: false },
    code: 'blank-password-policy',
  },
  {
    why: 'NLA demanded and an explicit absence of any credential',
    input: { declared: true, tcpOpen: true, sshAlive: true, nlaRequired: true, hasCredential: false },
    code: 'nla-credential-missing',
  },
];

// Each of these is the only rule that could refuse it, so an answer of "yes"
// here means no rule fired by accident.
const ACCEPTANCES: Array<{ why: string; input: RdpProbeInput }> = [
  { why: 'an open listener and a live ssh answer', input: { declared: true, tcpOpen: true, sshAlive: true } },
  // limitBlankPasswordUse on its own is a registry value, not a refusal: the
  // account has to be blank for policy to matter.
  { why: 'the blank-password limit is set but the account is not blank', input: { declared: true, tcpOpen: true, sshAlive: true, limitBlankPasswordUse: 1 } },
  // A missing credential is only refused when hasCredential is explicitly false.
  { why: 'NLA is required and no credential was reported missing', input: { declared: true, tcpOpen: true, sshAlive: true, nlaRequired: true } },
  { why: 'NLA is required and a credential resolves', input: { declared: true, tcpOpen: true, sshAlive: true, nlaRequired: true, hasCredential: true } },
  { why: 'no credential but NLA is not required', input: { declared: true, tcpOpen: true, sshAlive: true, nlaRequired: false, hasCredential: false } },
  // An open listener with no ssh reply is still RDP: only both-down is down.
  { why: 'the listener is open and only ssh is silent', input: { declared: true, tcpOpen: true, sshAlive: false } },
];

describe('classifyRdp', () => {
  it.each(REFUSALS)('$why: refuses with code $code', (row) => {
    const verdict = classifyRdp(row.input);
    expect(verdict.available).toBe(false);
    expect(verdict.code).toBe(row.code);
  });

  it.each(ACCEPTANCES)('$why: reports rdp as available', (row) => {
    expect(classifyRdp(row.input).available).toBe(true);
  });

  describe('the blank-password refusal carries its proof', () => {
    const n100: RdpProbeInput = { declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true, limitBlankPasswordUse: 1, nlaRequired: true };

    it('names LimitBlankPasswordUse and System error 1327', () => {
      const verdict = classifyRdp(n100);
      expect(verdict.available).toBe(false);
      expect(verdict.code).toBe('blank-password-policy');
      expect(verdict.reason).toContain('LimitBlankPasswordUse');
      expect(verdict.reason).toContain('1327');
      expect(verdict.reason).toContain('net use');
      expect(verdict.reason).toContain('UserAuthentication=1');
      expect(verdict.reason).toContain('Not a transport problem');
    });

    it('hands back the probe that produced the verdict', () => {
      const verdict = classifyRdp(n100);
      expect(verdict.evidence).toEqual({ declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true, limitBlankPasswordUse: 1, nlaRequired: true });
    });

    it('still names the policy when the registry value was unreadable', () => {
      const verdict = classifyRdp({ declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true });
      expect(verdict.available).toBe(false);
      expect(verdict.reason).toContain('typically LimitBlankPasswordUse');
      // The 1327 proof text is only claimed when the probe read lbp=1.
      expect(verdict.reason).not.toContain('1327');
    });
  });

  describe('the blank-password prose says only what the probe observed', () => {
    const blank: RdpProbeInput = { declared: true, tcpOpen: true, sshAlive: true, blankPasswordAccount: true };

    it('names the registry value when the probe read it as enforced', () => {
      const verdict = classifyRdp({ ...blank, limitBlankPasswordUse: 1 });
      expect(verdict.code).toBe('blank-password-policy');
      expect(verdict.reason).toContain('LimitBlankPasswordUse=1 (Windows default)');
    });

    it('hedges the registry when the probe did not read it', () => {
      const verdict = classifyRdp({ ...blank, nlaRequired: true });
      expect(verdict.available).toBe(false);
      expect(verdict.code).toBe('blank-password-policy');
      expect(verdict.reason).toContain('typically LimitBlankPasswordUse');
      // "Windows default" is only claimed when the value was actually observed.
      expect(verdict.reason.includes('Windows default')).toBe(false);
      expect(verdict.reason).toContain('(UserAuthentication=1)');
    });

    it('hedges the registry when the probe read a value that is not enforced', () => {
      const verdict = classifyRdp({ ...blank, limitBlankPasswordUse: 0 });
      expect(verdict.code).toBe('blank-password-policy');
      expect(verdict.reason).toContain('typically LimitBlankPasswordUse');
      expect(verdict.reason.includes('Windows default')).toBe(false);
    });

    it('only mentions NLA when the probe says it is required', () => {
      expect(classifyRdp(blank).reason.includes('UserAuthentication')).toBe(false);
    });
  });

  it('attaches no evidence to an answer of yes', () => {
    // Only refusals carry evidence: an availability answer has nothing to cite.
    expect(classifyRdp({ declared: true, tcpOpen: true, sshAlive: true }).evidence).toBeUndefined();
  });
});

describe('pickInterface', () => {
  const PICKS: Array<{ why: string; primary: string; alternates: string[]; reachable: Record<string, boolean>; expected: InterfacePick }> = [
    { why: 'the primary answers and there is nothing to fall back to', primary: '10.0.0.7', alternates: [], reachable: { '10.0.0.7': true }, expected: { address: '10.0.0.7', degraded: false } },
    { why: 'the primary answers even though an alternate would', primary: '10.0.0.7', alternates: ['10.0.0.9'], reachable: { '10.0.0.7': true, '10.0.0.9': true }, expected: { address: '10.0.0.7', degraded: false } },
    { why: 'the primary answers ahead of a longer alternate list', primary: '10.0.0.7', alternates: ['10.0.0.9', '10.0.0.11'], reachable: { '10.0.0.7': true, '10.0.0.9': true }, expected: { address: '10.0.0.7', degraded: false } },
    { why: 'a down primary falls to the only alternate, flagged degraded', primary: '10.0.0.7', alternates: ['10.0.0.9'], reachable: { '10.0.0.7': false, '10.0.0.9': true }, expected: { address: '10.0.0.9', degraded: true } },
    { why: 'the first reachable alternate wins over a later one', primary: '10.0.0.7', alternates: ['10.0.0.9', '10.0.0.11'], reachable: { '10.0.0.7': false, '10.0.0.9': false, '10.0.0.11': true }, expected: { address: '10.0.0.11', degraded: true } },
    { why: 'a primary nobody probed is treated as unreachable', primary: '10.0.0.7', alternates: ['10.0.0.9', '10.0.0.11'], reachable: { '10.0.0.9': true, '10.0.0.11': true }, expected: { address: '10.0.0.9', degraded: true } },
  ];

  it.each(PICKS)('$why: picks the best reachable interface', (row) => {
    expect(pickInterface(row.primary, row.alternates, row.reachable)).toEqual(row.expected);
  });

  it('returns no interface when the primary and every alternate are down', () => {
    expect(pickInterface('10.0.0.7', [], { '10.0.0.7': false })).toBeNull();
    expect(pickInterface('10.0.0.7', ['10.0.0.9', '10.0.0.11'], { '10.0.0.7': false, '10.0.0.9': false, '10.0.0.11': false })).toBeNull();
    // A primary nobody probed is not assumed reachable.
    expect(pickInterface('10.0.0.7', ['10.0.0.9'], { '10.0.0.9': false })).toBeNull();
  });

  it('does not offer an alternate that is not in the alternates list', () => {
    expect(pickInterface('10.0.0.7', [], { '10.0.0.7': false, '10.0.0.9': true })).toBeNull();
  });

  describe('reachability is an own property, not a prototype lookup', () => {
    it('does not mistake an inherited key for a reachable address', () => {
      // Any plain object inherits a truthy `constructor` from Object.prototype,
      // so a bare `reachable[name]` test would answer "reachable" here.
      const nobodyProbed: Record<string, boolean> = {};
      expect(pickInterface('constructor', [], nobodyProbed)).toBeNull();
      expect(pickInterface('constructor', ['valueOf', 'toString'], nobodyProbed)).toBeNull();
      expect(pickInterface('10.0.0.7', ['constructor'], { '10.0.0.7': false })).toBeNull();
    });

    it('still honours an own key that happens to be named constructor', () => {
      const own = JSON.parse('{"constructor": true}') as Record<string, boolean>;
      expect(pickInterface('constructor', [], own)).toEqual({ address: 'constructor', degraded: false });
    });
  });
});
