import { describe, it, expect } from 'vitest';
import {
  defenderRealtimeSetCommand,
  encodePs,
  extractJson,
  firewallAddRuleCommand,
  firewallRemoveRuleCommand,
  firewallSetProfileCommand,
  updateTriggerCommand,
} from '../src/transports/windows.js';

// The built command is `powershell -NoProfile -NonInteractive -EncodedCommand <b64>`;
// decode the script back out to assert on what PowerShell will actually run.
const decode = (cmd: string): string => Buffer.from(cmd.split(' ')[4], 'base64').toString('utf16le');

describe('encodePs / psCommand', () => {
  it('round-trips a script through base64 UTF-16LE', () => {
    const script = 'Get-NetFirewallProfile | ConvertTo-Json -Compress';
    expect(Buffer.from(encodePs(script), 'base64').toString('utf16le')).toBe(script);
  });

  it('handles non-ASCII without mangling (the reason for utf16le)', () => {
    const script = "Write-Output 'café ok'";
    expect(Buffer.from(encodePs(script), 'base64').toString('utf16le')).toBe(script);
  });

  it('wraps in -EncodedCommand so it runs regardless of the default shell', () => {
    expect(firewallRemoveRuleCommand('x')).toMatch(/^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/);
  });
});

describe('extractJson', () => {
  it('parses a leading array', () => {
    expect(extractJson('[{"a":1},{"b":2}]')).toEqual([{ a: 1 }, { b: 2 }]);
  });
  it('skips a leading log line and parses the object', () => {
    expect(extractJson('INFO: starting\n{"ok":true}')).toEqual({ ok: true });
  });
  it('returns null when nothing parses', () => {
    expect(extractJson('no json here')).toBeNull();
  });
  it('parses a valid payload followed by trailing text (the bracket-balance fix)', () => {
    // The old code JSON.parsed the whole tail, so a status line after the JSON
    // made an otherwise-valid payload fail. These fail before / pass after.
    expect(extractJson('{"ok":true}\nDONE')).toEqual({ ok: true });
    expect(extractJson('warn: thing [x]\n{"a":[1,2]} tail')).toEqual({ a: [1, 2] });
  });
});

describe('firewall command builders', () => {
  it('validates the profile name and encodes the write+read-back', () => {
    expect(() => firewallSetProfileCommand('Nope', true)).toThrow(/profile/);
    expect(decode(firewallSetProfileCommand('Private', true))).toContain("-Name 'Private' -Enabled True");
    expect(decode(firewallSetProfileCommand('Public', false))).toContain('-Enabled False');
  });

  it('validates port, protocol, and quotes for add_allow_rule', () => {
    expect(() => firewallAddRuleCommand('ok', 70000, 'tcp')).toThrow(/port/);
    expect(() => firewallAddRuleCommand('ok', 443, 'icmp')).toThrow(/protocol/);
    expect(() => firewallAddRuleCommand("bad'name", 443, 'tcp')).toThrow(/quotes/);
  });

  it('add_allow_rule reads the rule back and remove_rule reports REMOVED', () => {
    const add = decode(firewallAddRuleCommand('ctrl', 8080, 'tcp'));
    expect(add).toContain('New-NetFirewallRule');
    expect(add).toContain('Get-NetFirewallRule');
    expect(decode(firewallRemoveRuleCommand('ctrl'))).toContain("'REMOVED'");
  });
});

describe('other builders', () => {
  it('defender realtime_set writes the inverse Disable flag', () => {
    expect(decode(defenderRealtimeSetCommand(true))).toContain('-DisableRealtimeMonitoring $false');
    expect(decode(defenderRealtimeSetCommand(false))).toContain('-DisableRealtimeMonitoring $true');
  });

  it('update trigger maps verbs to usoclient and rejects unknown', () => {
    expect(decode(updateTriggerCommand('scan'))).toContain('usoclient StartScan');
    expect(() => updateTriggerCommand('nuke')).toThrow(/unknown update action/);
  });
});
