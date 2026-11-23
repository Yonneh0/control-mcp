import { describe, it, expect } from 'vitest';
import { ControlError } from '../src/errors.js';
import {
  decodeWinEventJson,
  eventQueryCommand,
  isSelfSeverService,
  SELF_SEVER_SERVICES,
  serviceChangeCommand,
  serviceStatusCommand,
} from '../src/transports/windows.js';

// Same decode trick as windows.test.ts: the built command is
// `powershell -NoProfile -NonInteractive -EncodedCommand <b64>`; decode the
// script back out to assert on what PowerShell will actually run.
const decode = (cmd: string): string => Buffer.from(cmd.split(' ')[4], 'base64').toString('utf16le');

// Event-payload fixtures ride the same base64-of-UTF8 side channel the builder
// emits on the wire.
const b64 = (x: unknown): string => Buffer.from(JSON.stringify(x), 'utf8').toString('base64');

describe('serviceStatusCommand', () => {
  it('always array-wraps and emits compressed JSON', () => {
    const s = decode(serviceStatusCommand());
    expect(s).toContain('ConvertTo-Json -Compress');
    expect(s).toContain('@(');
    expect(s).toContain('$ErrorActionPreference=');
    // StartType is joined from CIM because Get-Service has no StartType on PS 5.1.
    expect(s).toContain('Get-CimInstance Win32_Service');
    expect(s).toContain('StartType');
  });

  it('filters by -Name when a service is given', () => {
    expect(decode(serviceStatusCommand('spooler'))).toContain("-Name 'spooler'");
  });

  it('filters by Status for running/stopped', () => {
    expect(decode(serviceStatusCommand(undefined, 'running'))).toContain("Where-Object { $_.Status -eq 'Running' }");
    expect(decode(serviceStatusCommand(undefined, 'stopped'))).toContain("Where-Object { $_.Status -eq 'Stopped' }");
  });

  it('combines name and state filters', () => {
    const s = decode(serviceStatusCommand('spooler', 'stopped'));
    expect(s).toContain("-Name 'spooler'");
    expect(s).toContain("Where-Object { $_.Status -eq 'Stopped' }");
  });
});

describe('serviceChangeCommand', () => {
  it('start runs Start-Service and reads the state back', () => {
    const s = decode(serviceChangeCommand('spooler', 'start'));
    expect(s).toContain("Start-Service -Name 'spooler'");
    expect(s).toContain("Get-Service -Name 'spooler'");
    expect(s).toContain('ConvertTo-Json -Compress');
    expect(s).toContain("$ErrorActionPreference='Stop'");
  });

  it('stop runs Stop-Service with the read-back, restart runs Restart-Service', () => {
    const stop = decode(serviceChangeCommand('spooler', 'stop'));
    expect(stop).toContain("Stop-Service -Name 'spooler'");
    expect(stop).toContain("Get-Service -Name 'spooler'");
    const restart = decode(serviceChangeCommand('spooler', 'restart'));
    expect(restart).toContain("Restart-Service -Name 'spooler'");
    expect(restart).toContain("Get-Service -Name 'spooler'");
  });
});

describe('needServiceName (via the builders)', () => {
  it('doubles embedded single quotes for the -Name literal', () => {
    expect(decode(serviceChangeCommand("a'b", 'start'))).toContain("-Name 'a''b'");
    expect(decode(serviceStatusCommand("a'b"))).toContain("-Name 'a''b'");
  });

  it('refuses newlines and tabs (control chars signal injection)', () => {
    expect(() => serviceChangeCommand('sp\nooler', 'start')).toThrow(ControlError);
    expect(() => serviceChangeCommand('sp\r\nooler', 'stop')).toThrow(ControlError);
    expect(() => serviceChangeCommand('sp\tooler', 'restart')).toThrow(ControlError);
    expect(() => serviceChangeCommand('sp\nooler', 'start')).toThrow(/control characters/);
  });

  it('allows semicolons and spaces (valid service/display names) but keeps them inside the quoted literal', () => {
    const s = decode(serviceChangeCommand('my srv; name', 'start'));
    expect(s).toContain("-Name 'my srv; name'");
  });

  it('refuses empty and >200-char names', () => {
    expect(() => serviceChangeCommand('', 'start')).toThrow(ControlError);
    expect(() => serviceChangeCommand('   ', 'start')).toThrow(ControlError);
    expect(() => serviceChangeCommand('s'.repeat(201), 'start')).toThrow(/200/);
  });
});

describe('isSelfSeverService', () => {
  it('matches the blocklist case-insensitively', () => {
    for (const n of ['SSHD', 'sshd', 'termservice', 'TerminalServices', 'ssh-agent', 'WinRM', 'winrm']) {
      expect(isSelfSeverService(n)).toBe(true);
    }
  });

  it('does not match ordinary services', () => {
    for (const n of ['Spooler', 'wuauserv', 'BITS']) {
      expect(isSelfSeverService(n)).toBe(false);
    }
  });

  it('exposes the blocklist itself', () => {
    expect(SELF_SEVER_SERVICES).toContain('sshd');
    expect(isSelfSeverService(SELF_SEVER_SERVICES[0])).toBe(true);
  });
});

describe('eventQueryCommand', () => {
  it('emits the base64-of-UTF8 side channel with the requested log/levels/count', () => {
    const s = decode(eventQueryCommand('System', [1, 2, 3], 20));
    expect(s).toContain('Get-WinEvent');
    expect(s).toContain("LogName='System'");
    expect(s).toContain('Level=1,2,3');
    expect(s).toContain('-MaxEvents 20');
    expect(s).toContain('ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) }');
  });

  it('bounds count at 200 and rejects out-of-range', () => {
    expect(() => eventQueryCommand('System', [1], 201)).toThrow(/count/);
    expect(() => eventQueryCommand('System', [1], 0)).toThrow(/count/);
    expect(() => eventQueryCommand('System', [1], 1.5)).toThrow(/count/);
  });

  it('rejects levels outside 1..5 and empty level lists', () => {
    expect(() => eventQueryCommand('System', [1, 6], 20)).toThrow(/levels/);
    expect(() => eventQueryCommand('System', [0], 20)).toThrow(/levels/);
    expect(() => eventQueryCommand('System', [], 20)).toThrow(/levels/);
  });

  it('rejects path-ish / injection log names but accepts ETW channel names with "/"', () => {
    expect(() => eventQueryCommand('..\\evil', [1], 20)).toThrow(ControlError); // backslash
    expect(() => eventQueryCommand("System'; Get-Process", [1], 20)).toThrow(ControlError); // quote + semicolon
    expect(() => eventQueryCommand('System`x', [1], 20)).toThrow(ControlError); // backtick
    // ETW channel names carry '/', now supported; the value is single-quoted into
    // PowerShell and quotes/$/backtick/backslash/newline stay rejected above.
    expect(() => eventQueryCommand('Microsoft-Windows-PowerShell/Operational', [4], 1)).not.toThrow();
  });
});

describe('decodeWinEventJson', () => {
  it('returns the array for base64-of-UTF8 JSON', () => {
    const events = [{ Id: 7034, Level: 2 }, { Id: 7031, Level: 2 }];
    expect(decodeWinEventJson(b64(events))).toEqual(events);
  });

  it('wraps a single object as a one-item array (PS unwraps single pipeline items)', () => {
    const one = { Id: 7000, Level: 3 };
    expect(decodeWinEventJson(b64(one))).toEqual([one]);
  });

  it('maps empty stdout to [] — genuinely no events, not an error', () => {
    expect(decodeWinEventJson('')).toEqual([]);
    expect(decodeWinEventJson('\r\n  \n')).toEqual([]);
  });

  it('maps non-base64/non-JSON text (e.g. a PowerShell error) to null, NOT []', () => {
    expect(decodeWinEventJson('This is not base64 json')).toBeNull();
    expect(
      decodeWinEventJson('Get-WinEvent : The log was not found.\r\nAt line:2 char:1'),
    ).toBeNull();
  });

  it('survives SSH console line-wrapping inside the base64', () => {
    const events = [{ Id: 1, Message: 'x'.repeat(200) }];
    const wrapped = b64(events).replace(/(.{20})/g, '$1\r\n');
    expect(decodeWinEventJson(wrapped)).toEqual(events);
  });

  it('round-trips a realistic event with unicode and a newline in Message', () => {
    const ev = {
      TimeCreated: '2026-11-23T10:00:00.0000000Z',
      Id: 7034,
      Level: 2,
      ProviderName: 'Service Control Manager',
      Message: 'Der Dienst "Druckspooler" wurde unerwartet beendet.\nCafé — ünïcode ✓ line two',
    };
    expect(decodeWinEventJson(b64([ev]))).toEqual([ev]);
  });
});
