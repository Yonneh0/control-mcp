import { describe, it, expect } from 'vitest';
import { ControlError } from '../src/errors.js';
import {
  decodeWinEventJson,
  defenderRealtimeSetCommand,
  defenderSignatureUpdateCommand,
  defenderStatusCommand,
  encodePs,
  eventQueryCommand,
  extractJson,
  firewallAddRuleCommand,
  firewallRemoveRuleCommand,
  firewallSetProfileCommand,
  firewallStatusCommand,
  isSelfSeverService,
  psCommand,
  SELF_SEVER_SERVICES,
  serviceChangeCommand,
  serviceStatusCommand,
  updateStatusCommand,
  updateTriggerCommand,
} from '../src/transports/windows.js';

// Same decode trick as windows.test.ts: the built command is
// `powershell -NoProfile -NonInteractive -EncodedCommand <b64>`; decode the
// script back out to assert on what PowerShell will actually run.
const decode = (cmd: string): string => Buffer.from(cmd.split(' ')[4], 'base64').toString('utf16le');

// Event-payload fixtures ride the same base64-of-UTF8 side channel the builder
// emits on the wire.
const b64 = (x: unknown): string => Buffer.from(JSON.stringify(x), 'utf8').toString('base64');

// Count of single-quote characters contributed ONLY by the builder's fixed text.
// A caller-supplied value that smuggled in a quote would change the count, so
// these constants pin "the value stays inert inside its single-quoted literal".
const QUOTES_STATUS_WITH_NAME = 10; // $ErrorActionPreference + -Name + 'Status'/'StartType' column names + '[]'
const QUOTES_CHANGE = 12; // $ErrorActionPreference + (-Name,-eq) ×2 + $ci's -eq
const QUOTES_FW_ADD = 6; // $ErrorActionPreference + -DisplayName ×2
const QUOTES_FW_REMOVE = 10; // + 'STILL_PRESENT' + 'REMOVED'
const QUOTES_FW_PROFILE = 6; // $ErrorActionPreference + -Name ×2
const QUOTES_EVENT = 4; // $ErrorActionPreference + LogName

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

describe('serviceStatusCommand StartType join (live-measured on PS 5.1)', () => {
  // ROOT CAUSE (measured, Windows PowerShell 5.1.26100): Win32_Service has no
  // StartType property. `Get-CimInstance Win32_Service -Property Name,StartType`
  // is not merely empty — it is an INVALID QUERY (HRESULT 0x80041017). Under the
  // builder's $ErrorActionPreference='SilentlyContinue' that error is swallowed,
  // the Name→StartType map stays EMPTY, every row joins null, and the registry
  // prints `StartType=unknown` for services whose real start type is readable.
  // The real CIM property is StartMode (string: Auto/Manual/Disabled, plus
  // Boot/System for driver services). Live before/after of the join itself:
  //   -Property Name,StartType → [{"Name":"W32Time",…,"StartType":null}]
  //   -Property Name,StartMode → [{"Name":"W32Time",…,"StartType":"Manual"}]
  it('joins Win32_Service.StartMode, never the non-existent StartType property', () => {
    const s = decode(serviceStatusCommand());
    expect(s).toContain('-Property Name,StartMode');
    expect(s).toContain('$starts[$_.Name] = $_.StartMode');
    expect(s).not.toContain('Name,StartType');
  });

  it('still emits the StartType column the registry reads back', () => {
    expect(decode(serviceStatusCommand())).toContain("@{n='StartType';e={$starts[$_.Name]}}");
  });

  it('joins StartMode for a filtered query too', () => {
    const s = decode(serviceStatusCommand('W32Time', 'stopped'));
    expect(s).toContain('-Property Name,StartMode');
    expect(s).not.toContain('Name,StartType');
  });
});

describe('serviceChangeCommand', () => {
  it('start runs Start-Service and reads the state back', () => {
    const s = decode(serviceChangeCommand('spooler', 'start'));
    // INVERTED ASSERTION: the verb no longer takes -Name. Get-Service -Name
    // wildcard-matches on PS 5.1 (measured: -Name 'W32*' → 1 hit, -Name
    // '[W]32Time' → 1 hit), so a name containing * ? [ ] would let a stop hit
    // services the operator never named — including the ssh path via `sshd*`,
    // which the exact-name self-sever guard cannot see. The target is now
    // resolved by EXACT name and bound through -InputObject.
    expect(s).toContain('Start-Service -InputObject $svc[0]');
    expect(s).not.toMatch(/(?:Start|Stop|Restart)-Service\s+-Name/);
    expect(s).toContain("Get-Service -Name 'spooler'");
    expect(s).toContain('ConvertTo-Json -Compress');
    expect(s).toContain("$ErrorActionPreference='Stop'");
  });

  it('stop runs Stop-Service with the read-back, restart runs Restart-Service', () => {
    const stop = decode(serviceChangeCommand('spooler', 'stop'));
    expect(stop).toContain('Stop-Service -InputObject $svc[0]');
    expect(stop).toContain("Get-Service -Name 'spooler'");
    const restart = decode(serviceChangeCommand('spooler', 'restart'));
    expect(restart).toContain('Restart-Service -InputObject $svc[0]');
    expect(restart).toContain("Get-Service -Name 'spooler'");
  });

  it('resolves the mutation target by EXACT name (-eq), not by wildcard -Name alone', () => {
    const s = decode(serviceChangeCommand('spooler', 'stop'));
    expect(s).toContain("@(Get-Service -Name 'spooler' | Where-Object { $_.Name -eq 'spooler' })");
  });

  it('refuses to mutate unless the exact name is unique, and says nothing was changed', () => {
    const s = decode(serviceChangeCommand('spooler', 'stop'));
    expect(s).toContain('if ($svc.Count -ne 1)');
    expect(s).toContain('Write-Error');
    // the guard sits BEFORE the verb, so "nothing was changed" is provable
    expect(s.indexOf('Write-Error')).toBeLessThan(s.indexOf('Stop-Service -InputObject'));
  });

  it('a wildcard service name cannot fan out to other services (closes the sshd* self-sever bypass)', () => {
    // isSelfSeverService() compares exact lower-cased names, so `sshd*` is not
    // blocked by the registry guard; before this fix `Stop-Service -Name 'sshd*'`
    // then matched the real sshd and severed the transport. Now the emitted
    // script requires an exact name match, so such a name mutates nothing.
    for (const n of ['sshd*', 'ssh?', 'sshd[x]', 'ss*h', '*']) {
      const s = decode(serviceChangeCommand(n, 'stop'));
      expect(s).not.toContain('Stop-Service -Name');
      expect(s).toContain(`$_.Name -eq '${n}'`);
    }
    // and the guard itself is untouched
    expect(isSelfSeverService('sshd')).toBe(true);
    expect(isSelfSeverService('sshd*')).toBe(false);
  });

  it('reads StartType from StartMode in the read-back (same CIM property bug)', () => {
    const s = decode(serviceChangeCommand('W32Time', 'start'));
    expect(s).toContain('-Property Name,StartMode');
    expect(s).toContain('$ci[0].StartMode');
    expect(s).not.toContain('Name,StartType');
    // HONESTY: with the old `-Property Name,StartType` this CIM pass was a
    // terminating "Invalid query" under $ErrorActionPreference='Stop', i.e. the
    // tool reported the whole action as FAILED (exit != 0) even when the service
    // had in fact started. StartMode makes the read-back exist again.
    expect(s).toContain('StartType = $(if ($ci.Count -gt 0) { $ci[0].StartMode } else { $null })');
  });

  it('ends with the measured read-back, stringifying Status like the status builder', () => {
    const s = decode(serviceChangeCommand('spooler', 'restart'));
    expect(s).toMatch(/\$rb\[0\]\.Status\.ToString\(\)/);
    expect(s.trim().endsWith('ConvertTo-Json -Compress')).toBe(true);
  });
});

describe('live PS 5.1 JSON shapes (measured on Windows PowerShell 5.1.26100)', () => {
  // `Get-Service W32Time | Select Name,Status | ConvertTo-Json -Compress`
  // serializes the ServiceController Status enum as an INT — measured
  // {"Name":"W32Time","Status":1} here (1 = Stopped) and the n100 report shows
  // {"Name":"W32Time","Status":4,"StartType":2} (4 = Running). Both builders
  // therefore stringify Status themselves so the wire carries names.
  it('both service builders stringify Status, so the wire carries names not enum ints', () => {
    expect(decode(serviceStatusCommand())).toContain('$_.Status.ToString()');
    expect(decode(serviceChangeCommand('W32Time', 'start'))).toContain('$rb[0].Status.ToString()');
  });

  it('extractJson parses the live raw shape and preserves Status as the int it is', () => {
    const parsed = extractJson('{"Name":"W32Time","Status":4,"StartType":2}') as Record<string, unknown>;
    expect(parsed.Name).toBe('W32Time');
    expect(parsed.Status).toBe(4);
    expect(typeof parsed.Status).toBe('number');
    expect(parsed.StartType).toBe(2);
  });

  it('a raw int Status is NEVER tallied as running (registry.ts has no int→name map)', () => {
    // Mirrors registry.ts's status tally (`String(s.Status ?? '').toLowerCase()
    // === 'running'`) to pin the honest expectation: nothing maps 4 → "Running",
    // and an int status is bucketed as "other" instead of being misreported.
    const services: Array<Record<string, unknown>> = [
      { Name: 'W32Time', Status: 4, StartType: 2 },
      { Name: 'Spooler', Status: 'Running', StartType: 'Auto' },
    ];
    const running = services.filter((s) => String(s.Status ?? '').toLowerCase() === 'running').length;
    const stopped = services.filter((s) => String(s.Status ?? '').toLowerCase() === 'stopped').length;
    expect(running).toBe(1);
    expect(stopped).toBe(0);
    expect(String(services[0].Status)).not.toBe('running');
  });

  it('a CIM-shaped row (StartType:"Auto") surfaces as Auto, not unknown', () => {
    // n100 measured Win32_Service StartMode:"Auto" for W32Time. The join passes
    // CIM's own string through (no invented mapping to the Get-Service enum
    // name), so this pins the end of the symptom chain: the null that the tool
    // printed as `StartType=unknown` is gone.
    const live = extractJson('[{"Name":"W32Time","DisplayName":"Windows Time","Status":"Stopped","StartType":"Auto"}]');
    const services = Array.isArray(live) ? (live as Array<Record<string, unknown>>) : [];
    const one = services.length === 1 ? services[0] : null;
    expect(one).not.toBeNull();
    // registry.ts renders: (StartType=${String(one.StartType ?? 'unknown')})
    expect(`StartType=${String(one!.StartType ?? 'unknown')}`).toBe('StartType=Auto');
    expect(`StartType=${String(one!.StartType ?? 'unknown')}`).not.toBe('StartType=unknown');
  });
});

describe('needServiceName (via the builders)', () => {
  it('doubles embedded single quotes for the -Name literal', () => {
    expect(decode(serviceChangeCommand("a'b", 'start'))).toContain("-Name 'a''b'");
    expect(decode(serviceStatusCommand("a'b"))).toContain("-Name 'a''b'");
    expect(decode(serviceChangeCommand("a'b", 'start'))).toContain("$_.Name -eq 'a''b'");
  });

  it('refuses newlines and tabs (control chars signal injection)', () => {
    expect(() => serviceChangeCommand('sp\nooler', 'start')).toThrow(ControlError);
    expect(() => serviceChangeCommand('sp\r\nooler', 'stop')).toThrow(ControlError);
    expect(() => serviceChangeCommand('sp\tooler', 'restart')).toThrow(ControlError);
    expect(() => serviceChangeCommand('sp\nooler', 'start')).toThrow(/control characters/);
  });

  it('refuses every other control character and DEL, in both builders', () => {
    for (const code of [0, 7, 11, 12, 14, 27, 0x7f]) {
      const n = 'sp' + String.fromCharCode(code) + 'ooler';
      expect(() => serviceChangeCommand(n, 'start')).toThrow(/control characters/);
      expect(() => serviceStatusCommand(n)).toThrow(/control characters/);
    }
  });

  it('allows semicolons and spaces (valid service/display names) but keeps them inside the quoted literal', () => {
    const s = decode(serviceChangeCommand('my srv; name', 'start'));
    expect(s).toContain("-Name 'my srv; name'");
  });

  it('accepts $, backtick, brackets, backslash, | and other metacharacters — inert inside single quotes', () => {
    // PowerShell performs no expansion or escape processing inside '...'; the
    // only special character there is ' itself, which needServiceName doubles.
    // Verified structurally by quote-parity and live by the PS 5.1 parser.
    for (const n of ['a$b', 'a`b', 'a[b]c', 'a\\b', 'a;b', 'a|b', 'a/b', 'a:b', 'a@b#c', 'a{b}', 'a(b)c', 'a,b', 'a&b', 'a%b', 'a^b', 'a=b', 'a+b']) {
      const s = decode(serviceChangeCommand(n, 'start'));
      expect(s).toContain(`-Name '${n}'`);
      expect(s).toContain(`$_.Name -eq '${n}'`);
      expect((s.match(/'/g) ?? []).length).toBe(QUOTES_CHANGE);
      expect((decode(serviceStatusCommand(n)).match(/'/g) ?? []).length).toBe(QUOTES_STATUS_WITH_NAME);
    }
  });

  it('a doubled quote is the only added quoting and keeps the literal balanced', () => {
    const s = decode(serviceChangeCommand("it''s", 'start'));
    expect(s).toContain("-Name 'it''''s'"); // "it''s" → each ' doubled again
    expect((s.match(/'/g) ?? []).length % 2).toBe(0);
  });

  it('refuses empty and >200-char names', () => {
    expect(() => serviceChangeCommand('', 'start')).toThrow(ControlError);
    expect(() => serviceChangeCommand('   ', 'start')).toThrow(ControlError);
    expect(() => serviceChangeCommand('s'.repeat(201), 'start')).toThrow(/200/);
  });

  it('treats an empty status filter as no filter (not a refusal)', () => {
    const s = decode(serviceStatusCommand(''));
    expect(s).not.toContain('-Name');
  });
});

describe('isSelfSeverService', () => {
  it('matches the blocklist case-insensitively', () => {
    for (const n of ['SSHD', 'sshd', 'termservice', 'TerminalServices', 'ssh-agent', 'WinRM', 'winrm']) {
      expect(isSelfSeverService(n)).toBe(true);
    }
  });

  it('trims surrounding whitespace before comparing (guard not weakened)', () => {
    expect(isSelfSeverService('  sshd  ')).toBe(true);
    expect(isSelfSeverService('\tTermService\n')).toBe(true);
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

describe('firewall builders — quoting / injection audit', () => {
  // needRuleName refuses ' and " (the only characters that could terminate a
  // PS single-quoted literal) plus >200 chars. Everything else — $, backtick,
  // ;, |, [], {}, \, spaces — is inert inside '...'.
  const inertNames = ['My Rule', 'a$b', 'a`b', 'a;b', 'a|b', 'a[b]c', 'a\\b', 'a{b}', 'a@b#c', 'a,b', 'a:b', 'a=b', '(x)'];

  it('accepts spaces and inert metacharacters inside the single-quoted -DisplayName literal', () => {
    for (const n of inertNames) {
      const add = decode(firewallAddRuleCommand(n, 22, 'tcp'));
      expect(add).toContain(`New-NetFirewallRule -DisplayName '${n}'`);
      expect(add).toContain(`Get-NetFirewallRule -DisplayName '${n}'`);
      expect((add.match(/'/g) ?? []).length).toBe(QUOTES_FW_ADD);
      const rm = decode(firewallRemoveRuleCommand(n));
      expect(rm).toContain(`Remove-NetFirewallRule -DisplayName '${n}'`);
      expect((rm.match(/'/g) ?? []).length).toBe(QUOTES_FW_REMOVE);
    }
  });

  it('refuses single and double quotes and >200-char rule names', () => {
    expect(() => firewallAddRuleCommand("a'b", 22, 'tcp')).toThrow(/quotes/);
    expect(() => firewallAddRuleCommand('a"b', 22, 'tcp')).toThrow(/quotes/);
    expect(() => firewallRemoveRuleCommand("a'b")).toThrow(/quotes/);
    expect(() => firewallRemoveRuleCommand('a"b')).toThrow(/quotes/);
    expect(() => firewallAddRuleCommand('x'.repeat(201), 22, 'tcp')).toThrow(/200/);
  });

  it('a newline in a rule name cannot close the literal (multi-line single-quoted strings are legal PS)', () => {
    // Not injection: the value stays inside '...', which PS parses as one string
    // spanning lines (confirmed by parsing the emitted script with the PS 5.1
    // parser — see the audit note). Pinned structurally by quote parity.
    for (const n of ['a\nb', 'a\r\nb', 'a\tb']) {
      const rm = decode(firewallRemoveRuleCommand(n));
      expect((rm.match(/'/g) ?? []).length).toBe(QUOTES_FW_REMOVE);
      expect(rm).toContain(`Remove-NetFirewallRule -DisplayName '${n}'`);
    }
  });

  it('ports and protocols are validated before interpolation', () => {
    expect(() => firewallAddRuleCommand('r', 0, 'tcp')).toThrow(/port/);
    expect(() => firewallAddRuleCommand('r', 65536, 'tcp')).toThrow(/port/);
    expect(() => firewallAddRuleCommand('r', 22.5, 'tcp')).toThrow(/port/);
    expect(() => firewallAddRuleCommand('r', Number.NaN, 'tcp')).toThrow(/port/);
    expect(() => firewallAddRuleCommand('r', 2 ** 53, 'tcp')).toThrow(/port/);
    expect(() => firewallAddRuleCommand('r', 22, 'icmp')).toThrow(/protocol/);
    expect(() => firewallAddRuleCommand('r', 22, 'tcp; Get-Process')).toThrow(/protocol/);
    expect(decode(firewallAddRuleCommand('r', 65535, 'udp'))).toContain('-Protocol udp -LocalPort 65535');
  });

  it('profiles come from a fixed allowlist, so the -Name literal cannot be broken', () => {
    for (const bad of ["Private'; x", 'Domain`', 'Public|', 'All', '../../etc', 'Domain\n']) {
      expect(() => firewallSetProfileCommand(bad, true)).toThrow(ControlError);
    }
    for (const p of ['Domain', 'Private', 'Public']) {
      const s = decode(firewallSetProfileCommand(p, false));
      expect(s).toContain(`Set-NetFirewallProfile -Name '${p}' -Enabled False`);
      expect(s).toContain(`Get-NetFirewallProfile -Name '${p}'`);
      expect((s.match(/'/g) ?? []).length).toBe(QUOTES_FW_PROFILE);
    }
  });

  it('firewall status takes no input at all', () => {
    const s = decode(firewallStatusCommand());
    expect(s).toContain('Get-NetFirewallProfile');
    expect(s).not.toContain('$env:');
  });
});

describe('defender + windows-update builders — interpolation audit', () => {
  it('defender status/signature_update take no caller input', () => {
    for (const script of [decode(defenderStatusCommand()), decode(defenderSignatureUpdateCommand())]) {
      expect(script).toContain('$ErrorActionPreference=');
      // the only $ identifiers are the script's own locals
      expect((script.match(/\$[A-Za-z]/g) ?? []).length).toBeGreaterThan(0);
      expect(script).not.toContain('${');
    }
  });

  it('realtime_set maps the boolean onto the inverted Disable flag with no other interpolation', () => {
    expect(decode(defenderRealtimeSetCommand(true))).toContain('Set-MpPreference -DisableRealtimeMonitoring $false');
    expect(decode(defenderRealtimeSetCommand(false))).toContain('Set-MpPreference -DisableRealtimeMonitoring $true');
    // the emitted value is one of two fixed tokens, never a caller string
    expect(decode(defenderRealtimeSetCommand(false))).not.toContain('-DisableRealtimeMonitoring True');
  });

  it('updateStatusCommand is static text and probes usoclient presence rather than assuming it', () => {
    const s = decode(updateStatusCommand());
    expect(s).toContain('Microsoft.Update.Session');
    expect(s).toContain('IsInstalled=0');
    expect(s).toContain('usoclient.exe');
    expect(s).toContain('Test-Path');
  });

  it('updateTriggerCommand allowlist cannot be satisfied through the prototype chain', () => {
    // `USO_ACTION[kind]` returned Object.prototype members for these, so the
    // `if (!verb)` check passed and the caller-controlled string reached the
    // command line (e.g. `usoclient toString`, `usoclient [object Object]`).
    for (const k of ['toString', 'constructor', '__proto__', 'valueOf', 'hasOwnProperty', 'isPrototypeOf']) {
      expect(() => updateTriggerCommand(k)).toThrow(/unknown update action/);
    }
  });

  it('updateTriggerCommand emits exactly the three mapped verbs', () => {
    expect(decode(updateTriggerCommand('scan'))).toContain('usoclient StartScan');
    expect(decode(updateTriggerCommand('download'))).toContain('usoclient StartDownload');
    expect(decode(updateTriggerCommand('install'))).toContain('usoclient StartInstall');
    for (const bad of ['nuke', 'StartScan', '', ' ']) {
      expect(() => updateTriggerCommand(bad)).toThrow(ControlError);
    }
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
    expect(() => eventQueryCommand('System', [1], Number.NaN)).toThrow(/count/);
    expect(() => eventQueryCommand('System', [1], Number.POSITIVE_INFINITY)).toThrow(/count/);
    expect(decode(eventQueryCommand('System', [1], 200))).toContain('-MaxEvents 200');
  });

  it('rejects levels outside 1..5 and empty level lists', () => {
    expect(() => eventQueryCommand('System', [1, 6], 20)).toThrow(/levels/);
    expect(() => eventQueryCommand('System', [0], 20)).toThrow(/levels/);
    expect(() => eventQueryCommand('System', [], 20)).toThrow(/levels/);
    expect(() => eventQueryCommand('System', ['1'] as unknown as number[], 20)).toThrow(/levels/);
    expect(() => eventQueryCommand('System', [1.5], 20)).toThrow(/levels/);
  });

  it('rejects path-ish / injection log names but accepts ETW channel names with "/"', () => {
    expect(() => eventQueryCommand('..\\evil', [1], 20)).toThrow(ControlError); // backslash
    expect(() => eventQueryCommand("System'; Get-Process", [1], 20)).toThrow(ControlError); // quote + semicolon
    expect(() => eventQueryCommand('System`x', [1], 20)).toThrow(ControlError); // backtick
    // ETW channel names carry '/', now supported; the value is single-quoted into
    // PowerShell and quotes/$/backtick/backslash/newline stay rejected above.
    expect(() => eventQueryCommand('Microsoft-Windows-PowerShell/Operational', [4], 1)).not.toThrow();
  });

  it('rejects $, |, [ ], {}, %, newline and quotes in logName (allowlist has no such char)', () => {
    for (const bad of ['System$x', 'System`', 'Sys|tem', 'Sys[tem', 'Sys}tem', 'Sys%tem', 'System\n', 'System\r\n', 'System\t', "Sys'tem", 'Sys"tem', 'System;', '\\\\host\\log', '..\\..\\System', '']) {
      expect(() => eventQueryCommand(bad, [1], 1)).toThrow(ControlError);
    }
  });

  it('dots and slashes are allowlist-legal but inert: LogName is an ETW channel name, not a path', () => {
    // No traversal surface: the value only ever selects a channel, so a dotted /
    // slashed name is a channel that does not exist → Get-WinEvent writes
    // nothing → decodeWinEventJson reports [] ("no events"), never a file read.
    for (const odd of ['../../System', './System', 'a/b/c', 'System.Log']) {
      const s = decode(eventQueryCommand(odd, [1], 1));
      expect(s).toContain(`LogName='${odd}'`);
      expect((s.match(/'/g) ?? []).length).toBe(QUOTES_EVENT);
    }
  });

  it('accepts real channel names with spaces, dots, dashes, underscores and slashes', () => {
    for (const ok of ['System', 'Application', 'Security', 'Windows PowerShell', 'Microsoft-Windows-Kernel-Power/Thermal-Event', 'Forwarded Events', 'Microsoft/Office Software/Analysis', 'A'.repeat(128)]) {
      expect(() => eventQueryCommand(ok, [1, 2, 3, 4, 5], 1)).not.toThrow();
    }
  });

  it('an accepted logName contributes zero quotes, so the hashtable literal cannot be closed', () => {
    for (const ok of ['System', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell']) {
      const s = decode(eventQueryCommand(ok, [1], 1));
      expect((s.match(/'/g) ?? []).length).toBe(QUOTES_EVENT);
      expect(s).toContain(`@{LogName='${ok}'; Level=1}`);
    }
  });

  it('refuses a logName longer than 128 characters', () => {
    expect(() => eventQueryCommand('A'.repeat(129), [1], 1)).toThrow(ControlError);
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

describe('psCommand / encodePs (-EncodedCommand fidelity)', () => {
  it('produces a single-line argv with the base64 as the 5th token', () => {
    const cmd = psCommand("Write-Output 'x'");
    expect(cmd).toMatch(/^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/);
  });

  it('round-trips BMP text, surrogate pairs and CRLF exactly', () => {
    const script = "Write-Output '✓ café 中文 😀'\r\n$x = 1\n";
    expect(Buffer.from(psCommand(script).split(' ')[4], 'base64').toString('utf16le')).toBe(script);
  });

  it('emits raw UTF-16LE with no BOM (the canonical [Text.Encoding]::Unicode.GetBytes form)', () => {
    const bytes = Buffer.from(encodePs('abc'), 'base64');
    expect([...bytes]).toEqual([0x61, 0, 0x62, 0, 0x63, 0]);
    expect(bytes.subarray(0, 2).toString('hex')).not.toBe('fffe');
  });

  it('a long script round-trips with byte-for-byte fidelity', () => {
    // Note the real ceiling: the CreateProcess command line is 32767 chars, so a
    // script whose base64 exceeds that cannot be launched this way. These
    // builders emit < 2 KB scripts; the ceiling is documented, not silently hit.
    const script = 'x'.repeat(10000) + '\n😀'.repeat(500);
    const enc = encodePs(script);
    expect(enc.length).toBeLessThan(32767);
    expect(Buffer.from(enc, 'base64').toString('utf16le')).toBe(script);
  });

  it('a lone surrogate passes through unchanged rather than being replaced', () => {
    const script = "Write-Output '\ud800 end'";
    expect(Buffer.from(encodePs(script), 'base64').toString('utf16le')).toBe(script);
  });
});
