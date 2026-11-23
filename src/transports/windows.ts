import { ControlError } from '../errors.js';

// Windows host administration helpers, run over the SSH transport. The remote
// login shell may be cmd.exe (Windows OpenSSH default), so every script is
// handed to PowerShell via `-EncodedCommand` (UTF-16LE base64): that removes
// all cmd/PowerShell quoting and newline hazards and is not subject to
// ExecutionPolicy. Callers run the returned command via the audited
// runChecked path; mutations read state back so success is measured, and the
// caller reports effective privilege.

export function encodePs(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64');
}

export function psCommand(script: string): string {
  return `powershell -NoProfile -NonInteractive -EncodedCommand ${encodePs(script)}`;
}

// Extract the first JSON array/object out of stdout (ConvertTo-Json output may
// be preceded by unrelated lines). Returns null when nothing parses, so the
// caller reports raw text rather than inventing a structure.
export function extractJson(stdout: string): unknown | null {
  const s = stdout.replace(/\r/g, '');
  // Try each opening bracket and find its MATCHING close by depth (string- and
  // escape-aware), so a valid payload followed by trailing text still parses —
  // JSON.parse of "…}\nDONE" fails, and the old whole-tail attempt lost it.
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== '[' && s[i] !== '{') continue;
    const end = matchBracket(s, i);
    if (end === -1) continue;
    try {
      return JSON.parse(s.slice(i, end + 1));
    } catch {
      continue;
    }
  }
  return null;
}

function matchBracket(s: string, open: number): number {
  const openCh = s[open];
  const closeCh = openCh === '[' ? ']' : '}';
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === openCh) {
      depth++;
    } else if (c === closeCh) {
      if (--depth === 0) return i;
    }
  }
  return -1;
}

// ---- firewall -------------------------------------------------------------

const FIREWALL_PROFILES = ['Domain', 'Private', 'Public'];
function needProfile(name: string): string {
  if (!FIREWALL_PROFILES.includes(name)) {
    throw new ControlError('BAD_ARGS', `invalid firewall profile "${name}"`, { name, allowed: FIREWALL_PROFILES });
  }
  return name;
}
function needRuleName(name: string): string {
  if (name.includes("'") || name.includes('"') || name.length > 200) {
    throw new ControlError('BAD_ARGS', 'rule name must not contain quotes and must be <=200 chars', { name });
  }
  return name;
}

export function firewallStatusCommand(): string {
  return psCommand(
    `$ErrorActionPreference='Stop'
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress`,
  );
}

export function firewallSetProfileCommand(name: string, enabled: boolean): string {
  const p = needProfile(name);
  const on = enabled ? 'True' : 'False';
  // Write, then read the single profile back so the caller reports measured state.
  return psCommand(
    `$ErrorActionPreference='Stop'
Set-NetFirewallProfile -Name '${p}' -Enabled ${on}
Get-NetFirewallProfile -Name '${p}' | Select-Object Name,Enabled | ConvertTo-Json -Compress`,
  );
}

export function firewallAddRuleCommand(displayName: string, port: number, protocol: string): string {
  const n = needRuleName(displayName);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new ControlError('BAD_ARGS', 'port must be 1..65535', { port });
  }
  if (protocol !== 'tcp' && protocol !== 'udp') {
    throw new ControlError('BAD_ARGS', 'protocol must be tcp or udp', { protocol });
  }
  return psCommand(
    `$ErrorActionPreference='Stop'
New-NetFirewallRule -DisplayName '${n}' -Direction Inbound -Action Allow -Protocol ${protocol} -LocalPort ${port} | Out-Null
Get-NetFirewallRule -DisplayName '${n}' | Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress`,
  );
}

export function firewallRemoveRuleCommand(displayName: string): string {
  const n = needRuleName(displayName);
  // Idempotent removal with a verified read-back token.
  return psCommand(
    `$ErrorActionPreference='SilentlyContinue'
Remove-NetFirewallRule -DisplayName '${n}'
if (Get-NetFirewallRule -DisplayName '${n}') { 'STILL_PRESENT' } else { 'REMOVED' }`,
  );
}

// ---- defender -------------------------------------------------------------

export function defenderStatusCommand(): string {
  return psCommand(
    `$ErrorActionPreference='Stop'
$s = Get-MpComputerStatus
$p = Get-MpPreference
[PSCustomObject]@{
  RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
  AntivirusEnabled = $s.AntivirusEnabled
  AntispywareEnabled = $s.AntispywareEnabled
  AVSignatureVersion = $s.AntivirusSignatureVersion
  AVSignatureLastUpdated = $s.AntivirusSignatureLastUpdated
  QuickScanOverdue = $s.QuickScanOverdue
  FullScanOverdue = $s.FullScanOverdue
  DisableRealtimeMonitoring = $p.DisableRealtimeMonitoring
} | ConvertTo-Json -Compress`,
  );
}

export function defenderRealtimeSetCommand(on: boolean): string {
  // Real-time monitoring is expressed inversely (Disable flag). Read the
  // boolean back afterwards so the tool can say whether it actually changed.
  const disable = on ? '$false' : '$true';
  return psCommand(
    `$ErrorActionPreference='Stop'
Set-MpPreference -DisableRealtimeMonitoring ${disable}
(Get-MpComputerStatus).RealTimeProtectionEnabled`,
  );
}

export function defenderSignatureUpdateCommand(): string {
  return psCommand(
    `$ErrorActionPreference='Stop'
Update-MpSignature | Out-Null
(Get-MpComputerStatus).AntivirusSignatureVersion`,
  );
}

// ---- windows update -------------------------------------------------------

export function updateStatusCommand(): string {
  // COM searcher gives pending updates without an external module; the query
  // touches the network so callers give it a generous timeout. usoclient
  // presence is reported so trigger availability is known, not assumed.
  return psCommand(
    `$ErrorActionPreference='Continue'
$usoc = Test-Path (Join-Path $env:SystemRoot 'System32\\usoclient.exe')
try {
  $s = New-Object -ComObject Microsoft.Update.Session
  $sr = $s.CreateUpdateSearcher()
  $r = $sr.Search('IsInstalled=0')
  $need = @($r.Updates | Where-Object { (-not $_.IsInstalled) -and (-not $_.IsHidden) })
  [PSCustomObject]@{
    PendingCount = $need.Count
    Usoclient = $usoc
    Top = @($need | Select-Object -First 8 | ForEach-Object { $_.Title })
  } | ConvertTo-Json -Compress
} catch {
  [PSCustomObject]@{ error = $_.Exception.Message; Usoclient = $usoc } | ConvertTo-Json -Compress
}`,
  );
}

const USO_ACTION: Record<string, string> = {
  scan: 'StartScan',
  download: 'StartDownload',
  install: 'StartInstall',
};
export function updateTriggerCommand(kind: string): string {
  const verb = USO_ACTION[kind];
  if (!verb) throw new ControlError('BAD_ARGS', `unknown update action "${kind}"`, { kind, allowed: Object.keys(USO_ACTION) });
  // usoclient verbs are asynchronous: they kick the Update session and return.
  // Success is "triggered", verified separately via updateStatusCommand.
  return psCommand(`usoclient ${verb}\nWrite-Output "USO_EXIT=$LASTEXITCODE"`);
}

// ---- services --------------------------------------------------------------

// Service names reach PowerShell inside single-quoted literals. A printable name
// is inert there EXCEPT for control characters: CR/LF/tab (and any other <0x20)
// cannot appear in a real service name and would splice script into the quoted
// argument, so they are refused outright rather than escaped. Embedded single
// quotes are escaped by doubling ('' is PowerShell's only escape inside '...').
function needServiceName(name: string): string {
  if (typeof name !== 'string' || name.trim() === '') {
    throw new ControlError('BAD_ARGS', 'service name must not be empty', { name });
  }
  if (name.length > 200) {
    throw new ControlError('BAD_ARGS', 'service name must be <=200 chars', { name: name.slice(0, 64) });
  }
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) {
      throw new ControlError('BAD_ARGS', `service name must not contain control characters (char code ${c})`, { name: name.slice(0, 64) });
    }
  }
  return name.replace(/'/g, "''");
}

// Services whose stop/restart would drop the transport the operator is riding:
// sshd/ssh-agent carry the SSH path; TerminalService (RDP) and WinRM carry the
// other remote paths that may host a control session. The registry handler
// refuses stop/restart on these BEFORE running anything (start is harmless).
export const SELF_SEVER_SERVICES: readonly string[] = ['sshd', 'ssh-agent', 'termservice', 'terminalservices', 'winrm'];

export function isSelfSeverService(name: string): boolean {
  return SELF_SEVER_SERVICES.includes(name.trim().toLowerCase());
}

// Status snapshot. StartType is not exposed by Get-Service on Windows PowerShell
// 5.1, so it is joined from one Get-CimInstance Win32_Service pass (Name→StartType
// map; Automatic/Manual/Disabled). Status is stringified so the JSON reads
// "Running"/"Stopped" instead of the 5.1 enum's raw integer.
// NOTE on the array guarantee: piping @(...) to ConvertTo-Json does NOT keep a
// single result array-wrapped (PS3+ unwraps one pipeline item) and an empty
// pipeline emits nothing, so the builder uses -InputObject plus an explicit '[]'
// — "always an array" is measured by construction, not asserted.
export function serviceStatusCommand(name?: string, state?: 'running' | 'stopped'): string {
  const nameArg = name === undefined || name === '' ? '' : ` -Name '${needServiceName(name)}'`;
  const stateFilter =
    state === 'running' ? " | Where-Object { $_.Status -eq 'Running' }"
    : state === 'stopped' ? " | Where-Object { $_.Status -eq 'Stopped' }"
    : '';
  return psCommand(
    `$ErrorActionPreference='SilentlyContinue'
$starts = @{}
Get-CimInstance Win32_Service -Property Name,StartType | ForEach-Object { $starts[$_.Name] = $_.StartType }
$out = @(Get-Service${nameArg}${stateFilter} | Select-Object Name,DisplayName,@{n='Status';e={$_.Status.ToString()}},@{n='StartType';e={$starts[$_.Name]}})
if ($out.Count -eq 0) { '[]' } else { ConvertTo-Json -Compress -InputObject $out }`,
  );
}

// Start/stop/restart, then ALWAYS read the service back: the script ends with
// the measured Name/DisplayName/Status/StartType JSON. A failed change raises a
// terminating error ($ErrorActionPreference='Stop') → exit code != 0, which the
// registry surfaces; the caller still compares the read-back Status. StartType
// comes from one CIM pass matched in-script (single-quoted name, so no PS
// string-injection surface beyond needServiceName).
export function serviceChangeCommand(name: string, action: 'start' | 'stop' | 'restart'): string {
  const esc = needServiceName(name);
  const verb = action === 'start' ? 'Start-Service' : action === 'stop' ? 'Stop-Service' : 'Restart-Service';
  return psCommand(
    `$ErrorActionPreference='Stop'
${verb} -Name '${esc}'
$svc = Get-Service -Name '${esc}'
$ci = @(Get-CimInstance Win32_Service -Property Name,StartType | Where-Object { $_.Name -eq '${esc}' })
[PSCustomObject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; Status = $svc.Status.ToString(); StartType = $(if ($ci.Count -gt 0) { $ci[0].StartType } else { $null }) } | ConvertTo-Json -Compress`,
  );
}

// ---- historical event query ------------------------------------------------

// On-demand bounded Get-WinEvent (distinct from monitor_start, which only ever
// reports NEW events after its baseline). Levels: Critical=1, Error=2,
// Warning=3, Info=4, Verbose=5. The payload is emitted as base64-of-UTF8 exactly
// like monitor.ts's WIN_PS_QUERY, because event Messages carry arbitrary unicode
// and the SSH console text encoding cannot be trusted to carry ConvertTo-Json
// output intact. When nothing matches, Get-WinEvent writes NOTHING to stdout —
// decodeWinEventJson turns that into [] (genuinely no events), never an error.
export function eventQueryCommand(logName: string, levels: number[], count: number): string {
  if (typeof logName !== 'string' || !/^[A-Za-z0-9 ./_-]{1,128}$/.test(logName)) {
    throw new ControlError('BAD_ARGS', 'logName must match /^[A-Za-z0-9 ./_-]{1,128}$/ (letters, digits, space, dot, slash, underscore, hyphen — enough for ETW channel names like Microsoft-Windows-PowerShell/Operational; quotes/$/backtick are refused)', { logName });
  }
  if (!Array.isArray(levels) || levels.length === 0 || !levels.every((l) => Number.isSafeInteger(l) && l >= 1 && l <= 5)) {
    throw new ControlError('BAD_ARGS', 'levels must be a non-empty subset of [1,2,3,4,5] (Critical=1,Error=2,Warning=3,Info=4,Verbose=5)', { levels });
  }
  if (!Number.isSafeInteger(count) || count < 1 || count > 200) {
    throw new ControlError('BAD_ARGS', 'count must be an integer 1..200', { count });
  }
  return psCommand(
    `$ErrorActionPreference='SilentlyContinue'
Get-WinEvent -FilterHashtable @{LogName='${logName}'; Level=${levels.join(',')}} -MaxEvents ${count} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Level,ProviderName,Message | ConvertTo-Json -Compress | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) }`,
  );
}

// Mirror of monitor.ts's decodeWinStdout, but the failure mode is HONEST:
// '' → [] (the command ran and matched nothing — a real answer), while text that
// is not valid base64-of-JSON → null so the caller reports REMOTE_ERROR instead
// of quietly claiming zero events for a command that actually failed.
export function decodeWinEventJson(stdout: string): unknown[] | null {
  const b64 = stdout.trim().replace(/\s+/g, '');
  if (!b64) return [];
  // Buffer.from(.,'base64') drops invalid characters rather than throwing, so a
  // plain error message decodes to mojibake and fails the JSON.parse below.
  let text = Buffer.from(b64, 'base64').toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const json = text.trim();
  if (!json) return null;
  try {
    const parsed: unknown = JSON.parse(json);
    if (Array.isArray(parsed)) return parsed;
    if (parsed !== null && typeof parsed === 'object') return [parsed];
    return null;
  } catch {
    return null;
  }
}
