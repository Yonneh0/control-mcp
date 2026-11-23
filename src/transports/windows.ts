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
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '[' || c === '{') {
      const candidate = s.slice(i);
      try {
        return JSON.parse(candidate);
      } catch {
        // Try the next opening brace (a log line may have contained one).
        continue;
      }
    }
  }
  return null;
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
