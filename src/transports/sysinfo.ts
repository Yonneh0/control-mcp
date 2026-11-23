import { psCommand } from './windows.js';

// Pure command builders and parsers for the host_metrics tool (one SSH exec ->
// a normalized system snapshot: hostname, uptime, load, cpu count, memory,
// per-mount disk usage, top processes). Nothing here touches a transport: every
// function is synchronous and unit-testable with no host, and the registry runs
// the returned command through the audited runChecked path (safety gate ->
// ssh.exec) and feeds stdout to the parsers — the same shape as fileops.ts.
//
// Injection-safety: buildMetricsCommand takes NO caller input. Every byte of the
// command is a fixed string, so there is nothing to quote and nothing to escape.
//
// Honesty: a field a source cannot give is null, never a guess, and every
// null that came from missing/partial data gets a matching note in `warnings`.
// In particular Linux memUsedMb is NOT reconstructed from MemFree+Buffers+Cached
// when MemAvailable is absent (old kernels), and Windows cpuPct per process is
// null because the cheap snapshot does not measure it. A pair of counters that
// contradicts itself (free > total, or a negative size) is stated as a warning
// with nulls — never a negative "used", never clamped to a plausible figure.
//
// Units: memory is MB as DECIMAL megabytes (10^6 bytes), converted from the
// source unit of each field — /proc/meminfo is kB (1024 bytes), df -P is
// 1024-byte blocks, Win32_LogicalDisk is bytes. So MB here is 1e6 bytes, not
// MiB, and the same convention carries to the GB figures in the tool text.

export type OS = 'linux' | 'windows';

export interface DiskUsage {
  mount: string;
  filesystem: string | null;
  totalMb: number | null;
  usedMb: number | null;
  freeMb: number | null;
  usedPct: number | null;
}

export interface ProcessSample {
  name: string;
  pid: number | null;
  memMb: number | null;
  cpuPct: number | null;
}

export interface HostMetrics {
  os: OS;
  hostname: string | null;
  uptimeSec: number | null;
  /** Unix load average (1/5/15). Always null on Windows — no such measure. */
  loadAvg: [number, number, number] | null;
  cpuCount: number | null;
  memTotalMb: number | null;
  memUsedMb: number | null;
  swapTotalMb: number | null;
  swapUsedMb: number | null;
  disks: DiskUsage[];
  topProcesses: ProcessSample[];
  /** Honest notes about anything missing, dropped or partial. Never empty by luck. */
  warnings: string[];
  /** When this snapshot was parsed (ISO-8601), not when the host sampled it. */
  collectedAt: string;
}

// ------------------------------------------------------------------ builders --

// The fixed section names, in the order the Linux command emits them. The
// parser keys off these markers; nothing is caller-supplied.
const SECTIONS = ['HOSTNAME', 'UPTIME', 'LOAD', 'CPU', 'MEM', 'DISK', 'PS'] as const;
type Section = (typeof SECTIONS)[number];

// One POSIX shell string. Each section is preceded by an `echo '===NAME==='`
// marker line so the parser can split on markers even if a command prints
// unexpected noise. Every command has its stderr sent to /dev/null: the goal is
// a snapshot, and a missing /proc file or an unsupported ps option must degrade
// to an empty section (which the parser turns into null + a warning), never to
// a hard failure. The overall exit code is head's, so a partial snapshot is
// normal here — which is exactly why the parser, not the exit code, is the
// authority on what was measured.
function linuxMetricsScript(): string {
  const parts: string[] = [];
  const add = (name: Section, command: string): void => {
    parts.push(`echo '===${name}==='; ${command}`);
  };
  add('HOSTNAME', 'hostname 2>/dev/null || uname -n');
  add('UPTIME', 'cat /proc/uptime 2>/dev/null');
  add('LOAD', 'cat /proc/loadavg 2>/dev/null');
  add('CPU', 'nproc 2>/dev/null');
  // -E with an anchored alternation so only the fields we convert are echoed;
  // MemAvailable is included on purpose (its absence is a warning, not a guess).
  add('MEM', "grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null");
  // -P forces one line per filesystem (no wrapped long device names) and the -x
  // exclusions drop pseudo-mounts. busybox df has no -x: it exits non-zero with
  // no stdout, which the parser reports as "df produced no rows" — honest, and
  // the operator still gets memory/load/processes.
  add('DISK', 'df -P -x tmpfs -x devtmpfs -x overlay 2>/dev/null');
  // comm= etc. suppress the header row; --sort=-%mem is GNU-only (busybox
  // prints nothing -> parser warns). head bounds the payload.
  add('PS', 'ps -eo comm=,pid=,%mem=,%cpu= --sort=-%mem 2>/dev/null | head -n 6');
  return parts.join('; ');
}

// One PowerShell script, handed to psCommand() so it runs as -EncodedCommand
// (UTF-16LE base64): immune to cmd.exe quoting and to ExecutionPolicy.
// -Depth is REQUIRED, not decoration: Windows PowerShell 5.1 defaults to
// -Depth 2, at which the nested Win32_OperatingSystem object serializes to its
// ToString() and every memory/boot field is silently lost. Depth 6 keeps the
// object the parser needs (root=1, OS=2, its fields=3) without letting a
// pathological object run away.
// DriveType=3 is a local disk; Get-Process WS is the working set in bytes.
function windowsMetricsScript(): string {
  return psCommand(
    `$ErrorActionPreference='SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
  ComputerName = $env:COMPUTERNAME
  OS = $os
  CpuCount = $env:NUMBER_OF_PROCESSORS
  Disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,Size,FreeSpace)
  Top = @(Get-Process | Sort-Object WS -Descending | Select-Object -First 6 Name,Id,WS)
  Now = (Get-Date)
} | ConvertTo-Json -Compress -Depth 6`,
  );
}

export function buildMetricsCommand(os: OS): string {
  return os === 'windows' ? windowsMetricsScript() : linuxMetricsScript();
}

// ------------------------------------------------------------------- parsers --

// 'x 1.5 -' -> ['x','1.5','-']; leading/trailing whitespace never yields ''.
function tokens(line: string): string[] {
  return line.trim().split(/\s+/).filter((t) => t.length > 0);
}

// A token as a finite number, or null. Number('') is 0 and Number('1/123') is
// NaN, so emptiness and non-numeric junk both have to be rejected explicitly.
function asFloat(token: string | undefined): number | null {
  if (token === undefined) return null;
  const n = Number(token);
  return Number.isFinite(n) ? n : null;
}

// A JSON value as a finite number. CIM/PowerShell sometimes surfaces numerics
// as strings (CpuCount from an env var is always a string), so a clean numeric
// string is a measurement too; anything else is null.
function num(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && /^[+-]?\d+(\.\d+)?$/.test(v.trim())) {
    const n = Number(v.trim());
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

// kB (1024 bytes, /proc/meminfo and the Win32 memory properties) -> decimal MB.
const kbToMb = (kb: number): number => Math.round(kb / 1024);
// 1024-byte blocks (df -P) -> decimal MB.
const blocksToMb = (blocks: number): number => Math.round((blocks * 1024) / 1e6);
// bytes (Win32_LogicalDisk, Process.WS) -> decimal MB.
const bytesToMb = (bytes: number): number => Math.round(bytes / 1e6);

// Split stdout on `===NAME===` marker lines into a map of section name -> body
// text. Text before the first marker is dropped (a MOTD or shell banner on a
// login shell must never become the hostname). A section is registered even
// when its body is empty, because "marker present, body empty" and "marker
// absent" are different honest findings; an unknown marker's body is dropped.
function splitSections(stdout: string): Map<Section, string> {
  const known = new Set<string>(SECTIONS);
  const map = new Map<Section, string[]>();
  let cur: Section | null = null;
  for (const raw of stdout.split(/\r?\n/)) {
    const m = /^===([A-Za-z_]+)===$/.exec(raw.trim());
    if (m) {
      cur = known.has(m[1]) ? (m[1] as Section) : null;
      if (cur && !map.has(cur)) map.set(cur, []);
      continue;
    }
    if (cur !== null) map.get(cur)!.push(raw);
  }
  const out = new Map<Section, string>();
  for (const [name, lines] of map) out.set(name, lines.join('\n'));
  return out;
}

const emptyMetrics = (os: OS, collectedAt?: string): HostMetrics => ({
  os,
  hostname: null,
  uptimeSec: null,
  loadAvg: null,
  cpuCount: null,
  memTotalMb: null,
  memUsedMb: null,
  swapTotalMb: null,
  swapUsedMb: null,
  disks: [],
  topProcesses: [],
  warnings: [],
  collectedAt: collectedAt ?? new Date().toISOString(),
});

export function parseLinuxMetrics(stdout: string): HostMetrics {
  const m = emptyMetrics('linux');
  const w = m.warnings;
  const sections = splitSections(stdout);
  if (sections.size === 0) {
    w.push('no ===NAME=== markers in stdout — nothing was parsed (the snapshot command did not run, or produced no output)');
    return m;
  }

  // body() returns the section text, or null when the marker never appeared.
  const body = (name: Section): string | null => (sections.has(name) ? sections.get(name)! : null);
  const linesOf = (text: string): string[] => text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
  const absent = (name: Section, field: string): void => {
    w.push(`${name} section absent — ${field} not measured`);
  };

  // hostname ----------------------------------------------------------------
  const hostBody = body('HOSTNAME');
  if (hostBody === null) absent('HOSTNAME', 'hostname');
  else {
    const first = linesOf(hostBody)[0];
    if (first) m.hostname = first;
    else w.push('hostname printed nothing — hostname not measured');
  }

  // uptime: first float of "<seconds> <idle>" -------------------------------
  const upBody = body('UPTIME');
  if (upBody === null) absent('UPTIME', 'uptimeSec');
  else {
    const first = linesOf(upBody)[0];
    const v = asFloat(tokens(first ?? '')[0]);
    if (v !== null && v >= 0) m.uptimeSec = v;
    else w.push('uptimeSec unparsable — not measured');
  }

  // load: first three floats of "0.12 0.08 0.03 1/123 4567" -----------------
  const loadBody = body('LOAD');
  if (loadBody === null) absent('LOAD', 'loadAvg');
  else {
    const first = linesOf(loadBody)[0];
    const t = tokens(first ?? '');
    const l1 = asFloat(t[0]);
    const l5 = asFloat(t[1]);
    const l15 = asFloat(t[2]);
    // All three or none: a partial load average would imply a precision the
    // source did not deliver, and [0,0,0] would be a fabricated idle machine.
    if (l1 !== null && l5 !== null && l15 !== null) m.loadAvg = [l1, l5, l15];
    else w.push('loadAvg unparsable — not measured (no [0,0,0] default)');
  }

  // cpu count: nproc ---------------------------------------------------------
  const cpuBody = body('CPU');
  if (cpuBody === null) absent('CPU', 'cpuCount');
  else {
    const v = asFloat(tokens(linesOf(cpuBody)[0] ?? '')[0]);
    if (v !== null && Number.isInteger(v) && v > 0) m.cpuCount = v;
    else w.push('cpuCount is not a positive integer — not measured');
  }

  // memory: /proc/meminfo, every value kB -----------------------------------
  const memBody = body('MEM');
  if (memBody === null) {
    absent('MEM', 'memory');
  } else if (linesOf(memBody).length === 0) {
    w.push('meminfo section empty — no memory data');
  } else {
    const kb = new Map<string, number>();
    for (const line of linesOf(memBody)) {
      const mm = /^(\w+):\s+(\d+)\s*kB$/i.exec(line);
      if (mm) kb.set(mm[1], Number(mm[2]));
      else w.push(`meminfo line unparsable, skipped: ${line}`);
    }
    const total = kb.get('MemTotal');
    if (total === undefined) w.push('MemTotal absent — memTotalMb not measured');
    else m.memTotalMb = kbToMb(total);

    const avail = kb.get('MemAvailable');
    if (avail !== undefined && total !== undefined) {
      // MemAvailable above MemTotal happens under some cgroup/container
      // reporting; the difference would be a negative "used", not a measurement.
      if (avail > total) w.push('MemAvailable exceeds MemTotal — memUsedMb not computed (inconsistent counters)');
      else m.memUsedMb = kbToMb(total - avail);
    } else if (avail === undefined)
      w.push('MemAvailable absent in /proc/meminfo — memUsedMb not computed (pre-3.14 kernel; NOT guessed from MemFree+Buffers+Cached)');
    else w.push('MemAvailable present but MemTotal absent — memUsedMb not computed');

    const swapTotal = kb.get('SwapTotal');
    if (swapTotal === undefined) w.push('SwapTotal absent — swap not measured');
    else m.swapTotalMb = kbToMb(swapTotal);
    const swapFree = kb.get('SwapFree');
    if (swapTotal !== undefined && swapFree !== undefined) {
      if (swapFree > swapTotal) w.push('SwapFree exceeds SwapTotal — swapUsedMb not computed (inconsistent counters)');
      else m.swapUsedMb = kbToMb(swapTotal - swapFree);
    } else if (swapTotal !== undefined) w.push('SwapFree absent — swapUsedMb not computed');
  }

  // disks: df -P, columns Filesystem 1024-blocks Used Available Capacity on --
  // Parsed from the RIGHT: a device name can legally contain spaces (rare), so
  // everything before the last five fields is the filesystem. The mount is the
  // last field because df -P escapes spaces inside a mount point as \040.
  const diskBody = body('DISK');
  const noDiskRows = 'df produced no rows (busybox -x unsupported? snapshot has no disk data)';
  if (diskBody === null) absent('DISK', 'disks');
  else {
    for (const line of linesOf(diskBody)) {
      const t = tokens(line);
      if (t[0] === 'Filesystem') continue; // header row
      if (t.length < 6) {
        w.push(`df row skipped (fewer than 6 fields, mount unknown): ${line}`);
        continue;
      }
      const tail = t.slice(-5);
      const row: DiskUsage = {
        mount: tail[4],
        filesystem: t.slice(0, -5).join(' ') || null,
        totalMb: null,
        usedMb: null,
        freeMb: null,
        usedPct: null,
      };
      const blocks = asFloat(tail[0]);
      const used = asFloat(tail[1]);
      const avail = asFloat(tail[2]);
      // Capacity may be "67%" (GNU) or "67%" with a decimal on some ports.
      const pct = /^(\d+(?:\.\d+)?)%$/.exec(tail[3]);
      if (blocks === null || used === null || avail === null) {
        w.push(`df row has non-numeric size fields (only mount/percentage reported): ${line}`);
      } else {
        row.totalMb = blocksToMb(blocks);
        row.usedMb = blocksToMb(used);
        row.freeMb = blocksToMb(avail);
      }
      row.usedPct = pct ? Number(pct[1]) : null;
      if (!pct) w.push(`df row has no parsable Capacity%: ${line}`);
      m.disks.push(row);
    }
    if (m.disks.length === 0) w.push(noDiskRows);
  }

  // processes: "comm pid %mem %cpu" -----------------------------------------
  // comm may itself contain spaces, so the LAST three tokens are pid/%mem/%cpu
  // and everything before them is the command name.
  const psBody = body('PS');
  if (psBody === null) absent('PS', 'topProcesses');
  else if (linesOf(psBody).length === 0) w.push('ps produced no rows (unsupported ps? --sort unsupported on busybox?) — topProcesses not measured');
  else {
    for (const line of linesOf(psBody)) {
      const t = tokens(line);
      if (t.length < 4) {
        w.push(`ps row skipped (fewer than 4 fields): ${line}`);
        continue;
      }
      const tail = t.slice(-3);
      // Some ps builds ignore the `comm=` header suppression and print
      // "COMMAND PID %MEM %CPU"; unguarded it becomes a bogus process named
      // COMMAND with all-null fields. Recognized by a header word in the name
      // position AND a non-numeric pid position, so a real process actually
      // named COMMAND (which has a numeric pid) is still kept.
      if (/^(COMMAND|CMD|PID|PROCESS)$/i.test(t[0]) && !/^\d+$/.test(tail[0])) continue;
      const name = t.slice(0, -3).join(' ');
      if (!name) {
        w.push(`ps row skipped (no command name): ${line}`);
        continue;
      }
      const pidTok = /^\d+$/.test(tail[0]) ? Number(tail[0]) : null;
      const memPct = asFloat(tail[1]);
      const cpuPct = asFloat(tail[2]);
      // %mem is a percentage of physical memory, so MB is derived from the
      // measured MemTotal — null (never a guess) when MemTotal is unknown.
      const memMb = memPct === null || m.memTotalMb === null ? null : Math.round((memPct * m.memTotalMb) / 100);
      if (pidTok === null) w.push(`ps row pid unparsable ("${tail[0]}"), pid reported as null: ${line}`);
      if (memPct === null) w.push(`ps row %mem unparsable ("${tail[1]}"), memMb reported as null: ${line}`);
      else if (m.memTotalMb === null) w.push('MemTotal unknown — process memMb not computed');
      m.topProcesses.push({ name, pid: pidTok, memMb, cpuPct });
    }
  }

  return m;
}

// A .NET date as milliseconds since the epoch. Every form a ConvertTo-Json
// payload has actually been observed in is accepted; anything else yields null,
// so uptime is not measured rather than invented.
//
// Windows PowerShell 5.1 writes a [DateTime] in one of two shapes depending on
// where it came from (both live-measured):
//   bare string  "\/Date(1795362141500)\/"                       — a CIM property (host X1)
//   object       {"value":"\/Date(1795434601250)\/","DateTime":"Monday, November 23, 2026 11:50:01 AM"}
//                — (Get-Date) as a property (hosts n100 and X1; X1 adds a
//                DisplayHint member, and n100 sent LastBootUpTime this way too)
// After JSON.parse the `\/` escape is just `/`. The ms figure is already UTC
// since the epoch and the ±HHmm suffix is only the sender's display offset, so
// the suffix is ignored — applying it to one side of a difference and not the
// other would shift the result. The sibling "DateTime" member is a locale
// display string with NO timezone, so it is never parsed: guessing from it
// could shift uptime by hours. PowerShell 7 writes ISO-8601 strings; a bare
// number is epoch ms.
function dotNetDateMsFromScalar(v: string | number): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  const s = v.trim();
  const m = /^\/?Date\((-?\d+)(?:[+-]\d{4})?\)\/?$/.exec(s);
  if (m) {
    const ms = Number(m[1]);
    return Number.isFinite(ms) ? ms : null;
  }
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

function parseDotNetDateMs(v: unknown): number | null {
  if (typeof v === 'string' || typeof v === 'number') return dotNetDateMsFromScalar(v);
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    const inner = (v as Record<string, unknown>).value;
    if (typeof inner === 'string' || typeof inner === 'number') return dotNetDateMsFromScalar(inner);
  }
  return null;
}

// Rows of a ConvertTo-Json section, accepting object OR array. PowerShell keeps
// `@( … )` as an array even for one row (live-verified on 5.1.26100), but the
// same query without the wrapper — and any producer that collapses a
// single-element collection — delivers a bare object instead of [ {...} ]. One
// real disk/process must be parsed, not reported as "returned nothing"; a
// string or number is NOT arrayified (that is a truncated section, not a row).
function asRows(v: unknown): unknown[] | null {
  if (Array.isArray(v)) return v;
  if (v !== null && typeof v === 'object') return [v];
  return null;
}

export function parseWindowsMetrics(json: unknown, collectedAt?: string): HostMetrics {
  const m = emptyMetrics('windows', collectedAt);
  const w = m.warnings;
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    w.push('no parseable metrics payload');
    return m;
  }
  const o = json as Record<string, unknown>;

  if (typeof o.ComputerName === 'string' && o.ComputerName) m.hostname = o.ComputerName;
  else w.push('ComputerName absent — hostname not measured');

  const cpu = num(o.CpuCount);
  if (cpu !== null && Number.isInteger(cpu) && cpu > 0) m.cpuCount = cpu;
  else w.push('NUMBER_OF_PROCESSORS absent or not a positive integer — cpuCount not measured');

  // Win32_OperatingSystem: memory properties are kB; the boot time is a date.
  const osObj = o.OS !== null && typeof o.OS === 'object' && !Array.isArray(o.OS) ? (o.OS as Record<string, unknown>) : null;
  if (osObj === null) {
    w.push('OS payload missing or unparsable — memory and uptime not measured');
  } else {
    const totalVis = num(osObj.TotalVisibleMemorySize);
    const freePhys = num(osObj.FreePhysicalMemory);
    const totalVirt = num(osObj.TotalVirtualMemorySize);
    const freeVirt = num(osObj.FreeVirtualMemory);

    if (totalVis === null) w.push('TotalVisibleMemorySize absent — memTotalMb not measured');
    else m.memTotalMb = kbToMb(totalVis);

    if (totalVis !== null && freePhys !== null) {
      // Free memory larger than total memory is a counter inconsistency; the
      // difference would be a negative "used", which is not a measurement.
      if (freePhys > totalVis) w.push('FreePhysicalMemory exceeds TotalVisibleMemorySize — memUsedMb not computed');
      else m.memUsedMb = kbToMb(totalVis - freePhys);
    } else if (totalVis !== null) w.push('FreePhysicalMemory absent — memUsedMb not computed');

    if (totalVirt === null) w.push('TotalVirtualMemorySize absent — swapTotalMb not measured');
    else m.swapTotalMb = kbToMb(totalVirt);

    if (totalVirt !== null && freeVirt !== null) {
      if (freeVirt > totalVirt) w.push('FreeVirtualMemory exceeds TotalVirtualMemorySize — swapUsedMb not computed');
      else m.swapUsedMb = kbToMb(totalVirt - freeVirt);
    } else if (totalVirt !== null) w.push('FreeVirtualMemory absent — swapUsedMb not computed');

    const bootMs = parseDotNetDateMs(osObj.LastBootUpTime);
    const nowMs = parseDotNetDateMs(o.Now);
    if (bootMs === null || nowMs === null) w.push('LastBootUpTime and/or Now unparsable — uptimeSec not measured');
    else if (nowMs < bootMs) w.push('Now is earlier than LastBootUpTime (clock skew) — uptimeSec not measured');
    else m.uptimeSec = (nowMs - bootMs) / 1000;
  }

  // Win32_LogicalDisk DriveType=3 rows: Size/FreeSpace in BYTES.
  const diskRows = asRows(o.Disks);
  if (diskRows === null || diskRows.length === 0) w.push('no disk rows (Win32_LogicalDisk returned nothing)');
  for (const raw of diskRows ?? []) {
    if (raw === null || typeof raw !== 'object') {
      w.push('disk row is not an object, skipped');
      continue;
    }
    const d = raw as Record<string, unknown>;
    const mount = typeof d.DeviceID === 'string' && d.DeviceID ? d.DeviceID : null;
    if (mount === null) {
      w.push('disk row has no DeviceID, skipped');
      continue;
    }
    const size = num(d.Size);
    const free = num(d.FreeSpace);
    if (size === null) w.push(`disk ${mount}: Size absent — sizes not measured`);
    if (free === null) w.push(`disk ${mount}: FreeSpace absent — used/free not measured`);
    // A negative counter, or one that leaves nothing for "used" (FreeSpace >
    // Size), is a corrupted CIM read, not a measurement: bytesToMb of the
    // difference would report an impossible negative disk. The row is kept
    // (its DeviceID and any sane figure were measured) with null replacing the
    // impossible ones, and the inconsistency stated.
    const inverted = size !== null && free !== null && (size < 0 || free < 0 || free > size);
    if (inverted) w.push(`disk ${mount}: inconsistent Size/FreeSpace (Size=${size}, FreeSpace=${free}) — used/usedPct not measured`);
    m.disks.push({
      mount,
      filesystem: null, // DriveType=3 rows carry no volume label/filesystem here
      totalMb: size === null || size < 0 ? null : bytesToMb(size),
      usedMb: size === null || free === null || inverted ? null : bytesToMb(size - free),
      freeMb: free === null || free < 0 ? null : bytesToMb(free),
      // Size=0 (a media-less removable drive) makes the ratio meaningless.
      usedPct: size === null || free === null || inverted || size <= 0 ? null : Math.round(((size - free) / size) * 100),
    });
  }

  // Get-Process rows: WS is bytes; per-process CPU% is not in this snapshot,
  // so cpuPct is null for every row (a one-shot CPU read needs a second sample
  // window — that is a capability gap, stated here rather than faked).
  const topRows = asRows(o.Top);
  if (topRows === null || topRows.length === 0) w.push('no process rows (Get-Process returned nothing)');
  for (const raw of topRows ?? []) {
    if (raw === null || typeof raw !== 'object') {
      w.push('process row is not an object, skipped');
      continue;
    }
    const p = raw as Record<string, unknown>;
    const name = typeof p.Name === 'string' && p.Name ? p.Name : null;
    if (name === null) {
      w.push('process row has no Name, skipped');
      continue;
    }
    const ws = num(p.WS);
    if (ws === null) w.push(`process ${name}: WS absent — memMb not measured`);
    const pid = num(p.Id);
    if (pid === null) w.push(`process ${name}: Id absent — pid not measured`);
    m.topProcesses.push({ name, pid, memMb: ws === null ? null : bytesToMb(ws), cpuPct: null });
  }

  // loadAvg stays null: Windows has no Unix load average.
  return m;
}
