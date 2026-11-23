import { describe, expect, it } from 'vitest';
import { buildMetricsCommand, parseLinuxMetrics, parseWindowsMetrics } from '../src/transports/sysinfo.js';

// Pure tests only: fixtures in, values out. No ssh, no network, no fs.
//
// Every expected number below is hand-computed from the fixture and shown in a
// comment — the point is that the arithmetic in the parser is pinned by literal
// expectations, not by re-running the same expression through the code.

// decode a psCommand() wrapper back to the PowerShell it will run
const decodePs = (cmd: string): string => Buffer.from(cmd.split(' ')[4], 'base64').toString('utf16le');

// A realistic Linux snapshot: a login banner BEFORE the first marker (must be
// dropped, never mistaken for the hostname), and one df row at 100%.
const LINUX_STDOUT = [
  'Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)',
  '',
  '===HOSTNAME===',
  'web-01',
  '===UPTIME===',
  '892134.56 1623411.02',
  '===LOAD===',
  '0.12 0.08 0.03 1/123 4567',
  '===CPU===',
  '8',
  '===MEM===',
  'MemTotal:       16316428 kB',
  'MemFree:          534212 kB',
  'MemAvailable:    8214520 kB',
  'Buffers:          231004 kB',
  'Cached:          6102332 kB',
  'SwapTotal:       4194300 kB',
  'SwapFree:        3145728 kB',
  '===DISK===',
  'Filesystem     1024-blocks    Used Available Capacity Mounted on',
  '/dev/sda1         49170820 31200100  15456200  67% /',
  '/dev/sdb1        961302528 614592448 298698240  68% /data',
  '/dev/loop0           51200     51200         0 100% /snap/core/1',
  '===PS===',
  'nginx              1234 12.5  1.3',
  'kworker/0:1-events    0  0.0  0.0',
  'postgres            987  8.1  0.4',
  'java               4321  3.2  0.9',
  '',
].join('\n');

describe('parseLinuxMetrics — full snapshot', () => {
  const m = parseLinuxMetrics(LINUX_STDOUT);

  it('parses identity, uptime, load and cpu count', () => {
    // the pre-marker banner is dropped, not treated as the hostname
    expect(m.os).toBe('linux');
    expect(m.hostname).toBe('web-01');
    expect(m.uptimeSec).toBe(892134.56); // first float of /proc/uptime
    expect(m.loadAvg).toEqual([0.12, 0.08, 0.03]); // first three floats, "1/123" untouched
    expect(m.cpuCount).toBe(8);
    expect(m.collectedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('converts /proc/meminfo kB to decimal MB without guessing', () => {
    // MemTotal 16316428 kB / 1024 = 15934.01171875 -> 15934
    expect(m.memTotalMb).toBe(15934);
    // (16316428 - 8214520) = 8101908 kB / 1024 = 7912.01953125 -> 7912
    expect(m.memUsedMb).toBe(7912);
    // SwapTotal 4194300 / 1024 = 4095.99609375 -> 4096
    expect(m.swapTotalMb).toBe(4096);
    // (4194300 - 3145728) = 1048572 / 1024 = 1023.99609375 -> 1024
    expect(m.swapUsedMb).toBe(1024);
  });

  it('parses df -P rows (1024-blocks -> decimal MB) including a 100% row', () => {
    expect(m.disks).toHaveLength(3); // header row skipped
    expect(m.disks[0]).toEqual({
      mount: '/',
      filesystem: '/dev/sda1',
      // 49170820 blocks * 1024 = 50350919680 B / 1e6 = 50350.91968 -> 50351
      totalMb: 50351,
      // 31200100 * 1024 = 31948902400 / 1e6 = 31948.9024 -> 31949
      usedMb: 31949,
      // 15456200 * 1024 = 15827148800 / 1e6 = 15827.1488 -> 15827
      freeMb: 15827,
      usedPct: 67,
    });
    expect(m.disks[1]).toMatchObject({ mount: '/data', filesystem: '/dev/sdb1', totalMb: 984374, usedMb: 629343, freeMb: 305867, usedPct: 68 });
    // the full disk: 51200 blocks * 1024 = 52428800 / 1e6 = 52.4288 -> 52
    expect(m.disks[2]).toEqual({ mount: '/snap/core/1', filesystem: '/dev/loop0', totalMb: 52, usedMb: 52, freeMb: 0, usedPct: 100 });
  });

  it('derives process memMb from %mem of the measured MemTotal', () => {
    expect(m.topProcesses).toHaveLength(4);
    // 12.5% of 15934 MB = 1991.75 -> 1992
    expect(m.topProcesses[0]).toEqual({ name: 'nginx', pid: 1234, memMb: 1992, cpuPct: 1.3 });
    // comm containing no spaces, pid 0, 0.0% -> 0 MB (a measurement, not a null)
    expect(m.topProcesses[1]).toEqual({ name: 'kworker/0:1-events', pid: 0, memMb: 0, cpuPct: 0 });
    // 8.1% of 15934 = 1290.654 -> 1291
    expect(m.topProcesses[2]).toEqual({ name: 'postgres', pid: 987, memMb: 1291, cpuPct: 0.4 });
    // 3.2% of 15934 = 509.888 -> 510
    expect(m.topProcesses[3]).toEqual({ name: 'java', pid: 4321, memMb: 510, cpuPct: 0.9 });
  });

  it('is silent when nothing is missing — a clean snapshot has no warnings', () => {
    expect(m.warnings).toEqual([]);
  });
});

describe('parseLinuxMetrics — honesty regressions', () => {
  it('reports memUsedMb as null (never a guess) when MemAvailable is absent', () => {
    const oldKernel = LINUX_STDOUT.replace('MemAvailable:    8214520 kB\n', '');
    expect(oldKernel).not.toContain('MemAvailable');
    const m = parseLinuxMetrics(oldKernel);
    expect(m.memTotalMb).toBe(15934); // still measured
    expect(m.memUsedMb).toBeNull(); // NOT reconstructed from MemFree+Buffers+Cached
    expect(m.warnings.some((x) => x.includes('MemAvailable') && x.includes('memUsedMb'))).toBe(true);
    // and the process column that depends on MemTotal is still fine
    expect(m.topProcesses[0].memMb).toBe(1992);
  });

  it('warns instead of inventing when the DISK section is empty', () => {
    const noDf = LINUX_STDOUT.replace(/===DISK===\n[\s\S]*?(?====PS===)/, '===DISK===\n');
    const m = parseLinuxMetrics(noDf);
    expect(m.disks).toEqual([]);
    expect(m.warnings.some((x) => x.includes('df produced no rows'))).toBe(true);
    // the rest of the snapshot is still real
    expect(m.memTotalMb).toBe(15934);
    expect(m.warnings).toHaveLength(1);
  });

  it('warns instead of inventing when df emitted only its header', () => {
    const headerOnly = LINUX_STDOUT.replace(/===DISK===\n[\s\S]*?(?====PS===)/, '===DISK===\nFilesystem     1024-blocks    Used Available Capacity Mounted on\n');
    const m = parseLinuxMetrics(headerOnly);
    expect(m.disks).toEqual([]);
    expect(m.warnings.some((x) => x.includes('df produced no rows'))).toBe(true);
  });

  it('keeps loadAvg null on a malformed load line — no [0,0,0] default', () => {
    const bad = LINUX_STDOUT.replace('0.12 0.08 0.03 1/123 4567', 'load average: n/a');
    expect(parseLinuxMetrics(bad).loadAvg).toBeNull();
    const partial = LINUX_STDOUT.replace('0.12 0.08 0.03 1/123 4567', '0.12 0.08');
    expect(parseLinuxMetrics(partial).loadAvg).toBeNull();
    const warns = parseLinuxMetrics(bad).warnings;
    expect(warns.some((x) => x.includes('loadAvg'))).toBe(true);
  });

  it('reports a missing section as absent, not as zero', () => {
    const noCpu = LINUX_STDOUT.replace('===CPU===\n8\n', '');
    const m = parseLinuxMetrics(noCpu);
    expect(m.cpuCount).toBeNull();
    expect(m.warnings.some((x) => x.includes('CPU section absent') && x.includes('cpuCount'))).toBe(true);
  });

  it('parses nothing and says so for output with no markers', () => {
    const m = parseLinuxMetrics('');
    expect(m.hostname).toBeNull();
    expect(m.uptimeSec).toBeNull();
    expect(m.loadAvg).toBeNull();
    expect(m.cpuCount).toBeNull();
    expect(m.memTotalMb).toBeNull();
    expect(m.disks).toEqual([]);
    expect(m.topProcesses).toEqual([]);
    expect(m.warnings[0]).toContain('no ===NAME=== markers');
  });

  it('warns when ps is unsupported instead of returning an empty success', () => {
    const noPs = LINUX_STDOUT.replace(/===PS===\n[\s\S]*$/, '===PS===\n');
    const m = parseLinuxMetrics(noPs);
    expect(m.topProcesses).toEqual([]);
    expect(m.warnings.some((x) => x.includes('ps produced no rows'))).toBe(true);
  });

  it('keeps process memMb null when MemTotal is unknown rather than assuming a size', () => {
    const noMemTotal = LINUX_STDOUT.replace('MemTotal:       16316428 kB\n', '');
    const m = parseLinuxMetrics(noMemTotal);
    expect(m.memTotalMb).toBeNull();
    expect(m.topProcesses[0].memMb).toBeNull();
    expect(m.topProcesses[0].name).toBe('nginx'); // the name/pid reading does not depend on memory
    expect(m.warnings.some((x) => x.includes('MemTotal'))).toBe(true);
  });

  it('parses a df filesystem name containing a space by reading from the right', () => {
    // df -P escapes spaces in the MOUNT column, so only the device column can
    // hold raw spaces; reading the last five fields keeps the split correct.
    const odd = LINUX_STDOUT.replace(
      '/dev/sda1         49170820 31200100  15456200  67% /',
      'my volume name      49170820 31200100  15456200  67% /mnt/x',
    );
    const m = parseLinuxMetrics(odd);
    expect(m.disks[0].mount).toBe('/mnt/x');
    expect(m.disks[0].filesystem).toBe('my volume name');
    expect(m.disks[0].totalMb).toBe(50351);
    expect(m.disks[0].usedPct).toBe(67);
    expect(m.warnings).toEqual([]);
  });
});

// What the registry gets after extractJson() on ConvertTo-Json output.
// CpuCount is a STRING because it comes from $env:NUMBER_OF_PROCESSORS.
const WINDOWS_JSON = {
  ComputerName: 'WS-DEPLOY-01',
  CpuCount: '12',
  OS: {
    LastBootUpTime: '2026-11-20T06:20:00.000Z',
    TotalVisibleMemorySize: 33423020, // kB
    FreePhysicalMemory: 8123456, // kB
    TotalVirtualMemorySize: 40894444, // kB
    FreeVirtualMemory: 12345678, // kB
  },
  Disks: [
    { DeviceID: 'C:', Size: 511101104128, FreeSpace: 193273528320 }, // bytes
    { DeviceID: 'D:', Size: 1000000000000, FreeSpace: 1000000000000 },
  ],
  Top: [
    { Name: 'chrome', Id: 8812, WS: 1234567890 },
    { Name: 'Code', Id: 4004, WS: 850000000 },
  ],
  Now: '2026-11-23T10:37:05.000Z',
};

describe('parseWindowsMetrics — full snapshot', () => {
  const m = parseWindowsMetrics(WINDOWS_JSON, '2026-11-23T10:37:07.000Z');

  it('maps identity and cpu count, and keeps loadAvg null', () => {
    expect(m.os).toBe('windows');
    expect(m.hostname).toBe('WS-DEPLOY-01');
    expect(m.cpuCount).toBe(12); // '12' from the environment, coerced
    // Windows has no Unix load average: null, not zeros.
    expect(m.loadAvg).toBeNull();
    expect(m.collectedAt).toBe('2026-11-23T10:37:07.000Z');
  });

  it('converts the kB memory properties to decimal MB', () => {
    // 33423020 / 1024 = 32639.66796875 -> 32640
    expect(m.memTotalMb).toBe(32640);
    // (33423020 - 8123456) = 25299564 / 1024 = 24706.60546875 -> 24707
    expect(m.memUsedMb).toBe(24707);
    // 40894444 / 1024 = 39935.98046875 -> 39936
    expect(m.swapTotalMb).toBe(39936);
    // (40894444 - 12345678) = 28548766 / 1024 = 27879.654296875 -> 27880
    expect(m.swapUsedMb).toBe(27880);
  });

  it('computes uptimeSec from Now - LastBootUpTime', () => {
    // 2026-11-23T10:37:05Z - 2026-11-20T06:20:00Z = 3d 4h 17m 5s
    // = 259200 + 14400 + 1020 + 5 = 274625 s
    expect(m.uptimeSec).toBe(274625);
  });

  it('converts disk BYTES to decimal MB and computes used%', () => {
    expect(m.disks).toHaveLength(2);
    expect(m.disks[0]).toEqual({
      mount: 'C:',
      filesystem: null,
      // 511101104128 / 1e6 = 511101.104128 -> 511101
      totalMb: 511101,
      // (511101104128 - 193273528320) = 317827575808 / 1e6 = 317827.575808 -> 317828
      usedMb: 317828,
      // 193273528320 / 1e6 = 193273.52832 -> 193274
      freeMb: 193274,
      // 317827575808 / 511101104128 * 100 = 62.184... -> 62
      usedPct: 62,
    });
    // an empty volume is a measurement, not a missing value
    expect(m.disks[1]).toEqual({ mount: 'D:', filesystem: null, totalMb: 1000000, usedMb: 0, freeMb: 1000000, usedPct: 0 });
  });

  it('reports process working set in MB and per-process cpuPct as null', () => {
    expect(m.topProcesses).toHaveLength(2);
    // 1234567890 B / 1e6 = 1234.56789 -> 1235
    expect(m.topProcesses[0]).toEqual({ name: 'chrome', pid: 8812, memMb: 1235, cpuPct: null });
    expect(m.topProcesses[1]).toEqual({ name: 'Code', pid: 4004, memMb: 850, cpuPct: null });
    expect(m.topProcesses.every((p) => p.cpuPct === null)).toBe(true);
  });

  it('produces no warnings for a complete payload', () => {
    expect(m.warnings).toEqual([]);
  });
});

describe('parseWindowsMetrics — honesty regressions', () => {
  it('says so when there is no payload at all', () => {
    for (const bad of [null, undefined, 'not json', 42, [1, 2]]) {
      const m = parseWindowsMetrics(bad);
      expect(m.warnings.length).toBeGreaterThan(0);
      expect(m.warnings).toContain('no parseable metrics payload');
      expect(m.hostname).toBeNull();
      expect(m.uptimeSec).toBeNull();
      expect(m.loadAvg).toBeNull();
      expect(m.cpuCount).toBeNull();
      expect(m.memTotalMb).toBeNull();
      expect(m.memUsedMb).toBeNull();
      expect(m.swapTotalMb).toBeNull();
      expect(m.swapUsedMb).toBeNull();
      expect(m.disks).toEqual([]);
      expect(m.topProcesses).toEqual([]);
    }
  });

  it('does not invent memory when the OS object is missing', () => {
    const m = parseWindowsMetrics({ ComputerName: 'BOX', CpuCount: '4' });
    expect(m.hostname).toBe('BOX');
    expect(m.cpuCount).toBe(4);
    expect(m.memTotalMb).toBeNull();
    expect(m.memUsedMb).toBeNull();
    expect(m.uptimeSec).toBeNull();
    expect(m.warnings.some((x) => x.includes('OS payload'))).toBe(true);
  });

  it('survives the PS 5.1 -Depth truncation shape (OS serialized as a string)', () => {
    // ConvertTo-Json -Depth 2 writes the nested CimInstance as its ToString().
    const m = parseWindowsMetrics({ ComputerName: 'BOX', OS: 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_OperatingSystem' });
    expect(m.memTotalMb).toBeNull();
    expect(m.uptimeSec).toBeNull();
    expect(m.warnings.some((x) => x.includes('OS payload'))).toBe(true);
  });

  it('nulls memory rather than assuming a boot when a date is unparsable', () => {
    const m = parseWindowsMetrics({ ...WINDOWS_JSON, Now: 'tomorrow-ish' });
    expect(m.uptimeSec).toBeNull();
    expect(m.memTotalMb).toBe(32640); // the other OS fields are still real
    expect(m.warnings.some((x) => x.includes('uptimeSec'))).toBe(true);
  });

  it('refuses a negative uptime from clock skew', () => {
    const m = parseWindowsMetrics({ ...WINDOWS_JSON, Now: '2026-11-19T06:20:00.000Z' });
    expect(m.uptimeSec).toBeNull();
    expect(m.warnings.some((x) => x.includes('clock skew'))).toBe(true);
  });

  it('reads the PowerShell 5.1 "/Date(ms+offset)/" form', () => {
    // The number is UTC ms; the ±HHmm suffix is display-only, so a differing
    // suffix on the two values must not shift the difference.
    const m = parseWindowsMetrics({
      ComputerName: 'BOX',
      OS: { ...WINDOWS_JSON.OS, LastBootUpTime: '/Date(1000000000000+0000)/' },
      Now: '/Date(1000274625000-0500)/',
    });
    expect(m.uptimeSec).toBe(274625);
  });

  it('nulls the fields of a disk row with no Size instead of dividing by zero', () => {
    const m = parseWindowsMetrics({ ...WINDOWS_JSON, Disks: [{ DeviceID: 'E:', Size: 0, FreeSpace: 0 }] });
    expect(m.disks).toHaveLength(1);
    expect(m.disks[0]).toEqual({ mount: 'E:', filesystem: null, totalMb: 0, usedMb: 0, freeMb: 0, usedPct: null });
    const noSize = parseWindowsMetrics({ ...WINDOWS_JSON, Disks: [{ DeviceID: 'E:' }] });
    expect(noSize.disks[0]).toEqual({ mount: 'E:', filesystem: null, totalMb: null, usedMb: null, freeMb: null, usedPct: null });
    expect(noSize.warnings.some((x) => x.includes('E:') && x.includes('Size absent'))).toBe(true);
  });

  it('warns when a whole section returned nothing', () => {
    const m = parseWindowsMetrics({ ComputerName: 'BOX', CpuCount: '2', OS: WINDOWS_JSON.OS, Now: WINDOWS_JSON.Now });
    expect(m.disks).toEqual([]);
    expect(m.topProcesses).toEqual([]);
    expect(m.warnings.some((x) => x.includes('no disk rows'))).toBe(true);
    expect(m.warnings.some((x) => x.includes('no process rows'))).toBe(true);
    expect(m.uptimeSec).toBe(274625);
  });
});

describe('buildMetricsCommand', () => {
  it('emits every labeled section and the fixed Linux commands', () => {
    const cmd = buildMetricsCommand('linux');
    for (const name of ['HOSTNAME', 'UPTIME', 'LOAD', 'CPU', 'MEM', 'DISK', 'PS']) {
      expect(cmd).toContain(`echo '===${name}==='`);
    }
    expect(cmd).toContain('hostname 2>/dev/null || uname -n');
    expect(cmd).toContain('cat /proc/uptime 2>/dev/null');
    expect(cmd).toContain('cat /proc/loadavg 2>/dev/null');
    expect(cmd).toContain('nproc 2>/dev/null');
    expect(cmd).toContain("grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null");
    expect(cmd).toContain('df -P -x tmpfs -x devtmpfs -x overlay 2>/dev/null');
    expect(cmd).toContain('ps -eo comm=,pid=,%mem=,%cpu= --sort=-%mem 2>/dev/null | head -n 6');
  });

  it('wraps the Windows snapshot in -EncodedCommand', () => {
    const cmd = buildMetricsCommand('windows');
    expect(cmd.startsWith('powershell')).toBe(true);
    expect(cmd).toContain('EncodedCommand');
    // the encoded payload is what actually runs: assert on the decoded script
    const ps = decodePs(cmd);
    expect(ps).toContain("$ErrorActionPreference='SilentlyContinue'");
    expect(ps).toContain('$env:COMPUTERNAME');
    expect(ps).toContain('Get-CimInstance Win32_OperatingSystem');
    expect(ps).toContain('$env:NUMBER_OF_PROCESSORS');
    expect(ps).toContain("Win32_LogicalDisk -Filter 'DriveType=3'");
    expect(ps).toContain('Get-Process');
    expect(ps).toContain('ConvertTo-Json -Compress');
    // -Depth is not decoration: at 5.1's default depth of 2 the memory fields
    // never reach the parser, so the snapshot would be silently empty.
    expect(ps).toContain('-Depth');
    expect(ps).toContain('Now = (Get-Date)');
  });

  it('takes no caller input: the argument only selects between two constants', () => {
    // Exactly one parameter (the OS discriminant) and no string parameter, so
    // there is no caller value that could reach the command line. Pinning it:
    // an adversarial os value cannot alter the emitted command either — the
    // builder compares it to 'windows' and emits one of two fixed strings.
    expect(buildMetricsCommand.length).toBe(1);
    expect(buildMetricsCommand('linux')).toBe(buildMetricsCommand('linux'));
    expect(buildMetricsCommand('windows')).toBe(buildMetricsCommand('windows'));
    // A hostile value in the only parameter still cannot change the command.
    const asOs = (s: string): 'linux' => s as 'linux';
    expect(buildMetricsCommand(asOs('linux; reboot'))).toBe(buildMetricsCommand('linux'));
    expect(buildMetricsCommand(asOs(''))).toBe(buildMetricsCommand('linux'));
    // No interpolation leftovers. ("/dev/null" carries a real "null", so only
    // undefined/[object Object — the shapes a missed substitution produces.)
    expect(buildMetricsCommand('linux')).not.toMatch(/\bundefined\b|\[object Object/);
    expect(decodePs(buildMetricsCommand('windows'))).not.toMatch(/\bundefined\b|\[object Object/);
  });
});
