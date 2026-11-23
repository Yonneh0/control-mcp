import { readFileSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { hostname, networkInterfaces, platform, release } from 'node:os';
import { promisify } from 'node:util';
import { connect as netConnect, type Socket } from 'node:net';
import { createSocket } from 'node:dgram';
import { classifyRdp, pickInterface, type RdpVerdict } from '../capability.js';
import { ControlError } from '../errors.js';
import type { HostConfig } from '../config/schema.js';
import type { SshTransport } from './ssh.js';

const execFileP = promisify(execFile);

// Distinguishes "the host is down" from "the host is up but the SSH daemon is
// not accepting on this port" — the distinction that matters most after a
// cold boot, where Windows answers ICMP and opens RDP seconds before sshd
// binds. A TCP RST (ECONNREFUSED) is positive proof the host is ALIVE, so it
// must never be read as "down".
export type SshProbeState = 'ready' | 'auth' | 'refused' | 'filtered' | 'down' | 'error';

export function classifySshState(pingOk: boolean, probe: { ok: boolean; error?: string } | null): SshProbeState {
  if (!pingOk) return 'down';
  if (!probe) return 'down';
  if (probe.ok) return 'ready';
  const msg = probe.error ?? '';
  if (/authentication|no matching (key|method)|all configured authentication/i.test(msg)) return 'auth';
  if (/ECONNREFUSED/i.test(msg)) return 'refused';
  if (/ETIMEDOUT|timed out|handshake|ECONNRESET|EHOSTUNREACH|ENETUNREACH/i.test(msg)) return 'filtered';
  return 'error';
}

export interface HostStatus {
  name: string;
  address: string;
  os: string;
  // True when ANY configured interface answered ICMP — the box is on the network
  // regardless of whether any service is listening.
  hostUp: boolean;
  ssh: { reachable: boolean; listening: boolean; state: SshProbeState; user: string; error?: string };
  rdp: RdpVerdict;
  interfaces: Record<string, boolean>;
}

export async function ping(address: string, timeoutMs = 2000): Promise<boolean> {
  const isWin = platform() === 'win32';
  const args = isWin ? ['-n', '1', '-w', String(timeoutMs), address] : ['-c', '1', '-W', String(Math.ceil(timeoutMs / 1000)), address];
  try {
    // Exit 0 alone lies (Windows returns it for unresolvable/bad targets too);
    // require an actual reply line.
    const { stdout } = await execFileP(isWin ? 'ping.exe' : 'ping', args, { timeout: timeoutMs + 1500 });
    return /TTL=|bytes from|icmp_seq=/i.test(stdout);
  } catch {
    return false;
  }
}

export function probeTcp(address: string, port: number, timeoutMs = 2000): Promise<{ open: boolean; error?: string }> {
  return new Promise((resolve) => {
    const sock: Socket = netConnect({ host: address, port, timeout: timeoutMs });
    let done = false;
    const finish = (open: boolean, error?: string) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ open, error });
    };
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false, 'timeout'));
    sock.once('error', (e) => finish(false, e.message));
  });
}

async function windowsRdpPolicy(host: HostConfig, address: string, ssh: SshTransport): Promise<{ blankPasswordAccount?: boolean; limitBlankPasswordUse?: number; nlaRequired?: boolean; netuseCode?: string; netuseErr?: string }> {
  const out: { blankPasswordAccount?: boolean; limitBlankPasswordUse?: number; nlaRequired?: boolean; netuseCode?: string; netuseErr?: string } = {};
  // UserAuthentication is the NLA switch (1 = require NLA); SecurityLayer is a
  // different value and would misreport. The blank-password probe targets the
  // account RDP would actually use: rdp.user when configured, otherwise it is
  // NOT meaningful for ssh-only accounts (a wrong non-blank password also fails)
  // — so without an rdp block we skip the probe entirely. Measured on this LAN
  // (2026-11-22): `cmd /c "net use \\<ip>\IPC$ \"\" /user:<blank-acct>"` against
  // n100 User returns exit 2 with stderr "System error 1326 ... user name or
  // password is incorrect" — on this Server SKU that is what blank rejection
  // under LimitBlankPasswordUse=1 looks like; client SKUs show the classic 1327
  // ("blank passwords aren't allowed"). Nonzero exit with lbp=1 = refused;
  // exit 0 would mean blank network logon IS allowed (probe established a
  // session, which we immediately clean up).
  const probeUser = host.rdp?.user;
  // Run net use through cmd /c with NO inner quotes around the empty password:
  // measured on this LAN 2026-11-22 — `cmd /c net use \\<ip>\IPC$ "" /user:<acct>`
  // against n100's blank User returns exit 2 + "System error 1327 ... blank
  // passwords aren't allowed" (the documented proof). Any inner quote layer
  // mangles the empty argument into 1326/usage errors. EncodedCommand base64
  // carries the "" token intact through ssh -> powershell -> cmd.
  const ps = [
    `$ErrorActionPreference='SilentlyContinue'`,
    `$ProgressPreference='SilentlyContinue'`,
    `$lbp=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LimitBlankPasswordUse`,
    `$nla=(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication`,
    `$o = cmd /c net use \\\\${address}\\IPC$ "" /user:${probeUser} 2>&1`,
    `$code=$LASTEXITCODE`,
    `net use \\\\${address}\\IPC$ /delete 2>&1 | Out-Null`,
    `$m = ($o | Out-String)`,
    `$ec=''; if($m -match 'System error (\\d+)'){$ec=$Matches[1]}`,
    `Write-Output "lbp=$lbp nla=$nla netuse=$code err=$ec"`,
  ].join('; ');
  const b64 = Buffer.from(ps, 'utf16le').toString('base64');
  try {
    const res = await ssh.exec(host, address, `powershell -NoProfile -EncodedCommand ${b64}`, { timeoutMs: 20000 });
    const line = res.stdout.split(/\r?\n/).find((l) => l.includes('lbp=')) ?? '';
    const lbp = /lbp=(\d+)/.exec(line);
    const nla = /nla=(\d+)/.exec(line);
    const nu = /netuse=(-?\d+)/.exec(line);
    const ec = /err=(\d+)/.exec(line);
    if (lbp) out.limitBlankPasswordUse = Number(lbp[1]);
    if (nla) out.nlaRequired = nla[1] === '1';
    if (nu) out.netuseCode = nu[1];
    if (ec) out.netuseErr = ec[1];
    // Only System error 1327 ("blank passwords aren't allowed") proves the
    // blank-password rejection. cmd's exit code alone is NOT enough: a wrong
    // NON-blank password also exits 2 (error 1326), so the code must not be
    // reported as "the account is blank". The error number decides.
    if (ec && ec[1] === '1327') out.blankPasswordAccount = true;
    else if (ec) out.blankPasswordAccount = false;
    else if (nu && nu[1] === '0') out.blankPasswordAccount = false; // blank network logon actually succeeded
  } catch {
    /* best effort */
  }
  return out;
}

async function hasStoredRdpCredential(address: string): Promise<boolean> {
  try {
    const { stdout } = await execFileP('cmdkey.exe', ['/list'], { timeout: 8000 });
    return new RegExp(`target=.*termsrv/${address}\\b`, 'i').test(stdout);
  } catch {
    return false;
  }
}

export async function probeHost(host: HostConfig, ssh: SshTransport): Promise<HostStatus> {
  const candidates = [host.address, ...host.alternateAddresses];
  const interfaces: Record<string, boolean> = {};
  await Promise.all(
    candidates.map(async (addr) => {
      const p = await ping(addr, 1500);
      interfaces[addr] = p;
    }),
  );
  const pick = pickInterface(host.address, host.alternateAddresses, interfaces);
  // Separate the HOST from the SSH SERVICE (see classifySshState): a box that
  // answers ICMP is up even if sshd has not bound its port yet.
  const hostUp = candidates.some((a) => interfaces[a]);
  let sshProbe: { ok: boolean; error?: string } | null = null;
  if (pick) {
    sshProbe = await ssh.probe(host, pick.address);
  }
  const sshState = classifySshState(hostUp, sshProbe);
  const sshError = !pick
    ? 'no interface answered ping'
    : sshProbe && !sshProbe.ok
      ? sshProbe.error
      : undefined;

  const rdpTcp = host.capabilities.rdp || host.rdp ? await probeTcp(pick?.address ?? host.address, host.rdp?.port ?? 3389) : { open: false };
  let policy: Awaited<ReturnType<typeof windowsRdpPolicy>> = {};
  // The blank-password probe only makes sense for a declared RDP account.
  if (host.os === 'windows' && hostUp && host.rdp?.user) {
    policy = await windowsRdpPolicy(host, pick?.address ?? host.address, ssh);
  }

  // Declared means "control-mcp should have RDP for this host": either the
  // capability flag or a full [hosts.rdp] block; gate and verdict must agree.
  const declared = Boolean(host.capabilities.rdp || host.rdp);
  let hasCredential: boolean | undefined;
  if (declared) {
    hasCredential = Boolean(host.rdp?.credentialTarget || host.rdp?.passwordEnv || process.env.CONTROL_MCP_HAS_CRED === '1');
    // A stored Windows Credential-Manager entry (cmdkey) is how msi actually
    // authenticates; consult it before declaring the credential missing.
    if (!hasCredential && platform() === 'win32') {
      hasCredential = await hasStoredRdpCredential(pick?.address ?? host.address);
    }
  }
  const verdict = classifyRdp({
    declared,
    tcpOpen: rdpTcp.open,
    sshAlive: hostUp,
    hasCredential,
    ...policy,
  });

  return {
    name: host.name,
    address: pick?.address ?? host.address,
    os: host.os,
    hostUp,
    ssh: { reachable: sshState === 'ready', listening: sshState === 'ready' || sshState === 'auth', state: sshState, user: host.ssh.user, error: sshError },
    rdp: verdict,
    interfaces,
  };
}

export interface LocalInfo {
  hostname: string;
  platform: string;
  release: string;
  addresses: Array<{ iface: string; address: string; family: string }>;
}

export function localInfo(): LocalInfo {
  const out: LocalInfo = { hostname: hostname(), platform: platform(), release: release(), addresses: [] };
  for (const [name, addrs] of Object.entries(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === 'IPv4') out.addresses.push({ iface: name, address: a.address, family: 'IPv4' });
    }
  }
  return out;
}

export interface WakeResult {
  sent: boolean;
  target: string;
  broadcast: string;
  port: number;
  detail?: string;
}

function normalizeMac(mac: string): string | null {
  const hex = mac.replace(/[:\-\s.]/g, '').toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(hex)) return null;
  return hex;
}

export function magicPacket(mac: string): Buffer | null {
  const hex = normalizeMac(mac);
  if (!hex) return null;
  const macBytes = Buffer.from(hex, 'hex');
  const buf = Buffer.alloc(6 + 16 * 6);
  buf.fill(0xff, 0, 6);
  for (let i = 0; i < 16; i++) macBytes.copy(buf, 6 + i * 6);
  return buf;
}

export async function sendWake(mac: string, opts: { broadcast?: string; port?: number } = {}): Promise<WakeResult[]> {
  const pkt = magicPacket(mac);
  if (!pkt) throw new ControlError('BAD_ARGS', `Invalid MAC address: ${mac}`, { mac });
  const port = opts.port ?? 9;
  // Without an explicit broadcast target, fan out to every IPv4 interface's
  // directed broadcast (ip & netmask | ~netmask) plus the global limited
  // broadcast, so multi-homed hosts reach each LAN. One UDP send only reaches
  // the default route's subnet and would lie about "over the LAN".
  const broadcasts = opts.broadcast ? [opts.broadcast] : localBroadcastTargets();
  const results: WakeResult[] = [];
  for (const b of broadcasts) {
    try {
      await new Promise<void>((resolve, reject) => {
        const sock = createSocket('udp4');
        sock.once('error', (e) => {
          sock.close();
          reject(e);
        });
        sock.bind(() => {
          sock.setBroadcast(true);
          sock.send(pkt, 0, pkt.length, port, b, (err) => {
            sock.close();
            err ? reject(err) : resolve();
          });
        });
      });
      results.push({ sent: true, target: mac, broadcast: b, port });
    } catch (e) {
      results.push({ sent: false, target: mac, broadcast: b, port, detail: (e as Error).message });
    }
  }
  return results;
}

function localBroadcastTargets(): string[] {
  const targets = new Set<string>(['255.255.255.255']);
  for (const infos of Object.values(networkInterfaces())) {
    for (const info of infos ?? []) {
      if (info.family !== 'IPv4' || !info.netmask || info.internal) continue;
      const ip = ipToLong(info.address);
      const mask = ipToLong(info.netmask);
      if (ip === null || mask === null) continue;
      targets.add(longToIp((ip & mask) | ~mask >>> 0));
    }
  }
  return [...targets];
}

function ipToLong(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function longToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export interface ArpEntry {
  address: string;
  mac: string | null;
  iface?: string;
  source: string;
}

function parseArpWindows(text: string): ArpEntry[] {
  const out: ArpEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([0-9.]+)\s+([0-9a-fA-F-]{17})\s+(dynamic|static)/.exec(line);
    if (m) out.push({ address: m[1], mac: m[2].toUpperCase(), source: 'arp' });
  }
  return out;
}

function parseArpLinux(text: string): ArpEntry[] {
  const out: ArpEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^([0-9.]+)\s+(?:incomplete|([0-9a-fA-F:]{17}))\b.*?\bon\s+(\S+)/.exec(line);
    if (m) out.push({ address: m[1], mac: m[2]?.toUpperCase() ?? null, iface: m[3], source: 'arp' });
  }
  return out;
}

export async function localArpTable(): Promise<ArpEntry[]> {
  const isWin = platform() === 'win32';
  try {
    const { stdout } = await execFileP(isWin ? 'arp.exe' : 'arp', isWin ? ['-a'] : ['-an'], { timeout: 8000 });
    return isWin ? parseArpWindows(stdout) : parseArpLinux(stdout);
  } catch {
    return [];
  }
}

export interface CdpNeighbor {
  deviceId: string;
  portId: string;
  address?: string;
  platform?: string;
  raw: Record<string, string>;
}

export async function listenCdpWindows(ifaceIndex: number, timeoutMs = 5000): Promise<CdpNeighbor[] | null> {
  const { spawn } = await import('node:child_process');
  return new Promise((resolve) => {
    const child = spawn('powershell', ['-NoProfile', '-EncodedCommand', Buffer.from(cdpScript(ifaceIndex, timeoutMs), 'utf16le').toString('base64')], { windowsHide: true });
    let out = '';
    let errTail = '';
    child.stdout.on('data', (d) => { if (out.length < 1024 * 1024) out += d.toString(); });
    child.stderr.on('data', (d) => { errTail = (errTail + d.toString()).slice(-2000); });
    const t = setTimeout(() => child.kill(), timeoutMs + 5000);
    // A spawn failure (powershell missing, EACCES) emits 'error' on the event
    // loop, OUTSIDE any promise chain — with no listener that is an uncaught
    // exception that takes down the whole MCP server. Resolve null instead.
    child.on('error', () => {
      clearTimeout(t);
      resolve(null);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      const trimmed = out.trim();
      if (trimmed === '' || code !== 0) {
        // Listener could not run (raw sockets need elevation) or produced nothing:
        // null lets the tool answer REMOTE_ERROR instead of a fake empty scan.
        void errTail;
        resolve(trimmed === '' ? null : tryParse(trimmed, errTail));
        return;
      }
      resolve(tryParse(trimmed, errTail));
    });
  });
}

function tryParse(json: string, errTail: string): CdpNeighbor[] | null {
  if (json === 'LISTEN_FAILED') return null;
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? (parsed as CdpNeighbor[]) : null;
  } catch {
    void errTail;
    return null;
  }
}

function cdpScript(ifaceIndex: number, timeoutMs: number): string {
  // SIO_RCVALL = IOC_IN(0x80000000)|IOC_VENDOR(0x10000000)|41; must be applied to a
  // socket bound to the adapter's IPv4 address, or nothing arrives on multi-homed hosts.
  return [
    `$ErrorActionPreference='SilentlyContinue'`,
    `$idx=${ifaceIndex}; $ms=${timeoutMs}`,
    `$ip=(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 | Select-Object -First 1).IPAddress`,
    `if(-not $ip){ Write-Output 'LISTEN_FAILED'; exit }`,
    `$ps=New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::IP)`,
    `try{ $ps.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip),0))) }catch{ Write-Output 'LISTEN_FAILED'; exit }`,
    `try{ $ps.IOControl(-1719656446, 2, $null) | Out-Null }catch{ Write-Output 'LISTEN_FAILED'; exit }`,
    `$end=[DateTime]::Now.AddMilliseconds($ms)`,
    `$frames=@()`,
    `while([DateTime]::Now -lt $end){ if($ps.Available -gt 0){ $b=New-Object byte[] 65536; try{ $n=$ps.Receive($b); if($n -gt 40){ $f=New-Object byte[] $n; [Array]::Copy($b,$f,$n); $frames+=,$f } }catch{} } else { Start-Sleep -Milliseconds 100 } }`,
    `try{ $ps.Close() }catch{}`,
    `$out=@()`,
    `foreach($fr in $frames){ try{`,
    `$e=[System.BitConverter]::ToString($fr).Replace('-','')`,
    `if(-not $e.StartsWith('aaaaaaaaaaaa')){continue}`,
    `$hex=$e.Substring(28)`,
    `if($hex.Substring(0,12) -ne 'aaaa0300000c'){continue}`,
    `$i=44; $d=''; $p=''`,
    `while($i+8 -le $hex.Length){`,
    `$t=[Convert]::ToUInt16($hex.Substring($i,4),16)`,
    `$l=[Convert]::ToUInt16($hex.Substring($i+4,4),16)*2`,
    `if($t -eq 0 -or $l -lt 8 -or ($i+$l) -gt $hex.Length){break}`,
    `$v=$hex.Substring($i+8,$l-8)`,
    `if($t -eq 6){$d=[Text.Encoding]::ASCII.GetString([byte[]](0..(($v.Length/2)-1)|ForEach-Object{ [Convert]::ToByte($v.Substring($_*2,2),16) }))}`,
    `if($t -eq 3){$p=[Text.Encoding]::ASCII.GetString([byte[]](0..(($v.Length/2)-1)|ForEach-Object{ [Convert]::ToByte($v.Substring($_*2,2),16) }))}`,
    `$i+=$l }`,
    `if($d){ $out+=,[pscustomobject]@{deviceId=$d;portId=$p} } }catch{ continue } }`,
    `if($out.Count -eq 0){ Write-Output '[]' } else { $out | ConvertTo-Json -Compress }`,
  ].join('; ');
}
