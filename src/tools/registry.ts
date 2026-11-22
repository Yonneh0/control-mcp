import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { type AnySchema, type ShapeOutput, type ZodRawShapeCompat } from '@modelcontextprotocol/sdk/server/zod-compat.js';
import { ControlError, toolError, toolText } from '../errors.js';
import { ConfigError, getHost } from '../config/loader.js';
import type { ControlConfig, HostConfig } from '../config/schema.js';
import { checkCommand } from '../safety.js';
import { pickInterface } from '../capability.js';
import { SshTransport, type ExecResult } from '../transports/ssh.js';
import { localArpTable, localInfo, listenCdpWindows, ping, probeHost, probeTcp, sendWake, type CdpNeighbor } from '../transports/netprobe.js';
import { CLSID_MsRdpClientNotSafeForScripting, DLL_PATH_DEFAULT, IID_IMsRdpExInstance, createInstanceViaFactory, failed, guidBuffer, hr, loadMsRdpEx, loadOle32, wrapCom, type ComObject } from '../transports/msrdpex.js';
import { findAllWindows, findWindow, hotkey, keyPress, mouseClick, typeText, VK } from '../transports/wininput.js';
import { captureWindowPng } from '../transports/winsnapshot.js';
import { EventMonitor, describeEventSinkPolicy, type SystemEvent } from '../transports/monitor.js';
import { adminRoot, adbAvailable, adbExec, inputSwipe, inputTap, inputText, listDevices, screencapPng } from '../transports/adb.js';
import { join, win32 } from 'node:path';
import { homedir } from 'node:os';
import { existsSync, writeFileSync } from 'node:fs';

// Resolve the config location: an explicit CONTROL_MCP_CONFIG_PATH env var wins,
// otherwise the per-user %APPDATA%\control-mcp\config.toml default. The env
// override makes the server relocatable and testable without code changes.
export const CONTROL_MCP_CONFIG_PATH =
  process.env.CONTROL_MCP_CONFIG_PATH
  ?? join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'control-mcp', 'config.toml');

function requireAbsolute(value: string, argName: string): void {
  // win32 semantics: the server runs on Windows and a POSIX-looking path would
  // silently land on the current drive.
  if (!win32.isAbsolute(value)) throw new ControlError('BAD_ARGS', `${argName} must be an absolute local path`, { [argName]: value });
}

function exitLabel(res: ExecResult): string {
  // A tool-call timeout is its own outcome: say so explicitly (with the "may
  // still be running" caveat) rather than as a bare null exit code.
  if (res.timedOut) return 'timed out (TERM requested; the remote process may still be running)';
  // ssh2 delivers signal=undefined (not null) on a normal close; only a real
  // server-confirmed signal is reported here.
  if (res.signal) return `killed by ${res.signal}`;
  return res.code === null ? 'exit code not reported' : `exit ${res.code}`;
}

// A bounded preview of the command's output appended to the tool-result TEXT line.
// structuredContent always carries the full stdout/stderr, but many clients show
// only the text, so without a preview a failed command teaches the caller nothing
// (just "exit 3"). On failure stderr leads; output is truncated rather than dropped.
function outputPreview(res: ExecResult): string {
  const cap = 1200;
  const take = (s: string): string => (s.length > cap ? `${s.slice(0, cap)}…` : s);
  const so = res.stdout.trim();
  const se = res.stderr.trim();
  const parts: string[] = [];
  if (res.code !== 0 || se) {
    if (se) parts.push(`stderr: ${take(se)}`);
    if (so) parts.push(`stdout: ${take(so)}`);
  } else if (so) {
    parts.push(`stdout: ${take(so)}`);
  }
  return parts.length ? `\n${parts.join('\n')}` : '';
}

interface RdpSessionState {
  host: string;
  attempted: boolean;
  connected: boolean;
  hwnd: number | null;
  lastError: string | null;
  updatedAt: number;
}

function hostMapOf(cfg: ControlConfig | null): Record<string, HostConfig> {
  const map: Record<string, HostConfig> = {};
  if (cfg !== null) for (const h of cfg.hosts) map[h.name] = h;
  return map;
}

// msrdpex.ts exports no session manager, so the manager lives here, on top of the
// koffi functions msrdpex.ts does export. It never fakes a connect: state stays
// unconnected with the real lastError unless an input window is actually returned.
class RdpSessionManager {
  private states = new Map<string, RdpSessionState>();

  private fresh(hostName: string): RdpSessionState {
    return { host: hostName, attempted: false, connected: false, hwnd: null, lastError: 'no connect has been attempted for this host', updatedAt: 0 };
  }

  public snapshot(hostName: string): RdpSessionState {
    return this.states.get(hostName) ?? this.fresh(hostName);
  }

  public connect(host: HostConfig): RdpSessionState {
    const st = this.fresh(host.name);
    st.attempted = true;
    st.updatedAt = Date.now();
    st.lastError = null;
    let factory: ComObject | null = null;
    let instance: ComObject | null = null;
    try {
      // COM must be initialized on this thread before activating a class object,
      // or DllGetClassObject fails with CO_E_NOTINITIALIZED and the reported
      // cause is misleading. APTYPE_DONTCARE (0) is fine for our single-threaded use.
      const ole = loadOle32();
      const init = ole.CoInitializeEx(null, 0);
      if (failed(init)) throw new Error(`CoInitializeEx -> ${hr(init)}`);
      const lib = loadMsRdpEx();
      const clsOut = Buffer.alloc(8);
      const cls = lib.DllGetClassObject(guidBuffer(CLSID_MsRdpClientNotSafeForScripting), guidBuffer(IID_IMsRdpExInstance), clsOut);
      if (failed(cls)) throw new Error(`DllGetClassObject(CLID MsRdpClientNotSafeForScripting) -> ${hr(cls)}`);
      factory = wrapCom(clsOut.readBigUInt64LE(0));
      instance = createInstanceViaFactory(factory.ptr, IID_IMsRdpExInstance);
      const winOut = Buffer.alloc(8);
      const win = lib.Instance_GetInputWindow(instance.ptr, winOut);
      if (failed(win)) throw new Error(`Instance_GetInputWindow on the never-connected control -> ${hr(win)}`);
      const hwnd = Number(winOut.readBigUInt64LE(0));
      if (!(hwnd >= 1)) throw new Error('Instance_GetInputWindow returned no window: this module does not export the MsRdpEx Set*/Connect calls, so no connection state is set and headless connect cannot open a window.');
      // Honest wording: an input window exists, but nothing here ever reached
      // Connected=1 (MsRdpEx hooks only attach inside real client processes).
      st.connected = false;
      st.hwnd = hwnd;
      st.lastError = 'control created with an input window, but no live RDP session: in-process hosting cannot connect (see README RDP section); use the axhost-on-target path for a real session.';
    } catch (err: unknown) {
      st.connected = false;
      st.hwnd = null;
      st.lastError = `MsRdpEx connect failed (control creation via DllGetClassObject, ${DLL_PATH_DEFAULT}): ${err instanceof Error ? err.message : String(err)}`;
    } finally {
      // Release what we own on every exit path so repeated attempts do not leak.
      try { instance?.release(); } catch { /* ignore */ }
      try { factory?.release(); } catch { /* ignore */ }
    }
    this.states.set(host.name, st);
    return st;
  }

  public disconnect(hostName: string): RdpSessionState {
    const st = { ...this.snapshot(hostName) };
    st.connected = false;
    st.hwnd = null;
    st.attempted = false;
    st.lastError = null;
    st.updatedAt = Date.now();
    this.states.set(hostName, st);
    return st;
  }
}

/**
 * The one audited route from caller input to an effect: zod validation (the
 * SDK validates against inputSchema), then safety.checkCommand inside
 * runChecked before any remote command, then every thrown ControlError maps to
 * toolError(code) and everything else to INTERNAL.
 */
export function createPipeline(server: McpServer, cfg: ControlConfig | null, ssh: SshTransport) {
  const rdp = new RdpSessionManager();
  const state: { events: EventMonitor } = { events: new EventMonitor(ssh, { hosts: hostMapOf(cfg) }) };

  async function guarded(name: string, body: () => CallToolResult | Promise<CallToolResult>): Promise<CallToolResult> {
    try {
      return await body();
    } catch (err: unknown) {
      if (err instanceof ControlError) return toolError(err.code, err.message, err.detail, err.hint);
      return toolError('INTERNAL', `${name} failed: ${err instanceof Error ? err.message : String(err)}`, { tool: name });
    }
  }

  function requireHost(name?: string): HostConfig {
    if (cfg === null) {
      throw new ControlError(
        'CAPABILITY_UNAVAILABLE',
        `control-mcp has no hosts: the config at ${CONTROL_MCP_CONFIG_PATH} is missing or invalid. Fix or create that config to use host-scoped tools; local tools (net_ping, arp_table, wol_wake, cdp_discover) still work.`,
        { configPath: CONTROL_MCP_CONFIG_PATH },
      );
    }
    try {
      return getHost(cfg, name);
    } catch (err: unknown) {
      if (err instanceof ConfigError) {
        const known = cfg.hosts.map((h) => h.name).join(', ');
        throw new ControlError(
          'BAD_ARGS',
          `${err.message} Known hosts (name or any configured address): ${known}. Omit host only when exactly one is configured.`,
          { path: err.path, hint: err.hint, knownHosts: cfg.hosts.map((h) => h.name) },
        );
      }
      throw err;
    }
  }

  function define<S extends ZodRawShapeCompat>(name: string, description: string, shape: S, run: (args: ShapeOutput<S>) => CallToolResult | Promise<CallToolResult>): void {
    // SDK types the callback against InputArgs; our audited wrapper returns a
    // plain object literal that satisfies CallToolResult at runtime, so one
    // cast here bridges the generic indirection.
    const cb = async (args: ShapeOutput<S>) => guarded(name, () => run(args));
    server.registerTool(name, { description, inputSchema: shape }, cb as unknown as Parameters<McpServer['registerTool']>[2]);
  }

  function noArgs(name: string, description: string, run: () => CallToolResult | Promise<CallToolResult>): void {
    const cb = async () => guarded(name, run);
    server.registerTool(name, { description }, cb as unknown as Parameters<McpServer['registerTool']>[2]);
  }

  // The one audited route from caller input to an effect: zod validation (the
  // SDK validates against inputSchema), then safety.checkCommand inside
  // runChecked before any remote command, then every thrown ControlError maps to
  // toolError(code) and everything else to INTERNAL.
  async function safetyGate(host: HostConfig, toolName: string, command: string, override?: string): Promise<void> {
    if (override === 'sever-transport') {
      console.error(`AUDIT control-mcp: ${toolName} on host=${host.name} ran with override=sever-transport: ${JSON.stringify(command)}`);
    }
    const refuseSelfSevering = cfg === null || cfg.safety.refuseSelfSevering;
    const guard = checkCommand(command, { refuseSelfSevering, transport: 'ssh', platform: host.os });
    if (!guard.allowed && override !== 'sever-transport') {
      throw new ControlError(guard.code ?? 'TRANSPORT_SEVERED_RISK', guard.reason ?? 'Refused by the safety gate.', { tool: toolName, host: host.name, command });
    }
  }

  async function runChecked(host: HostConfig, toolName: string, command: string, timeoutMs: number, override?: string): Promise<ExecResult> {
    await safetyGate(host, toolName, command, override);
    return await ssh.exec(host, host.address, command, { timeoutMs });
  }

  async function power(host: HostConfig, kind: 'reboot' | 'shutdown', timeoutMs: number): Promise<{ command: string; result: ExecResult; note: string }> {
    const me = localInfo();
    const localAddrs = new Set<string>(me.addresses.map((a) => a.address.toLowerCase()));
    localAddrs.add(me.hostname.toLowerCase());
    // localhost/loopback resolve to this machine even when the config names them
    // differently, so refuse those forms before comparing addresses.
    const loopbackish = /^(localhost|loopback|\[?::1\]?|127(\.\d+){3})$/i;
    const candidates = [host.address, ...host.alternateAddresses];
    if (candidates.some((c) => loopbackish.test(c))) {
      throw new ControlError(
        'TRANSPORT_SEVERED_RISK',
        `Refused: "${host.name}" targets localhost/loopback — the machine running control-mcp. This tool is for LAN boxes, not the control origin.`,
        { host: host.name, localHostname: me.hostname },
      );
    }
    if (candidates.some((c) => localAddrs.has(c.toLowerCase()))) {
      throw new ControlError(
        'TRANSPORT_SEVERED_RISK',
        `Refused: "${host.name}" shares an address with the machine running control-mcp (${me.hostname}); powering it takes the server and every transport with it. This tool is for LAN boxes, not the control origin.`,
        { host: host.name, localHostname: me.hostname, localAddresses: me.addresses.map((a) => a.address) },
      );
    }
    const command = host.os === 'windows'
      ? (kind === 'reboot' ? 'shutdown /r /t 5' : 'shutdown /s /t 5')
      : (kind === 'reboot' ? 'systemctl reboot' : 'systemctl poweroff');
    const result = await runChecked(host, `host_${kind}`, command, timeoutMs);
    const note = host.os === 'linux'
      ? 'linux path used systemctl reboot/poweroff; the safety gate does not flag those, so no transport-sever override was needed.'
      : 'windows shutdown schedule starts in 5s; the SSH channel may close when the box powers down.';
    return { command, result, note };
  }

  function rdpWindowHwnd(hostName: string): number {
    // Prefer the hwnd this host's rdp_connect recorded; a machine-wide class
    // lookup is only safe when exactly one such window exists, or two hosts'
    // sessions would trade inputs.
    const st = rdp.snapshot(hostName);
    if (st.hwnd) return st.hwnd;
    const host = cfg?.hosts.find((h) => h.name === hostName);
    if (!host || (!host.rdp && !host.capabilities.rdp)) {
      throw new ControlError('BAD_ARGS', `no RDP window for host "${hostName}": it has no rdp configured and rdp_connect recorded nothing. Run host_status to see whether RDP is refused by policy.`, { host: hostName });
    }
    const matches = findAllWindows({ className: 'AxHostWindow' });
    if (matches.length === 1) return matches[0];
    if (matches.length > 1) {
      throw new ControlError('BAD_ARGS', `${matches.length} RDP windows are open and none is recorded for host "${hostName}"; rdp_* tools refuse to guess which session to drive. Connect through this server (rdp_connect) so the window handle is tracked per host.`, { host: hostName, candidates: matches });
    }
    throw new ControlError('BAD_ARGS', 'no RDP window to act on: no "AxHostWindow" window is open and rdp_connect has not recorded an hwnd for this host. Run rdp_connect first, and host_status to see whether RDP is refused by policy.', { host: hostName });
  }

  async function listenCdpGuarded(ifaceIndex: number, timeoutMs: number): Promise<CdpNeighbor[] | null> {
    // Hard bound: the powershell listener self-kills at +5 s; +10 s is the outer
    // safety net so this tool call can never run away past ~60 s.
    return await new Promise<CdpNeighbor[] | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), Math.min(timeoutMs, 50000) + 10000);
      void (async () => {
        try {
          resolve(await listenCdpWindows(ifaceIndex, timeoutMs));
        } catch {
          resolve(null);
        } finally {
          clearTimeout(timer);
        }
      })();
    });
  }

  return { define, noArgs, safetyGate, runChecked, power, requireHost, rdp, get events() { return state.events; }, setEvents(m: EventMonitor) { state.events = m; }, rdpWindowHwnd, listenCdpGuarded };
}

// POSIX single-quote escaping: wrap in '...' and turn each embedded ' into '\''.
// Nothing inside single quotes is expanded by the shell, so a remotePath like
// /tmp/$(reboot) or /tmp/`reboot` is matched as a literal name, never executed.
function shSingleQuote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`;
}

async function refuseExistingRemote(p: { runChecked: (h: HostConfig, t: string, c: string, ms: number, o?: string) => Promise<ExecResult> }, h: HostConfig, remotePath: string): Promise<void> {
  // Exit code 0 means exists. Windows paths may not contain a double quote, so
  // reject rather than strip one (stripping would probe a different path than the
  // one we are about to write). POSIX uses single-quote escaping — no expansion.
  let probe: string;
  if (h.os === 'windows') {
    if (remotePath.includes('"')) {
      throw new ControlError('BAD_ARGS', `remotePath for a Windows host cannot contain a double quote: ${remotePath}`, { remotePath, host: h.name });
    }
    probe = `cmd /c "if exist \\"${remotePath}\\" (exit 0) else (exit 1)"`;
  } else {
    probe = `test -e ${shSingleQuote(remotePath)}`;
  }
  let exists = false;
  try {
    const res = await p.runChecked(h, 'file_exists_check', probe, 15000);
    exists = res.code === 0;
  } catch {
    // Unprovable destination: do not claim it is absent. Proceed — the transfer
    // itself reports real errors — but leave a trace so an overwrite-after-a-
    // failed-probe is discoverable rather than silent.
    console.error(`control-mcp: could not pre-check remote destination ${remotePath} on ${h.name}; proceeding, the transfer will report real errors.`);
  }
  if (exists) {
    throw new ControlError('BAD_ARGS', `Remote destination already exists: ${remotePath} on ${h.name}. Pass overwrite:true to replace it.`, { remotePath, host: h.name });
  }
}

function formatEvent(e: SystemEvent): string {
  return `${e.host} [${e.level}] ${e.category}: ${e.summary}`;
}

export function registerTools(server: McpServer, cfg: ControlConfig | null, ssh: SshTransport): () => void {
  const p = createPipeline(server, cfg, ssh);

  // ---------------------------------------------------------------- hosts --
  p.noArgs(
    'host_list',
    'List configured hosts (name, address, os, alternate addresses, declared capabilities, ssh user, rdp configured flag) and never any secrets; answers CAPABILITY_UNAVAILABLE when control-mcp started without a valid config.',
    () => {
      if (cfg === null) {
        return toolError('CAPABILITY_UNAVAILABLE', `no hosts: the config at ${CONTROL_MCP_CONFIG_PATH} is missing or invalid, so nothing is configured.`, { configPath: CONTROL_MCP_CONFIG_PATH });
      }
      const summary = cfg.hosts.map((h) => ({
        name: h.name,
        address: h.address,
        os: h.os,
        alternateAddresses: h.alternateAddresses,
        capabilities: h.capabilities,
        sshUser: h.ssh.user,
        rdpConfigured: Boolean(h.rdp),
      }));
      return toolText(
        summary.map((h) => `${h.name} ${h.address} ${h.os} ssh-user=${h.sshUser} rdp=${h.rdpConfigured} alternates=${h.alternateAddresses.join(',') || '-'}`).join('\n') || 'no hosts configured',
        { hosts: summary },
      );
    },
  );

  p.define(
    'host_status',
    'Probe one host over every configured interface (ping, tcp/22, tcp/3389, Windows RDP policy) and report the honest verdict for each transport, including the exact reason RDP is refused; run this before any RDP tool when you do not know why a box is unreachable.',
    { host: z.string().optional().describe('Host name or address (default when only one host is configured)') },
    async ({ host }) => {
      const h = p.requireHost(host);
      const status = await probeHost(h, ssh);
      const pick = pickInterface(h.address, h.alternateAddresses, status.interfaces);
      const rd = status.rdp;
      const iface = Object.entries(status.interfaces).map(([a, ok]) => `${a}: ping ${ok ? 'ok' : 'failed'}`).join('; ');
      const degradedNote = pick?.degraded ? ` (via alternate ${pick.address}; the primary ${h.address} did not answer)` : '';
      return toolText(
        `host ${status.name} via ${status.address}${degradedNote}\n` +
        `interfaces: ${iface || 'none probed'}\n` +
        `ssh: reachable=${status.ssh.reachable} user=${status.ssh.user}${status.ssh.error ? ' error=' + status.ssh.error : ''}\n` +
        `rdp: ${rd.available ? 'available' : 'refused'} -- ${rd.reason}`,
        { status, rdpVerdict: rd, interfacePick: pick },
      );
    },
  );

  // ---------------------------------------------------------------- command --
  p.define(
    'exec',
    'Run a shell command on a host over SSH and report stdout/stderr/exit code/truncation; commands that would stop the service carrying the live transport are refused with TRANSPORT_SEVERED_RISK unless override is "sever-transport".',
    {
      host: z.string().optional().describe('Host name or address'),
      command: z.string().min(1).describe('Shell command for the host platform'),
      timeoutMs: z.number().int().min(100).max(120000).default(30000).describe('Kill the command after this many ms'),
      override: z.enum(['sever-transport']).optional().describe('Set to "sever-transport" to run a command the safety gate refused'),
    },
    async ({ host, command, timeoutMs, override }) => {
      const h = p.requireHost(host);
      const res = await p.runChecked(h, 'exec', command, timeoutMs, override);
      return toolText(
        `exec ${h.name}: ${exitLabel(res)}${res.truncated ? ' [output truncated; full data in structuredContent]' : ''}${outputPreview(res)}`,
        { host: h.name, address: h.address, command, stdout: res.stdout, stderr: res.stderr, exitCode: res.code, signal: res.signal, truncated: res.truncated, timedOut: res.timedOut, durationMs: res.durationMs },
      );
    },
  );

  p.define(
    'admin_exec',
    'Run a command over SSH expecting administrator effect. Elevation is NOT faked or added: control-mcp runs the command on the same SSH connection and first measures the effective privilege of that account (Windows: whether the sshd token carries the High mandatory label S-1-16-12288; Linux: whether uid is 0). If the account is not privileged the command still runs with whatever rights it has and access-denied comes back from the target. Same safety gate as exec; there is no runas/UAC wrapper.',
    {
      host: z.string().optional().describe('Host name or address'),
      command: z.string().min(1).describe('Shell command for the host platform'),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
      override: z.enum(['sever-transport']).optional().describe('Set to "sever-transport" to run a command the safety gate refused'),
    },
    async ({ host, command, timeoutMs, override }) => {
      const h = p.requireHost(host);
      // Measure the effective privilege of the SSH account itself so the result
      // says what the command actually ran with. Robust and read-only: run the
      // introspection command and inspect ITS output rather than trusting a
      // pipeline's exit code (a missing findstr would otherwise fake "STANDARD").
      // We report 'not measured' whenever the probe is inconclusive.
      const probeCmd = h.os === 'windows' ? 'whoami /groups' : 'id -u';
      let privilege = 'not measured (introspection unavailable)';
      try {
        const probe = await p.runChecked(h, 'admin_exec_probe', probeCmd, 15000);
        if (h.os === 'windows') {
          if (probe.stdout.includes('S-1-16-12288')) privilege = 'elevated-high-integrity';
          else if (probe.stdout.includes('S-1-16-')) privilege = 'standard-integrity (NOT elevated; admin effect needs an elevated sshd token)';
          // else: whoami gave us no mandatory-label line -> leave 'not measured'.
        } else {
          const uid = probe.stdout.trim();
          if (uid === '0') privilege = 'root';
          else if (/^\d+$/.test(uid)) privilege = `non-root (uid ${uid}; sudo may still work if passwordless)`;
        }
      } catch {
        /* probe failures never block the actual command; privilege stays 'not measured' */
      }
      const res = await p.runChecked(h, 'admin_exec', command, timeoutMs, override);
      return toolText(
        `admin_exec ${h.name}: ${exitLabel(res)} [effective privilege: ${privilege}]${res.truncated ? ' [output truncated; full data in structuredContent]' : ''}${outputPreview(res)}`,
        { host: h.name, address: h.address, command, privilege, stdout: res.stdout, stderr: res.stderr, exitCode: res.code, signal: res.signal, truncated: res.truncated, timedOut: res.timedOut, durationMs: res.durationMs },
      );
    },
  );

  // ---------------------------------------------------------------- shells --
  p.define(
    'shell_open',
    'Open a persistent interactive shell session on a host over SSH and return its session id; auth or network failures are reported honestly (AUTH_FAILED/HOST_UNREACHABLE).',
    { host: z.string().optional() },
    async ({ host }) => {
      const h = p.requireHost(host);
      const s = await ssh.openShell(h, h.address);
      return toolText(`shell session ${s.id} open on ${h.name}`, { id: s.id, host: s.host, address: s.address, user: s.user });
    },
  );

  p.define(
    'shell_run',
    'Run one command inside an open shell session (it keeps cwd and env); unknown or dead session ids fail with SESSION_GONE, and the safety gate applies like exec.',
    {
      id: z.string().min(1).describe('Session id from shell_open'),
      command: z.string().min(1),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
      override: z.enum(['sever-transport']).optional().describe('Set to "sever-transport" to run a command the safety gate refused'),
    },
    async ({ id, command, timeoutMs, override }) => {
      const sess = ssh.getSession(id);
      if (!sess) throw new ControlError('SESSION_GONE', `No such shell session: ${id} (list them with shell_list)`);
      const h = p.requireHost(sess.host);
      await p.safetyGate(h, 'shell_run', command, override);
      const res = await ssh.runInShell(id, command, timeoutMs);
      return toolText(res.output, { id, closed: res.closed, output: res.output });
    },
  );

  p.noArgs(
    'shell_list',
    'List open shell sessions (id, host, open/closed) so ids can be found and reused; an empty list honestly means none are open.',
    () => {
      const list = ssh.listSessions();
      return toolText(
        list.map((s) => `${s.id} ${s.host} ${s.closed ? 'closed' : 'open'} last-used=${new Date(s.lastUsedAt).toISOString()}`).join('\n') || 'no shell sessions are open',
        { sessions: list },
      );
    },
  );

  p.define(
    'shell_close',
    'Close an open shell session by id and free its channel; returns SESSION_GONE when the id is unknown or already closed.',
    { id: z.string().min(1) },
    async ({ id }) => {
      const closed = await ssh.closeShell(id);
      if (!closed) throw new ControlError('SESSION_GONE', `Shell session ${id} is not open (already closed or never existed)`);
      return toolText(`closed ${id}`, { id, closed: true });
    },
  );

  // ----------------------------------------------------------------- files --
  p.define(
    'file_upload',
    'Upload a local file (absolute path) to a remote path on a host over SFTP and report byte counts; auth/network failures appear as AUTH_FAILED/HOST_UNREACHABLE. Refuses an existing remote destination unless overwrite:true.',
    {
      host: z.string().optional(),
      remotePath: z.string().min(1).describe('Remote destination path'),
      localPath: z.string().min(1).describe('Absolute local file path'),
      overwrite: z.boolean().optional().describe('Replace the remote file if it already exists (default false)'),
    },
    async ({ host, remotePath, localPath, overwrite }) => {
      const h = p.requireHost(host);
      requireAbsolute(localPath, 'localPath');
      // Fail fast on a bad local path: otherwise a typo reaches SFTP and comes
      // back as REMOTE_ERROR, which mispoints the caller at the remote host.
      if (!existsSync(localPath)) {
        throw new ControlError('BAD_ARGS', `Local source does not exist: ${localPath}. Nothing was uploaded. Check the path (must be an absolute path to an existing local file).`, { localPath }, 'confirm localPath exists on this machine (the host running control-mcp), not on the target; list it to correct the name');
      }
      if (overwrite !== true) {
        await refuseExistingRemote(p, h, remotePath);
      }
      const res = await ssh.uploadFile(h, h.address, localPath, remotePath);
      return toolText(`uploaded ${res.bytes} bytes from ${localPath} to ${remotePath} on ${h.name}`, { host: h.name, remotePath, localPath, bytes: res.bytes });
    },
  );

  p.define(
    'file_download',
    'Download a remote file to an absolute local path over SFTP and report byte counts; missing remote files fail with REMOTE_ERROR. Refuses an existing local destination unless overwrite:true.',
    {
      host: z.string().optional(),
      remotePath: z.string().min(1).describe('Remote source path'),
      localPath: z.string().min(1).describe('Absolute local destination path'),
      overwrite: z.boolean().optional().describe('Replace the local file if it already exists (default false)'),
    },
    async ({ host, remotePath, localPath, overwrite }) => {
      const h = p.requireHost(host);
      requireAbsolute(localPath, 'localPath');
      if (overwrite !== true && existsSync(localPath)) {
        throw new ControlError('BAD_ARGS', `Local destination already exists: ${localPath}. Pass overwrite:true to replace it.`, { localPath });
      }
      const res = await ssh.downloadFile(h, h.address, remotePath, localPath);
      return toolText(`downloaded ${res.bytes} bytes from ${remotePath} to ${localPath}`, { host: h.name, remotePath, localPath, bytes: res.bytes });
    },
  );

  p.define(
    'file_list',
    'List a remote directory over SFTP (name, size, mode, mtime); missing directories fail with REMOTE_ERROR.',
    {
      host: z.string().optional(),
      remotePath: z.string().min(1),
    },
    async ({ host, remotePath }) => {
      const h = p.requireHost(host);
      const entries = await ssh.listDir(h, h.address, remotePath);
      // Cap the returned list: a directory like C:\Windows\System32 has thousands
      // of entries and would otherwise dump megabytes into the model's context.
      const cap = 500;
      const shown = entries.slice(0, cap);
      const truncated = entries.length > cap;
      const lines = shown.map((e) => `${e.type ?? '?'} ${e.name}${e.size !== undefined ? ` ${e.size}B` : ''}`).join('\n');
      return toolText(
        `${entries.length} entries in ${remotePath} on ${h.name}${truncated ? ` (showing first ${cap}; more available — narrow the path)` : ''}\n${lines}`,
        { host: h.name, remotePath, total: entries.length, shown: shown.length, truncated, entries: shown },
      );
    },
  );

  // ------------------------------------------------------- local networking --
  p.define(
    'net_ping',
    'Ping an address from this machine and report whether it answers; a pure local network probe that needs no host config.',
    {
      address: z.string().min(1),
      timeoutMs: z.number().int().min(100).max(15000).default(2000),
    },
    async ({ address, timeoutMs }) => {
      const reachable = await ping(address, timeoutMs);
      return toolText(`ping ${address}: ${reachable ? 'reachable' : `no reply within ${timeoutMs}ms`}`, { address, reachable, timeoutMs });
    },
  );

  p.define(
    'net_probe_tcp',
    'Open a TCP socket to address:port and report whether something listens there (22 = ssh, 3389 = rdp); timeout/error strings explain refusals.',
    {
      address: z.string().min(1),
      port: z.number().int().min(1).max(65535),
      timeoutMs: z.number().int().min(100).max(15000).default(2000),
    },
    async ({ address, port, timeoutMs }) => {
      const r = await probeTcp(address, port, timeoutMs);
      return toolText(`tcp ${address}:${port}: ${r.open ? 'open' : 'closed'}${r.error ? ' (' + r.error + ')' : ''}`, { address, port, open: r.open, error: r.error });
    },
  );

  p.define(
    'wol_wake',
    'Send the Wake-on-LAN magic packet for a MAC address over the LAN and report per-interface send results. Without an explicit broadcast target it fans out to every IPv4 interface\'s directed broadcast plus 255.255.255.255; malformed MACs fail with BAD_ARGS.',
    {
      mac: z.string().min(1),
      broadcast: z.string().optional(),
      port: z.number().int().min(1).max(65535).optional(),
    },
    async ({ mac, broadcast, port }) => {
      const results = await sendWake(mac, { broadcast, port });
      const okCount = results.filter((r) => r.sent).length;
      return toolText(
        `wake ${mac}: sent via ${okCount}/${results.length} target(s): ${results.map((r) => `${r.broadcast}=${r.sent ? 'sent' : 'FAILED (' + (r.detail ?? '?') + ')'}`).join(', ')}`,
        { mac, results },
      );
    },
  );

  p.noArgs(
    'arp_table',
    'Read this machine ARP route cache (address to MAC) so MACs and addresses can be cross-checked; an empty table honestly means the arp command yielded nothing parseable.',
    async () => {
      const entries = await localArpTable();
      return toolText(
        entries.map((e) => `${e.address} ${e.mac ?? '(no mac)'}${e.iface ? ' on ' + e.iface : ''}`).join('\n') || 'arp table is empty',
        { entries },
      );
    },
  );

  p.define(
    'cdp_discover',
    'Listen with a raw-socket CDP listener on a network interface (Get-NetAdapter InterfaceIndex) for Windows CDP neighbor frames up to timeoutMs; an empty result honestly means no neighbors were observed, and a listener that cannot run fails with REMOTE_ERROR.',
    {
      interfaceIndex: z.number().int().min(0).max(32),
      timeoutMs: z.number().int().min(1000).max(50000).default(15000),
    },
    async ({ interfaceIndex, timeoutMs }) => {
      const neighbors = await p.listenCdpGuarded(interfaceIndex, timeoutMs);
      if (neighbors === null) {
        return toolError('REMOTE_ERROR', 'the raw-socket CDP listener (powershell) could not start or exited abnormally; raw sockets typically need an elevated control-mcp process.', { interfaceIndex, timeoutMs });
      }
      return toolText(`cdp interface ${interfaceIndex}: ${neighbors.length} neighbor(s)`, { interfaceIndex, timeoutMs, neighbors });
    },
  );

  // ------------------------------------------------------------------- rdp --
  p.define(
    'rdp_connect',
    'Create or inspect an MsRdpEx RDP control session for a host (action: connect/disconnect/status); headless connect fails against MsRdpEx on this box, so status honestly reports the real last error and never fakes success.',
    {
      host: z.string().optional(),
      action: z.enum(['connect', 'disconnect', 'status']),
    },
    async ({ host, action }) => {
      const h = p.requireHost(host);
      const st = action === 'connect' ? p.rdp.connect(h) : action === 'disconnect' ? p.rdp.disconnect(h.name) : p.rdp.snapshot(h.name);
      return toolText(
        `rdp ${h.name}: connected=${st.connected} attempted=${st.attempted}${st.lastError ? ' lastError=' + st.lastError : ' (no error recorded)'}`,
        { state: st, note: st.connected ? 'window handle recorded; rdp_* tools can act on it' : 'MsRdpEx exports no terminate API, so disconnect only clears our state.' },
      );
    },
  );

  p.define(
    'rdp_screenshot',
    'Capture the RDP window (found by class "AxHostWindow", else the hwnd rdp_connect recorded) to an absolute PNG path via PrintWindow and write it with fs; fails with BAD_ARGS on hosts where rdp_connect never connected or no window is open -- run host_status first.',
    {
      host: z.string().optional(),
      outputPath: z.string().min(1).describe('Absolute path for the PNG file'),
    },
    async ({ host, outputPath }) => {
      const h = p.requireHost(host);
      requireAbsolute(outputPath, 'outputPath');
      const hwnd = p.rdpWindowHwnd(h.name);
      const png = captureWindowPng(hwnd);
      writeFileSync(outputPath, png);
      return toolText(`wrote ${png.length} bytes of PNG to ${outputPath} (window ${hwnd})`, { host: h.name, outputPath, hwnd, bytes: png.length });
    },
  );

  p.define(
    'rdp_click',
    'Send mouse-click window messages (WM_*) to the RDP control window, which forwards them to the remote desktop; BAD_ARGS when no window exists for this host.',
    {
      host: z.string().optional(),
      x: z.number().int().min(0).max(65535),
      y: z.number().int().min(0).max(65535),
      button: z.enum(['left', 'right', 'middle']).default('left'),
      doubleClick: z.boolean().default(false),
    },
    async ({ host, x, y, button, doubleClick }) => {
      const h = p.requireHost(host);
      const hwnd = p.rdpWindowHwnd(h.name);
      mouseClick(hwnd, x, y, button, doubleClick);
      return toolText(`clicked ${button} at ${x},${y} on window ${hwnd}`, { host: h.name, hwnd, x, y, button, doubleClick });
    },
  );

  p.define(
    'rdp_key',
    'Send key window messages to the RDP control window: key is a VK name (ENTER, LEFT, F1, ...) or vk is a number, with optional modifiers for a hotkey; fails BAD_ARGS when no window is found.',
    {
      host: z.string().optional(),
      key: z.string().optional(),
      vk: z.number().int().min(0).max(65535).optional(),
      modifiers: z.array(z.enum(['ctrl', 'alt', 'shift', 'win'])).default([]),
    },
    async ({ host, key, vk, modifiers }) => {
      const h = p.requireHost(host);
      const hwnd = p.rdpWindowHwnd(h.name);
      let code: number | undefined = vk;
      if (code === undefined) {
        if (!key) throw new ControlError('BAD_ARGS', 'give key (a VK name like ENTER) or vk (a number)');
        const mapped: number | undefined = VK[key.toUpperCase()];
        if (mapped === undefined) throw new ControlError('BAD_ARGS', `unknown key name: ${key}. Valid names include A–Z, 0–9, ENTER, ESC, TAB, SPACE, BACKSPACE, DELETE, INSERT, UP/DOWN/LEFT/RIGHT, HOME, END, PAGEUP, PAGEDOWN, F1–F12, and CTRL/ALT/SHIFT/LWIN (used via modifiers). Or pass vk as a number.`, { key }, 'for printable text use rdp_type; rdp_key is for control keys and named hotkeys; vk accepts the raw virtual-key code');
        code = mapped;
      }
      if (modifiers.length > 0) hotkey(hwnd, modifiers, code);
      else keyPress(hwnd, code);
      return toolText(`key ${key ?? 'vk ' + code} sent to window ${hwnd}`, { host: h.name, hwnd, code, modifiers });
    },
  );

  p.define(
    'rdp_type',
    'Type text into the RDP control window via WM_CHAR window messages (the control forwards them to the remote desktop); BAD_ARGS when no window exists.',
    {
      host: z.string().optional(),
      text: z.string().min(1),
    },
    async ({ host, text }) => {
      const h = p.requireHost(host);
      const hwnd = p.rdpWindowHwnd(h.name);
      typeText(hwnd, text);
      return toolText(`typed ${text.length} chars to window ${hwnd}`, { host: h.name, hwnd, text });
    },
  );

  // ------------------------------------------------------- system events --
  p.define(
    'monitor_start',
    'Start polling a host\'s system log (Windows event log critical/error/warning via Get-WinEvent; journald priority<=3 on Linux) every intervalMs. The first poll only baselines existing records and emits nothing, so only events occurring while watched are reported. Events reach the caller by monitor_events drains (poll-based, never push): an MCP client calls monitor_events periodically and any drained events are returned there. Re-calling start() for a watched host is a no-op.',
    {
      host: z.string().min(1),
      intervalMs: z.number().int().min(5000).max(3600000).optional(),
    },
    async ({ host, intervalMs }) => {
      const h = p.requireHost(host);
      if (intervalMs !== undefined) {
        // The monitor holds one shared interval; recreating it at a new cadence
        // resets every watched host's baseline and drops queued-but-undrained
        // events. Say so rather than pretending the restart is free.
        const previous = p.events.listWatched();
        p.events.dispose();
        p.setEvents(new EventMonitor(ssh, { intervalMs, hosts: hostMapOf(cfg) }));
        const ok: string[] = [];
        const failed: string[] = [];
        // Start the subject host FIRST so an unrelated host that is down cannot
        // abort the call for the host this request is actually about.
        try {
          await p.events.start(h.name);
          ok.push(h.name);
        } catch (e) {
          failed.push(`${h.name}: ${e instanceof Error ? e.message : String(e)}`);
        }
        for (const name of previous) {
          if (name === h.name) continue;
          try {
            await p.events.start(name);
            ok.push(name);
          } catch (e) {
            failed.push(`${name}: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const eff = p.events.getIntervalMs();
        const others = ok.filter((n) => n !== h.name);
        let line = `monitor ${h.name}: monitor re-created at every ${eff}ms (all watched-host baselines reset; previously queued events dropped).`;
        if (others.length) line += ` Re-watched other hosts: ${others.join(', ')}.`;
        if (failed.length) line += ` RESTART FAILED for: ${failed.join('; ')}.`;
        return toolText(`${line} Drain with monitor_events. ${describeEventSinkPolicy()}`, { host: h.name, intervalMs: eff, restartFailed: failed });
      }
      if (p.events.listWatched().includes(h.name)) {
        return toolText(`monitor ${h.name}: already watching every ${p.events.getIntervalMs()}ms (no-op; no new baseline). Drain with monitor_events.`, { host: h.name, intervalMs: p.events.getIntervalMs(), noop: true });
      }
      await p.events.start(h.name);
      return toolText(`monitor ${h.name}: watching every ${p.events.getIntervalMs()}ms; the first poll only baselines existing records, so only events after now are reported. Drain with monitor_events. ${describeEventSinkPolicy()}`, { host: h.name, intervalMs: p.events.getIntervalMs() });
    },
  );

  p.define(
    'monitor_stop',
    'Stop polling a host\'s system log; queued undrained events are dropped.',
    { host: z.string().min(1) },
    async ({ host }) => {
      const h = p.requireHost(host);
      if (!p.events.listWatched().includes(h.name)) {
        throw new ControlError('BAD_ARGS', `host "${h.name}" is not being watched; nothing to stop. monitor_list shows which hosts are watched.`, { host: h.name, watched: p.events.listWatched() }, 'run monitor_list to see watched hosts, or monitor_start to begin watching this one');
      }
      p.events.stop(h.name);
      return toolText(`monitor ${h.name}: stopped (any queued undrained events were dropped)`, { host: h.name });
    },
  );

  p.noArgs(
    'monitor_list',
    'List hosts currently watched by the system-event monitor; empty means none.',
    () => {
      const list = p.events.listWatched();
      return toolText(list.join('\n') || 'no hosts are being watched', { watched: list });
    },
  );

  p.define(
    'monitor_events',
    'Drain and clear queued system events (critical/error/warning) from all watched hosts or one host; returns immediately, possibly empty -- call it on your own cadence to poll. This is how monitored log events reach the caller: no push exists over stdio MCP.',
    { host: z.string().optional() },
    async ({ host }) => {
      if (host !== undefined) {
        const h = p.requireHost(host);
        if (!p.events.listWatched().includes(h.name)) {
          const watched = p.events.listWatched();
          throw new ControlError('BAD_ARGS', `host "${h.name}" is not being watched (watched: ${watched.join(', ') || 'none'}); an empty drain here does not mean "no events", it means this host is not monitored.`, { host: h.name, watched }, 'monitor_start this host first, then drain');
        }
        const one = p.events.drainEvents(h.name);
        return toolText(one.map(formatEvent).join('\n') || `no new events from ${h.name} since the last drain`, { count: one.length, events: one });
      }
      const evs = p.events.drainEvents();
      const watched = p.events.listWatched();
      if (watched.length === 0) {
        throw new ControlError('BAD_ARGS', 'no hosts are being watched, so there are no events to drain; run monitor_start first.', { watched: [] }, 'monitor_start <host> begins watching; events arrive via subsequent monitor_events drains');
      }
      return toolText(evs.map(formatEvent).join('\n') || 'no new events since the last drain', { count: evs.length, events: evs, watched });
    },
  );

  // ------------------------------------------------------------------ adb --
  p.noArgs(
    'adb_status',
    'Probe the local adb CLI (Android Debug Bridge) and list connected devices with serial/state/model; honestly reports adb not installed as available=false rather than failing.',
    async () => {
      const probe = await adbAvailable();
      if (!probe.available) return toolText(`adb unavailable: ${probe.error}`, { available: false, error: probe.error });
      const devices = await listDevices();
      return toolText(
        `adb ${probe.version ?? 'unknown version'}; ${devices.length} device(s)` + (devices.length ? '\n' + devices.map((d) => `${d.serial} ${d.state}${d.model ? ' model=' + d.model : ''}`).join('\n') : ''),
        { available: true, version: probe.version, devices },
      );
    },
  );

  p.define(
    'adb_exec',
    'Run a shell command on an adb-connected Android device (adb -s <serial> shell); returns stdout/stderr/exit; timeouts kill the adb child.',
    {
      serial: z.string().min(1),
      command: z.string().min(1),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ serial, command, timeoutMs }) => {
      const res = await adbExec(serial, command, timeoutMs);
      return toolText(`adb exec ${serial}: exit ${res.code ?? 'n/a'}`, { serial, command, ...res });
    },
  );

  p.define(
    'adb_screencap',
    'Capture the Android device screen to an absolute local PNG path (screencap -p streamed via exec-out); validates the PNG signature before writing.',
    {
      serial: z.string().min(1),
      outputPath: z.string().min(1),
      timeoutMs: z.number().int().min(100).max(120000).default(15000),
    },
    async ({ serial, outputPath, timeoutMs }) => {
      requireAbsolute(outputPath, 'outputPath');
      const png = await screencapPng(serial, timeoutMs);
      writeFileSync(outputPath, png);
      return toolText(`wrote ${png.length} bytes of PNG to ${outputPath}`, { serial, outputPath, bytes: png.length });
    },
  );

  p.define(
    'adb_tap',
    'Tap the Android device screen at (x,y) via input tap.',
    {
      serial: z.string().min(1),
      x: z.number().int().min(0).max(65535),
      y: z.number().int().min(0).max(65535),
      timeoutMs: z.number().int().min(100).max(120000).default(15000),
    },
    async ({ serial, x, y, timeoutMs }) => {
      await inputTap(serial, x, y, timeoutMs);
      return toolText(`tapped ${x},${y} on ${serial}`, { serial, x, y });
    },
  );

  p.define(
    'adb_swipe',
    'Swipe the Android device screen from (x1,y1) to (x2,y2) over durationMs via input swipe.',
    {
      serial: z.string().min(1),
      x1: z.number().int().min(0).max(65535),
      y1: z.number().int().min(0).max(65535),
      x2: z.number().int().min(0).max(65535),
      y2: z.number().int().min(0).max(65535),
      durationMs: z.number().int().min(1).max(60000).default(300),
      timeoutMs: z.number().int().min(100).max(120000).default(15000),
    },
    async ({ serial, x1, y1, x2, y2, durationMs, timeoutMs }) => {
      await inputSwipe(serial, x1, y1, x2, y2, durationMs, timeoutMs);
      return toolText(`swiped ${x1},${y1} -> ${x2},${y2} over ${durationMs}ms on ${serial}`, { serial, x1, y1, x2, y2, durationMs });
    },
  );

  p.define(
    'adb_type',
    'Type text into the Android device via input text; restricted to [A-Za-z0-9 ._-] (spaces become %s) so no control characters can reach the shell.',
    {
      serial: z.string().min(1),
      text: z.string().min(1),
      timeoutMs: z.number().int().min(100).max(120000).default(15000),
    },
    async ({ serial, text, timeoutMs }) => {
      await inputText(serial, text, timeoutMs);
      return toolText(`typed ${text.length} chars on ${serial}`, { serial, length: text.length });
    },
  );

  p.define(
    'adb_root',
    'Restart adbd as root on an Android device (adb root); honest about devices that refuse (production builds, verified boot).',
    {
      serial: z.string().min(1),
      timeoutMs: z.number().int().min(100).max(120000).default(15000),
    },
    async ({ serial, timeoutMs }) => {
      const r = await adminRoot(serial, timeoutMs);
      return toolText(`adb root ${serial}: ${r.ok ? 'ok' : 'refused'} -- ${r.output.slice(0, 300)}`, { serial, ok: r.ok, output: r.output });
    },
  );

  // ------------------------------------------------------------ power ops --
  const powerShape = {
    host: z.string().optional(),
    confirm: z.enum(['yes']).optional().describe('Must be exactly "yes" or the tool refuses'),
    timeoutMs: z.number().int().min(100).max(30000).default(15000),
  };

  p.define(
    'host_reboot',
    'Reboot a LAN host over its transport (windows: shutdown /r /t 5, linux: systemctl reboot); it refuses unless confirm is exactly "yes" and refuses any host whose address matches this machine, because these power ops are loud by design.',
    powerShape,
    async ({ host, confirm, timeoutMs }) => {
      if (confirm !== 'yes') return toolError('BAD_ARGS', 'host_reboot refuses without confirm:"yes" -- a reboot is a one-way transport event, so it must be requested intentionally.');
      const h = p.requireHost(host);
      const pw = await p.power(h, 'reboot', timeoutMs);
      return toolText(
        `host_reboot ${h.name}: "${pw.command}" issued; ${exitLabel(pw.result)} -- the box will come back up; re-probe with host_status. ${pw.note}`,
        { host: h.name, command: pw.command, exitCode: pw.result.code, signal: pw.result.signal, stdout: pw.result.stdout, stderr: pw.result.stderr, truncated: pw.result.truncated, durationMs: pw.result.durationMs, note: pw.note },
      );
    },
  );

  p.define(
    'host_shutdown',
    'Power a LAN host off over its transport (windows: shutdown /s /t 5, linux: systemctl poweroff); it refuses unless confirm is exactly "yes" and refuses any host whose address matches this machine, because powering the wrong box off is only reachable by rebooting it on site.',
    powerShape,
    async ({ host, confirm, timeoutMs }) => {
      if (confirm !== 'yes') return toolError('BAD_ARGS', 'host_shutdown refuses without confirm:"yes" -- powering a LAN box off is only reachable by reboot or network setup, so confirm it intentionally.');
      const h = p.requireHost(host);
      const pw = await p.power(h, 'shutdown', timeoutMs);
      return toolText(
        `host_shutdown ${h.name}: "${pw.command}" issued; ${exitLabel(pw.result)} -- the box powers off; reach it again only by rebooting it on site. ${pw.note}`,
        { host: h.name, command: pw.command, exitCode: pw.result.code, signal: pw.result.signal, stdout: pw.result.stdout, stderr: pw.result.stderr, truncated: pw.result.truncated, durationMs: pw.result.durationMs, note: pw.note },
      );
    },
  );

  // Disposal handle for index.ts: stops every EventMonitor poll before the SSH
  // transport closes, so teardown cannot resurrect connections.
  return () => {
    p.events.dispose();
  };
}
