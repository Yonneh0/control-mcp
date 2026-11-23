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
import { findAllWindows, hotkey, keyPress, mouseClick, typeText, VK } from '../transports/wininput.js';
import { captureWindowPng } from '../transports/winsnapshot.js';
import { EventMonitor, describeEventSinkPolicy, type SystemEvent } from '../transports/monitor.js';
import { adminRoot, adbAvailable, adbBinInfo, adbExec, currentApp, deviceState, dumpUi, findUiNodes, getSetting, inputKey, inputSwipe, inputTap, inputText, knownKeyNames, launchApp, listApps, listDevices, listDir, mediaControl, nowPlaying, openUrl, putSetting, pullFile, pushFile, recordScreen, resolveKeyCode, runUiPreset, screencapPng, setTextField, UI_PRESETS } from '../transports/adb.js';
import type { AppsScope, SettingsNs, UiNode, UiPreset, UiTarget } from '../transports/adb.js';
import { decodeWinEventJson, defenderRealtimeSetCommand, defenderSignatureUpdateCommand, defenderStatusCommand, eventQueryCommand, extractJson, firewallAddRuleCommand, firewallRemoveRuleCommand, firewallSetProfileCommand, firewallStatusCommand, isSelfSeverService, serviceChangeCommand, serviceStatusCommand, updateStatusCommand, updateTriggerCommand } from '../transports/windows.js';

// When a PowerShell command run over ssh fails, stderr can carry the echoed
// script, the CLIXML framing a redirected Write-Error produces, and the real
// error text all at once. Slicing the first 200 chars then shows framing/echo and
// buries the reason — e.g. win_service's "nothing was changed" guard sentence.
// Prefer a line that names a known failure, else the last non-empty non-CLIXML
// line; fall back to a leading slice only when stderr is nothing but framing.
function psErrorReason(text: string, max = 240): string {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#<Objs'));
  const preferred = lines.find((l) => /nothing was changed|did not resolve|read-back unverified|Cannot |not found|Access is denied|terminating|Exception/i.test(l));
  const reason = preferred ?? lines[lines.length - 1] ?? text.trim();
  return reason.length > max ? reason.slice(0, max) + '…' : reason;
}
import { applyPatch, buildGlobCommand, buildSearchCommand, looksBinary, parseFindOutput, parseGrepOutput, parseWinGlobOutput, parseWinSearchOutput, sliceLines } from '../transports/fileops.js';
import { buildMetricsCommand, parseLinuxMetrics, parseWindowsMetrics } from '../transports/sysinfo.js';
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
// The param is the structural subset this needs, so both the SSH ExecResult and
// the adb AdbExecResult can share it — an adb command's stdout must not be any
// harder to see in the text view than an ssh command's.
export function outputPreview(res: { stdout: string; stderr: string; code: number | null }): string {
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

// Measure the effective privilege of the SSH account so admin-style tools can
// report what a command actually ran with (Windows: the High mandatory label
// S-1-16-12288; Linux: uid 0). Read-only, and 'not measured' on any doubt.
async function measurePrivilege(
  run: (h: HostConfig, toolName: string, command: string, timeoutMs: number) => Promise<ExecResult>,
  h: HostConfig,
): Promise<string> {
  const probeCmd = h.os === 'windows' ? 'whoami /groups' : 'id -u';
  let privilege = 'not measured (introspection unavailable)';
  try {
    const probe = await run(h, 'admin_exec_probe', probeCmd, 15000);
    if (h.os === 'windows') {
      if (probe.stdout.includes('S-1-16-12288')) privilege = 'elevated-high-integrity';
      else if (probe.stdout.includes('S-1-16-')) privilege = 'standard-integrity (NOT elevated; admin effect needs an elevated sshd token)';
    } else {
      const uid = probe.stdout.trim();
      if (uid === '0') privilege = 'root';
      else if (/^\d+$/.test(uid)) privilege = `non-root (uid ${uid}; sudo may still work if passwordless)`;
    }
  } catch {
    /* probe failures never block the actual command; privilege stays 'not measured' */
  }
  return privilege;
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
    'Probe one host over every configured interface (ping, tcp/22, tcp/3389, Windows RDP policy) and report the honest verdict for each transport, including the exact reason RDP is refused. It separates HOST reachability (does anything answer ping / ARP) from SSH-SERVICE reachability: a refused or filtered port on a pinging host means the box is UP and only the SSH daemon is down, NOT that you should try to wake it. Run this before any RDP tool when you do not know why a box will not connect.',
    { host: z.string().optional().describe('Host name or address (default when only one host is configured)') },
    async ({ host }) => {
      const h = p.requireHost(host);
      const status = await probeHost(h, ssh);
      const pick = pickInterface(h.address, h.alternateAddresses, status.interfaces);
      const rd = status.rdp;
      const iface = Object.entries(status.interfaces).map(([a, ok]) => `${a}: ping ${ok ? 'ok' : 'failed'}`).join('; ');
      const degradedNote = pick?.degraded ? ` (via alternate ${pick.address}; the primary ${h.address} did not answer)` : '';
      const upAddrs = Object.entries(status.interfaces).filter(([, ok]) => ok).map(([a]) => a);
      const st = status.ssh.state;
      const sshLine =
        st === 'ready'
          ? `ssh: READY — service listening and authenticating (user=${status.ssh.user})`
          : st === 'auth'
            ? `ssh: LISTENING but not authenticated (user=${status.ssh.user}): the port is open and the daemon answered; fix the key/password, the host is up`
            : st === 'listening'
              ? `ssh: LISTENING — :${h.ssh.port} is open and the daemon answered, but the SSH handshake did not complete (the service is still starting up, or a key-exchange/host-key algorithm mismatch). The box is UP and the service is answering — do NOT wake it; retry shortly, and treat it as a config problem only if it persists`
              : st === 'refused'
              ? `ssh: NOT LISTENING — the host is UP (it answered and refused the TCP connect on :${h.ssh.port}); the SSH service is stopped or not started yet (common seconds after boot). Do NOT try to wake this box`
              : st === 'filtered'
                ? `ssh: NO RESPONSE — the host answers ping but :${h.ssh.port} timed out/reset (service down or firewalled-to-drop). The box itself is reachable`
                : st === 'down'
                  ? `ssh: host not reachable — no interface answered ping (likely powered off or off-network); this is the case WoL is for`
                  : `ssh: probe error: ${status.ssh.error ?? 'unknown'}`;
      return toolText(
        `host ${status.name} via ${status.address}${degradedNote}\n` +
        `host: ${status.hostUp ? 'UP' : 'DOWN'} (${upAddrs.length ? `pinged ${upAddrs.join(', ')}` : 'no interface answered'})\n` +
        `interfaces: ${iface || 'none probed'}\n` +
        sshLine + '\n' +
        `rdp: ${rd.available ? 'prerequisites present (NOT a verified session)' : 'refused'} -- ${rd.reason}`,
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
        `exec ${h.name}: ${exitLabel(res)}${res.truncated ? ' [output truncated at the 2 MiB transport cap — the remaining bytes were dropped and are NOT available elsewhere in this result; re-run piping to e.g. "tail -c 2097152" or redirect to a file]' : ''}${outputPreview(res)}`,
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
      // Measure the effective privilege of the SSH account so the result says
      // what the command actually ran with (never assume elevation).
      const privilege = await measurePrivilege((hh, tt, cc, mm) => p.runChecked(hh, tt, cc, mm), h);
      const res = await p.runChecked(h, 'admin_exec', command, timeoutMs, override);
      return toolText(
        `admin_exec ${h.name}: ${exitLabel(res)} [effective privilege: ${privilege}]${res.truncated ? ' [output truncated at the 2 MiB transport cap — the remaining bytes were dropped and are NOT available elsewhere in this result; re-run piping to e.g. "tail -c 2097152" or redirect to a file]' : ''}${outputPreview(res)}`,
        { host: h.name, address: h.address, command, privilege, stdout: res.stdout, stderr: res.stderr, exitCode: res.code, signal: res.signal, truncated: res.truncated, timedOut: res.timedOut, durationMs: res.durationMs },
      );
    },
  );

  // ---------------------------------------------------------- system metrics --
  p.define(
    'host_metrics',
    'One SSH exec returning a normalized system snapshot for any SSH host: hostname, uptime, load average, cpu count, memory and swap, per-mount disk usage, and the top processes by memory. Linux reads /proc plus df -P and ps; Windows runs one encoded PowerShell script over Get-CimInstance. Every field a source cannot give is null with a matching note in warnings — never a guess (no MemAvailable means no memUsed; Windows has no load average and no per-process CPU%). Sizes are DECIMAL MB/GB (10^6 bytes), not MiB.',
    {
      host: z.string().optional(),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, timeoutMs }) => {
      const h = p.requireHost(host);
      const os: 'windows' | 'linux' = h.os === 'windows' ? 'windows' : 'linux';
      const res = await p.runChecked(h, 'host_metrics', buildMetricsCommand(os), timeoutMs);
      const metrics = os === 'windows' ? parseWindowsMetrics(extractJson(res.stdout)) : parseLinuxMetrics(res.stdout);
      // The Linux command is joined with ';' so its exit code is head's: a
      // non-zero exit (or a timeout) deserves a note, never a silent pass.
      if (res.code !== 0) metrics.warnings.push(`snapshot may be partial (exit ${res.code ?? 'not reported'})`);

      // Text built ONLY from non-null fields; every number on it is the
      // structured object's own value (/1024 for GB) — no extra precision.
      const gb = (mb: number): string => (mb / 1024).toFixed(1);
      const pair = (used: number | null, total: number | null): string | null =>
        total === null ? null : used === null ? `${gb(total)} GB total` : `${gb(used)}/${gb(total)} GB`;
      const fmtUp = (sec: number): string => {
        const s = Math.floor(sec);
        const d = Math.floor(s / 86400);
        const hr = Math.floor((s % 86400) / 3600);
        const mn = Math.floor((s % 3600) / 60);
        return d > 0 ? `${d}d ${hr}h` : hr > 0 ? `${hr}h ${mn}m` : mn > 0 ? `${mn}m` : `${s}s`;
      };
      const line = [`${h.name} (${os}):`];
      line.push(`up ${metrics.uptimeSec === null ? '-' : fmtUp(metrics.uptimeSec)}`);
      line.push(`load ${metrics.loadAvg === null ? '-' : metrics.loadAvg.map((v) => v.toFixed(2)).join(' ')}`);
      line.push(`cpu ${metrics.cpuCount ?? '-'}`);
      line.push(`mem ${pair(metrics.memUsedMb, metrics.memTotalMb) ?? '-'}`);
      const swap = pair(metrics.swapUsedMb, metrics.swapTotalMb);
      if (swap !== null) line.push(`swap ${swap}`);
      for (const d of metrics.disks) {
        const t = pair(d.usedMb, d.totalMb);
        line.push(t ? `${d.mount} ${t}${d.usedPct === null ? '' : ` (${d.usedPct}%)`}` : `${d.mount} size not measured`);
      }
      const shown = metrics.topProcesses.slice(0, 3);
      if (shown.length > 0) {
        const more = metrics.topProcesses.length > shown.length ? ` (showing ${shown.length} of ${metrics.topProcesses.length})` : '';
        line.push(`top: ${shown.map((pr) => `${pr.name}${pr.memMb === null ? '' : ` ${gb(pr.memMb)} GB`}`).join(', ')}${more}`);
      }
      const notes =
        (metrics.warnings.length ? `\nwarnings: ${metrics.warnings.join('; ')}` : '') +
        (res.truncated ? '\n[remote output was truncated at 2 MiB; this snapshot is incomplete]' : '') +
        (res.timedOut ? '\n[timeout: TERM was requested; the remote command may still be running]' : '');
      return toolText(`${line.join(', ')}${notes}`, { host: h.name, ...metrics });
    },
  );

  // ------------------------------------------------------- windows controls --
  // Firewall / Defender / Update over SSH PowerShell. Every mutation reads the
  // affected setting back and reports the effective privilege, so a success is
  // always measured and a token that cannot elevate is reported, not hidden.
  const winPriv = (h: HostConfig) => measurePrivilege((hh, tt, cc, mm) => p.runChecked(hh, tt, cc, mm), h);
  const requireWindows = (h: HostConfig): void => {
    if (h.os !== 'windows') throw new ControlError('CAPABILITY_UNAVAILABLE', `${h.name} is ${h.os}; these controls are Windows-only`, { host: h.name, os: h.os });
  };

  p.define(
    'win_firewall',
    'Windows Firewall control over SSH PowerShell. action: status (all profiles), set_profile (name + enabled, reads state back), add_allow_rule (inbound Allow for a port; reads the rule back), remove_rule (idempotent, verified). Mutations need the elevated sshd token; effective privilege and the measured read-back are always reported.',
    {
      host: z.string().optional(),
      action: z.enum(['status', 'set_profile', 'add_allow_rule', 'remove_rule']),
      name: z.enum(['Domain', 'Private', 'Public']).optional().describe('profile for set_profile'),
      enabled: z.boolean().optional().describe('target state for set_profile'),
      ruleName: z.string().min(1).max(200).optional().describe('rule DisplayName for add_allow_rule / remove_rule'),
      port: z.number().int().min(1).max(65535).optional(),
      protocol: z.enum(['tcp', 'udp']).optional(),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, action, name, enabled, ruleName, port, protocol, timeoutMs }) => {
      const h = p.requireHost(host);
      requireWindows(h);
      if (action === 'status') {
        const res = await p.runChecked(h, 'win_firewall', firewallStatusCommand(), timeoutMs);
        if (res.code !== 0) return toolError('REMOTE_ERROR', `firewall status failed: ${(res.stderr || res.stdout).trim().slice(0, 200)}`, { host: h.name });
        const profiles = extractJson(res.stdout);
        return toolText(`win_firewall ${h.name}: ${JSON.stringify(profiles ?? res.stdout.trim())}`, { host: h.name, profiles });
      }
      if (action === 'set_profile' && (name === undefined || enabled === undefined)) {
        throw new ControlError('BAD_ARGS', 'set_profile needs name and enabled', { action });
      }
      if (action === 'add_allow_rule' && (!ruleName || port === undefined)) {
        throw new ControlError('BAD_ARGS', 'add_allow_rule needs ruleName and port (protocol defaults to tcp)', { action });
      }
      if (action === 'remove_rule' && !ruleName) throw new ControlError('BAD_ARGS', 'remove_rule needs ruleName', { action });
      const command =
        action === 'set_profile' ? firewallSetProfileCommand(name as string, enabled as boolean)
        : action === 'add_allow_rule' ? firewallAddRuleCommand(ruleName as string, port as number, protocol ?? 'tcp')
        : firewallRemoveRuleCommand(ruleName as string);
      const res = await p.runChecked(h, 'win_firewall', command, timeoutMs);
      const privilege = await winPriv(h);
      const readBack = res.stdout.trim().slice(0, 300);
      if (res.code !== 0) {
        return toolError('REMOTE_ERROR', `firewall ${action} failed: ${(res.stderr || res.stdout).trim().slice(0, 200)}`, { host: h.name, action, privilege }, privilege.includes('elevated') ? 'the token is elevated — check the arguments' : 'this mutation needs an elevated sshd token; a standard-integrity token cannot change the firewall, and the read-back above shows the unchanged state');
      }
      if (action === 'remove_rule') {
        const rb = res.stdout.trim();
        // The builder emits REMOVED or STILL_PRESENT. A zero exit with the rule
        // still present is NOT a success — report it as failed, not success-shaped.
        const removed = /REMOVED/.test(rb) && !/STILL_PRESENT/.test(rb);
        if (!removed) {
          return toolError('REMOTE_ERROR', `firewall remove_rule "${ruleName}" on ${h.name}: the rule is still present after Remove-NetFirewallRule (read-back: ${rb.slice(0, 120) || 'empty'})`, { host: h.name, action, removed: false, privilege }, 'the rule may live under a different DisplayName than the one matched, or the token could not delete it (a non-elevated token cannot); inspect win_firewall status first');
        }
        return toolText(`win_firewall remove_rule "${ruleName}" on ${h.name} [privilege: ${privilege}]: removed (verified absent)`, { host: h.name, action, removed: true, privilege });
      }
      return toolText(`win_firewall ${action} on ${h.name} [privilege: ${privilege}]; read-back: ${readBack}`, { host: h.name, action, privilege, result: extractJson(res.stdout), readBack });
    },
  );

  p.define(
    'win_defender',
    'Windows Defender control over SSH PowerShell. action: status (real-time / signature version / scan-overdue snapshot), realtime_set (on|off, reads the boolean back), signature_update (Update-MpSignature, reads the version back). Scans are intentionally NOT started here — they run for minutes and would outlive a tool timeout. Mutations need the elevated sshd token; privilege and read-back are always reported.',
    {
      host: z.string().optional(),
      action: z.enum(['status', 'realtime_set', 'signature_update']),
      on: z.boolean().optional().describe('real-time protection target for realtime_set'),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, action, on, timeoutMs }) => {
      const h = p.requireHost(host);
      requireWindows(h);
      if (action === 'status') {
        const res = await p.runChecked(h, 'win_defender', defenderStatusCommand(), timeoutMs);
        if (res.code !== 0) return toolError('REMOTE_ERROR', `defender status failed: ${(res.stderr || res.stdout).trim().slice(0, 200)}`, { host: h.name });
        const status = extractJson(res.stdout);
        return toolText(`win_defender ${h.name}: ${JSON.stringify(status ?? res.stdout.trim())}`, { host: h.name, status });
      }
      if (action === 'realtime_set' && on === undefined) {
        throw new ControlError('BAD_ARGS', 'realtime_set needs on:true|false — refusing to guess, because the wrong guess would disable real-time protection', { action });
      }
      const desired = action === 'realtime_set' ? (on as boolean) : undefined;
      const command = action === 'realtime_set' ? defenderRealtimeSetCommand(desired as boolean) : defenderSignatureUpdateCommand();
      const res = await p.runChecked(h, 'win_defender', command, timeoutMs);
      const privilege = await winPriv(h);
      const readBack = res.stdout.trim().slice(0, 200);
      if (res.code !== 0) {
        return toolError('REMOTE_ERROR', `defender ${action} failed: ${(res.stderr || res.stdout).trim().slice(0, 200)}`, { host: h.name, action, privilege }, privilege.includes('elevated') ? 'the token is elevated — check the arguments' : 'this mutation needs an elevated sshd token');
      }
      if (action === 'realtime_set') {
        // Only a literal true/false read-back proves the state. Coercing empty
        // or garbage to `false` would falsely "match" an on:false request and
        // report protection off when nothing was actually read.
        const raw = readBack.trim().toLowerCase();
        const actual = raw === 'true' ? true : raw === 'false' ? false : null;
        const matched = actual === null ? null : actual === desired;
        const outcome =
          matched === true ? ' (matched)' :
          matched === false ? ' (DID NOT MATCH)' :
          ' (read-back was not a boolean; the protection state is NOT verified)';
        return toolText(`win_defender realtime_set ${desired} on ${h.name} [privilege: ${privilege}]; read-back RealTimeProtectionEnabled=${readBack || '<empty>'}${outcome}`, { host: h.name, action, desired, actual, matched, readBack, privilege });
      }
      return toolText(`win_defender signature_update on ${h.name} [privilege: ${privilege}]; new AV signature: ${readBack}`, { host: h.name, action, signatureVersion: readBack, privilege });
    },
  );

  p.define(
    'win_update',
    'Windows Update over SSH. action: status (pending count + top titles + usoclient availability via the Update COM API) and the asynchronous triggers scan|download|install via usoclient — these kick the Update session and return immediately (usoclient\'s own exit code is unreliable, so verify progress with status). No automatic reboot. Reads work on any token; triggers need the elevated sshd token.',
    {
      host: z.string().optional(),
      action: z.enum(['status', 'scan', 'download', 'install']),
      timeoutMs: z.number().int().min(100).max(120000).default(60000),
    },
    async ({ host, action, timeoutMs }) => {
      const h = p.requireHost(host);
      requireWindows(h);
      if (action === 'status') {
        const res = await p.runChecked(h, 'win_update', updateStatusCommand(), timeoutMs);
        const parsed = extractJson(res.stdout) as { PendingCount?: number; Top?: string[]; Usoclient?: boolean; error?: string } | null;
        if (parsed && parsed.error) return toolError('REMOTE_ERROR', `win_update status: ${parsed.error}`, { host: h.name, usoclient: parsed.Usoclient });
        if (!parsed) return toolError('REMOTE_ERROR', `win_update status returned no parseable result: ${res.stdout.trim().slice(0, 160)}`, { host: h.name });
        return toolText(`${h.name}: ${parsed.PendingCount ?? '?'} pending update(s); usoclient=${parsed.Usoclient}${parsed.Top?.length ? `\n` + parsed.Top.map((t) => `- ${t}`).join('\n') : ''}`, { host: h.name, pendingCount: parsed.PendingCount, usoclient: parsed.Usoclient, top: parsed.Top });
      }
      const res = await p.runChecked(h, 'win_update', updateTriggerCommand(action), timeoutMs);
      const privilege = await winPriv(h);
      if (res.code !== 0) {
        return toolError('REMOTE_ERROR', `win_update ${action}: the command failed (exit ${res.code}): ${psErrorReason(res.stderr || res.stdout)}`, { host: h.name, action, privilege }, privilege.includes('elevated') ? 'the token is elevated — usoclient may still have failed to start the session; check win_update status' : 'this trigger needs the elevated sshd token');
      }
      const m = /USO_EXIT=(-?\d+)/.exec(res.stdout);
      if (!m) {
        return toolError('REMOTE_ERROR', `win_update ${action}: usoclient produced no completion marker, so the trigger is unconfirmed.`, { host: h.name, action, privilege }, 'check win_update status (usoclient=true/false); if usoclient is present, retry, then verify progress with win_update status');
      }
      const exitTok = m[1];
      // Honest framing: usoclient was invoked and returned, but the Update
      // session it starts is asynchronous and its progress is NOT observable
      // from here — so this reports invocation, not a verified trigger.
      return toolText(`win_update ${action}: usoclient invoked on ${h.name} (USO_EXIT=${exitTok}) [privilege: ${privilege}] — the trigger was NOT verified (usoclient is asynchronous); confirm with win_update status`, { host: h.name, action, usoclientExit: exitTok, privilege, invoked: true, verified: false, stdout: res.stdout.trim().slice(0, 200) });
    },
  );

  p.define(
    'win_service',
    'Inspect and start/stop/restart Windows services over SSH PowerShell. action: status (all services, or one via service, optionally filtered by state; Name/DisplayName/Status/StartType, StartType joined from one Get-CimInstance Win32_Service pass). start/stop/restart ALWAYS read the service back and report the measured Status plus effective privilege — the read-back, not the exit code, decides whether the action is confirmed. Refuses stop/restart of services that carry the control path (sshd, ssh-agent, termservice, terminalservices, winrm) with TRANSPORT_SEVERED_RISK before running anything; start of those is allowed.',
    {
      host: z.string().optional(),
      action: z.enum(['status', 'start', 'stop', 'restart']),
      service: z.string().min(1).max(200).optional().describe('service name (required for start/stop/restart; optional -Name filter for status)'),
      state: z.enum(['running', 'stopped']).optional().describe('status filter on current Status'),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, action, service, state, timeoutMs }) => {
      const h = p.requireHost(host);
      requireWindows(h);
      if (action === 'status') {
        const res = await p.runChecked(h, 'win_service', serviceStatusCommand(service, state), timeoutMs);
        if (res.code !== 0) return toolError('REMOTE_ERROR', `win_service status failed: ${(res.stderr || res.stdout).trim().slice(0, 200)}`, { host: h.name, service, state }, 'Get-Service/Get-CimInstance may be blocked or the service filter wrong; retry with no service filter to see the full list');
        const parsed = extractJson(res.stdout);
        const services: Array<Record<string, unknown>> = parsed === null ? [] : Array.isArray(parsed) ? parsed as Array<Record<string, unknown>> : [parsed as Record<string, unknown>];
        const running = services.filter((s) => String(s.Status ?? '').toLowerCase() === 'running').length;
        const stopped = services.filter((s) => String(s.Status ?? '').toLowerCase() === 'stopped').length;
        const other = services.length - running - stopped;
        const summary = `win_service status on ${h.name}: ${services.length} service(s) — running=${running} stopped=${stopped}${other > 0 ? ' other=' + other : ''}`;
        const one = services.length === 1 ? services[0] : null;
        return toolText(
          one
            ? `${summary}\n${String(one.Name ?? '?')} "${String(one.DisplayName ?? '')}" — ${String(one.Status ?? '?')} (StartType=${String(one.StartType ?? 'unknown')})`
            : summary,
          { host: h.name, action: 'status', count: services.length, services },
        );
      }
      if (!service) throw new ControlError('BAD_ARGS', `${action} needs a service name`, { action });
      if (isSelfSeverService(service)) {
        throw new ControlError(
          'TRANSPORT_SEVERED_RISK',
          `win_service refuses to ${action} "${service}" on ${h.name} — it carries the ssh path`,
          { host: h.name, service },
          'stopping it drops your control path; use the console (or RDP) on the box, or run the raw Stop/Restart-Service through exec with override=sever-transport if you truly mean it',
        );
      }
      const res = await p.runChecked(h, 'win_service', serviceChangeCommand(service, action), timeoutMs);
      const privilege = await winPriv(h);
      const rb = extractJson(res.stdout);
      const rec = rb !== null && typeof rb === 'object' ? (Array.isArray(rb) ? (rb.length === 1 ? rb[0] : null) : rb) : null;
      const actual = rec && typeof (rec as Record<string, unknown>).Status === 'string' ? (rec as Record<string, unknown>).Status as string : null;
      if (res.code !== 0) {
        return toolError('REMOTE_ERROR', `win_service ${action} "${service}" on ${h.name} failed (exit ${res.code}): ${psErrorReason(res.stderr || res.stdout)}`, { host: h.name, action, service, privilege }, privilege.includes('elevated') ? 'the token is elevated — the service may have dependents (stop/restart refuses without -Force), may be disabled, or the name may not match; run win_service status first' : 'this mutation typically needs the elevated sshd token; a standard-integrity token cannot start/stop most services');
      }
      if (action === 'restart') {
        return toolText(`win_service restart "${service}" on ${h.name} [privilege: ${privilege}]: command completed (exit 0); read-back Status=${actual ?? '<unparsed>'} — verify this is the state you want (no match is claimed for restart)`, { host: h.name, action, service, actual, privilege });
      }
      const desired = action === 'start' ? 'Running' : 'Stopped';
      const matched = actual !== null && actual.toLowerCase() === desired.toLowerCase();
      return toolText(`win_service ${action} "${service}" on ${h.name} [privilege: ${privilege}]: read-back Status=${actual ?? '<unparsed>'} ${matched ? '(confirmed)' : '(DID NOT MATCH — verify)'}`, { host: h.name, action, service, desired, actual, matched, privilege });
    },
  );

  p.define(
    'win_events_query',
    'Bounded historical Windows event-log query over SSH PowerShell — "the last N System errors, now" — distinct from monitor_start/monitor_events, which only report NEW events after a baseline. levels: Critical=1, Error=2, Warning=3, Info=4, Verbose=5. The payload returns as base64-of-UTF8 (event Messages carry arbitrary unicode); empty output means genuinely zero matching events, while an undecodable payload is reported as REMOTE_ERROR — never quietly as zero events.',
    {
      host: z.string().optional(),
      logName: z.string().default('System'),
      levels: z.array(z.number().int().min(1).max(5)).default([1, 2, 3]),
      count: z.number().int().min(1).max(200).default(20),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, logName, levels, count, timeoutMs }) => {
      const h = p.requireHost(host);
      requireWindows(h);
      const res = await p.runChecked(h, 'win_events_query', eventQueryCommand(logName, levels, count), timeoutMs);
      if (res.code !== 0) return toolError('REMOTE_ERROR', `win_events_query ${logName} on ${h.name} failed (exit ${res.code}): ${psErrorReason(res.stderr || res.stdout)}`, { host: h.name, logName, levels, count }, 'check the log name and that the sshd token may read the event log; retry, or run the raw Get-WinEvent via exec');
      const events = decodeWinEventJson(res.stdout);
      if (events === null) return toolError('REMOTE_ERROR', 'win_events_query: could not decode the event payload', { host: h.name, logName, levels, count, stdoutPreview: res.stdout.trim().slice(0, 200) }, 'the command may have failed (check the log name/permissions); retry, or run the raw Get-WinEvent via exec');
      const n = events.length;
      const lines = events.slice(0, 5).map((e) => {
        const r = (e ?? {}) as Record<string, unknown>;
        return `${String(r.TimeCreated ?? '?')} ${String(r.Id ?? '?')} L${String(r.Level ?? '?')} ${String(r.ProviderName ?? '?')}`;
      });
      return toolText(
        `win_events_query ${logName} L${levels.join(',')} on ${h.name}: ${n} event(s)${lines.length ? '\n' + lines.join('\n') : ''}${n === count ? '\nnote: returned exactly the count cap — possibly truncated by the count cap — raise count (max 200)' : ''}`,
        { host: h.name, logName, levels, count, returned: n, truncated: n >= count, events },
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
      if (res.timedOut) {
        return toolError('TIMEOUT', `shell_run on ${id} did not complete before the timeout; the session is now desynchronized. Last output:\n${res.output}`, { id, closed: res.closed, timedOut: true }, 'the command may still be running on the host; its output/exit can no longer be attributed, so open a fresh session with shell_open before running more commands');
      }
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

  // ------------------------------------------------------- file management --
  // The read/write family `exec` can only do clumsily, over the same audited
  // route. Cross-OS by design: Linux uses GNU find (its own glob, via -path) and
  // grep -E, Windows uses PowerShell (-like, Select-String with a .NET regex).
  // The dialects genuinely differ, so each description says which one applies
  // instead of pretending they are interchangeable. Every result is bounded and
  // every bound it hits is reported.

  p.define(
    'file_glob',
    'Find files by name under a directory over SSH, newest-first: GNU find -path on Linux, Get-ChildItem + -like on Windows. The pattern is relative to path on both (Windows matches the full path, so the root is prefixed and "/" is read as "\"). Bounded by maxResults and a capped answer says so. Glob dialect differs by OS: find treats ** as * because -path spans "/", PowerShell -like uses * ? [ ].',
    {
      host: z.string().optional(),
      pattern: z.string().min(1).describe('Glob relative to path, e.g. "*.log" or "src/**/*.ts"'),
      path: z.string().optional().describe('Directory to search under (default "/" on linux, "C:\\" on windows)'),
      maxResults: z.number().int().min(1).max(2000).default(200),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, pattern, path, maxResults, timeoutMs }) => {
      const h = p.requireHost(host);
      const root = path ?? (h.os === 'windows' ? 'C:\\' : '/');
      const res = await p.runChecked(h, 'file_glob', buildGlobCommand(h.os, { root, pattern, filesOnly: true, maxResults }), timeoutMs);
      if (res.code !== 0) {
        // Honesty about what can be diagnosed: the query ends in 2>/dev/null (it
        // suppresses the permission-denied noise of a recursive walk), so on Linux
        // find's own message — including "command not found" — never reaches us and
        // the exit code is the only evidence. Windows PowerShell writes to stderr,
        // which is NOT redirected, so its text is usable there.
        const out = `${res.stderr}\n${res.stdout}`;
        const missing = /is not recognized|not recognized|: not found|command not found/i.test(out);
        const gone = h.os === 'linux' && res.code === 127;
        const why = missing || gone
          ? ` — no find(1)/powershell on the target${gone ? ' (exit 127)' : ''}`
          : '';
        return toolError(
          'REMOTE_ERROR',
          `file_glob ${pattern} under ${root} on ${h.name}: ${exitLabel(res)}${why}`,
          { host: h.name, root, pattern, exitCode: res.code, signal: res.signal, timedOut: res.timedOut, stdout: res.stdout, stderr: res.stderr },
          missing || gone
            ? 'install the search tool the target lacks (GNU findutils on Linux, PowerShell on Windows), or run an equivalent command via exec'
            : h.os === 'linux'
              ? 'the query suppresses find\'s stderr (2>/dev/null), so re-run the equivalent find via exec without it to read the reason; confirm the root with file_list, and raise timeoutMs for a very large tree'
              : 'check the root exists with file_list and raise timeoutMs for a very large tree',
        );
      }
      // Parse everything the target sent, then bound the result here so the count
      // reported is the count actually seen.
      const all = (h.os === 'windows' ? parseWinGlobOutput : parseFindOutput)(res.stdout, Number.MAX_SAFE_INTEGER);
      const shown = all.slice(0, maxResults);
      // Windows caps remotely (Select-Object -First), so filling the cap means
      // more matches exist that were never sent; on Linux the count is exact
      // unless the transport's 2 MiB output ceiling truncated it.
      const capped = h.os === 'windows' ? shown.length >= maxResults : all.length > maxResults;
      const capNote = !capped ? ''
        : h.os === 'windows' ? ` (capped at ${maxResults} by the remote query — more matches may exist; narrow the pattern or raise maxResults)`
        : ` (${all.length} matched, showing the newest ${shown.length}; narrow the pattern or raise maxResults)`;
      return toolText(
        `${shown.length} file(s) matching ${pattern} under ${root} on ${h.name}${capNote}${res.truncated ? ' [remote output was truncated at 2 MiB; this list is incomplete]' : ''}` +
          (shown.length ? '\n' + shown.map((f) => `${new Date(f.mtimeMs).toISOString()} ${f.path}`).join('\n') : ''),
        { host: h.name, root, pattern, matches: shown.length, totalSeen: all.length, capped, truncatedOutput: res.truncated, files: shown },
      );
    },
  );

  p.define(
    'file_search',
    'Search file contents under a directory over SSH and return path:line:text matches. Regex dialect differs by OS and is NOT interchangeable: POSIX ERE via grep -E on Linux, .NET regex via Select-String on Windows. Binary files are skipped; output is capped by maxResults and a capped answer says so.',
    {
      host: z.string().optional(),
      pattern: z.string().min(1).describe('Regex: ERE on Linux (grep -E), .NET on Windows (Select-String)'),
      path: z.string().optional().describe('Directory to search (default "." = the SSH login cwd; a relative path is fine)'),
      include: z.string().optional().describe('Restrict file names, e.g. "*.ts" (grep --include on Linux, -like on Windows)'),
      maxResults: z.number().int().min(1).max(2000).default(200),
      timeoutMs: z.number().int().min(100).max(120000).default(30000),
    },
    async ({ host, pattern, path, include, maxResults, timeoutMs }) => {
      const h = p.requireHost(host);
      const root = path ?? '.';
      const res = await p.runChecked(h, 'file_search', buildSearchCommand(h.os, { root, pattern, include, maxResults }), timeoutMs);
      // grep exits 1 for "no matches": that is success with zero results. >=2 is a
      // real remote failure, and a missing exit status (timeout, or no exit-status
      // payload) is never reported as success.
      if (res.code === null || res.code >= 2) {
        // 127 is measurable evidence of a missing search tool even when the shell
        // says nothing usable; the text forms are the Windows/cmd spellings.
        const missing = /command not found|: not found|is not recognized|not recognized/i.test(`${res.stderr}\n${res.stdout}`);
        const gone = h.os === 'linux' && res.code === 127;
        const need = h.os === 'windows' ? 'powershell' : 'grep';
        return toolError(
          'REMOTE_ERROR',
          `file_search in ${root} on ${h.name}: ${exitLabel(res)}${missing || gone ? ` — no ${need} on the target${gone ? ' (exit 127)' : ''}` : ''}`,
          { host: h.name, root, pattern, include, exitCode: res.code, signal: res.signal, timedOut: res.timedOut, stdout: res.stdout, stderr: res.stderr },
          missing || gone
            ? `install ${need} on the target, or run an equivalent search via exec`
            : 'check the root exists with file_list; a bad regex can also fail this way (ERE on Linux, .NET on Windows)',
        );
      }
      const all = (h.os === 'windows' ? parseWinSearchOutput : parseGrepOutput)(res.stdout, Number.MAX_SAFE_INTEGER);
      const shown = all.slice(0, maxResults);
      const capped = h.os === 'windows' ? shown.length >= maxResults : all.length > maxResults;
      const capNote = !capped ? ''
        : h.os === 'windows' ? ` (capped at ${maxResults} by the remote query — more matches may exist; narrow the pattern or raise maxResults)`
        : ` (${all.length} matched, showing the first ${shown.length}; raise maxResults for the rest)`;
      // A non-zero exit here is meaningful, not noise: on Linux it is grep's
      // "no matches" code; on Windows the script only fails if PowerShell did.
      const exitNote = res.code === 0 ? ''
        : h.os === 'linux' ? ' [grep exit 1 = no matches]'
        : ` [powershell exit ${res.code}: ${(res.stderr || res.stdout).trim().slice(0, 160) || 'no output'}]`;
      return toolText(
        `${shown.length} match(es) for ${pattern} under ${root} on ${h.name}${capNote}${exitNote}${res.truncated ? ' [remote output was truncated at 2 MiB; this list is incomplete]' : ''}` +
          (shown.length ? '\n' + shown.map((m) => `${m.path}:${m.line}:${m.text}`).join('\n') : ''),
        { host: h.name, root, pattern, include: include ?? null, matches: shown.length, totalSeen: all.length, capped, truncatedOutput: res.truncated, exitCode: res.code, results: shown },
      );
    },
  );

  p.define(
    'file_read',
    'Read a bounded window of a remote text file over SFTP (no shell involved) and return numbered lines under a header stating the window and the real line count. A file larger than maxBytes is read truncated and says so; a file with a NUL byte in the first 8 KiB is refused in favour of file_download.',
    {
      host: z.string().optional(),
      remotePath: z.string().min(1),
      offset: z.number().int().min(1).default(1).describe('1-based first line to return'),
      limit: z.number().int().min(1).max(20000).default(2000).describe('Maximum lines to return'),
      maxBytes: z.number().int().min(1).max(8388608).default(1048576).describe('Stream ceiling; a larger file is read truncated'),
    },
    async ({ host, remotePath, offset, limit, maxBytes }) => {
      const h = p.requireHost(host);
      const r = await ssh.readRemoteFile(h, h.address, remotePath, { maxBytes });
      if (looksBinary(r.buffer)) {
        return toolError(
          'BAD_ARGS',
          'file looks binary; use file_download',
          { host: h.name, remotePath, bytesRead: r.buffer.length },
          'file_download copies it verbatim — decoding it as text here would return mojibake, so nothing is shown',
        );
      }
      const w = sliceLines(r.buffer.toString('utf8'), offset, limit);
      const notes: string[] = [];
      if (r.truncated) notes.push(`(file larger than maxBytes ${maxBytes}B — read truncated, use file_download or raise maxBytes)`);
      if (w.shown.length === 0) notes.push(`(offset ${offset} is past the end of the file — ${w.totalLinesSeen} line(s) seen)`);
      const header = `${remotePath} lines ${w.firstLine}-${w.lastLine} of ${w.totalLinesSeen}${notes.length ? ' ' + notes.join(' ') : ''}`;
      return toolText(
        `${header}${w.shown.length ? '\n' + w.shown.map((line, i) => `${w.firstLine + i}: ${line}`).join('\n') : ''}${w.truncatedByLimit ? `\n… use offset=${w.lastLine + 1} to continue` : ''}`,
        { host: h.name, remotePath, offset, firstLine: w.firstLine, lastLine: w.lastLine, totalLinesSeen: w.totalLinesSeen, truncatedByBytes: r.truncated, truncatedByLimit: w.truncatedByLimit, lines: w.shown },
      );
    },
  );

  p.define(
    'file_write',
    'Write (or append) text to a remote file over SFTP as UTF-8 and report the byte count. Without append, an existing destination is refused unless overwrite:true and a directory target is refused — the same guard as file_upload. For targeted edits use file_patch.',
    {
      host: z.string().optional(),
      remotePath: z.string().min(1),
      content: z.string().default('').describe('Text to write as UTF-8; an empty string truncates the file (or appends nothing)'),
      append: z.boolean().default(false).describe('Append instead of replacing the file'),
      overwrite: z.boolean().default(false).describe('Replace an existing file when not appending (default false)'),
    },
    async ({ host, remotePath, content, append, overwrite }) => {
      const h = p.requireHost(host);
      let mode: 'created' | 'replaced' | 'appended' = append ? 'appended' : 'created';
      if (!append) {
        const st = await ssh.statRemote(h, h.address, remotePath);
        if (st?.isDirectory) {
          throw new ControlError('BAD_ARGS', `target is a directory: ${remotePath} on ${h.name}`, { remotePath, host: h.name }, 'file_write writes files — pass a file path (file_list shows each entry type)');
        }
        if (st && overwrite !== true) {
          throw new ControlError('BAD_ARGS', `Remote destination already exists: ${remotePath} on ${h.name}. Pass overwrite:true to replace it.`, { remotePath, host: h.name, size: st.size, mtime: new Date(st.mtime).toISOString() });
        }
        if (st) mode = 'replaced';
      }
      const w = await ssh.writeRemoteFile(h, h.address, remotePath, Buffer.from(content, 'utf8'), { append });
      return toolText(`wrote ${w.bytes} bytes (${mode}) to ${remotePath} on ${h.name}`, { host: h.name, remotePath, bytes: w.bytes, mode });
    },
  );

  // A truncated read must never be written back — it would silently truncate the
  // remote file — so the patch path reads at the family ceiling and refuses above it.
  const PATCH_MAX_BYTES = 8 * 1024 * 1024;

  p.define(
    'file_patch',
    'Apply targeted string edits to a remote text file (read -> patch -> write over SFTP). Each edit\'s oldString must match exactly once unless replaceAll:true; a 0-match or ambiguous match refuses the WHOLE patch, so no edit lands on its own. Binary files and files over 8 MiB are refused rather than rewritten from a truncated read.',
    {
      host: z.string().optional(),
      remotePath: z.string().min(1),
      edits: z
        .array(z.object({ oldString: z.string(), newString: z.string(), replaceAll: z.boolean().optional() }).strict())
        .min(1)
        .describe('Applied in order against the working text: each edit sees the previous edit\'s result'),
    },
    async ({ host, remotePath, edits }) => {
      const h = p.requireHost(host);
      const r = await ssh.readRemoteFile(h, h.address, remotePath, { maxBytes: PATCH_MAX_BYTES });
      if (looksBinary(r.buffer)) {
        return toolError('BAD_ARGS', 'file looks binary; use file_download, edit locally, then file_upload', { host: h.name, remotePath, bytesRead: r.buffer.length }, 'a string patch on bytes decoded as text can corrupt the file, so nothing was written');
      }
      if (r.truncated) {
        return toolError(
          'BAD_ARGS',
          `file is larger than the ${PATCH_MAX_BYTES}B read ceiling, so this read is truncated — writing it back would truncate the remote file`,
          { host: h.name, remotePath, bytesRead: r.buffer.length },
          'use file_download + file_upload for a file this large, or run a stream editor on the target via exec',
        );
      }
      // applyPatch validates every edit against a working copy first, so a bad
      // edit anywhere means nothing is written.
      const { newText, results } = applyPatch(r.buffer.toString('utf8'), edits);
      await ssh.writeRemoteFile(h, h.address, remotePath, Buffer.from(newText, 'utf8'), { append: false });
      return toolText(
        `patched ${remotePath}: ${results.map((x) => `edit#${x.index} replaced ${x.replaced}`).join('; ')} — read-modify-write, not atomic: concurrent edits can be lost`,
        { host: h.name, remotePath, results, bytesWritten: newText.length },
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
    'Listen with a raw-socket CDP listener on a network interface (Get-NetAdapter InterfaceIndex) for Windows CDP neighbor frames up to timeoutMs; an empty result honestly means no neighbors were observed, and a listener that cannot run fails with CAPABILITY_UNAVAILABLE.',
    {
      interfaceIndex: z.number().int().min(0).max(32),
      timeoutMs: z.number().int().min(1000).max(50000).default(15000),
    },
    async ({ interfaceIndex, timeoutMs }) => {
      const neighbors = await p.listenCdpGuarded(interfaceIndex, timeoutMs);
      if (neighbors === null) {
        return toolError('CAPABILITY_UNAVAILABLE', 'the raw-socket CDP listener (powershell) could not start or exited abnormally on the control machine (this is a local failure, not a target failure); raw sockets typically need an elevated control-mcp process.', { interfaceIndex, timeoutMs }, 'run control-mcp elevated, or skip CDP discovery if raw-socket capture is not available here');
      }
      return toolText(`cdp interface ${interfaceIndex}: ${neighbors.length} neighbor(s)`, { interfaceIndex, timeoutMs, neighbors });
    },
  );

  // ------------------------------------------------------------------- rdp --
  p.define(
    'rdp_connect',
    'Create or inspect an MsRdpEx RDP control for a host (action: connect/disconnect/status). IMPORTANT — this does NOT establish a working session on the control host: the in-process MsRdpEx control cannot reach a live session here (MsRdpEx Detours hooks only attach inside a real mstsc/msrdc process), so connect returns connected=false with the measured HRESULT (e.g. 0x80040111 = control class not registered) and never fakes success. The rdp_screenshot/rdp_click/rdp_key/rdp_type tools act on an ALREADY-OPEN RDP window (class AxHostWindow) — for example one launched with mstsc — and do not create the session themselves.',
    {
      host: z.string().optional(),
      action: z.enum(['connect', 'disconnect', 'status']),
    },
    async ({ host, action }) => {
      const h = p.requireHost(host);
      const st = action === 'connect' ? p.rdp.connect(h) : action === 'disconnect' ? p.rdp.disconnect(h.name) : p.rdp.snapshot(h.name);
      return toolText(
        `rdp ${h.name}: connected=${st.connected} attempted=${st.attempted}${st.lastError ? ' lastError=' + st.lastError : ' (no error recorded)'}`,
        { state: st, note: st.connected ? 'input-window handle recorded; rdp_screenshot/rdp_click/rdp_key/rdp_type can act on it' : 'No live session: this server cannot open a scripted RDP session in-process on this host. To drive a desktop, open an RDP window on the control machine first (e.g. mstsc); then the rdp_* tools act on that window. disconnect only clears our recorded state (MsRdpEx exports no terminate API).' },
      );
    },
  );

  p.define(
    'rdp_screenshot',
    'Capture an ALREADY-OPEN RDP window (found by class "AxHostWindow", else the hwnd rdp_connect recorded) to an absolute PNG path via PrintWindow and write it with fs. It cannot create a session — on the acceptance box rdp_connect does not connect, so there is usually no window unless one was opened with mstsc; fails with BAD_ARGS when no window exists. Run host_status / rdp_connect status first.',
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
    'Send a mouse-click window message (WM_*) to an ALREADY-OPEN RDP window (class AxHostWindow), which forwards it to the remote desktop. This drives a session that already exists (e.g. opened with mstsc); it does not create one. BAD_ARGS when no window is recorded/open for this host.',
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
    'Send a key window message to an ALREADY-OPEN RDP window (class AxHostWindow): key is a VK name (ENTER, LEFT, F1, ...) or vk is a number, with optional modifiers for a hotkey. Drives a session that already exists (e.g. opened with mstsc); it does not create one. Fails BAD_ARGS when no window is recorded/open for this host.',
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
        if (mapped === undefined) throw new ControlError('BAD_ARGS', `unknown key name: ${key}. Valid names include A–Z, 0–9, ENTER, ESC, TAB, SPACE, BACKSPACE, DELETE, INSERT, UP/DOWN/LEFT/RIGHT, HOME, END, PAGEUP, PAGEDOWN, F1–F12, and CTRL/ALT/SHIFT/WIN (used via modifiers). Or pass vk as a number.`, { key }, 'for printable text use rdp_type; rdp_key is for control keys and named hotkeys; vk accepts the raw virtual-key code');
        code = mapped;
      }
      if (modifiers.length > 0) hotkey(hwnd, modifiers, code);
      else keyPress(hwnd, code);
      return toolText(`key ${key ?? 'vk ' + code} sent to window ${hwnd}`, { host: h.name, hwnd, code, modifiers });
    },
  );

  p.define(
    'rdp_type',
    'Type text into an ALREADY-OPEN RDP window (class AxHostWindow) via WM_CHAR window messages, which the control forwards to the remote desktop. Drives a session that already exists (e.g. opened with mstsc); it does not create one. BAD_ARGS when no window is recorded/open for this host.',
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
        const dropped = p.events.getDroppedCount(h.name);
        const dropNote = dropped > 0 ? `\n(+${dropped} older event(s) dropped by the 500-deep queue cap since this host was watched)` : '';
        return toolText((one.map(formatEvent).join('\n') || `no new events from ${h.name} since the last drain`) + dropNote, { count: one.length, dropped, events: one });
      }
      const evs = p.events.drainEvents();
      const watched = p.events.listWatched();
      if (watched.length === 0) {
        throw new ControlError('BAD_ARGS', 'no hosts are being watched, so there are no events to drain; run monitor_start first.', { watched: [] }, 'monitor_start <host> begins watching; events arrive via subsequent monitor_events drains');
      }
      const dropped = p.events.getDroppedCount();
      const dropNote = dropped > 0 ? `\n(+${dropped} older event(s) dropped by the 500-deep queue cap across watched hosts)` : '';
      return toolText((evs.map(formatEvent).join('\n') || 'no new events since the last drain') + dropNote, { count: evs.length, dropped, events: evs, watched });
    },
  );

  // ------------------------------------------------------------------ adb --
  p.noArgs(
    'adb_status',
    'Probe the local adb CLI (Android Debug Bridge) and list connected devices with serial/state/model; honestly reports adb not installed as available=false rather than failing.',
    async () => {
      const bin = adbBinInfo();
      const binLabel = bin.source === 'path' ? 'adb (resolved via PATH)' : bin.bin;
      const probe = await adbAvailable();
      if (!probe.available) {
        return toolText(`adb unavailable: ${probe.error}`, { available: false, error: probe.error, adbBinary: bin.bin, adbBinarySource: bin.source, probedPaths: bin.checked });
      }
      const devices = await listDevices();
      return toolText(
        `adb ${probe.version ?? 'unknown version'} (binary: ${binLabel}); ${devices.length} device(s)` + (devices.length ? '\n' + devices.map((d) => `${d.serial} ${d.state}${d.model ? ' model=' + d.model : ''}`).join('\n') : ''),
        { available: true, version: probe.version, adbBinary: bin.bin, adbBinarySource: bin.source, probedPaths: bin.checked, devices },
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
      if (res.missing) return toolError('CAPABILITY_UNAVAILABLE', `adb not installed: cannot run "${command}" on ${serial}`, { serial, command }, 'install Android platform-tools and put it on PATH, or set CONTROL_MCP_ADB_PATH to the adb binary; run adb_status to see which path control-mcp resolved');
      return toolText(`adb exec ${serial}: exit ${res.code ?? 'n/a'}` + outputPreview(res), { serial, command, ...res });
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

  p.define(
    'adb_device_state',
    'Compact health/power snapshot of a connected Android device: battery level/status/plugged/temperature (dumpsys battery), wakefulness + screen state + doze (dumpsys power), airplane mode and screen brightness/mode (settings), and free space on /data (df). Each read is independent: a field the dump did not yield is null (never guessed), and the sections that could not be read are listed as unavailable.',
    { serial: z.string().min(1), timeoutMs: z.number().int().min(100).max(120000).default(15000) },
    async ({ serial, timeoutMs }) => {
      const s = await deviceState(serial, timeoutMs);
      const parts: string[] = [];
      const bat: string[] = [];
      if (s.battery.status !== null) bat.push(s.battery.status);
      if (s.battery.plugged !== null) bat.push(s.battery.plugged);
      if (s.battery.temperatureC !== null) bat.push(`${s.battery.temperatureC}°C`);
      if (s.battery.level !== null) parts.push(`battery ${s.battery.level}%${bat.length ? ` (${bat.join(', ')})` : ''}`);
      else if (bat.length) parts.push(`battery ${bat.join(', ')}`);
      const pw: string[] = [];
      if (s.power.wakefulness !== null) pw.push(s.power.wakefulness);
      if (s.power.screenOn !== null) pw.push(s.power.screenOn ? 'screenOn' : 'screenOff');
      if (s.power.doze !== null) pw.push(`doze:${s.power.doze}`);
      if (pw.length) parts.push(pw.join(', '));
      if (s.airplaneModeOn !== null) parts.push(`airplane ${s.airplaneModeOn ? 'on' : 'off'}`);
      const br: string[] = [];
      if (s.screenBrightness !== null) br.push(`brightness ${s.screenBrightness}`);
      if (s.screenBrightnessMode !== null) br.push(s.screenBrightnessMode === '1' ? 'auto' : s.screenBrightnessMode === '0' ? 'manual' : `mode:${s.screenBrightnessMode}`);
      if (br.length) parts.push(br.join('/'));
      if (s.dataFreeMb !== null) parts.push(`/data ${s.dataFreeMb >= 1024 ? `${(s.dataFreeMb / 1024).toFixed(1)} GB` : `${s.dataFreeMb} MB`} free`);
      const failedNote = s.failed.length ? ` (unavailable: ${s.failed.join(', ')})` : '';
      return toolText(`${serial} : ${parts.length ? parts.join(', ') : 'no state field could be read'}${failedNote}`, { ...s });
    },
  );

  // ------------------------------------------- adb UI control & device ops --
  // These mirror the browser-mcp affordance model (snapshot / find / click by
  // target / press / goto) so the same workflow applies to a real device, and
  // every screen action targets parsed uiautomator nodes instead of guessed
  // pixel coordinates.
  const serialArg = z.string().min(1).describe('adb device serial (from adb_status)');
  const tm15 = z.number().int().min(100).max(120000).default(15000);
  const summarize = (n: UiNode) => ({
    text: n.text || undefined,
    desc: n.desc || undefined,
    id: n.resourceId || undefined,
    class: n.className,
    clickable: n.clickable,
    enabled: n.enabled,
    center: [n.centerX, n.centerY],
    bounds: n.bounds,
  });
  const targetFrom = (a: { text?: string; desc?: string; id?: string; className?: string; contains?: boolean }): UiTarget => ({
    text: a.text,
    desc: a.desc,
    id: a.id,
    className: a.className,
    contains: a.contains,
  });
  const hasSelector = (a: UiTarget): boolean =>
    a.text !== undefined || a.desc !== undefined || a.id !== undefined || a.className !== undefined;

  p.define(
    'adb_ui_dump',
    'Snapshot the Android UI to a structured element tree (uiautomator dump) — the device equivalent of a browser snapshot: text, content-desc, resource-id, class, clickable and centre/bounds for every node. The foundation for selector-based control.',
    { serial: serialArg, limit: z.number().int().min(1).max(400).default(200), timeoutMs: z.number().int().min(1000).max(60000).default(20000) },
    async ({ serial, limit, timeoutMs }) => {
      const nodes = await dumpUi(serial, timeoutMs);
      const shown = nodes.slice(0, limit);
      return toolText(
        `UI dump ${serial}: ${nodes.length} node(s)${nodes.length > shown.length ? ` (showing ${shown.length})` : ''}\n` +
          shown.map((n) => `[${n.centerX},${n.centerY}] ${n.className.split('.').pop()}${n.text ? ` text="${n.text}"` : ''}${n.desc ? ` desc="${n.desc}"` : ''}${n.resourceId ? ` id=${n.resourceId}` : ''}${n.clickable ? ' CLICKABLE' : ''}`).join('\n'),
        { serial, total: nodes.length, shown: shown.length, truncated: nodes.length > shown.length, nodes: shown.map(summarize) },
      );
    },
  );

  p.define(
    'adb_ui_find',
    'Find UI elements on the Android device by text, content-desc, resource-id, or class (substring or exact) — the device equivalent of browser find. Returns matching nodes with their centre coordinates.',
    {
      serial: serialArg,
      text: z.string().min(1).optional(),
      desc: z.string().min(1).optional(),
      id: z.string().min(1).optional(),
      className: z.string().min(1).optional(),
      contains: z.boolean().default(true).describe('substring match (default); set false for exact equality'),
      timeoutMs: z.number().int().min(1000).max(60000).default(20000),
    },
    async ({ serial, text, desc, id, className, contains, timeoutMs }) => {
      const t = targetFrom({ text, desc, id, className, contains });
      if (!hasSelector(t)) return toolError('BAD_ARGS', 'adb_ui_find needs at least one of text, desc, id, or className', {}, 'pass text, desc (content-description), id (resource-id), or className to search for');
      const nodes = await dumpUi(serial, timeoutMs);
      const found = findUiNodes(nodes, t);
      return toolText(
        found.length ? `${found.length} match(es) on ${serial}:\n` + found.map((n) => `[${n.centerX},${n.centerY}] ${n.className.split('.').pop()}${n.text ? ` text="${n.text}"` : ''}${n.desc ? ` desc="${n.desc}"` : ''} click=${n.clickable}`).join('\n') : `no elements match on ${serial}`,
        { serial, count: found.length, matches: found.map(summarize) },
      );
    },
  );

  p.define(
    'adb_ui_tap',
    'Tap a UI element by selector (text/desc/id/className) — the device equivalent of browser click<target>. Dumps the hierarchy, resolves the element, and taps its centre; safer and self-correcting versus guessing pixel coordinates.',
    {
      serial: serialArg,
      text: z.string().min(1).optional(),
      desc: z.string().min(1).optional(),
      id: z.string().min(1).optional(),
      className: z.string().min(1).optional(),
      contains: z.boolean().default(true),
      index: z.number().int().min(0).optional().describe('which match to tap when several match (0-based); defaults to the first clickable'),
      timeoutMs: z.number().int().min(1000).max(60000).default(20000),
    },
    async ({ serial, text, desc, id, className, contains, index, timeoutMs }) => {
      const t = targetFrom({ text, desc, id, className, contains });
      if (!hasSelector(t)) return toolError('BAD_ARGS', 'adb_ui_tap needs at least one of text, desc, id, or className', {}, 'identify the element with text/desc/id/className; run adb_ui_dump first to see the tree');
      const nodes = await dumpUi(serial, timeoutMs);
      const found = findUiNodes(nodes, t);
      if (found.length === 0) {
        const hints = nodes.filter((n) => n.clickable && (n.text || n.desc)).slice(0, 12).map((n) => (n.text || n.desc));
        return toolError('BAD_ARGS', `no element matches the selector on ${serial}`, { selector: t }, `pick one of the on-screen controls: ${hints.join(' | ') || 'no labelled controls found — the screen may be animating or secure; retry after adb_screencap confirms the state'}`);
      }
      const clickableFirst = [...found].sort((a, b) => Number(b.clickable) - Number(a.clickable));
      const chosen = index !== undefined ? found[index] : clickableFirst[0];
      if (!chosen) return toolError('BAD_ARGS', `index ${index} is out of range: ${found.length} match(es)`, { index, count: found.length });
      await inputTap(serial, chosen.centerX, chosen.centerY, timeoutMs);
      return toolText(
        `tapped ${chosen.className.split('.').pop()} at [${chosen.centerX},${chosen.centerY}] on ${serial}${chosen.text ? ` text="${chosen.text}"` : ''}${chosen.desc ? ` desc="${chosen.desc}"` : ''}${found.length > 1 ? ` (${found.length} matched, tapped ${index ?? 'first-clickable'})` : ''}`,
        { serial, center: [chosen.centerX, chosen.centerY], matched: found.length, node: summarize(chosen) },
      );
    },
  );

  p.define(
    'adb_ui_set_text',
    'Focus a UI field by selector and type into it (browser "fill" equivalent). Honest limitation: input text APPENDS to the focused field and cannot reliably select-all across keyboards, so clear the field first (adb_key backspace / dpad) if a replace is required.',
    {
      serial: serialArg,
      text: z.string().min(1).optional(),
      desc: z.string().min(1).optional(),
      id: z.string().min(1).optional(),
      className: z.string().min(1).optional(),
      contains: z.boolean().default(true),
      value: z.string().min(1).describe('text to type into the focused field ([A-Za-z0-9 ._-] only)'),
      timeoutMs: z.number().int().min(1000).max(60000).default(20000),
    },
    async ({ serial, text, desc, id, className, contains, value, timeoutMs }) => {
      const t = targetFrom({ text, desc, id, className, contains });
      if (!hasSelector(t)) return toolError('BAD_ARGS', 'adb_ui_set_text needs a selector for the field', {}, 'identify the input field with text/desc/id/className');
      const nodes = await dumpUi(serial, timeoutMs);
      const found = findUiNodes(nodes, t);
      if (found.length === 0) return toolError('BAD_ARGS', `no field matches the selector on ${serial}`, { selector: t }, 'run adb_ui_dump to find the input node, then retry');
      await setTextField(serial, found[0], value, timeoutMs);
      return toolText(`typed ${value.length} chars into ${found[0].className.split('.').pop()} on ${serial} (appended)`, { serial, node: summarize(found[0]), typed: value.length });
    },
  );

  p.define(
    'adb_key',
    'Send a named Android key event (browser "press" equivalent): home, back, recents, enter, search, menu, power, volume_up/down/mute, media_play/pause/next/previous/stop, dpad_*, delete, tab, escape, or a raw numeric code.',
    { serial: serialArg, key: z.string().min(1), timeoutMs: tm15 },
    async ({ serial, key, timeoutMs }) => {
      const code = resolveKeyCode(key);
      if (code === null) return toolError('BAD_ARGS', `unknown key "${key}"`, { key }, `known keys: ${knownKeyNames().join(', ')} — or pass a numeric key code`);
      await inputKey(serial, code, timeoutMs);
      return toolText(`sent key "${key}" (code ${code}) to ${serial}`, { serial, key, code });
    },
  );

  p.define(
    'adb_current_app',
    'Report the foreground package and activity (browser "get url/title" equivalent) via dumpsys window mCurrentFocus — use it to confirm where you are before/after a navigation.',
    { serial: serialArg, timeoutMs: tm15 },
    async ({ serial, timeoutMs }) => {
      const app = await currentApp(serial, timeoutMs);
      return toolText(`${serial} foreground: ${app.package ?? 'unknown'}/${app.activity ?? '?'}`, { serial, package: app.package, activity: app.activity, focus: app.focus });
    },
  );

  p.define(
    'adb_open_app',
    'Launch an installed app by package via the launcher intent (monkey), which cannot be MIME-hijacked. Verifies the launch and returns the app output.',
    { serial: serialArg, package: z.string().min(1), timeoutMs: tm15 },
    async ({ serial, package: pkg, timeoutMs }) => {
      const r = await launchApp(serial, pkg, timeoutMs);
      if (!r.ok) return toolError('REMOTE_ERROR', `launch of ${pkg} did not confirm: ${r.output.slice(0, 200)}`, { package: pkg, output: r.output }, 'confirm the package is installed with adb_apps and that it has a launcher activity');
      return toolText(`launched ${pkg} on ${serial}`, { serial, package: pkg, output: r.output });
    },
  );

  p.define(
    'adb_open_url',
    'Open an http(s) URL (browser "goto" equivalent). Only http(s) is accepted, and browserPackage pins the handler so a rogue MIME registration cannot swallow the link.',
    { serial: serialArg, url: z.string().min(4), browserPackage: z.string().min(1).optional(), timeoutMs: tm15 },
    async ({ serial, url, browserPackage, timeoutMs }) => {
      const r = await openUrl(serial, url, browserPackage, timeoutMs);
      if (!r.ok) return toolError('REMOTE_ERROR', `open_url ${url.slice(0, 80)} did not confirm: ${r.output.slice(0, 200)}`, { url: url.slice(0, 80), output: r.output }, browserPackage ? 'the browserPackage may not handle VIEW — try without it or check adb_apps' : 'pass browserPackage (e.g. com.android.chrome) to pin a handler');
      return toolText(`opened ${url.slice(0, 80)} on ${serial}${browserPackage ? ` via ${browserPackage}` : ''}`, { serial, url, browserPackage: browserPackage ?? null, output: r.output });
    },
  );

  p.define(
    'adb_ls',
    'List a device directory (filesystem access) into name/type/size/mode/mtime entries — parses ls -l. Absolute device path (e.g. /sdcard/DCIM/Camera).',
    { serial: serialArg, remotePath: z.string().min(1), timeoutMs: tm15 },
    async ({ serial, remotePath, timeoutMs }) => {
      const entries = await listDir(serial, remotePath, timeoutMs);
      return toolText(`${entries.length} entr(y|ies) in ${remotePath}:\n` + entries.map((e) => `${e.type}  ${String(e.size).padStart(10)}B  ${e.mtime}  ${e.name}`).join('\n'), { serial, remotePath, count: entries.length, entries });
    },
  );

  p.define(
    'adb_pull',
    'Copy a file FROM the device to an absolute local path (streamed via adb pull; verifies the local file afterwards).',
    { serial: serialArg, remotePath: z.string().min(1), localPath: z.string().min(1), timeoutMs: z.number().int().min(1000).max(600000).default(60000) },
    async ({ serial, remotePath, localPath, timeoutMs }) => {
      requireAbsolute(localPath, 'localPath');
      const r = await pullFile(serial, remotePath, localPath, timeoutMs);
      return toolText(`pulled ${remotePath} -> ${localPath} (${r.bytes} bytes)`, { serial, remotePath, localPath, bytes: r.bytes });
    },
  );

  p.define(
    'adb_push',
    'Copy a local file TO the device (streamed via adb push). Requires an existing absolute localPath and an absolute device remotePath.',
    { serial: serialArg, localPath: z.string().min(1), remotePath: z.string().min(1), timeoutMs: z.number().int().min(1000).max(600000).default(60000) },
    async ({ serial, localPath, remotePath, timeoutMs }) => {
      requireAbsolute(localPath, 'localPath');
      const r = await pushFile(serial, localPath, remotePath, timeoutMs);
      return toolText(`pushed ${localPath} -> ${remotePath} (${r.bytes} bytes)`, { serial, localPath, remotePath, bytes: r.bytes });
    },
  );

  p.define(
    'adb_apps',
    'Inventory installed packages (app inventory). scope: all | system | third_party.',
    { serial: serialArg, scope: z.enum(['all', 'system', 'third_party']).default('all'), timeoutMs: tm15 },
    async ({ serial, scope, timeoutMs }) => {
      const pkgs = await listApps(serial, scope as AppsScope, timeoutMs);
      return toolText(`${pkgs.length} ${scope} package(s) on ${serial}:\n` + pkgs.join('\n'), { serial, scope, count: pkgs.length, packages: pkgs });
    },
  );

  p.define(
    'adb_settings',
    'Read (no value) or write (with value) an Android settings key in the system|secure|global namespace. A write reads the value back and returns both, so success is measured, not assumed.',
    { serial: serialArg, namespace: z.enum(['system', 'secure', 'global']), key: z.string().min(1), value: z.string().optional(), timeoutMs: tm15 },
    async ({ serial, namespace, key, value, timeoutMs }) => {
      if (value === undefined) {
        const v = await getSetting(serial, namespace as SettingsNs, key, timeoutMs);
        return toolText(`${namespace}/${key} = ${v === null ? '(unset)' : v}`, { serial, namespace, key, value: v });
      }
      const r = await putSetting(serial, namespace as SettingsNs, key, value, timeoutMs);
      return toolText(`settings put ${namespace}/${key}: wrote "${r.written}", read-back "${r.readBack}"`, { serial, namespace, key, written: r.written, readBack: r.readBack, matched: r.readBack === r.written });
    },
  );

  p.define(
    'adb_media',
    'Control the active media session (audio playback): play, pause, play-pause, next, previous, stop, rewind, fast-forward, volume_up/down/mute. Uses cmd media_session dispatch (routes to the live session) with a keyevent fallback, then returns the resulting now-playing state.',
    { serial: serialArg, action: z.enum(['play', 'pause', 'play-pause', 'next', 'previous', 'stop', 'rewind', 'fast-forward', 'volume_up', 'volume_down', 'mute']), timeoutMs: tm15 },
    async ({ serial, action, timeoutMs }) => {
      const r = await mediaControl(serial, action, timeoutMs);
      return toolText(`media ${action} on ${serial} via ${r.via}; now ${r.nowPlaying.active ? 'PLAYING' : 'not playing'}${r.nowPlaying.title ? `: ${r.nowPlaying.title}` : ''}`, { serial, action, via: r.via, nowPlaying: r.nowPlaying });
    },
  );

  p.define(
    'adb_media_state',
    'Read the device media session: whether something is playing and its state/title/artist/package (best-effort; formats vary by OEM).',
    { serial: serialArg, timeoutMs: tm15 },
    async ({ serial, timeoutMs }) => {
      const np = await nowPlaying(serial, timeoutMs);
      return toolText(np.active ? `playing${np.title ? `: ${np.title}` : ''}${np.artist ? ` — ${np.artist}` : ''}${np.package ? ` (${np.package})` : ''}` : `no active media session on ${serial}`, { serial, ...np });
    },
  );

  p.define(
    'adb_screenrecord',
    'Record a bounded silent video clip of the screen (screenrecord, max 180s/run) to an absolute local MP4 path. Honest: Android screenrecord captures NO audio; live streaming needs a scrcpy bridge, which this tool does not provide.',
    { serial: serialArg, outputPath: z.string().min(1), durationMs: z.number().int().min(500).max(180000).default(5000), bitRateMbps: z.number().int().min(1).max(60).default(4), timeoutMs: z.number().int().min(3000).max(240000).default(30000) },
    async ({ serial, outputPath, durationMs, bitRateMbps, timeoutMs }) => {
      requireAbsolute(outputPath, 'outputPath');
      const eff = Math.min(240000, Math.max(timeoutMs, durationMs + 30000));
      const r = await recordScreen(serial, outputPath, durationMs, bitRateMbps, eff);
      return toolText(`recorded ${r.durationMs}ms clip -> ${r.localPath} (${r.bytes} bytes) — ${r.note}`, { serial, outputPath, bytes: r.bytes, durationMs: r.durationMs, note: r.note });
    },
  );

  p.define(
    'adb_preset',
    'Run a common one-shot device action so operators need not memorise key codes or shell incantations: home, back, recents, notification_shade, quick_settings, collapse_shade, camera_rear, camera_front. camera_front opens the camera and performs the selector-driven flip to the front lens, re-reading the hierarchy to CONFIRM it (not assume).',
    { serial: serialArg, preset: z.enum(UI_PRESETS), timeoutMs: z.number().int().min(1000).max(60000).default(20000) },
    async ({ serial, preset, timeoutMs }) => {
      const r = await runUiPreset(serial, preset as UiPreset, timeoutMs);
      if (!r.ok) return toolError('REMOTE_ERROR', `preset "${preset}" ran but was not verified: ${r.detail}`, { preset, observed: r.observed }, 'capture adb_screencap or adb_ui_dump to see the real on-screen state before retrying');
      return toolText(`preset ${preset}: ${r.detail}${r.observed ? ` — ${r.observed}` : ''}`, { serial, ...r });
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
        { host: h.name, command: pw.command, exitCode: pw.result.code, signal: pw.result.signal, timedOut: pw.result.timedOut, stdout: pw.result.stdout, stderr: pw.result.stderr, truncated: pw.result.truncated, durationMs: pw.result.durationMs, note: pw.note },
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
        { host: h.name, command: pw.command, exitCode: pw.result.code, signal: pw.result.signal, timedOut: pw.result.timedOut, stdout: pw.result.stdout, stderr: pw.result.stderr, truncated: pw.result.truncated, durationMs: pw.result.durationMs, note: pw.note },
      );
    },
  );

  // Disposal handle for index.ts: stops every EventMonitor poll before the SSH
  // transport closes, so teardown cannot resurrect connections.
  return () => {
    p.events.dispose();
  };
}
