import { readFileSync, statSync } from 'node:fs';
import { connect as netConnect, type Socket } from 'node:net';
import { Client, type ClientChannel, type ConnectConfig, type SFTPWrapper } from 'ssh2';
import { ControlError, type ErrCode } from '../errors.js';
import type { HostConfig } from '../config/schema.js';
import { expandPath, readPasswordFromEnv, requirePrivateKey } from '../config/secrets.js';

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
  signal: string | null;
  truncated: boolean;
  timedOut: boolean;
  durationMs: number;
}

export interface ShellSession {
  id: string;
  host: string;
  address: string;
  user: string;
  createdAt: number;
  lastUsedAt: number;
  cwd: string | null;
  channel: ClientChannel;
  buffer: string;
  pending: Array<{ marker: string; resolve: (v: string) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>;
  closed: boolean;
  /** Incremented per command so every command gets a unique sentinel. That is
   *  what lets a session recover after a timeout: a late marker from an earlier,
   *  unfinished command can never be mistaken for the next command's. */
  cmdSeq: number;
  /** Set when a command timed out. The next shell_run first interrupts the stuck
   *  foreground job (Ctrl-C) and resynchronises to a clean prompt, discarding
   *  stale output; cwd/env are preserved, so the session is reused rather than
   *  discarded. Cleared once a clean prompt is confirmed. */
  needsResync?: boolean;
  /** True when the shell buffer was head-dropped over the capture cap. */
  droppedFromBuffer?: boolean;
}

export interface TransferProgress {
  bytes: number;
  total: number;
}

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
// In-band completion sentinel for shell sessions: after every command the shell
// prints a marker line carrying the exit code, and the reader resolves only on
// that line. The marker is UNIQUE PER COMMAND (session id + an incrementing
// command sequence), not per session — that is what lets a session recover after
// a command times out: a stale marker from the earlier, unfinished command can
// never be mistaken for the next command's, so the shell is reused (keeping its
// cwd and environment) instead of being discarded.
const RESYNC_SETTLE_MS = 200; // let the line editor settle after Ctrl-C
const RESYNC_TIMEOUT_MS = 4000; // cap for the resync probe itself

// The marker for command <seq> in <sessionId>, sanitised to regex- and
// shell-safe characters (letters/digits/underscore).
export function sentinelFor(sessionId: string, seq: number): string {
  const s = sessionId.replace(/[^a-zA-Z0-9_-]/g, '');
  return `CTL_MCP_${s}_${seq}_END`;
}

// The line written to the shell: run <command>, then print the marker with the
// command's exit code. printf captures $? portably; the `|| echo <marker>?`
// fallback covers shells (cmd.exe) with no $?/printf, where the reader still
// sees the marker (with a literal '?') and knows the command reached the end.
export function wrapShellCommand(command: string, marker: string): string {
  return `${command}\n{ printf '\\n${marker}%s\\n' "$?" 2>/dev/null || echo ${marker}?; } 2>/dev/null\n`;
}

// Scan <buffer> for THIS command's completed marker. Returns the exit code and
// the output up to (excluding) the echoed wrapper line, or null if the marker
// has not completed. Only <marker> matches, so a stale marker from a different
// command — a timed-out command that finished late — is ignored, not attributed.
export function parseShellResult(buffer: string, marker: string): { exit: string; output: string } | null {
  const re = new RegExp(`\\n${marker}(\\d+)\\r?\\n`);
  const m = re.exec(buffer);
  if (!m) return null;
  const echoAt = buffer.lastIndexOf(`{ printf '\\n${marker}`);
  const cut = echoAt >= 0 && echoAt < m.index ? echoAt : m.index;
  return { exit: m[1], output: buffer.slice(0, cut) };
}

function mapAuthError(err: Error): ControlError {
  const msg = err.message || String(err);
  if (/all configured authentication methods failed|no matching key|cannot parse key|Encrypted private/i.test(msg)) {
    return new ControlError('AUTH_FAILED', `SSH authentication failed: ${msg}`);
  }
  if (/ECONNREFUSED/i.test(msg)) {
    return new ControlError(
      'HOST_UNREACHABLE',
      `SSH connection refused: ${msg} — the host answered on the network and rejected the connection, so it is UP but nothing is listening on the SSH port (the service is stopped, not started yet — e.g. seconds after boot — or bound elsewhere)`,
      { reason: 'refused' },
      'the box is reachable and powered on — do NOT wake it. Start the SSH service on the target (e.g. start sshd), or confirm the port; a connection-refused is different from a timeout (that one can mean down).',
    );
  }
  if (/ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ECONNRESET|Timed out while waiting for handshake/i.test(msg)) {
    return new ControlError('HOST_UNREACHABLE', `SSH connection failed: ${msg}`);
  }
  return new ControlError('INTERNAL', `SSH error: ${msg}`);
}

// A raw TCP open check, independent of SSH negotiation. On failure it returns
// the connect error code (ECONNREFUSED / ETIMEDOUT / ...) so the caller can
// classify a network-level down/refused apart from a handshake failure.
function rawTcpOpen(address: string, port: number, timeoutMs: number): Promise<{ open: boolean; error?: string }> {
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
    sock.once('timeout', () => finish(false, 'connect ETIMEDOUT'));
    sock.once('error', (e) => finish(false, `connect ${(e as NodeJS.ErrnoException).code ?? e.message}`));
  });
}

// Pure, testable mapping from an ssh2 handshake failure to a probe outcome,
// given whether the raw TCP connection had already opened. Enforces two honesty
// rules: an AUTHENTICATION failure is NEVER ok:true (ok:true would be reported
// as "ready"/authenticating with a credential we did not resolve); and a
// handshake failure AFTER the port was proven open is a LISTENING verdict
// (tcpOpen true), never a network "down"/"firewalled".
export function probeResultFromError(msg: string, tcpOpen: boolean): { ok: false; error: string; tcpOpen: boolean } {
  if (/all configured authentication|cannot parse key|Encrypted private|Too many authentication/i.test(msg)) {
    return { ok: false, error: 'All configured authentication methods failed', tcpOpen };
  }
  if (tcpOpen) return { ok: false, error: `listening: handshake incomplete (${msg})`, tcpOpen: true };
  return { ok: false, error: msg, tcpOpen: false };
}

export class SshTransport {
  private connections = new Map<string, Promise<Client>>();
  private sessions = new Map<string, ShellSession>();
  private seq = 0;

  private connectKey(host: HostConfig, address: string): string {
    return `${host.name}|${address}|${host.ssh.user}`;
  }

  async getConnection(host: HostConfig, address: string): Promise<Client> {
    const key = this.connectKey(host, address);
    const inflight = this.connections.get(key);
    if (inflight) return await inflight;

    const opening = this.openConnection(host, address, key);
    this.connections.set(key, opening);
    // Once resolved, swap the map entry to a promise that also lets the error/
    // close handlers below compare identity against the live Client.
    const client = await opening.catch((err: unknown) => {
      if (this.connections.get(key) === opening) this.connections.delete(key);
      throw err;
    });
    return client;
  }

  private liveClients = new Map<string, Client>();

  private openConnection(host: HostConfig, address: string, key: string): Promise<Client> {
    return this.openConnectionInner(host, address, key);
  }

  private async openConnectionInner(host: HostConfig, address: string, key: string): Promise<Client> {
    const keyPath = host.ssh.privateKeyPath ? requirePrivateKey(host.ssh.privateKeyPath, host.name) : undefined;
    const secret = readPasswordFromEnv(host.name, host.ssh.passwordEnv) ?? (host.ssh.password ? { value: host.ssh.password, source: 'config' } : undefined);
    if (!keyPath && !secret) {
      throw new ControlError('AUTH_FAILED', `No usable SSH credential for host "${host.name}": configure privateKeyPath or password/passwordEnv`, { host: host.name });
    }
    const cfg: ConnectConfig = {
      host: address,
      port: host.ssh.port,
      username: host.ssh.user,
      readyTimeout: 15000,
      keepaliveInterval: 15000,
      algorithms: undefined,
    };
    if (keyPath) cfg.privateKey = readFileSync(keyPath);
    if (secret) cfg.password = secret.value;

    const client = new Client();
    await new Promise<void>((resolve, reject) => {
      const onErr = (err: Error) => {
        client.removeListener('ready', onReady);
        reject(mapAuthError(err));
      };
      const onReady = () => {
        client.removeListener('error', onErr);
        resolve();
      };
      client.once('error', onErr);
      client.once('ready', onReady);
      client.connect(cfg);
    });
    client.on('error', () => {
      // Only evict this exact client; a reconnect may already own the key.
      if (this.liveClients.get(key) === client) {
        this.liveClients.delete(key);
        this.connections.delete(key);
      }
    });
    client.on('close', () => {
      if (this.liveClients.get(key) === client) {
        this.liveClients.delete(key);
        this.connections.delete(key);
      }
      for (const [, s] of this.sessions) if (s.host === host.name) s.closed = true;
    });
    this.liveClients.set(key, client);
    return client;
  }

  async probe(host: HostConfig, address: string): Promise<{ ok: boolean; error?: string; tcpOpen?: boolean }> {
    // Establish the network-level fact INDEPENDENTLY of the SSH handshake first:
    // does the port accept a raw TCP connection at all? This separates "service
    // down / firewalled" (TCP fails) from "a daemon is answering but the
    // handshake did not finish" — e.g. an ECONNRESET during sshd's post-boot
    // settling window, or an algorithm mismatch — which must NEVER be reported
    // as "service down" (see probeResultFromError / classifySshState). The
    // handshake budget matches the real connect (15s), not the old 5s, so a
    // slow-but-healthy service is not cut off.
    const tcp = await rawTcpOpen(address, host.ssh.port, 4000);
    if (!tcp.open) return { ok: false, error: tcp.error ?? 'connect ETIMEDOUT', tcpOpen: false };

    const client = new Client();
    try {
      const keyPath = host.ssh.privateKeyPath ? expandPath(host.ssh.privateKeyPath) : undefined;
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Timed out while waiting for handshake')), 15000);
        client.once('error', (e) => {
          clearTimeout(t);
          reject(e);
        });
        client.once('ready', () => {
          clearTimeout(t);
          resolve();
        });
        const cfg: ConnectConfig = {
          host: address,
          port: host.ssh.port,
          username: host.ssh.user,
          readyTimeout: 12000,
        };
        if (keyPath && requirePrivateKeyExists(keyPath)) cfg.privateKey = readFileSync(keyPath);
        const secret = readPasswordFromEnv(host.name, host.ssh.passwordEnv) ?? (host.ssh.password ? { value: host.ssh.password, source: 'config' } : undefined);
        if (secret) cfg.password = secret.value;
        client.connect(cfg);
      });
      return { ok: true, tcpOpen: true };
    } catch (err) {
      return probeResultFromError((err as Error).message || String(err), true);
    } finally {
      try { client.end(); } catch { /* already gone */ }
      try { client.destroy(); } catch { /* already gone */ }
    }
  }

  async exec(
    host: HostConfig,
    address: string,
    command: string,
    opts: { timeoutMs?: number; stdinData?: string } = {},
  ): Promise<ExecResult> {
    const client = await this.getConnection(host, address);
    const started = Date.now();
    return new Promise<ExecResult>((resolve, reject) => {
      client.exec(command, { env: { AI_AGENT: 'control-mcp' } }, (err, channel: ClientChannel) => {
        if (err) return reject(mapAuthError(err));
        const outChunks: Buffer[] = [];
        const errChunks: Buffer[] = [];
        let outLen = 0;
        let errLen = 0;
        let truncated = false;
        let timedOut = false;
        let exitCode: number | null | undefined;
        let exitSignal: string | null | undefined;
        let timer: ReturnType<typeof setTimeout> | undefined;
        channel.on('exit', (c?: number | null, s?: string | null) => {
          // Process finished: cancel the deadline so a command that exits right
          // around the timeout keeps its real exit code instead of being
          // reported as timed out with the code discarded.
          if (timer) clearTimeout(timer);
          exitCode = c ?? null;
          exitSignal = s ?? null;
        });
        timer = setTimeout(() => {
          // Ask the remote side (via the channel signal extension) to terminate,
          // then hard-close. Whether the server honored TERM can only be observed
          // through the exit/close signal field, so we never assert delivery here.
          timedOut = true;
          try {
            channel.signal('TERM');
          } catch {
            /* server may not support the signal extension */
          }
          channel.destroy();
        }, opts.timeoutMs ?? 30000);

        channel.on('data', (d: Buffer) => {
          if (outLen >= MAX_OUTPUT_BYTES) return (truncated = true);
          outChunks.push(d);
          outLen += d.length;
          if (outLen > MAX_OUTPUT_BYTES) truncated = true;
        });
        channel.stderr.on('data', (d: Buffer) => {
          if (errLen >= MAX_OUTPUT_BYTES) return (truncated = true);
          errChunks.push(d);
          errLen += d.length;
          if (errLen > MAX_OUTPUT_BYTES) truncated = true;
        });
        // Decode to a UTF-8 boundary so the byte cap never leaves a lone
        // replacement char from a split multibyte sequence.
        const decodeCap = (chunks: Buffer[]): string => {
          const buf = Buffer.concat(chunks);
          if (buf.length <= MAX_OUTPUT_BYTES) return buf.toString('utf8');
          let end = MAX_OUTPUT_BYTES;
          while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
          return buf.subarray(0, end).toString('utf8');
        };
        channel.on('close', (code?: number | null, signal?: string | null) => {
          clearTimeout(timer);
          const out = decodeCap(outChunks);
          const errText = decodeCap(errChunks);
          // ssh2 emits 'close' on a clean exit WITHOUT an exit-status payload in
          // some server paths; 'exit' always fires before the final 'close'. The
          // last observed code wins so a real nonzero exit is never reported 0.
          resolve({
            stdout: out,
            stderr: timedOut
              ? (errText + '\n[timeout: TERM was requested and the channel closed; if the server does not honor the signal extension, or the process ignores it, the remote process may still be running]').slice(-MAX_OUTPUT_BYTES)
              : errText,
            code: timedOut ? null : exitCode ?? code ?? null,
            // Report only the signal the server actually delivered via exit/close.
            // ssh2 sends undefined (not null) on a clean exit; normalize so callers
            // can compare against null. On timeout, TERM is only reflected here if
            // the server confirmed it; otherwise null (delivery unobserved).
            signal: exitSignal ?? signal ?? null,
            truncated,
            timedOut,
            durationMs: Date.now() - started,
          });
        });
        channel.on('error', (e: Error) => {
          clearTimeout(timer);
          reject(new ControlError(/ECONN|EPipe|reset/i.test(e.message) ? 'HOST_UNREACHABLE' : 'REMOTE_ERROR', `SSH channel error: ${e.message}`));
        });
        if (opts.stdinData !== undefined) {
          channel.end(opts.stdinData);
        } else {
          channel.end();
        }
      });
    });
  }

  async openShell(host: HostConfig, address: string, cols = 120, rows = 40): Promise<ShellSession> {
    const client = await this.getConnection(host, address);
    const channel = await new Promise<ClientChannel>((resolve, reject) => {
      client.shell({ cols, rows, term: 'dumb' }, (err, ch) => {
        if (err) return reject(mapAuthError(err));
        resolve(ch);
      });
    });
    const id = `sh-${++this.seq}`;
    const session: ShellSession = {
      id,
      host: host.name,
      address,
      user: host.ssh.user,
      createdAt: Date.now(),
      lastUsedAt: Date.now(),
      cwd: null,
      channel,
      buffer: '',
      pending: [],
      closed: false,
      cmdSeq: 0,
    };
    channel.on('data', (d: Buffer) => this.onShellData(session, d.toString('utf8')));
    channel.stderr.on('data', (d: Buffer) => this.onShellData(session, d.toString('utf8')));
    channel.on('close', () => {
      session.closed = true;
      for (const p of session.pending) {
        clearTimeout(p.timer);
        p.reject(new ControlError('SESSION_GONE', `Shell session ${id} closed`));
      }
      session.pending = [];
      // A dead shell must not linger in the map: callers get SESSION_GONE
      // immediately instead of after a safety-gate round-trip.
      if (this.sessions.get(id) === session) this.sessions.delete(id);
    });
    this.sessions.set(id, session);
    // Give the login banner a moment to arrive, then clear it so the first
    // sentinel-delimited command starts from an empty buffer.
    await new Promise<void>((resolve) => setTimeout(resolve, 1500));
    session.buffer = '';
    return session;
  }

  private onShellData(session: ShellSession, text: string) {
    session.buffer += text;
    if (session.buffer.length > MAX_OUTPUT_BYTES) {
      // Head-drop: the earliest bytes are lost. Mark it so the tail is not
      // presented to the caller as the command's complete output.
      session.buffer = session.buffer.slice(-MAX_OUTPUT_BYTES);
      session.droppedFromBuffer = true;
    }
    // Resolve only when a FULL sentinel line has arrived: the shell echoes our
    // own command back (with \r), so require the copy that starts on its own
    // line and ends with "<digits>\n" — an echoed fragment like '%s\n' never
    // matches this. The echo of the wrapped printf itself is stripped below.
    const waiters = session.pending;
    if (waiters.length === 0) return;
    // Match only the CURRENT command's marker. A stale marker from a different
    // command (e.g. one that timed out earlier and finished late) is never seen
    // here — which is exactly what makes post-timeout recovery safe.
    const w = waiters[0];
    const res = parseShellResult(session.buffer, w.marker);
    if (!res) return;
    session.buffer = '';
    clearTimeout(w.timer);
    session.pending.splice(0, 1);
    const note = session.droppedFromBuffer
      ? '\n[output exceeded the 2 MiB capture cap; earlier bytes were dropped]'
      : '';
    session.droppedFromBuffer = false;
    w.resolve(res.output + `\n[exit ${res.exit}]` + note);
  }

  // Wait for a specific command's marker. Resolves {output, timedOut}; on a
  // timeout it does NOT poison the session (recovery happens on the next
  // runInShell) — the stale marker is simply left unmatched, because every
  // command's marker is unique.
  private waitMarker(session: ShellSession, marker: string, timeoutMs: number): Promise<{ output: string; timedOut: boolean }> {
    return new Promise((resolve, reject) => {
      if (session.closed) return reject(new ControlError('SESSION_GONE', `Shell session ${session.id} closed`));
      const timer = setTimeout(() => {
        const idx = session.pending.findIndex((p) => p.timer === timer);
        if (idx >= 0) session.pending.splice(idx, 1);
        const out = session.buffer;
        session.buffer = '';
        resolve({ output: out + '\n[timeout: sentinel not seen; command may still be running]', timedOut: true });
      }, timeoutMs);
      session.pending.push({ marker, resolve: (v) => resolve({ output: v, timedOut: false }), reject, timer });
    });
  }

  // Bring a session that timed out back to a clean prompt WITHOUT discarding it:
  // interrupt the stuck foreground job with Ctrl-C, let the line editor settle,
  // then run a unique probe whose marker proves the shell is idle again. The
  // interactive shell's cwd and environment survive the interrupt, so context is
  // kept. Returns false only if the shell stays wedged (a SIGINT-ignoring hang),
  // in which case the caller must close the session.
  private async resyncShell(session: ShellSession, timeoutMs: number): Promise<boolean> {
    session.channel.write('\x03');
    await new Promise<void>((r) => setTimeout(r, RESYNC_SETTLE_MS));
    session.buffer = '';
    const probe = sentinelFor(session.id, ++session.cmdSeq);
    session.channel.write(wrapShellCommand('true', probe));
    const { timedOut } = await this.waitMarker(session, probe, timeoutMs);
    return !timedOut;
  }

  async runInShell(sessionId: string, command: string, timeoutMs = 30000): Promise<{ output: string; closed: boolean; timedOut: boolean; resynced: boolean }> {
    const session = this.sessions.get(sessionId);
    if (!session) throw new ControlError('SESSION_GONE', `No such shell session: ${sessionId}`);
    if (session.closed) throw new ControlError('SESSION_GONE', `Shell session ${sessionId} is closed`);
    if (session.pending.length > 0) {
      throw new ControlError('BAD_ARGS', `Shell session ${sessionId} still has a command in flight; wait for it or close the session`);
    }
    session.lastUsedAt = Date.now();
    let resynced = false;
    if (session.needsResync) {
      // A previous command timed out and the shell may still be busy with it.
      // Recover in place (cwd/env preserved) rather than discarding the session.
      const ok = await this.resyncShell(session, Math.min(timeoutMs, RESYNC_TIMEOUT_MS));
      if (!ok) {
        session.needsResync = true;
        throw new ControlError(
          'SESSION_GONE',
          `Shell session ${sessionId} is still busy after an interrupt — the earlier timed-out command did not stop, so its output/exit cannot be attributed and further commands would queue behind it.`,
          { sessionId },
          'close this session with shell_close and open a fresh one; the stuck command may ignore Ctrl-C or still be streaming output, so do not keep sending commands here.',
        );
      }
      resynced = true;
    }
    // Each command gets a unique marker (session id + command sequence), so a
    // late marker from a previous command can never be attributed to this one.
    const marker = sentinelFor(session.id, ++session.cmdSeq);
    session.channel.write(wrapShellCommand(command, marker));
    const { output, timedOut } = await this.waitMarker(session, marker, timeoutMs);
    session.needsResync = timedOut;
    return { output, closed: session.closed, timedOut, resynced };
  }

  getSession(id: string): ShellSession | undefined {
    return this.sessions.get(id);
  }

  listSessions(): Array<Omit<ShellSession, 'channel' | 'buffer' | 'pending'>> {
    return [...this.sessions.values()].map((s) => ({
      id: s.id,
      host: s.host,
      address: s.address,
      user: s.user,
      createdAt: s.createdAt,
      lastUsedAt: s.lastUsedAt,
      cwd: s.cwd,
      closed: s.closed,
      cmdSeq: s.cmdSeq,
      needsResync: Boolean(s.needsResync),
    }));
  }

  async closeShell(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    session.channel.end();
    session.channel.close();
    this.sessions.delete(sessionId);
    return true;
  }

  private getSftp(host: HostConfig, address: string): Promise<SFTPWrapper> {
    return new Promise((resolve, reject) => {
      this.getConnection(host, address).then(
        (client) => client.sftp((err, sftp) => (err ? reject(mapAuthError(err)) : resolve(sftp))),
        reject,
      );
    });
  }

  async uploadFile(
    host: HostConfig,
    address: string,
    localPath: string,
    remotePath: string,
    onProgress?: (p: TransferProgress) => void,
  ): Promise<{ bytes: number; remoteBytes: number | null; verified: boolean }> {
    const sftp = await this.getSftp(host, address);
    const resolved = expandPath(localPath);
    let remoteBytes: number | null = null;
    try {
      // fastPut streams from disk; do not also readFileSync the whole file.
      await new Promise<void>((resolve, reject) => {
        sftp.fastPut(resolved, remotePath, (err) => (err ? reject(new ControlError('REMOTE_ERROR', `SFTP upload failed: ${err.message}`, { code: (err as { code?: number }).code })) : resolve()));
      });
      // Measure the size that actually landed; a local statSync proves nothing
      // about the remote side (full filesystem, quota, partial write).
      remoteBytes = await new Promise<number | null>((resolve) => {
        sftp.stat(remotePath, (err, st) => resolve(err ? null : Number(st.size)));
      });
    } finally {
      sftp.end();
    }
    const bytes = statSync(resolved).size;
    const verified = remoteBytes !== null && remoteBytes === bytes;
    onProgress?.({ bytes, total: bytes });
    return { bytes, remoteBytes, verified };
  }

  async downloadFile(
    host: HostConfig,
    address: string,
    remotePath: string,
    localPath: string,
  ): Promise<{ bytes: number; remoteBytes: number | null; verified: boolean }> {
    const sftp = await this.getSftp(host, address);
    const resolved = expandPath(localPath);
    let remoteBytes: number | null = null;
    try {
      await new Promise<void>((resolve, reject) => {
        sftp.fastGet(remotePath, resolved, (err) =>
          err ? reject(new ControlError('REMOTE_ERROR', `SFTP download failed: ${err.message}`, { code: (err as { code?: number }).code })) : resolve(),
        );
      });
      // The remote source size, so callers can compare against the local file
      // that was written rather than trusting one side alone.
      remoteBytes = await new Promise<number | null>((resolve) => {
        sftp.stat(remotePath, (err, st) => resolve(err ? null : Number(st.size)));
      });
    } finally {
      sftp.end();
    }
    const bytes = statSync(resolved).size;
    return { bytes, remoteBytes, verified: remoteBytes !== null && remoteBytes === bytes };
  }

  async listDir(host: HostConfig, address: string, remotePath: string): Promise<Array<{ name: string; size: number; type: string; mode: number; mtime: number }>> {
    const sftp = await this.getSftp(host, address);
    try {
      const entries = await new Promise<Array<{ filename: string; attrs: import('ssh2').Stats }>>((resolve, reject) => {
        sftp.readdir(remotePath, (err, list) =>
          err ? reject(new ControlError('REMOTE_ERROR', `SFTP readdir failed: ${err.message}`, { code: (err as { code?: number }).code })) : resolve(list),
        );
      });
      return entries.map((e) => {
        // st_mode's file-type bits, not the raw integer, are what a reader means
        // by "type"; keep the raw mode alongside for detail.
        const mode = Number(e.attrs.mode ?? 0);
        const kind = mode & 0xf000;
        const type =
          kind === 0x4000 ? 'dir' : kind === 0xa000 ? 'link' : kind === 0x8000 ? 'file'
          : kind === 0x1000 ? 'fifo' : kind === 0x2000 ? 'char' : kind === 0x6000 ? 'block'
          : kind === 0xc000 ? 'socket' : 'other';
        return { name: e.filename, size: Number(e.attrs.size ?? 0), type, mode, mtime: Number(e.attrs.mtime ?? 0) * 1000 };
      });
    } finally {
      sftp.end();
    }
  }

  // Bounded remote read over SFTP: streams and stops once maxBytes is exceeded,
  // so reading a very large file never loads it all into memory. ENOENT maps to
  // BAD_ARGS (a missing file / directory is an argument problem, not a remote
  // fault); anything else stays REMOTE_ERROR.
  async readRemoteFile(
    host: HostConfig,
    address: string,
    remotePath: string,
    opts: { maxBytes: number },
  ): Promise<{ buffer: Buffer; truncated: boolean; size: number }> {
    const sftp = await this.getSftp(host, address);
    try {
      return await new Promise<{ buffer: Buffer; truncated: boolean; size: number }>((resolve, reject) => {
        const rs = sftp.createReadStream(remotePath);
        const chunks: Buffer[] = [];
        let len = 0;
        let overflow = false;
        let settled = false;
        rs.on('data', (d: Buffer) => {
          if (overflow) return;
          chunks.push(d);
          len += d.length;
          if (len > opts.maxBytes) {
            overflow = true;
            settled = true;
            try {
              rs.destroy();
            } catch {
              /* already closing */
            }
            resolve({ buffer: Buffer.concat(chunks, len).subarray(0, opts.maxBytes), truncated: true, size: len });
          }
        });
        rs.on('end', () => {
          if (!settled) {
            settled = true;
            resolve({ buffer: Buffer.concat(chunks, len), truncated: false, size: len });
          }
        });
        rs.on('error', (err: Error) => {
          if (settled) return;
          settled = true;
          const code = (err as { code?: number }).code;
          if (code === 2 || /no such file|enoent|not exist|is a directory/i.test(err.message)) {
            reject(new ControlError('BAD_ARGS', `No such remote file to read: ${remotePath}`, { remotePath }, 'confirm the path with file_list — a missing file or a directory cannot be read'));
          } else {
            reject(new ControlError('REMOTE_ERROR', `SFTP read failed: ${err.message}`, { code }));
          }
        });
      });
    } finally {
      sftp.end();
    }
  }

  async writeRemoteFile(
    host: HostConfig,
    address: string,
    remotePath: string,
    content: Buffer,
    opts: { append: boolean },
  ): Promise<{ bytes: number }> {
    const sftp = await this.getSftp(host, address);
    try {
      await new Promise<void>((resolve, reject) => {
        const ws = sftp.createWriteStream(remotePath, { flags: opts.append ? 'a' : 'w' });
        let settled = false;
        const done = () => {
          if (!settled) {
            settled = true;
            resolve();
          }
        };
        ws.on('close', done);
        ws.on('finish', done);
        ws.on('error', (err: Error) => {
          if (settled) return;
          settled = true;
          reject(new ControlError('REMOTE_ERROR', `SFTP write failed: ${err.message}`, { code: (err as { code?: number }).code }));
        });
        ws.end(content);
      });
      return { bytes: content.length };
    } finally {
      sftp.end();
    }
  }

  // stat with an honest null for "no such file" so callers can guard overwrites
  // without treating a missing file as an error.
  async statRemote(
    host: HostConfig,
    address: string,
    remotePath: string,
  ): Promise<{ size: number; mtime: number; isDirectory: boolean } | null> {
    const sftp = await this.getSftp(host, address);
    try {
      return await new Promise((resolve, reject) => {
        sftp.stat(remotePath, (err, st) => {
          if (err) {
            const code = (err as { code?: number }).code;
            if (code === 2 || /no such file|enoent|not exist/i.test(err.message)) return resolve(null);
            return reject(new ControlError('REMOTE_ERROR', `SFTP stat failed: ${err.message}`, { code }));
          }
          const mode = Number(st?.mode ?? 0);
          resolve({ size: Number(st?.size ?? 0), mtime: Number(st?.mtime ?? 0) * 1000, isDirectory: (mode & 0xf000) === 0x4000 });
        });
      });
    } finally {
      sftp.end();
    }
  }

  closeAll(): void {
    for (const [, s] of this.sessions) {
      try {
        s.channel.end();
        s.channel.close();
      } catch {
        /* ignore */
      }
    }
    this.sessions.clear();
    for (const [, pending] of this.connections) {
      void pending.then(
        (client) => {
          try {
            client.end();
            client.destroy();
          } catch {
            /* ignore */
          }
        },
        () => undefined,
      );
    }
    this.connections.clear();
  }
}

function requirePrivateKeyExists(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

export function errCodeFromSsh(err: unknown): ErrCode {
  if (err instanceof ControlError) return err.code;
  return 'INTERNAL';
}
