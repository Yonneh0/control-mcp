import { readFileSync, statSync } from 'node:fs';
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
  pending: Array<{ resolve: (v: string) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>;
  closed: boolean;
}

export interface TransferProgress {
  bytes: number;
  total: number;
}

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
// In-band completion sentinel for shell sessions: after every command we write
// `printf` of a marker with the exit code, and only resolve when that marker
// line arrives. Command output containing the literal marker text is extremely
// unlikely; the marker includes a per-session nonce so cross-talk is impossible.
const SENTINEL_MARK = 'CTL_MCP_END';

function sentinelFor(sessionId: string): string {
  return `CTL_MCP_${sessionId.replace(/[^a-zA-Z0-9_-]/g, '')}_END`;
}

function mapAuthError(err: Error): ControlError {
  const msg = err.message || String(err);
  if (/all configured authentication methods failed|no matching key|cannot parse key|Encrypted private/i.test(msg)) {
    return new ControlError('AUTH_FAILED', `SSH authentication failed: ${msg}`);
  }
  if (/ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ECONNREFUSED|ECONNRESET|Timed out while waiting for handshake/i.test(msg)) {
    return new ControlError('HOST_UNREACHABLE', `SSH connection failed: ${msg}`);
  }
  return new ControlError('INTERNAL', `SSH error: ${msg}`);
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

  async probe(host: HostConfig, address: string): Promise<{ ok: boolean; error?: string }> {
    const client = new Client();
    try {
      const keyPath = host.ssh.privateKeyPath ? expandPath(host.ssh.privateKeyPath) : undefined;
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('timed out')), 6000);
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
          readyTimeout: 5000,
        };
        if (keyPath && requirePrivateKeyExists(keyPath)) cfg.privateKey = readFileSync(keyPath);
        const secret = readPasswordFromEnv(host.name, host.ssh.passwordEnv) ?? (host.ssh.password ? { value: host.ssh.password, source: 'config' } : undefined);
        if (secret) cfg.password = secret.value;
        client.connect(cfg);
      });
      return { ok: true };
    } catch (err) {
      const e = err as Error;
      if (/authentication/i.test(e.message)) return { ok: true, error: 'auth' };
      return { ok: false, error: e.message };
    } finally {
      client.end();
      client.destroy();
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
        channel.on('exit', (c?: number | null, s?: string | null) => {
          exitCode = c ?? null;
          exitSignal = s ?? null;
        });
        const timer = setTimeout(() => {
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
        channel.on('close', (code?: number | null, signal?: string | null) => {
          clearTimeout(timer);
          const out = Buffer.concat(outChunks).subarray(0, MAX_OUTPUT_BYTES).toString('utf8');
          const errText = Buffer.concat(errChunks).subarray(0, MAX_OUTPUT_BYTES).toString('utf8');
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
    if (session.buffer.length > MAX_OUTPUT_BYTES) session.buffer = session.buffer.slice(-MAX_OUTPUT_BYTES);
    // Resolve only when a FULL sentinel line has arrived: the shell echoes our
    // own command back (with \r), so require the copy that starts on its own
    // line and ends with "<digits>\n" — an echoed fragment like '%s\n' never
    // matches this. The echo of the wrapped printf itself is stripped below.
    const waiters = session.pending;
    if (waiters.length === 0) return;
    const needle = sentinelFor(session.id);
    const re = new RegExp(`\\n${needle}(\\d+)\\r?\\n`);
    const m = re.exec(session.buffer);
    if (!m) return;
    const at = m.index;
    // Cut the output at the echoed wrapper line for this command (the shell
    // prints our sentinel block right after echoing it back), so callers see
    // only their command's output.
    const echoAt = session.buffer.lastIndexOf(`{ printf '\\n${needle}`);
    const cut = echoAt >= 0 && echoAt < at ? echoAt : at;
    const output = session.buffer.slice(0, cut);
    session.buffer = '';
    waiters.splice(0, waiters.length).forEach((w) => {
      clearTimeout(w.timer);
      w.resolve(output + `\n[exit ${m[1]}]`);
    });
  }

  private waitPrompt(session: ShellSession, timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      if (session.closed) return reject(new ControlError('SESSION_GONE', `Shell session ${session.id} closed`));
      const timer = setTimeout(() => {
        const idx = session.pending.findIndex((p) => p.timer === timer);
        if (idx >= 0) session.pending.splice(idx, 1);
        const out = session.buffer;
        session.buffer = '';
        resolve(out + '\n[timeout: sentinel not seen; command may still be running]');
      }, timeoutMs);
      session.pending.push({
        resolve,
        reject,
        timer,
      });
    });
  }

  async runInShell(sessionId: string, command: string, timeoutMs = 30000): Promise<{ output: string; closed: boolean }> {
    const session = this.sessions.get(sessionId);
    if (!session) throw new ControlError('SESSION_GONE', `No such shell session: ${sessionId}`);
    if (session.closed) throw new ControlError('SESSION_GONE', `Shell session ${sessionId} is closed`);
    if (session.pending.length > 0) {
      throw new ControlError('BAD_ARGS', `Shell session ${sessionId} still has a command in flight; wait for it or close the session`);
    }
    session.lastUsedAt = Date.now();
    // Sentinel: a marker line printed by the shell itself after the command,
    // carrying $?. The echo of this very line is wrapped mid-stream so it can
    // never match the real sentinel pattern. printf is used without %s because
    // dash's printf does not honor \\\\ escapes inside single quotes; cmd.exe has
    // no $? and gets the bare marker.
    const sentinel = sentinelFor(session.id);
    const wrapped = `${command}\n{ printf '\\n${sentinel}%s\\n' "$?" 2>/dev/null || echo ${sentinel}?; } 2>/dev/null\n`;
    session.channel.write(wrapped);
    const output = await this.waitPrompt(session, timeoutMs);
    return { output, closed: session.closed };
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
  ): Promise<{ bytes: number }> {
    const sftp = await this.getSftp(host, address);
    const resolved = expandPath(localPath);
    try {
      // fastPut streams from disk; do not also readFileSync the whole file.
      await new Promise<void>((resolve, reject) => {
        sftp.fastPut(resolved, remotePath, (err) => (err ? reject(new ControlError('REMOTE_ERROR', `SFTP upload failed: ${err.message}`, { code: (err as { code?: number }).code })) : resolve()));
      });
    } finally {
      sftp.end();
    }
    const bytes = statSync(resolved).size;
    onProgress?.({ bytes, total: bytes });
    return { bytes };
  }

  async downloadFile(
    host: HostConfig,
    address: string,
    remotePath: string,
    localPath: string,
  ): Promise<{ bytes: number }> {
    const sftp = await this.getSftp(host, address);
    const resolved = expandPath(localPath);
    try {
      await new Promise<void>((resolve, reject) => {
        sftp.fastGet(remotePath, resolved, (err) =>
          err ? reject(new ControlError('REMOTE_ERROR', `SFTP download failed: ${err.message}`, { code: (err as { code?: number }).code })) : resolve(),
        );
      });
    } finally {
      sftp.end();
    }
    return { bytes: statSync(resolved).size };
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
