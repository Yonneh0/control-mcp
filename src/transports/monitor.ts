import { ControlError } from '../errors.js';
import type { ExecResult } from './ssh.js';
import type { HostConfig } from '../config/schema.js';

export interface SystemEvent {
  host: string;
  source: string;
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'critical';
  category: string;
  summary: string;
  raw: string;
}

// Structural subset of SshTransport: a monitor only needs exec().
export interface SshTransportLike {
  exec(
    host: HostConfig,
    address: string,
    command: string,
    opts?: { timeoutMs?: number; stdinData?: string },
  ): Promise<ExecResult>;
}

type EventLevel = 'info' | 'warning' | 'error' | 'critical';

interface LogRecord {
  id: string;
  level: EventLevel;
  category: string;
  source: string;
  timestamp: string;
  summary: string;
  raw: string;
}

interface WatchState {
  name: string;
  host: HostConfig;
  address: string;
  timer: NodeJS.Timeout | null;
  watching: boolean;
  primed: boolean;
  seen: Set<string>;
  queued: SystemEvent[];
  /** Events discarded by the queue cap for this host (newest kept, oldest dropped). */
  dropped: number;
}

const DEFAULT_INTERVAL_MS = 30000;
const MIN_INTERVAL_MS = 5000;
const EXEC_TIMEOUT_MS = 20000;
const MAX_EVENTS_QUEUED = 500;
const MAX_TRACKED_IDS = 5000;
const SUMMARY_MAX = 200;

const WIN_PS_QUERY =
  "Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3} -MaxEvents 20 | ConvertTo-Json -Compress";
// cmd.exe is the login shell on Windows hosts: the query is handed over as one
// base64 UTF-16LE blob so no host-side quoting applies to it.
const WIN_POLL_COMMAND =
  'powershell -NoProfile -EncodedCommand ' + Buffer.from(WIN_PS_QUERY, 'utf16le').toString('base64');
const JOURNAL_POLL_COMMAND = 'journalctl -p 3 -n 20 --no-pager -o json';

const WIN_ID_KEYS = ['RecordId'];
const WIN_MESSAGE_KEYS = ['Message', 'message'];
const WIN_LEVEL_KEYS = ['Level', 'EventLevel'];
const WIN_CATEGORY_KEYS = ['ProviderName'];
const WIN_TIMESTAMP_KEYS = ['Timestamp', 'UtcTime', 'EventTime'];

// journald -o json field names, real names FIRST (verified live on um780: the
// message field is exactly MESSAGE, the cursor is __CURSOR, timestamp
// __REALTIME_TIMESTAMP, category SYSLOG_IDENTIFIER/_COMM); the legacy
// trailing-underscore spellings stay as fallbacks so hosts that use them parse.
const CURSOR_KEYS = ['__CURSOR', '__CURSOR__', 'CURSOR__', 'cursor'];
const MSG_KEYS = ['MESSAGE', 'MESSAGE__', '__MSG__', 'message'];
const PRIORITY_KEYS = ['PRIORITY', '__PRIORITY__', 'prio'];
const CATEGORY_KEYS = ['SYSLOG_IDENTIFIER', '_COMM', '_SYSTEMD_UNIT', '_UNIT', 'SERVICE', 'COMM', 'TAG'];
const TIMESTAMP_KEYS = ['__REALTIME_TIMESTAMP', '__REALTIME_TIMESTAMP__', '_SOURCE_REALTIME_TIMESTAMP', 'ts', 'timestamp'];

// journalctl on hosts without -o json support prints service[pid]: message lines.
const PLAIN_TEXT_RE =
  /^([A-Z][a-z]{2}[ ]+[ \d]\d[ ]+[\d:.]+[ ]+\S+[ ]+)?([^\s\[][^\r\n]*?)\[(\d+)\]:[ ]?([\s\S]*)$/;

function messageOf(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function firstLine(text: string): string {
  let end = text.length;
  const nl = text.indexOf('\n');
  if (nl >= 0) end = nl;
  const cr = text.indexOf('\r');
  if (cr >= 0 && cr < end) end = cr;
  const line = text.slice(0, end);
  return line.length > SUMMARY_MAX ? line.slice(0, SUMMARY_MAX) : line;
}

function winLevel(raw: number | null): EventLevel {
  if (raw === 1) return 'critical';
  if (raw === 2) return 'error';
  return 'warning';
}

function priLevel(raw: number | null): EventLevel {
  if (raw === null) return 'warning';
  if (raw <= 2) return 'critical';
  if (raw === 3) return 'error';
  if (raw >= 6) return 'info';
  return 'warning';
}

function asNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? Math.trunc(value) : null;
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text) return null;
    const parsed = Number(text);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
  }
  return null;
}

function textHash(text: string): string {
  let h = 5381;
  for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  return (h & 0x7fffffff).toString(16);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object') return null;
  return Array.isArray(value) ? null : value as Record<string, unknown>;
}

function asItems(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  const single = asRecord(value);
  return single === null ? [] : [single];
}

function pickField(rec: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = rec[key];
    if (typeof value === 'string') {
      if (value !== '') return value;
    } else if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
      return String(value);
    }
  }
  return '';
}

function tryParseJson(text: string): unknown {
  try {
    const parsed = JSON.parse(text);
    return typeof parsed === 'object' && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}

function decodeWinStdout(stdout: string): string {
  const b64 = stdout.trim().replace(/\s+/g, '');
  if (!b64) return '';
  let text = Buffer.from(b64, 'base64').toString('utf16le');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}

function parseWinRecords(stdout: string): LogRecord[] {
  const json = decodeWinStdout(stdout).trim();
  if (!json) return [];
  const parsed = tryParseJson(json);
  if (parsed === null) return [];
  const out: LogRecord[] = [];
  for (const item of asItems(parsed)) {
    const rec = asRecord(item);
    if (rec === null) continue;
    const raw = JSON.stringify(rec);
    const rid = pickField(rec, WIN_ID_KEYS);
    out.push({
      // RecordId ids are stable across polls, so they dedupe. A content hash cannot:
      // the same rendered text in a later poll may be a genuinely new event, so
      // within one poll the occurrence index keeps two identical records distinct.
      id: rid !== '' ? 'w:' + rid : 'w:h' + textHash(raw) + '#' + out.length,
      level: winLevel(asNumber(pickField(rec, WIN_LEVEL_KEYS))),
      category: pickField(rec, WIN_CATEGORY_KEYS) || 'eventlog',
      source: 'eventlog',
      timestamp: pickField(rec, WIN_TIMESTAMP_KEYS),
      summary: firstLine(pickField(rec, WIN_MESSAGE_KEYS)),
      raw,
    });
  }
  return out;
}

function humanTimestamp(raw: string): string {
  // journald __REALTIME_TIMESTAMP is microseconds since the epoch as a decimal
  // string; render it ISO-8601 so an event line is actually useful to a reader.
  if (/^\d{13,16}$/.test(raw)) {
    const ms = raw.length <= 13 ? Number(raw) : Math.floor(Number(raw) / 1000);
    const iso = new Date(ms).toISOString();
    if (!iso.startsWith('1970')) return iso;
  }
  return raw;
}

function journalRecord(rec: Record<string, unknown>, raw: string, occurrence: number): LogRecord {
  const cursor = pickField(rec, CURSOR_KEYS);
  return {
    // __CURSOR__ ids are stable across polls, so they dedupe. A content hash cannot:
    // the same content in a later poll may be a genuinely new event, so within one
    // poll the occurrence index keeps two identical records distinct.
    id: cursor !== '' ? 'j:' + cursor : 'j:h' + textHash(raw) + '#' + occurrence,
    level: priLevel(asNumber(pickField(rec, PRIORITY_KEYS))),
    category: pickField(rec, CATEGORY_KEYS) || 'journal',
    source: 'journal',
    timestamp: humanTimestamp(pickField(rec, TIMESTAMP_KEYS)),
    summary: firstLine(pickField(rec, MSG_KEYS)),
    raw,
  };
}

function parseJournalRecords(stdout: string): LogRecord[] {
  const text = stdout.trim();
  if (!text) return [];
  const whole = tryParseJson(text);
  if (whole !== null) {
    const out: LogRecord[] = [];
    for (const item of asItems(whole)) {
      const rec = asRecord(item);
      if (rec !== null) out.push(journalRecord(rec, JSON.stringify(rec), out.length));
    }
    return out;
  }
  // Whole-buffer JSON.parse failed: try per line, then the plain syslog-like form.
  const out: LogRecord[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const obj = tryParseJson(trimmed);
    if (obj !== null) {
      const rec = asRecord(obj);
      if (rec !== null) out.push(journalRecord(rec, trimmed, out.length));
      continue;
    }
    const m = PLAIN_TEXT_RE.exec(trimmed);
    if (!m) continue;
    out.push({
      // Content-hash id: the occurrence index ('#' + out.length) makes repeated
      // identical lines within one poll distinct events - two 'service restarted'
      // lines are two alerts, not one. Note that a content hash CANNOT dedupe
      // identical events across polls; only cursor/RecordId ids are stable enough
      // for that.
      id: 't:h' + textHash(trimmed) + '#' + out.length,
      level: 'warning',
      category: m[2] || 'journal',
      source: 'journal',
      timestamp: '',
      summary: firstLine(m[4]),
      raw: trimmed,
    });
  }
  return out;
}

function pollCommand(host: HostConfig): string {
  return host.os === 'windows' ? WIN_POLL_COMMAND : JOURNAL_POLL_COMMAND;
}

export function describeEventSinkPolicy(): string {
  return (
    'Event monitoring is poll-based, never push: each watched host is re-queried on a fixed interval ' +
    '(30000 ms default, 5000 ms floor) and every poll is diffed against the record identifiers this monitor ' +
    'has already seen, so the same log record can never be emitted twice. Monitors are per host and carry ' +
    'baseline semantics: the first poll of start() only records identifiers (RecordId for the Windows event ' +
    'log, __CURSOR__ for the journal) and emits nothing, so a fresh monitor reports only events ' +
    'that occur while it is active. A poll only counts as a usable baseline when the query exited cleanly or ' +
    'parsed at least one record, so a failed (including timed-out) or unparseable first poll leaves the ' +
    'monitor unprimed and re-baselines on the next tick instead of replaying history as new alerts. Windows ' +
    'hosts are read with Get-WinEvent levels 1-3 of the System channel ' +
    'rendered as compact JSON, with levels mapped 1=critical, 2=error, 3=warning; Linux hosts are read with ' +
    'journalctl -p 3 -n 20 --no-pager -o json (message field MESSAGE, identifier SYSLOG_IDENTIFIER) and its ' +
    'plain-text fallback, with priorities mapped ' +
    '2=critical, 3=error, otherwise warning/info. Emission uses push-based consumption: events are queued per ' +
    'host and drainEvents() returns and clears them, so callers must drain promptly. Each host queue is capped ' +
    'at 500 events: when it overflows the NEWEST events are kept and the OLDEST are dropped (the right policy ' +
    'for live alerting), and that loss is not silent - it is counted per host and reported by ' +
    'getDroppedCount(hostName). A poll that fails or returns unparseable output yields no events ' +
    'and no error; capability gaps are reported only by start() as CAPABILITY_UNAVAILABLE.'
  );
}

export class EventMonitor {
  private readonly ssh: SshTransportLike;
  private readonly intervalMs: number;
  private readonly hosts = new Map<string, HostConfig>();
  private readonly watched = new Map<string, WatchState>();

  constructor(ssh: SshTransportLike, opts?: { intervalMs?: number; hosts?: Record<string, HostConfig> }) {
    this.ssh = ssh;
    const raw = opts?.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.intervalMs = Number.isFinite(raw) ? Math.max(MIN_INTERVAL_MS, Math.floor(raw)) : MIN_INTERVAL_MS;
    const hosts = opts?.hosts;
    if (hosts) {
      for (const name of Object.keys(hosts)) this.hosts.set(name, hosts[name]);
    }
  }

  getIntervalMs(): number {
    return this.intervalMs;
  }

  async start(hostName: string): Promise<void> {
    const current = this.watched.get(hostName);
    if (current !== undefined && current.watching) return;
    const host = this.hosts.get(hostName);
    if (!host || (host.os !== 'windows' && host.os !== 'linux')) {
      throw new ControlError(
        'CAPABILITY_UNAVAILABLE',
        `Host "${hostName}" has no known OS: system event monitoring is unavailable`,
      );
    }
    const state: WatchState = {
      name: hostName,
      host,
      address: host.address,
      timer: null,
      watching: true,
      primed: false,
      seen: new Set<string>(),
      queued: [],
      dropped: 0,
    };
    // Register BEFORE awaiting the baseline poll so a stop()/dispose() issued while
    // that poll is in flight lands on this state and can be seen below; every exit
    // path that does not end up keeping the monitor takes the provisional entry back
    // out with unwatch().
    if (current !== undefined) this.clearTimer(current);
    this.watched.set(hostName, state);
    let res: ExecResult;
    try {
      res = await this.execPoll(state);
    } catch (err) {
      this.unwatch(state);
      throw new ControlError(
        'CAPABILITY_UNAVAILABLE',
        `Cannot start system event monitor for "${hostName}": ${messageOf(err)}`,
        { host: hostName },
      );
    }
    // Cancelled (stop()/dispose()) while the baseline poll was awaited: do not
    // resurrect the monitor - return without registering or scheduling.
    if (!state.watching) return;
    if (res.stdout.trim() === '' && res.code !== null && res.code !== 0) {
      const reason = res.stderr.trim() === '' ? 'the log query produced no output' : res.stderr.trim();
      this.unwatch(state);
      throw new ControlError(
        'CAPABILITY_UNAVAILABLE',
        `No system log source on "${hostName}": ${reason.slice(0, 200)}`,
        { host: hostName, code: res.code },
      );
    }
    // A timed-out baseline (res.code === null) is not a missing log source, so it is
    // not a CAPABILITY_UNAVAILABLE: the watch stays up, but applyPoll() finds the
    // poll unusable and leaves it unprimed so the next poll re-baselines quietly.
    this.applyPoll(state, res);
    this.schedule(state);
  }

  private execPoll(state: WatchState): Promise<ExecResult> {
    // Floor of 10 s so a fast cadence does not produce permanently-timing-out polls.
    const timeoutMs = Math.max(10000, Math.min(this.intervalMs, EXEC_TIMEOUT_MS));
    return this.ssh.exec(state.host, state.address, pollCommand(state.host), { timeoutMs });
  }

  private applyPoll(state: WatchState, res: ExecResult): void {
    const records = state.host.os === 'windows' ? parseWinRecords(res.stdout) : parseJournalRecords(res.stdout);
    // A poll is USABLE when the query exited cleanly (code 0) or produced at least
    // one parseable record. A failed poll - nonzero exit, or code === null meaning
    // the exec timed out - with nothing parseable must NOT prime the baseline: with
    // an empty seen-set the next successful poll would re-emit up to 20 historical
    // records as if they were brand-new alerts, so the monitor stays unprimed and
    // re-baselines on the next poll instead.
    const usable = res.code === 0 || records.length > 0;
    for (const rec of records) {
      if (state.seen.has(rec.id)) {
        // LRU touch: Set.add() on an existing member does not move it, so without
        // delete+add a still-recent identifier keeps its ancient insertion position
        // and the half-prune below can evict it - which would re-emit that record on
        // a later poll. Re-inserting keeps insertion order == recency order.
        state.seen.delete(rec.id);
        state.seen.add(rec.id);
        continue;
      }
      state.seen.add(rec.id);
      if (state.primed) {
        state.queued.push({
          host: state.name,
          source: rec.source,
          timestamp: rec.timestamp,
          level: rec.level,
          category: rec.category,
          summary: rec.summary,
          raw: rec.raw,
        });
        // Keep the NEWEST and drop the OLDEST, counting every discard so the loss is
        // visible instead of silent (see getDroppedCount).
        while (state.queued.length > MAX_EVENTS_QUEUED) {
          state.queued.shift();
          state.dropped += 1;
        }
      }
    }
    if (state.seen.size > MAX_TRACKED_IDS) {
      const keep = [...state.seen].slice(-Math.floor(MAX_TRACKED_IDS / 2));
      state.seen = new Set<string>(keep);
    }
    // Emission decisions above used the PREVIOUS primed state; only a usable poll is
    // allowed to mark the baseline as taken.
    state.primed = usable;
  }

  private schedule(state: WatchState): void {
    // One bad poll must never tear down the process or the schedule: without this
    // wrapper a synchronous throw from execPoll, or a rejection from the apply step
    // that nobody awaits (applyPoll throwing inside .then, or .finally re-throwing),
    // surfaces as an uncaught exception / unhandled rejection and exits Node,
    // killing every other monitored host. Everything here is swallowed and the next
    // tick still runs.
    state.timer = setTimeout(() => {
      state.timer = null;
      if (!state.watching) return;
      try {
        void this.execPoll(state)
          .then((res) => {
            if (state.watching) this.applyPoll(state, res);
          })
          .finally(() => {
            if (state.watching) this.schedule(state);
          })
          .catch(() => undefined);
      } catch {
        // execPoll threw synchronously, so the chain (and its rescheduling finally)
        // never existed: re-arm the next tick and let the failure go unreported,
        // exactly as a rejected poll is unreported by policy.
        if (state.watching) this.schedule(state);
      }
    }, this.intervalMs);
  }

  private clearTimer(state: WatchState): void {
    if (state.timer !== null) {
      clearTimeout(state.timer);
      state.timer = null;
    }
  }

  /**
   * Take back a provisional registration (failed baseline poll) without clobbering a
   * newer start() for the same host.
   */
  private unwatch(state: WatchState): void {
    state.watching = false;
    this.clearTimer(state);
    if (this.watched.get(state.name) === state) this.watched.delete(state.name);
  }

  stop(hostName: string): void {
    const state = this.watched.get(hostName);
    if (state === undefined) return;
    state.watching = false;
    this.clearTimer(state);
  }

  listWatched(): string[] {
    const names: string[] = [];
    for (const state of this.watched.values()) {
      if (state.watching) names.push(state.name);
    }
    return names;
  }

  /**
   * How many events the per-host queue cap (500, newest kept / oldest dropped) has
   * discarded: pass a host name for that host, or nothing for the total across every
   * host the monitor still holds. The counter belongs to the current watch session,
   * so it resets when a host is (re)started.
   */
  getDroppedCount(hostName?: string): number {
    if (hostName !== undefined) {
      const state = this.watched.get(hostName);
      return state === undefined ? 0 : state.dropped;
    }
    let total = 0;
    for (const state of this.watched.values()) total += state.dropped;
    return total;
  }

  drainEvents(hostName?: string): SystemEvent[] {
    if (hostName !== undefined) {
      const state = this.watched.get(hostName);
      if (state === undefined) return [];
      return this.takeQueued(state);
    }
    const all: SystemEvent[] = [];
    for (const state of this.watched.values()) all.push(...this.takeQueued(state));
    return all;
  }

  private takeQueued(state: WatchState): SystemEvent[] {
    const out = state.queued;
    state.queued = [];
    return out;
  }

  dispose(): void {
    for (const state of this.watched.values()) {
      state.watching = false;
      this.clearTimer(state);
    }
  }
}
