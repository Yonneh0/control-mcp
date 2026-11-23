import { describe, it, expect, vi } from 'vitest';
import { EventMonitor, describeEventSinkPolicy } from '../src/transports/monitor.js';
import type { SshTransportLike } from '../src/transports/monitor.js';
import type { ExecResult } from '../src/transports/ssh.js';
import type { HostConfig } from '../src/config/schema.js';
import { ControlError } from '../src/errors.js';

const HOSTS: Record<string, HostConfig> = {
  win: {
    name: 'winbox',
    address: '10.10.1.2',
    os: 'windows',
    ssh: { port: 22, user: 'op', privateKeyPath: 'C:/keys/win/op' },
    alternateAddresses: [],
    capabilities: { rdp: false },
  },
  lin: {
    name: 'lanbox',
    address: '10.10.1.3',
    os: 'linux',
    ssh: { port: 22, user: 'op', privateKeyPath: '/keys/lin/op' },
    alternateAddresses: [],
    capabilities: { rdp: false },
  },
};

function winRecordJson(rid: number, level: number, message: string): string {
  return JSON.stringify({
    Timestamp: '2025-11-21T09:14:22.000Z',
    EventSource: 'System',
    Level: level,
    ProviderName: 'network-service',
    Message: message,
    RecordId: rid,
  });
}

function winStdout(records: string[]): string {
  const json = records.length === 1 ? records[0] : `[${records.join(',')}]`;
  // The command base64-encodes the JSON as UTF-8 (see WIN_PS_QUERY); this fixture
  // mirrors that exactly so it is a regression test for the real contract, not
  // for the decoder in isolation (a UTF-16 fixture here once hid a silent
  // Windows capability failure).
  return Buffer.from(json, 'utf8').toString('base64');
}

// Field names are the REAL journald -o json fields, verified live on um780
// (MESSAGE, SYSLOG_IDENTIFIER, __CURSOR, __REALTIME_TIMESTAMP), so this fixture
// is a truthful regression test for the parser rather than its old fallbacks.
function journalRecord(cursor: string, priority: string, message: string): Record<string, unknown> {
  return {
    __CURSOR: cursor,
    __REALTIME_TIMESTAMP: '1763717662000000',
    PRIORITY: priority,
    SYSLOG_IDENTIFIER: 'network.service',
    _PID: '812',
    _COMM: 'network-daemon',
    MESSAGE: message,
  };
}

function journalStdout(records: Record<string, unknown>[]): string {
  return JSON.stringify(records);
}

function sequence(payloads: string[]): () => string {
  let index = 0;
  return () => {
    const out = payloads[Math.min(index, payloads.length - 1)];
    index += 1;
    return out;
  };
}

function makeFake(nextStdout: () => string, calls: string[]): SshTransportLike {
  return {
    exec: async (_host, _address, command) => {
      calls.push(command);
      return {
        stdout: nextStdout(),
        stderr: '',
        code: 0,
        signal: null,
        truncated: false,
        timedOut: false,
        durationMs: 1,
      };
    },
  };
}

function makeDispatch(
  winNext: () => string,
  linNext: () => string,
  winCalls: string[],
  linCalls: string[],
): SshTransportLike {
  return {
    exec: async (_host, _address, command) => {
      const isWin = command.startsWith('powershell');
      const calls = isWin ? winCalls : linCalls;
      const next = isWin ? winNext : linNext;
      calls.push(command);
      return {
        stdout: next(),
        stderr: '',
        code: 0,
        signal: null,
        truncated: false,
        timedOut: false,
        durationMs: 1,
      };
    },
  };
}

function captureControlError(run: () => Promise<void>): ControlErrorCapturer {
  const promise = run().then(
    () => null,
    (caught) => {
      if (caught instanceof ControlError) return caught;
      throw caught;
    },
  );
  // await it like a promise, or unwrap with the assertion that one WAS thrown.
  return Object.assign(promise, {
    must: async () => {
      const err = await promise;
      if (!err) throw new Error('expected a ControlError but the call resolved');
      return err;
    },
  });
}

interface ControlErrorCapturer extends Promise<ControlError | null> {
  must(): Promise<ControlError>;
}

describe('EventMonitor baseline semantics', () => {
  it('captures a baseline without emitting pre-existing Windows records', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const baseline = winStdout([winRecordJson(101, 3, 'pre-existing')]);
      const monitor = new EventMonitor(makeFake(() => baseline, calls), { intervalMs: 5000, hosts: HOSTS });
      await monitor.start('win');
      expect(calls).toHaveLength(1);
      expect(monitor.listWatched()).toEqual(['win']);
      expect(monitor.drainEvents()).toEqual([]);
      expect(monitor.drainEvents('win')).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('emits exactly one event when a new RecordId appears on the second poll', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const first = winStdout([winRecordJson(101, 3, 'pre-existing')]);
      const second = winStdout([
        winRecordJson(101, 3, 'pre-existing'),
        winRecordJson(102, 2, 'pump failure\nstack line'),
      ]);
      const monitor = new EventMonitor(makeFake(sequence([first, second]), calls), { intervalMs: 5000, hosts: HOSTS });
      await monitor.start('win');
      expect(monitor.drainEvents('win')).toEqual([]);
      await vi.advanceTimersByTimeAsync(5001);
      expect(calls).toHaveLength(2);
      const events = monitor.drainEvents('win');
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        host: 'win',
        source: 'eventlog',
        timestamp: '2025-11-21T09:14:22.000Z',
        level: 'error',
        category: 'network-service',
        summary: 'pump failure',
      });
      expect(JSON.parse(events[0].raw)).toMatchObject({ RecordId: 102, Level: 2 });
      expect(monitor.drainEvents('win')).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('maps Windows event levels 1, 2, and 3 to critical, error, and warning', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const first = winStdout([winRecordJson(101, 3, 'pre-existing')]);
      const second = winStdout([
        winRecordJson(101, 3, 'pre-existing'),
        winRecordJson(201, 1, 'critical msg'),
        winRecordJson(202, 2, 'error msg'),
        winRecordJson(203, 3, 'warning msg'),
      ]);
      const monitor = new EventMonitor(
        makeFake(sequence([first, second]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('win');
      await vi.advanceTimersByTimeAsync(5001);
      const events = monitor.drainEvents('win');
      expect(events).toHaveLength(3);
      expect(events.map((e) => e.level)).toEqual(['critical', 'error', 'warning']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('takes the summary from the first Message line and caps it at 200 chars', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const longText = 'x'.repeat(260);
      const first = winStdout([winRecordJson(101, 3, 'pre-existing')]);
      const second = winStdout([
        winRecordJson(101, 3, 'pre-existing'),
        winRecordJson(102, 1, `${longText}\nsecond line`),
      ]);
      const monitor = new EventMonitor(
        makeFake(sequence([first, second]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('win');
      await vi.advanceTimersByTimeAsync(5001);
      const events = monitor.drainEvents('win');
      expect(events).toHaveLength(1);
      expect(events[0].level).toBe('critical');
      expect(events[0].summary).toBe('x'.repeat(200));
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EventMonitor journal stream', () => {
  it('treats the first journal poll as baseline only', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const first = journalStdout([journalRecord('c0', '3', 'old failure')]);
      const monitor = new EventMonitor(
        makeFake(sequence([first]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('lin');
      expect(calls).toHaveLength(1);
      expect(monitor.drainEvents('lin')).toEqual([]);
      await vi.advanceTimersByTimeAsync(5001);
      expect(calls).toHaveLength(2);
      expect(monitor.drainEvents()).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('emits one event per new __CURSOR__ and maps priorities 2/3 to critical/error', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const first = journalStdout([journalRecord('c0', '3', 'old failure')]);
      const second = journalStdout([
        journalRecord('c0', '3', 'old failure'),
        journalRecord('c1', '2', 'disk critical'),
      ]);
      const monitor = new EventMonitor(
        makeFake(sequence([first, second]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('lin');
      await vi.advanceTimersByTimeAsync(5001);
      const events = monitor.drainEvents('lin');
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        host: 'lin',
        source: 'journal',
        timestamp: '2025-11-21T09:34:22.000Z',
        level: 'critical',
        category: 'network.service',
        summary: 'disk critical',
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('maps remaining priorities to warning or info', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const first = journalStdout([journalRecord('c0', '3', 'old')]);
      const second = journalStdout([
        journalRecord('c0', '3', 'old'),
        journalRecord('c1', '3', 'pump error'),
        journalRecord('c2', '5', 'routine notice'),
        journalRecord('c3', '6', 'debug chatter'),
      ]);
      const monitor = new EventMonitor(
        makeFake(sequence([first, second]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('lin');
      await vi.advanceTimersByTimeAsync(5001);
      const events = monitor.drainEvents('lin');
      expect(events).toHaveLength(3);
      expect(events.map((e) => e.level)).toEqual(['error', 'warning', 'info']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('deduplicates repeated journal payloads by __CURSOR__', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const payload = journalStdout([journalRecord('c1', '3', 'one'), journalRecord('c2', '2', 'two')]);
      const monitor = new EventMonitor(
        makeFake(sequence([payload]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('lin');
      await vi.advanceTimersByTimeAsync(15001);
      expect(calls).toHaveLength(4);
      expect(monitor.drainEvents('lin')).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('falls back to plain journal lines when the json payload is unsupported', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const plain1 = [
        'Nov 21 09:14:22 hostbox network-service[812]: standby pump skipped',
        'Nov 21 09:14:25 hostbox network-service[812]: standby pump skipped',
      ].join('\n');
      const plain2 = `${plain1}\nNov 21 09:14:31 hostbox network-service[812]: standby pump failed`;
      const monitor = new EventMonitor(
        makeFake(sequence([plain1, plain2]), calls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('lin');
      expect(monitor.drainEvents('lin')).toEqual([]);
      await vi.advanceTimersByTimeAsync(5001);
      const events = monitor.drainEvents('lin');
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        host: 'lin',
        source: 'journal',
        level: 'warning',
        category: 'network-service',
        summary: 'standby pump failed',
      });
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EventMonitor resilience and halting', () => {
  it('does not throw and yields no events for malformed remote payloads', async () => {
    vi.useFakeTimers();
    try {
      const winCalls: string[] = [];
      const garbageWin = Buffer.from('{ "Level": 2, "RecordId": [', 'utf16le').toString('base64');
      const winMonitor = new EventMonitor(
        makeFake(() => garbageWin, winCalls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await winMonitor.start('win');
      await vi.advanceTimersByTimeAsync(15001);
      expect(winCalls).toHaveLength(4);
      expect(winMonitor.drainEvents()).toEqual([]);

      const linCalls: string[] = [];
      const linMonitor = new EventMonitor(
        makeFake(() => 'not json at all', linCalls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await linMonitor.start('lin');
      await vi.advanceTimersByTimeAsync(10001);
      expect(linCalls).toHaveLength(3);
      expect(linMonitor.drainEvents()).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('halts polling after stop()', async () => {
    vi.useFakeTimers();
    try {
      const calls: string[] = [];
      const payload = winStdout([winRecordJson(101, 3, 'steady')]);
      const monitor = new EventMonitor(makeFake(() => payload, calls), { intervalMs: 5000, hosts: HOSTS });
      await monitor.start('win');
      expect(calls).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(5001);
      expect(calls).toHaveLength(2);
      monitor.stop('win');
      expect(monitor.listWatched()).toEqual([]);
      await vi.advanceTimersByTimeAsync(30001);
      expect(calls).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('dispose clears all pending timers', async () => {
    vi.useFakeTimers();
    try {
      const winCalls: string[] = [];
      const linCalls: string[] = [];
      const winPayload = winStdout([winRecordJson(101, 3, 'steady')]);
      const linPayload = journalStdout([journalRecord('c1', '3', 'steady')]);
      const monitor = new EventMonitor(
        makeDispatch(() => winPayload, () => linPayload, winCalls, linCalls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('win');
      await monitor.start('lin');
      expect(monitor.listWatched()).toEqual(['win', 'lin']);
      await vi.advanceTimersByTimeAsync(5001);
      expect(winCalls).toHaveLength(2);
      expect(linCalls).toHaveLength(2);
      monitor.dispose();
      await vi.advanceTimersByTimeAsync(30000);
      expect(winCalls).toHaveLength(2);
      expect(linCalls).toHaveLength(2);
      expect(monitor.listWatched()).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EventMonitor drainEvents', () => {
  it('filters by host and clears what it returns', async () => {
    vi.useFakeTimers();
    try {
      const winCalls: string[] = [];
      const linCalls: string[] = [];
      const winWin = sequence([
        winStdout([winRecordJson(11, 3, 'pre')]),
        winStdout([winRecordJson(11, 3, 'pre'), winRecordJson(12, 3, 'win new')]),
      ]);
      const linLin = sequence([
        journalStdout([journalRecord('c1', '3', 'pre')]),
        journalStdout([journalRecord('c1', '3', 'pre'), journalRecord('c2', '3', 'lin new')]),
      ]);
      const monitor = new EventMonitor(
        makeDispatch(winWin, linLin, winCalls, linCalls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('win');
      await monitor.start('lin');
      await vi.advanceTimersByTimeAsync(5001);
      expect(winCalls).toHaveLength(2);
      expect(linCalls).toHaveLength(2);
      const winEvents = monitor.drainEvents('win');
      expect(winEvents).toHaveLength(1);
      expect(winEvents.map((e) => e.host)).toEqual(['win']);
      const linEvents = monitor.drainEvents('lin');
      expect(linEvents).toHaveLength(1);
      expect(linEvents[0]).toMatchObject({ host: 'lin', summary: 'lin new' });
      expect(monitor.drainEvents()).toEqual([]);
      expect(monitor.drainEvents('win')).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('returns every queued event and clears it', async () => {
    vi.useFakeTimers();
    try {
      const winCalls: string[] = [];
      const linCalls: string[] = [];
      const winWin = sequence([
        winStdout([winRecordJson(21, 3, 'pre')]),
        winStdout([winRecordJson(21, 3, 'pre'), winRecordJson(22, 2, 'win new')]),
      ]);
      const linLin = sequence([
        journalStdout([journalRecord('c9', '3', 'pre')]),
        journalStdout([journalRecord('c9', '3', 'pre'), journalRecord('ca', '3', 'lin new')]),
      ]);
      const monitor = new EventMonitor(
        makeDispatch(winWin, linLin, winCalls, linCalls),
        { intervalMs: 5000, hosts: HOSTS },
      );
      await monitor.start('win');
      await monitor.start('lin');
      await vi.advanceTimersByTimeAsync(5001);
      const all = monitor.drainEvents();
      expect(all).toHaveLength(2);
      expect(all.map((e) => e.host)).toEqual(['win', 'lin']);
      expect(monitor.drainEvents()).toEqual([]);
      expect(monitor.drainEvents('lin')).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('EventMonitor capability reporting', () => {
  it('refuses a host whose configuration is unknown', async () => {
    const monitor = new EventMonitor(makeFake(() => '', []), { intervalMs: 5000, hosts: HOSTS });
    const err = await captureControlError(() => monitor.start('ghost')).must();
    expect(err.name).toBe('ControlError');
    expect(err.code).toBe('CAPABILITY_UNAVAILABLE');
  });

  it('wraps transport failures as CAPABILITY_UNAVAILABLE', async () => {
    const broken: SshTransportLike = {
      exec: async (): Promise<ExecResult> => {
        throw new Error('ssh exec failed');
      },
    };
    const monitor = new EventMonitor(broken, { intervalMs: 5000, hosts: HOSTS });
    const err = await captureControlError(() => monitor.start('lin')).must();
    expect(err.name).toBe('ControlError');
    expect(err.code).toBe('CAPABILITY_UNAVAILABLE');
    expect(err.message).toContain('ssh exec failed');
  });

  it('refuses a host whose log source is missing', async () => {
    const noLog: SshTransportLike = {
      exec: async (): Promise<ExecResult> => ({
        stdout: '',
        stderr: 'journalctl: command not found',
        code: 127,
        signal: null,
        truncated: false,
        timedOut: false,
        durationMs: 12,
      }),
    };
    const monitor = new EventMonitor(noLog, { intervalMs: 5000, hosts: HOSTS });
    const err = await captureControlError(() => monitor.start('lin')).must();
    expect(err.name).toBe('ControlError');
    expect(err.code).toBe('CAPABILITY_UNAVAILABLE');
    expect(err.message).toContain('journalctl: command not found');
  });
});

describe('describeEventSinkPolicy', () => {
  it('returns one paragraph about polling and baseline semantics', () => {
    const text = describeEventSinkPolicy();
    expect(typeof text).toBe('string');
    expect(text.includes('\n')).toBe(false);
    expect(text.length).toBeGreaterThan(500);
    expect(text).toContain('poll');
    expect(text).toContain('baseline');
    expect(text).toContain('__CURSOR__');
  });
});
