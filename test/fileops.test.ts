import { describe, it, expect } from 'vitest';
import { checkCommand } from '../src/safety.js';
import {
  applyPatch,
  buildGlobCommand,
  buildSearchCommand,
  looksBinary,
  parseFindOutput,
  parseGrepOutput,
  parseWinGlobOutput,
  parseWinSearchOutput,
  shq,
  sliceLines,
} from '../src/transports/fileops.js';

// decode a psCommand() wrapper back to the PowerShell it will run
const decodePs = (cmd: string): string => Buffer.from(cmd.split(' ')[4], 'base64').toString('utf16le');

// Remove what a POSIX shell treats as quoted or escaped — a '...' run (and shq's
// '\'' splice comes out of that naturally) plus any \x pair — so what remains can
// be asserted to carry no shell metacharacters: anything the caller supplied has
// to have been inside a quoted argument to be inert.
function stripQuotedArgs(s: string): string {
  let out = '';
  let i = 0;
  while (i < s.length) {
    if (s[i] === "'") {
      i++;
      while (i < s.length && s[i] !== "'") i++;
      i++;
      continue;
    }
    if (s[i] === '\\') {
      i += 2;
      continue;
    }
    out += s[i];
    i++;
  }
  return out;
}

describe('shq', () => {
  it('wraps in single quotes', () => {
    expect(shq('/tmp/a b')).toBe("'/tmp/a b'");
  });

  it('turns each embedded quote into the close-escape-reopen splice', () => {
    expect(shq("it's")).toBe(`'it'\\''s'`);
    // a lone quote becomes empty-quoted, escaped, empty-quoted: ''\''''
    expect(shq("'")).toBe("''\\'''");
  });

  it('neutralises command substitution', () => {
    expect(shq('$(reboot)')).toBe("'$(reboot)'");
    expect(shq('`reboot`')).toBe('\'`reboot`\'');
  });
});

describe('applyPatch', () => {
  it('applies one unique edit', () => {
    const { newText, results } = applyPatch('alpha\nbeta\n', [{ oldString: 'beta', newString: 'gamma' }]);
    expect(newText).toBe('alpha\ngamma\n');
    expect(results).toEqual([{ index: 0, occurrences: 1, replaced: 1, replaceAll: false }]);
  });

  it('refuses an ambiguous oldString with a message naming the fix', () => {
    let err: unknown;
    try {
      applyPatch('x x', [{ oldString: 'x', newString: 'y' }]);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
    const e = err as Error & { code?: string; detail?: Record<string, unknown> };
    expect(e.code).toBe('BAD_ARGS');
    expect(e.message).toMatch(/ambiguous/);
    expect(e.message).toMatch(/2 matches/);
    expect(e.detail).toMatchObject({ index: 0, occurrences: 2 });
  });

  it('refuses an oldString that is not found', () => {
    let err: unknown;
    try {
      applyPatch('alpha', [{ oldString: 'zzz', newString: 'y' }]);
    } catch (e) {
      err = e;
    }
    expect((err as Error).message).toMatch(/not found/);
    expect((err as Error & { code: string }).code).toBe('BAD_ARGS');
  });

  it('replaces every occurrence with replaceAll', () => {
    const { newText, results } = applyPatch('a,b,c', [{ oldString: ',', newString: ';', replaceAll: true }]);
    expect(newText).toBe('a;b;c');
    expect(results[0]).toMatchObject({ occurrences: 2, replaced: 2, replaceAll: true });
  });

  it('treats edit 2 against edit 1\'s output', () => {
    const { newText, results } = applyPatch('one', [
      { oldString: 'one', newString: 'two' },
      { oldString: 'two', newString: 'six' },
    ]);
    expect(newText).toBe('six');
    expect(results.map((r) => r.index)).toEqual([0, 1]);
  });

  it('fails atomically: a bad second edit applies nothing', () => {
    let threw = false;
    try {
      applyPatch('aaa bbb', [
        { oldString: 'aaa', newString: 'XXX' },
        { oldString: 'nope', newString: 'YYY' },
      ]);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });

  it('rejects an empty oldString (infinitely many positions)', () => {
    let err: unknown;
    try {
      applyPatch('abc', [{ oldString: '', newString: 'x' }]);
    } catch (e) {
      err = e;
    }
    expect((err as Error).message).toMatch(/empty/);
    expect((err as Error & { code: string }).code).toBe('BAD_ARGS');
  });

  it('keeps $-sequences in the replacement literal', () => {
    expect(applyPatch('aXb', [{ oldString: 'X', newString: '$&$1' }]).newText).toBe('a$&$1b');
  });
});

describe('sliceLines', () => {
  const text = 'l1\nl2\nl3\nl4\nl5';

  it('defaults to the whole file from line 1', () => {
    const r = sliceLines(text, 1, 2000);
    expect(r.shown).toEqual(['l1', 'l2', 'l3', 'l4', 'l5']);
    expect(r.firstLine).toBe(1);
    expect(r.lastLine).toBe(5);
    expect(r.totalLinesSeen).toBe(5);
    expect(r.truncatedByLimit).toBe(false);
  });

  it('starts mid-file and keeps the 1-based numbering', () => {
    const r = sliceLines(text, 3, 2000);
    expect(r.shown).toEqual(['l3', 'l4', 'l5']);
    expect(r.firstLine).toBe(3);
    expect(r.lastLine).toBe(5);
  });

  it('returns an empty window when offset is past the end', () => {
    const r = sliceLines(text, 99, 10);
    expect(r.shown).toEqual([]);
    expect(r.firstLine).toBe(99);
    expect(r.lastLine).toBe(98);
    expect(r.totalLinesSeen).toBe(5);
    expect(r.truncatedByLimit).toBe(false);
  });

  it('flags truncation by limit and reports how much is left', () => {
    const r = sliceLines(text, 1, 2);
    expect(r.shown).toEqual(['l1', 'l2']);
    expect(r.truncatedByLimit).toBe(true);
    const rest = sliceLines(text, r.lastLine + 1, 2000);
    expect(rest.shown).toEqual(['l3', 'l4', 'l5']);
    expect(rest.truncatedByLimit).toBe(false);
  });

  it('strips trailing CR from CRLF text', () => {
    const r = sliceLines('a\r\nb\r\n', 1, 10);
    expect(r.shown).toEqual(['a', 'b', '']);
    expect(r.shown.every((l) => !l.endsWith('\r'))).toBe(true);
    expect(r.totalLinesSeen).toBe(3);
  });

  it('treats a trailing newline as a final empty line', () => {
    expect(sliceLines('a\n', 1, 10).totalLinesSeen).toBe(2);
    expect(sliceLines('', 1, 10).totalLinesSeen).toBe(1);
  });
});

describe('looksBinary', () => {
  it('is false for plain text', () => {
    expect(looksBinary(Buffer.from('hello world\nsecond line\n', 'utf8'))).toBe(false);
  });

  it('is true when a NUL appears in the first 8 KiB', () => {
    const buf = Buffer.alloc(9000, 0x41);
    buf[100] = 0x00;
    expect(looksBinary(buf)).toBe(true);
    expect(looksBinary(Buffer.from([0x68, 0x00, 0x69]))).toBe(true);
  });

  it('is false for an empty buffer', () => {
    expect(looksBinary(Buffer.alloc(0))).toBe(false);
  });
});

describe('parseFindOutput', () => {
  // GNU find -printf '%T@\t%p\0' records, deliberately out of order, with a
  // comma decimal separator (a non-English locale) and one malformed record.
  const sample =
    '1700000002.0000000000\t/srv/a.log\0' +
    '1700000009,5000000000\t/srv/newer,with comma.log\0' +
    '1700000001.2500000000\t/srv/b.log\0' +
    'garbage-without-tab\0' +
    'not-a-time\t/srv/bad.log\0';

  it('parses, sorts newest-first, and converts seconds to ms', () => {
    const items = parseFindOutput(sample, 10);
    expect(items.map((i) => i.path)).toEqual([
      '/srv/newer,with comma.log',
      '/srv/a.log',
      '/srv/b.log',
    ]);
    expect(items[0].mtimeMs).toBe(1700000009500);
    expect(items[1].mtimeMs).toBe(1700000002000);
    expect(items[2].mtimeMs).toBe(1700000001250);
  });

  it('caps at maxResults', () => {
    expect(parseFindOutput(sample, 2).map((i) => i.path)).toEqual([
      '/srv/newer,with comma.log',
      '/srv/a.log',
    ]);
  });
});

describe('parseWinGlobOutput', () => {
  // 2023-11-14T22:13:22Z in ticks: (1700000002000 + 11644473600000) * 10000
  const ticksFor = (ms: number): string => String((ms + 11644473600000) * 10000);

  it('converts ticks to mtimeMs and sorts newest-first', () => {
    const out = [
      `${ticksFor(1700000002000)}\t\\srv\\a.log`,
      `${ticksFor(1700000009000)}\t\\srv\\b.log`,
      `${ticksFor(1700000001000)}\t\\srv\\c.log`,
      'malformed line without a tab',
      'noticks\tx',
    ].join('\r\n');
    const items = parseWinGlobOutput(out, 10);
    expect(items.map((i) => i.path)).toEqual(['\\srv\\b.log', '\\srv\\a.log', '\\srv\\c.log']);
    expect(items[0].mtimeMs).toBe(1700000009000);
    expect(items[2].mtimeMs).toBe(1700000001000);
  });

  it('caps at maxResults', () => {
    const out = `${ticksFor(1)}\ta\r\n${ticksFor(2)}\tb`;
    expect(parseWinGlobOutput(out, 1)).toEqual([{ path: 'b', mtimeMs: 2 }]);
  });
});

describe('parseGrepOutput', () => {
  it('splits on the first two colons only, so the match text may contain colons', () => {
    const items = parseGrepOutput('path:12:hello:world\n', 10);
    expect(items).toEqual([{ path: 'path', line: 12, text: 'hello:world' }]);
  });

  it('keeps a drive-quoted relative path and empty match text', () => {
    const items = parseGrepOutput('src/a.ts:1:\nsrc/b.ts:99:x:  \n', 10);
    expect(items).toEqual([
      { path: 'src/a.ts', line: 1, text: '' },
      { path: 'src/b.ts', line: 99, text: 'x:  ' },
    ]);
  });

  it('skips malformed lines (no separator, non-numeric line number)', () => {
    const items = parseGrepOutput('no separators here\nBinary file foo.bin matches\nok:7:y\n', 10);
    expect(items).toEqual([{ path: 'ok', line: 7, text: 'y' }]);
  });

  it('caps at maxResults', () => {
    const out = 'a:1:x\nb:2:y\nc:3:z\n';
    expect(parseGrepOutput(out, 2)).toHaveLength(2);
  });
});

describe('parseWinSearchOutput', () => {
  it('does not mistake the drive colon for the separator', () => {
    const items = parseWinSearchOutput('C:\\srv\\a.log:12:hello:world\r\n', 10);
    expect(items).toEqual([{ path: 'C:\\srv\\a.log', line: 12, text: 'hello:world' }]);
  });

  it('handles a UNC path and skips malformed lines', () => {
    const items = parseWinSearchOutput('\\\\box\\share\\f.txt:3:x\nnot a match line\n', 10);
    expect(items).toEqual([{ path: '\\\\box\\share\\f.txt', line: 3, text: 'x' }]);
  });

  it('caps at maxResults', () => {
    const out = 'C:\\a:1:x\r\nC:\\b:2:y\r\nC:\\c:3:z';
    expect(parseWinSearchOutput(out, 2)).toHaveLength(2);
  });
});

describe('buildGlobCommand — linux', () => {
  it('builds a GNU find with one slash between root and pattern', () => {
    const cmd = buildGlobCommand('linux', { root: '/srv/logs', pattern: '*.log', filesOnly: true, maxResults: 50 });
    expect(cmd).toBe(`find '/srv/logs' -type f -path '/srv/logs/*.log' -printf '%T@\\t%p\\0' 2>/dev/null`);
  });

  it('drops a trailing slash on the root so -path still matches', () => {
    expect(buildGlobCommand('linux', { root: '/srv/logs/', pattern: 'a/*', filesOnly: true, maxResults: 5 })).toContain("-path '/srv/logs/a/*'");
    expect(buildGlobCommand('linux', { root: '/', pattern: '*.log', filesOnly: true, maxResults: 5 })).toContain("-path '/*.log'");
  });

  it('collapses ** to * because find -path spans slashes with *', () => {
    expect(buildGlobCommand('linux', { root: '/srv', pattern: 'src/**/*.ts', filesOnly: true, maxResults: 5 })).toContain("-path '/srv/src/*.ts'");
    // '**/' must also match zero directories, which a literal '*' between slashes would not
    expect(buildGlobCommand('linux', { root: '/srv', pattern: 'a/**/b', filesOnly: true, maxResults: 5 })).toContain("-path '/srv/a/*b'");
    expect(buildGlobCommand('linux', { root: '/srv', pattern: 'a/**', filesOnly: true, maxResults: 5 })).toContain("-path '/srv/a/*'");
  });

  it('omits -type f when filesOnly is false', () => {
    expect(buildGlobCommand('linux', { root: '/srv', pattern: '*', filesOnly: false, maxResults: 5 })).not.toContain('-type f');
  });

  it('escapes a single quote in the pattern so nothing is executed', () => {
    const cmd = buildGlobCommand('linux', { root: "/tmp/it's", pattern: "a'; rm -rf /; echo '", filesOnly: true, maxResults: 5 });
    // the escape sequence itself is present...
    expect(cmd).toContain(`'\\''`);
    // ...and once the single-quoted arguments are removed, no shell metacharacter
    // survives outside them: nothing can break out of the argument.
    const outside = stripQuotedArgs(cmd);
    expect(outside).not.toContain(';');
    expect(outside).not.toContain('rm');
    expect(outside).not.toContain('$(');
    expect(outside).not.toContain('`');
    expect(outside).not.toContain("'");
    // the only thing left is the command skeleton itself
    expect(outside.replace(/\s+/g, ' ').trim()).toBe('find -type f -path -printf 2>/dev/null');
  });

  it('throws BAD_ARGS on an empty pattern', () => {
    let err: unknown;
    try {
      buildGlobCommand('linux', { root: '/srv', pattern: '', filesOnly: true, maxResults: 5 });
    } catch (e) {
      err = e;
    }
    expect((err as Error & { code: string }).code).toBe('BAD_ARGS');
    expect((err as Error).message).toMatch(/pattern/);
  });

  it('throws on a NUL and on a non-integer maxResults', () => {
    expect(() => buildGlobCommand('linux', { root: '/sr\0v', pattern: '*', filesOnly: true, maxResults: 5 })).toThrow(/NUL/);
    expect(() => buildGlobCommand('linux', { root: '/srv', pattern: '*', filesOnly: true, maxResults: 1.5 })).toThrow(/maxResults/);
    expect(() => buildGlobCommand('windows', { root: 'C:\\', pattern: 'a\0b', filesOnly: true, maxResults: 5 })).toThrow(/NUL/);
  });
});

describe('buildGlobCommand — windows', () => {
  it('runs Get-ChildItem newest-first with a remote cap and ticks output', () => {
    const ps = decodePs(buildGlobCommand('windows', { root: 'C:\\logs', pattern: '*.log', filesOnly: true, maxResults: 25 }));
    expect(ps).toContain("Get-ChildItem -LiteralPath 'C:\\logs' -Recurse -File -ErrorAction SilentlyContinue");
    // -like is applied to FullName, so the relative pattern is rooted: otherwise
    // a pattern that works on Linux would silently match nothing here.
    expect(ps).toContain("-like 'C:\\logs\\*.log'");
    expect(ps).toContain('Sort-Object LastWriteTimeUtc -Descending');
    expect(ps).toContain('Select-Object -First 25');
    expect(ps).toContain('LastWriteTimeUtc.Ticks');
  });

  it('roots a relative multi-directory pattern and reads / as \\', () => {
    const ps = decodePs(buildGlobCommand('windows', { root: 'C:\\logs\\', pattern: 'src/**/*.ts', filesOnly: true, maxResults: 5 }));
    expect(ps).toContain("-like 'C:\\logs\\src\\*.ts'");
  });

  it('doubles single quotes inside a PowerShell single-quoted string', () => {
    const ps = decodePs(buildGlobCommand('windows', { root: "C:\\it's", pattern: "a'b*.log", filesOnly: true, maxResults: 5 }));
    expect(ps).toContain("-LiteralPath 'C:\\it''s'");
    expect(ps).toContain("-like 'C:\\it''s\\a''b*.log'");
  });

  it('interpolates only a validated integer', () => {
    const ps = decodePs(buildGlobCommand('windows', { root: 'C:\\', pattern: '*', filesOnly: true, maxResults: 7 }));
    expect(ps).toContain('-First 7');
    expect(() => buildGlobCommand('windows', { root: 'C:\\', pattern: '*', filesOnly: true, maxResults: 7.5 })).toThrow(/maxResults/);
    expect(() => buildGlobCommand('windows', { root: 'C:\\', pattern: '*', filesOnly: true, maxResults: Number.MAX_SAFE_INTEGER + 2 })).toThrow(/maxResults/);
  });
});

describe('buildSearchCommand — linux', () => {
  it('builds grep -rnI with the pattern, include and root all quoted', () => {
    const cmd = buildSearchCommand('linux', { root: '/srv', pattern: "a['b", include: '*.ts', maxResults: 10 });
    expect(cmd).toBe(`grep -rnI --color=never --exclude-dir=.git -E ${"'a['\\''b'"} ${"'--include=*.ts'"} ${"'/srv'"}`);
  });

  it('omits --include when not given and never pipes to head', () => {
    const cmd = buildSearchCommand('linux', { root: '.', pattern: 'x', maxResults: 10 });
    expect(cmd).not.toContain('--include');
    expect(cmd).not.toContain('head');
    expect(cmd).not.toContain('|');
  });

  it('escapes a quote in the include glob', () => {
    const cmd = buildSearchCommand('linux', { root: '.', pattern: 'x', include: "a'; reboot; echo '", maxResults: 10 });
    expect(cmd).toContain(`'\\''`);
    const outside = stripQuotedArgs(cmd);
    expect(outside).not.toContain(';');
    expect(outside).not.toContain('reboot');
    expect(outside.replace(/\s+/g, ' ').trim()).toBe('grep -rnI --color=never --exclude-dir=.git -E');
  });
});

describe('buildSearchCommand — windows', () => {
  it('passes the pattern to Select-String and names the include filter', () => {
    const ps = decodePs(buildSearchCommand('windows', { root: 'C:\\src', pattern: 'foo|bar', include: '*.ts', maxResults: 30 }));
    expect(ps).toContain("-LiteralPath 'C:\\src' -Recurse -File");
    expect(ps).toContain("$_.Name -like '*.ts'");
    expect(ps).toContain("-Pattern 'foo|bar'");
    expect(ps).toContain('Select-String');
    expect(ps).toContain('Select-Object -First 30');
    expect(ps).toContain('$_.Path, $_.LineNumber, $_.Line');
  });

  it('uses a $true filter when there is no include', () => {
    const ps = decodePs(buildSearchCommand('windows', { root: 'C:\\src', pattern: 'x', maxResults: 3 }));
    expect(ps).toContain('Where-Object { $true }');
    expect(ps).not.toContain('-like');
  });

  it('throws on an empty pattern', () => {
    expect(() => buildSearchCommand('windows', { root: 'C:\\', pattern: '', maxResults: 5 })).toThrow(/pattern/);
    expect(() => buildSearchCommand('linux', { root: '/', pattern: '   ', maxResults: 5 })).not.toThrow();
  });
});

describe('the safety gate accepts every generated command', () => {
  // The builders emit real command lines, so they must survive the same audited
  // gate exec does (including its -EncodedCommand decoding). A refusal here would
  // be a capability regression for the whole tool, so it is asserted, not assumed.
  const guard = (os: 'linux' | 'windows') => ({ refuseSelfSevering: true, transport: 'ssh' as const, platform: os });
  const cases: Array<{ os: 'linux' | 'windows'; root: string; pattern: string; include?: string }> = [
    { os: 'linux', root: '/srv/logs', pattern: '*.log' },
    { os: 'linux', root: '/', pattern: "a'; rm -rf /; echo '" },
    { os: 'windows', root: 'C:\\logs', pattern: '*.log' },
    { os: 'windows', root: 'C:\\', pattern: 'src/**/*.ts', include: '*.ts' },
  ];
  for (const c of cases) {
    it(`file_glob ${c.os}: ${c.pattern}`, () => {
      expect(checkCommand(buildGlobCommand(c.os, { root: c.root, pattern: c.pattern, filesOnly: true, maxResults: 50 }), guard(c.os))).toEqual({ allowed: true });
    });
    it(`file_search ${c.os}: ${c.pattern}`, () => {
      expect(checkCommand(buildSearchCommand(c.os, { root: c.root, pattern: c.pattern, include: c.include, maxResults: 50 }), guard(c.os))).toEqual({ allowed: true });
    });
  }

  // A pattern whose TEXT names a transport service (searching a log for
  // "systemctl stop sshd" is a real thing to do) is quoted by the builder, so the
  // shell sees one literal argument. The gate screens a quote-stripped view, so on
  // Linux such a pattern is refused today. That refusal is honest and recoverable
  // (TRANSPORT_SEVERED_RISK + the override hint, surfaced by runChecked) — what
  // must never happen is the command running anyway, or a silent empty result.
  const mentionsService: Array<{ os: 'linux' | 'windows'; root: string; pattern: string }> = [
    { os: 'linux', root: '/var/log', pattern: 'systemctl stop sshd' },
    { os: 'windows', root: 'C:\\logs', pattern: 'Stop-Service sshd' },
  ];
  for (const c of mentionsService) {
    it(`file_search ${c.os}: naming ${c.pattern} passes or refuses, never silently`, () => {
      const v = checkCommand(buildSearchCommand(c.os, { root: c.root, pattern: c.pattern, maxResults: 50 }), guard(c.os));
      expect(v.allowed === true || v.code === 'TRANSPORT_SEVERED_RISK').toBe(true);
      if (!v.allowed) expect(v.reason).toMatch(/override:"sever-transport"/);
    });
  }
});
