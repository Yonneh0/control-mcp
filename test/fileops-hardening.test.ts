import { describe, expect, it } from 'vitest';
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

// Hardening suite for src/transports/fileops.ts: every caller-supplied string that
// reaches a remote shell, and every byte of the output that gets parsed back.
//
// The existing test/fileops.test.ts covers the happy paths and the shq/psq basics.
// This file attacks the seams: option injection (a value that begins with '-'),
// wildcard characters that are literal in a path but special to the matcher
// (find -path / PowerShell -like), colon-ambiguous output lines, silent-empty
// failure modes, and lax numeric coercion in the parsers.
//
// Tests marked BUG-n FAIL against the pre-hardening source and pass after the fix;
// the rest pin behaviour that was already safe so a later edit cannot regress it.

// ------------------------------------------------------------------- helpers --

// The Windows path is only ever handed to cmd.exe as a base64 -EncodedCommand
// payload, so the OUTER command line must contain no user bytes at all. Matching
// the exact wrapper shape is therefore itself an injection assertion: any user
// text that leaked out of the payload would fail this regex.
function decodePs(cmd: string): string {
  const m = /^powershell -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)$/.exec(cmd);
  if (!m) throw new Error(`outer command line is not a clean -EncodedCommand wrapper: ${cmd}`);
  return Buffer.from(m[1], 'base64').toString('utf16le');
}

// Re-tokenize a POSIX command line the way /bin/sh would (single quotes, double
// quotes, backslash) and return argv. If a builder ever leaves a caller string
// outside a quoted argument, this reconstructs MORE tokens than expected — that
// is the whole point: argv is what the program actually receives.
function posixArgv(cmd: string): string[] {
  const args: string[] = [];
  let cur = '';
  let started = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === ' ' || c === '\t' || c === '\n') {
      if (started) args.push(cur);
      cur = '';
      started = false;
      continue;
    }
    if (c === "'") {
      started = true;
      i++;
      while (i < cmd.length && cmd[i] !== "'") {
        cur += cmd[i];
        i++;
      }
      continue;
    }
    if (c === '"') {
      started = true;
      i++;
      while (i < cmd.length && cmd[i] !== '"') {
        if (cmd[i] === '\\') {
          cur += cmd[i + 1] ?? '';
          i++;
        } else cur += cmd[i];
        i++;
      }
      continue;
    }
    if (c === '\\') {
      started = true;
      cur += cmd[i + 1] ?? '';
      i++;
      continue;
    }
    started = true;
    cur += c;
  }
  if (started) args.push(cur);
  return args;
}

const FIND_REDIRECT = ' 2>/dev/null';
function findArgv(cmd: string): string[] {
  expect(cmd.endsWith(FIND_REDIRECT)).toBe(true); // find's noise stays suppressed
  return posixArgv(cmd.slice(0, -FIND_REDIRECT.length));
}

// PowerShell single-quoted literal (the builder's psq, re-derived here as the spec).
const psq = (v: string): string => `'${v.split("'").join("''")}'`;
// find -path: '**' collapses to '*' because '*' already spans '/'.
const collapseLinux = (p: string): string => p.replace(/\*\*\//g, '*').replace(/\*+/g, '*');
// -like: the relative pattern is rooted, '/' is read as '\'.
const collapseWin = (p: string): string => p.replace(/\*\*\//g, '*').replace(/\//g, '\\').replace(/\*+/g, '*');
// A starting point that begins with '-' must be given as './x' (find has no '--').
const guardedRoot = (root: string): string => (root.startsWith('-') ? `./${root}` : root);

// Adversarial corpus. Every entry is legal as a path/pattern fragment on a real
// filesystem (or a legitimate thing to search for) and each one stresses a
// different quoting, escaping or option-parsing hazard.
const NASTY: string[] = [
  'plain',
  'with space',
  'double"quote',
  "single'quote",
  'back\\slash',
  'dollar$HOME',
  'back`tick',
  'sub$(id)shell',
  'glob*?[char]',
  'regex(a|b){1,2}+^$.',
  'semi;colon',
  'amp&&and',
  'pipe||or|',
  'newline\nhere',
  'tab\there',
  '-rf',
  '-vn',
  '-e',
  '-',
  '--',
  '--include=*.env',
  '-delete',
  '-P',
  '..',
  '../..',
  '.',
  './..',
  '/absolute/path',
  'trailing/slash/',
  'üñíçode',
  'emoji🚩flag',
  'c:\\tmp\\win',
  '%VAR%expansion',
  "'\\''",
  '$(reboot)\n`reboot`',
  'a'.repeat(300),
];

const linuxGlob = (root: string, pattern: string, maxResults = 50): string =>
  buildGlobCommand('linux', { root, pattern, filesOnly: true, maxResults });
const linuxSearch = (root: string, pattern: string, include?: string, maxResults = 50): string =>
  buildSearchCommand('linux', { root, pattern, include, maxResults });
const winGlob = (root: string, pattern: string, maxResults = 50): string =>
  decodePs(buildGlobCommand('windows', { root, pattern, filesOnly: true, maxResults }));
const winSearch = (root: string, pattern: string, include?: string, maxResults = 50): string =>
  decodePs(buildSearchCommand('windows', { root, pattern, include, maxResults }));

// ------------------------------------------------- shq: one value, one argv --

describe('shq: the value survives as exactly one argv element', () => {
  for (const v of NASTY) {
    it(`round-trips ${JSON.stringify(v.slice(0, 24))}`, () => {
      expect(posixArgv(shq(v))).toEqual([v]);
    });
  }

  it('never emits an unquoted shell metacharacter', () => {
    // shq only ever emits: a quoted run, and the '\'' splice that closes, escapes
    // and reopens a quote. Remove the splices, then the quoted runs: nothing may be
    // left over — that is the statement "the value never appears unquoted".
    const SPLICE = String.fromCharCode(39, 92, 39, 39); // ' \ ' '
    for (const v of NASTY) {
      const withoutSplices = shq(v).split(SPLICE).join('');
      expect(withoutSplices.replace(/'[^']*'/g, '')).toBe('');
    }
  });
});

// ------------------------------------------ buildGlobCommand — linux (find) --

describe('buildGlobCommand linux: argv reconstruction', () => {
  it('pins the ordinary command line byte for byte', () => {
    expect(linuxGlob('/srv/logs', '*.log')).toBe(
      `find '/srv/logs' -type f -path '/srv/logs/*.log' -printf '%T@\\t%p\\0' 2>/dev/null`,
    );
  });

  it('delivers root and pattern as single intact argv elements', () => {
    for (const root of NASTY) {
      for (const pattern of ['*.log', "a'; reboot; echo '", '*?[x]', '..']) {
        const argv = findArgv(linuxGlob(root, pattern));
        const base = guardedRoot(root).replace(/\/+$/, '');
        expect(argv).toEqual([
          'find',
          guardedRoot(root),
          '-type',
          'f',
          '-path',
          `${base}/${collapseLinux(pattern)}`,
          '-printf',
          '%T@\\t%p\\0',
        ]);
      }
    }
  });

  it('BUG-1: a root that starts with "-" is passed as ./root, never as a find option', () => {
    // Measured with GNU find (findutils):
    //   find '-data'    -type f -path '-data/*'  -> "unknown predicate `-data'", exit 1
    //   find '-printf'  -type f -path ...        -> "paths must precede expression: `f'", exit 1
    //   find './-data'  -type f -path './-data/*' -> lists ./-data/c.log, exit 0
    // A valid option spelling would be worse than the error: '-P' is consumed as an
    // option and find silently searches '.' — a different tree from the one asked for.
    for (const root of ['-rf', '-vn', '-delete', '-P', '--', '-', '--include=*.env']) {
      const argv = findArgv(linuxGlob(root, '*.log'));
      expect(argv[1]).toBe(`./${root}`);
      // and the -path pattern must still match what find prints for that root
      expect(argv[5]).toBe(`./${root}/*.log`);
    }
    // A leading ./ is added ONLY when it is needed, so ordinary roots are untouched.
    for (const root of ['/srv', '.', '..', './x', 'srv', 'srv/']) {
      expect(findArgv(linuxGlob(root, '*.log'))[1]).toBe(root);
    }
  });

  it('collapses ** to * and joins root and pattern with exactly one slash', () => {
    expect(findArgv(linuxGlob('/srv', 'src/**/*.ts'))[5]).toBe('/srv/src/*.ts');
    expect(findArgv(linuxGlob('/srv/', 'a/**/b'))[5]).toBe('/srv/a/*b');
    expect(findArgv(linuxGlob('/', '*.log'))[5]).toBe('/*.log');
  });

  it('keeps -type f only when filesOnly is set', () => {
    expect(findArgv(buildGlobCommand('linux', { root: '/srv', pattern: '*', filesOnly: false, maxResults: 5 }))).toEqual([
      'find', '/srv', '-path', '/srv/*', '-printf', '%T@\\t%p\\0',
    ]);
  });

  it('refuses NUL, an empty pattern and a non-integer maxResults', () => {
    expect(() => linuxGlob('/sr\0v', '*')).toThrow(/NUL/);
    expect(() => linuxGlob('/srv', 'a\0b')).toThrow(/NUL/);
    expect(() => linuxGlob('/srv', '')).toThrow(/pattern/);
    expect(() => linuxGlob('/srv', '*', 0)).toThrow(/maxResults/);
    expect(() => linuxGlob('/srv', '*', Number.NaN)).toThrow(/maxResults/);
    expect(() => linuxGlob('/srv', '*', 2 ** 53)).toThrow(/maxResults/);
  });
});

// ---------------------------------------- buildSearchCommand — linux (grep) --

describe('buildSearchCommand linux: argv reconstruction', () => {
  it('pins the ordinary command line byte for byte', () => {
    expect(linuxSearch('/srv', 'x')).toBe(`grep -rnI --color=never --exclude-dir=.git -E 'x' '/srv'`);
    expect(linuxSearch('/srv', 'x', '*.ts')).toBe(`grep -rnI --color=never --exclude-dir=.git -E 'x' '--include=*.ts' '/srv'`);
  });

  it('BUG-2: a pattern that starts with "-" is bound with -e, so grep cannot read it as options', () => {
    // Measured with GNU grep: `grep -rnI --color=never --exclude-dir=.git -E '-vn' ./a.log`
    // printed "a.log:1:alpha" and "-data/c.log:1:gamma" for a tree whose only file
    // content is "alpha" — '-vn' was parsed as -v (invert) + -n, the file argument
    // became the pattern, and -r searched the whole cwd. The tool would report
    // matches that were never asked for, in files that were never named.
    // ('-F<file>' is worse: it reads patterns from a caller-chosen file.)
    for (const pattern of ['-vn', '-rf', '-Fpats', '--', '-', '--include=*', '-i']) {
      const argv = posixArgv(linuxSearch('/srv', pattern));
      const i = argv.indexOf('-E');
      expect(argv[i + 1]).toBe('-e');
      expect(argv[i + 2]).toBe(pattern);
      // and nothing after the operand may be re-read as an option of its own
      expect(argv.slice(i + 3)).toEqual(['/srv']);
    }
    // A pattern that does not start with '-' keeps the plain positional form.
    expect(posixArgv(linuxSearch('/srv', 'x'))).toEqual([
      'grep', '-rnI', '--color=never', '--exclude-dir=.git', '-E', 'x', '/srv',
    ]);
  });

  it('BUG-3: a root that starts with "-" is separated by --, so it is never an option', () => {
    for (const root of ['-rf', '-data', '--help', '-']) {
      const argv = posixArgv(linuxSearch(root, 'x'));
      expect(argv[argv.length - 1]).toBe(root);
      expect(argv[argv.length - 2]).toBe('--');
    }
    expect(posixArgv(linuxSearch('.', 'x'))).toEqual(['grep', '-rnI', '--color=never', '--exclude-dir=.git', '-E', 'x', '.']);
  });

  it('delivers pattern, include and root as single intact argv elements', () => {
    for (const pattern of NASTY) {
      for (const include of [undefined, '*.ts', "a'; reboot; echo '", '[]', '..']) {
        const argv = posixArgv(linuxSearch('/srv/logs', pattern, include));
        // exact argv: the caller's three strings each occupy exactly one slot, and
        // there is no slot left over for a metacharacter to have created.
        const want = ['grep', '-rnI', '--color=never', '--exclude-dir=.git', '-E'];
        if (pattern.startsWith('-')) want.push('-e');
        want.push(pattern);
        if (include !== undefined) want.push(`--include=${include}`);
        want.push('/srv/logs');
        expect(argv).toEqual(want);
      }
    }
  });

  it('BUG-6: an empty include is refused instead of silently matching nothing', () => {
    // Measured: grep -rnI -E hello '--include=' <dir> exits 1 with NO output while
    // the same search with '--include=*.txt' (or no filter) finds the file. On
    // Windows the filter becomes `$_.Name -like ''`, which is never true. An empty
    // string must not be silently reinterpreted as "every file".
    expect(() => linuxSearch('/srv', 'x', '')).toThrow(/include/);
    expect(() => winSearch('C:\\srv', 'x', '')).toThrow(/include/);
    let err: unknown;
    try {
      linuxSearch('/srv', 'x', '');
    } catch (e) {
      err = e;
    }
    expect((err as Error & { code: string }).code).toBe('BAD_ARGS');
    expect((err as Error).message).toMatch(/empty/);
    expect((err as Error & { hint?: string }).hint).toMatch(/omit include/);
    // an explicit '*' is the documented way to say "every file" and stays legal
    expect(() => linuxSearch('/srv', 'x', '*')).not.toThrow();
  });

  it('never pipes to head and keeps grep exit codes meaningful', () => {
    const cmd = linuxSearch('.', 'x', '*.ts');
    expect(cmd).not.toContain('head');
    expect(cmd).not.toContain('|');
  });

  it('refuses NUL in root, pattern and include', () => {
    expect(() => linuxSearch('/srv', 'a\0b')).toThrow(/NUL/);
    expect(() => linuxSearch('/sr\0v', 'x')).toThrow(/NUL/);
    expect(() => linuxSearch('/srv', 'x', 'a\0b')).toThrow(/NUL/);
  });
});

// ---------------------------------- buildGlobCommand — windows (Get-ChildItem) --

describe('buildGlobCommand windows: Resolve-Path, $rl escaping and the outer wrapper', () => {
  it('pins the ordinary script', () => {
    const ps = winGlob('C:\\logs', '*.log', 25);
    expect(ps).toContain("(Resolve-Path -LiteralPath 'C:\\logs' -ErrorAction SilentlyContinue).ProviderPath");
    expect(ps).toContain("Get-ChildItem -LiteralPath $r -Recurse -File -ErrorAction SilentlyContinue");
    expect(ps).toContain("$_.FullName -like ($rl + '\\' + '*.log')");
    expect(ps).toContain('Sort-Object LastWriteTimeUtc -Descending');
    expect(ps).toContain('Select-Object -First 25');
    expect(ps).toContain('LastWriteTimeUtc.Ticks');
  });

  it('never lets a single quote break out of a PowerShell literal', () => {
    const ps = winGlob("C:\\it's", "a'b*.log");
    expect(ps).toContain("(Resolve-Path -LiteralPath 'C:\\it''s' -ErrorAction SilentlyContinue).ProviderPath");
    expect(ps).toContain("$_.FullName -like ($rl + '\\' + 'a''b*.log')");
  });

  it('BUG-4: wildcard characters in the ROOT are escaped for -like, in-script', () => {
    // The root is a literal path but -like reads [ ] * ? as wildcards, so a real
    // directory named '[2024]' would otherwise act as a character class and report
    // "no matches" (measured live on n100: the unescaped root returned 0 for a real
    // '[2024]\' tree that exists). The escape runs in PowerShell on the RESOLVED
    // absolute path (so relative roots work too): a single -replace wraps each of
    // ] [ * ? in brackets (about_Wildcards). The capture group is essential — without
    // the parens '$1' is inserted literally, exactly the bug a live run caught.
    const ps = winGlob('C:\\logs[2024]', '*.log');
    expect(ps).toContain("$rl = $r -replace '([][*?])', '[$1]'");
    expect(ps).toContain("$_.FullName -like ($rl + '\\' + '*.log')");
    // Pin the escaping TRANSFORM itself (a mirror of the PS regex + replacement) so a
    // missing capture group — which yields the literal '[$1]' — fails here, not live.
    const psEscape = (v: string): string => v.replace(/([[\]*?])/g, '[$1]');
    expect(psEscape('C:\\logs[2024]')).toBe('C:\\logs[[]2024[]]');
    expect(psEscape('C:\\a*b')).toBe('C:\\a[*]b');
    expect(psEscape('C:\\a?b')).toBe('C:\\a[?]b');
    expect(psEscape('C:\\x[y]z*w?v')).toBe('C:\\x[[]y[]]z[*]w[?]v');
    expect(psEscape('C:\\plain')).toBe('C:\\plain');
  });

  it('the root wildcard-escape is one regex pass, not naive chained replaces', () => {
    // A naive sequence of String.replace calls would turn 'C:\[a]' into
    // 'C:\[[]]]a[]]'; the single -replace pass wraps each char once.
    expect(winGlob('C:\\[a]', '*.log')).toContain("$rl = $r -replace '([][*?])', '[$1]'");
    const psEscape = (v: string): string => v.replace(/([[\]*?])/g, '[$1]');
    expect(psEscape('C:\\[a]')).toBe('C:\\[[]a[]]');
  });

  it('keeps the pattern wildcards it is supposed to have', () => {
    expect(winGlob('C:\\logs', 'src/**/*.ts')).toContain("$_.FullName -like ($rl + '\\' + 'src\\*.ts')");
    expect(winGlob('C:\\logs', 'a/**')).toContain("$_.FullName -like ($rl + '\\' + 'a\\*')");
    expect(winGlob('C:\\logs', 'q?.log')).toContain("$_.FullName -like ($rl + '\\' + 'q?.log')");
  });

  it('BUG-5: a root that does not exist is an error, not a silent zero', () => {
    // Get-ChildItem on a missing root under SilentlyContinue exits 1 with empty
    // stdout AND stderr; file_search reads exit 1 as grep's "no matches" and
    // file_glob had no evidence. Resolve-Path doubles as the existence check: no
    // match -> Write-Error + exit 2, which both callers already map to REMOTE_ERROR.
    const ps = winGlob('C:\\logs', '*.log');
    expect(ps).toContain("Resolve-Path -LiteralPath 'C:\\logs'");
    expect(ps).toContain('exit 2');
    expect(winGlob("C:\\it's", '*')).toContain("Resolve-Path -LiteralPath 'C:\\it''s'");
  });

  it('interpolates only a validated integer and nothing else into the outer command', () => {
    expect(winGlob('C:\\', '*', 7)).toContain('-First 7');
    expect(() => buildGlobCommand('windows', { root: 'C:\\', pattern: '*', filesOnly: true, maxResults: 7.5 })).toThrow(/maxResults/);
    expect(() => buildGlobCommand('windows', { root: 'C:\\', pattern: '*', filesOnly: true, maxResults: Number.MAX_SAFE_INTEGER + 2 })).toThrow(/maxResults/);
    // the outer cmd.exe line is a fixed skeleton + base64, whatever the inputs are
    for (const root of NASTY) {
      for (const pattern of ['*', "'; Stop-Service sshd; echo '"]) {
        expect(() => decodePs(buildGlobCommand('windows', { root, pattern, filesOnly: true, maxResults: 5 }))).not.toThrow();
      }
    }
  });

  it('resolves the root and quotes the pattern for every adversarial input', () => {
    for (const root of NASTY) {
      for (const pattern of ['*.log', "a'b", 'x;y', '..']) {
        const ps = winGlob(root, pattern);
        expect(ps).toContain(`Resolve-Path -LiteralPath ${psq(root)}`);
        expect(ps).toContain(`-like ($rl + '\\' + ${psq(collapseWin(pattern))})`);
      }
    }
  });
});

// --------------------------------------- buildSearchCommand — windows (Select-String) --

describe('buildSearchCommand windows: Select-String quoting', () => {
  it('pins the ordinary script', () => {
    const ps = winSearch('C:\\src', 'foo|bar', '*.ts', 30);
    expect(ps).toContain("-LiteralPath 'C:\\src' -Recurse -File");
    expect(ps).toContain("$_.Name -like '*.ts'");
    expect(ps).toContain("-Pattern 'foo|bar'");
    expect(ps).toContain('Select-Object -First 30');
    expect(ps).toContain('$_.Path, $_.LineNumber, $_.Line');
  });

  it('uses $true only when there is no include and doubles quotes in both', () => {
    expect(winSearch('C:\\src', 'x')).toContain('Where-Object { $true }');
    expect(winSearch("C:\\sr'c", "fo'o", "in'*.ts")).toContain("-Pattern 'fo''o'");
    expect(winSearch("C:\\sr'c", "fo'o", "in'*.ts")).toContain("$_.Name -like 'in''*.ts'");
  });

  it('keeps the pattern a .NET regex (same dialect choice as the description), quoted', () => {
    for (const pattern of NASTY) {
      expect(winSearch('C:\\src', pattern)).toContain(`-Pattern ${psq(pattern)}`);
    }
  });

  it('BUG-5: guards the root the same way as the glob builder', () => {
    const ps = winSearch('C:\\src', 'x');
    expect(ps).toContain("Test-Path -LiteralPath 'C:\\src'");
    expect(ps).toContain('exit 2');
  });
});

// ------------------------------------------------------------- the gate ------

describe('the audited gate still sees the hardened commands', () => {
  const guard = (os: 'linux' | 'windows') => ({ refuseSelfSevering: true, transport: 'ssh' as const, platform: os });

  it('accepts glob/search commands built from quoting hazards', () => {
    const tricky: Array<[string, string]> = [
      ['/srv/logs', '*.log'],
      ['/srv/a b', "it's *"],
      ['C:\\logs[2024]', 'src/**/*.ts'],
      ['-data', '*.log'],
    ];
    for (const [root, pattern] of tricky) {
      const os = root.startsWith('C:') ? 'windows' : 'linux';
      expect(checkCommand(globCmd(os, root, pattern), guard(os))).toEqual({ allowed: true });
    }
  });

  it('a pattern naming a transport service is refused or quoted, never half-run', () => {
    for (const os of ['linux', 'windows'] as const) {
      const v = checkCommand(
        buildSearchCommand(os, { root: os === 'windows' ? 'C:\\logs' : '/var/log', pattern: os === 'windows' ? 'Stop-Service sshd' : 'systemctl stop sshd', maxResults: 50 }),
        guard(os),
      );
      expect(v.allowed === true || v.code === 'TRANSPORT_SEVERED_RISK').toBe(true);
      if (!v.allowed) expect(v.reason).toMatch(/override:"sever-transport"/);
    }
  });

  it('never produces a command the gate cannot decode', () => {
    for (const root of NASTY) {
      for (const pattern of ['*', "'; rm -rf /; echo '"]) {
        expect(checkCommand(buildGlobCommand('windows', { root, pattern, filesOnly: true, maxResults: 5 }), guard('windows')).allowed).toBe(true);
        expect(checkCommand(buildSearchCommand('windows', { root, pattern, maxResults: 5 }), guard('windows')).allowed).toBe(true);
      }
    }
  });
});

function globCmd(os: 'linux' | 'windows', root: string, pattern: string): string {
  return os === 'windows'
    ? buildGlobCommand('windows', { root, pattern, filesOnly: true, maxResults: 50 })
    : buildGlobCommand('linux', { root, pattern, filesOnly: true, maxResults: 50 });
}

// ------------------------------------------------------------ parseFindOutput --

describe('parseFindOutput: NUL-delimited records', () => {
  it('parses, sorts newest-first and caps', () => {
    // NUL is built by concatenation: '\0' immediately followed by a digit would be
    // read as an octal escape by the JS parser, not as the record separator.
    const NUL = String.fromCharCode(0);
    const out = '1700000002.0000000000\t/srv/a.log' + NUL + '1700000009.5000000000\t/srv/b.log' + NUL;
    expect(parseFindOutput(out, 10)).toEqual([
      { path: '/srv/b.log', mtimeMs: 1700000009500 },
      { path: '/srv/a.log', mtimeMs: 1700000002000 },
    ]);
    expect(parseFindOutput(out, 1)).toEqual([{ path: '/srv/b.log', mtimeMs: 1700000009500 }]);
  });

  it('keeps a path containing a newline, a tab, a colon or spaces intact', () => {
    const out =
      '1700000001.0000000000\t/srv/new\nline.log\0' +
      '1700000002.0000000000\t/srv/tab\there.log\0' +
      '1700000003.0000000000\t/srv/a:b c.log\0';
    expect(parseFindOutput(out, 10).map((i) => i.path)).toEqual(['/srv/a:b c.log', '/srv/tab\there.log', '/srv/new\nline.log']);
  });

  it('handles a comma decimal separator and a pre-1970 (negative) time', () => {
    expect(parseFindOutput('1700000009,5\t,x\0', 10)[0].mtimeMs).toBe(1700000009500);
    expect(parseFindOutput('-100.5\t/pre-epoch\0', 10)).toEqual([{ path: '/pre-epoch', mtimeMs: -100500 }]);
  });

  it('skips what it cannot parse instead of guessing', () => {
    const out =
      'garbage-without-tab\0' +
      '\t/no/time.log\0' +
      'not-a-time\t/bad.log\0' +
      '1700000001.0\t\0' +
      '99999999999999999999\t/overflow.log\0' +
      '1700000002.0\t/ok.log\0';
    expect(parseFindOutput(out, 10)).toEqual([{ path: '/ok.log', mtimeMs: 1700000002000 }]);
  });

  it('is empty for empty output and survives the MAX_SAFE_INTEGER cap the registry passes', () => {
    expect(parseFindOutput('', 10)).toEqual([]);
    expect(parseFindOutput('\0', 10)).toEqual([]);
    expect(parseFindOutput('1700000002.0\t/ok.log\0', Number.MAX_SAFE_INTEGER)).toHaveLength(1);
  });
});

// ------------------------------------------------------- parseWinGlobOutput --

describe('parseWinGlobOutput: ticks records', () => {
  const ticksFor = (ms: number): string => String((ms + 62135596800000) * 10000);

  it('converts ticks to ms, sorts newest-first and caps', () => {
    const out = `${ticksFor(1700000002000)}\tC:\\a\r\n${ticksFor(1700000009000)}\tC:\\b`;
    expect(parseWinGlobOutput(out, 10)).toEqual([
      { path: 'C:\\b', mtimeMs: 1700000009000 },
      { path: 'C:\\a', mtimeMs: 1700000002000 },
    ]);
    expect(parseWinGlobOutput(out, 1)).toEqual([{ path: 'C:\\b', mtimeMs: 1700000009000 }]);
  });

  it('accepts the 19-digit ticks a real DateTime produces (no false MAX_SAFE_INTEGER drop)', () => {
    const items = parseWinGlobOutput('638355968020000000\tC:\\x.log', 10);
    expect(items).toHaveLength(1);
    expect(new Date(items[0].mtimeMs).toISOString()).toBe('2023-11-14T22:13:22.000Z');
  });

  it('BUG-8: only a bare integer is a ticks field; nothing else invents a timestamp', () => {
    // Number() coerces far more than PowerShell ever emits: a whitespace-only field
    // becomes 0 (i.e. 1970-01-01) and '0x1F' becomes 31, so a truncated or
    // interleaved stream produced rows with fabricated mtimes.
    const out = [' \tC:\\bogus.log', '0x1F\tC:\\hex.log', '1e9\tC:\\exp.log', '+123\tC:\\plus.log', '-5\tC:\\minus.log', 'Infinity\tC:\\inf.log', 'NaN\tC:\\nan.log'].join('\r\n');
    // A negative tick value is not something DateTime.Ticks can be; whitespace,
    // hex, exponent, sign, Infinity and NaN must all be skipped, never coerced.
    expect(parseWinGlobOutput(out, 10)).toEqual([]);
    expect(parseWinGlobOutput(' \tC:\\bogus.log', 10)).toEqual([]);
  });

  it('skips malformed lines and keeps paths with spaces/commas/unicode', () => {
    const out = ['malformed line', 'noticks\tx', `${ticksFor(5)}\tC:\\a b,c é.log`].join('\r\n');
    expect(parseWinGlobOutput(out, 10)).toEqual([{ path: 'C:\\a b,c é.log', mtimeMs: 5 }]);
  });

  it('is empty for empty output', () => {
    expect(parseWinGlobOutput('', 10)).toEqual([]);
  });
});

// ----------------------------------------------------------- parseGrepOutput --

describe('parseGrepOutput: path:line:text', () => {
  it('splits on the first two colons only, so the match text may contain colons', () => {
    expect(parseGrepOutput('path:12:hello:world\n', 10)).toEqual([{ path: 'path', line: 12, text: 'hello:world' }]);
  });

  it('BUG-7: a file name that itself contains a colon is still a match', () => {
    // POSIX allows ':' in a file name, so `dir/a:b.log` is a real path and grep
    // prints 'dir/a:b.log:12:x'. Splitting on the first two colons read the line
    // number as 'ird.txt'... i.e. it dropped the row, and the tool reported
    // "0 match(es)" for a search that did find something. The separator is
    // ':<digits>:', exactly as parseWinSearchOutput already treats it.
    expect(parseGrepOutput('dir/a:b.log:12:x\n', 10)).toEqual([{ path: 'dir/a:b.log', line: 12, text: 'x' }]);
    expect(parseGrepOutput('/srv/we:ird/file:name.txt:7:body:tail\n', 10)).toEqual([
      { path: '/srv/we:ird/file:name.txt', line: 7, text: 'body:tail' },
    ]);
    // and the ordinary case still wins first, so nothing is re-associated later
    expect(parseGrepOutput('a:1:x\nb:2:y\n', 10)).toEqual([
      { path: 'a', line: 1, text: 'x' },
      { path: 'b', line: 2, text: 'y' },
    ]);
  });

  it('skips lines that carry no :<digits>: separator (grep messages)', () => {
    const out = 'no separators here\nBinary file foo.bin matches\nok:7:y\n:5:x\nabc:def\n';
    expect(parseGrepOutput(out, 10)).toEqual([{ path: 'ok', line: 7, text: 'y' }]);
  });

  it('keeps an empty match text and a trailing CR from a CRLF file', () => {
    expect(parseGrepOutput('src/a.ts:1:\r\nsrc/b.ts:99:x:  \n', 10)).toEqual([
      { path: 'src/a.ts', line: 1, text: '' },
      { path: 'src/b.ts', line: 99, text: 'x:  ' },
    ]);
  });

  it('is empty for empty output and caps at maxResults', () => {
    expect(parseGrepOutput('', 10)).toEqual([]);
    expect(parseGrepOutput('\n\n\n', 10)).toEqual([]);
    expect(parseGrepOutput('a:1:x\nb:2:y\nc:3:z\n', 2)).toHaveLength(2);
  });

  it('never invents a path: a leading colon is not a match', () => {
    expect(parseGrepOutput(':1:x\n', 10)).toEqual([]);
  });
});

// ----------------------------------------------------- parseWinSearchOutput --

describe('parseWinSearchOutput: drive-letter and stream-name colons', () => {
  it('does not mistake the drive colon for the separator', () => {
    expect(parseWinSearchOutput('C:\\srv\\a.log:12:hello:world\r\n', 10)).toEqual([
      { path: 'C:\\srv\\a.log', line: 12, text: 'hello:world' },
    ]);
    expect(parseWinSearchOutput('c:\\a.txt:1:x', 10)).toEqual([{ path: 'c:\\a.txt', line: 1, text: 'x' }]);
  });

  it('handles a UNC path and skips malformed lines', () => {
    expect(parseWinSearchOutput('\\\\box\\share\\f.txt:3:x\nnot a match line\n', 10)).toEqual([
      { path: '\\\\box\\share\\f.txt', line: 3, text: 'x' },
    ]);
  });

  it('takes the FIRST numeric separator, so text that starts with digits survives', () => {
    expect(parseWinSearchOutput('C:\\a:1:99:also\n', 10)).toEqual([{ path: 'C:\\a', line: 1, text: '99:also' }]);
  });

  it('reads an alternate-data-stream path (documented as not handled)', () => {
    // Measured behaviour, pinned so a change is deliberate: the ':stream:' form is
    // skipped because it carries no digits, and the real separator after it wins.
    expect(parseWinSearchOutput('C:\\f.txt:stream:4:x\n', 10)).toEqual([{ path: 'C:\\f.txt:stream', line: 4, text: 'x' }]);
  });

  it('keeps empty match text and caps at maxResults', () => {
    expect(parseWinSearchOutput('C:\\a:1:\r\n', 10)).toEqual([{ path: 'C:\\a', line: 1, text: '' }]);
    expect(parseWinSearchOutput('C:\\a:1:x\r\nC:\\b:2:y\r\nC:\\c:3:z', 2)).toHaveLength(2);
    expect(parseWinSearchOutput('', 10)).toEqual([]);
  });
});

// ---------------------------------------------------------------- sliceLines --

describe('sliceLines: window arithmetic', () => {
  const text = 'l1\nl2\nl3\nl4\nl5';

  it('is 1-based and reports what is left', () => {
    const r = sliceLines(text, 3, 2);
    expect(r).toEqual({ shown: ['l3', 'l4'], firstLine: 3, lastLine: 4, totalLinesSeen: 5, truncatedByLimit: true });
    expect(sliceLines(text, 1, 2000).truncatedByLimit).toBe(false);
  });

  it('clamps offset 0, negative and NaN to line 1', () => {
    for (const off of [0, -1, -1e9, Number.NaN]) {
      const r = sliceLines(text, off, 2);
      expect(r.firstLine).toBe(1);
      expect(r.shown).toEqual(['l1', 'l2']);
    }
  });

  it('clamps limit 0, negative and NaN to 1 line', () => {
    for (const lim of [0, -1, Number.NaN]) {
      expect(sliceLines(text, 1, lim).shown).toEqual(['l1']);
    }
  });

  it('truncates a fractional offset/limit instead of throwing', () => {
    expect(sliceLines(text, 2.9, 2.9).shown).toEqual(['l2', 'l3']);
  });

  it('offset past EOF is an empty window with lastLine one before firstLine', () => {
    for (const off of [6, 99, Number.MAX_SAFE_INTEGER]) {
      const r = sliceLines(text, off, 10);
      expect(r.shown).toEqual([]);
      expect(r.totalLinesSeen).toBe(5);
      expect(r.truncatedByLimit).toBe(false);
      expect(r.lastLine).toBe(r.firstLine - 1);
    }
  });

  it('offset exactly at the last line returns that line', () => {
    expect(sliceLines(text, 5, 10).shown).toEqual(['l5']);
  });

  it('treats a trailing newline as a final empty line and strips CR from CRLF', () => {
    expect(sliceLines('a\n', 1, 10).totalLinesSeen).toBe(2);
    expect(sliceLines('', 1, 10).totalLinesSeen).toBe(1);
    expect(sliceLines('\n', 1, 10).totalLinesSeen).toBe(2);
    const cr = sliceLines('a\r\nb\r\n', 1, 10);
    expect(cr.shown).toEqual(['a', 'b', '']);
    expect(cr.shown.every((l) => !l.endsWith('\r'))).toBe(true);
  });

  it('does not split on a lone CR (classic Mac line endings stay one line)', () => {
    expect(sliceLines('a\rb', 1, 10).totalLinesSeen).toBe(1);
  });
});

// --------------------------------------------------------------- looksBinary --

describe('looksBinary', () => {
  it('does not flag UTF-8 text, however multibyte', () => {
    expect(looksBinary(Buffer.from('üñíçode 🚩 with control-ish chars\n', 'utf8'))).toBe(false);
    expect(looksBinary(Buffer.from('日本語と中文\n', 'utf8'))).toBe(false);
    expect(looksBinary(Buffer.from('plain ascii\n', 'utf8'))).toBe(false);
  });

  it('flags a NUL anywhere in the first 8 KiB and only there', () => {
    const at = (n: number): Buffer => {
      const b = Buffer.alloc(9000, 0x41);
      b[n] = 0x00;
      return b;
    };
    expect(looksBinary(at(0))).toBe(true);
    expect(looksBinary(at(8191))).toBe(true); // last byte inspected
    expect(looksBinary(at(8192))).toBe(false); // outside the probe window (documented)
    expect(looksBinary(Buffer.from([0x68, 0x00, 0x69]))).toBe(true);
  });

  it('flags UTF-16 (which every UTF-16 text file contains) on purpose', () => {
    // A UTF-16LE file has NUL bytes in its ASCII range by construction. The tool
    // refuses it and points at file_download, which is the honest outcome: decoding
    // it as UTF-8 would return mojibake. Pinned so nobody "fixes" it by guessing.
    expect(looksBinary(Buffer.from('hello\x00world', 'utf16le'))).toBe(true);
    expect(looksBinary(Buffer.from([0xff, 0xfe, 0x68, 0x00]))).toBe(true);
  });

  it('is false for an empty buffer', () => {
    expect(looksBinary(Buffer.alloc(0))).toBe(false);
  });
});

// ----------------------------------------------------------------- applyPatch --

describe('applyPatch: literal text, never a regex', () => {
  it('treats regex metacharacters in oldString as literal text', () => {
    expect(applyPatch('a.b', [{ oldString: 'a.b', newString: 'X' }]).newText).toBe('X');
    // 'a.b' must NOT match 'axb'
    expect(() => applyPatch('axb', [{ oldString: 'a.b', newString: 'X' }])).toThrow(/not found/);
    for (const s of ['a|b', '(a)', '[a-z]', '{1,2}', 'a+', '^a$', '$', '\\d', '?', '*']) {
      expect(applyPatch(`pre ${s} post`, [{ oldString: s, newString: 'Z' }]).newText).toBe(`pre Z post`);
    }
  });

  it('keeps $-substitution tokens in newString literal', () => {
    for (const r of ['$&', '$1', '$<name>', '$$', "$`", "$'", '$0', '\\$1']) {
      expect(applyPatch('aXb', [{ oldString: 'X', newString: r }]).newText).toBe(`a${r}b`);
    }
    expect(applyPatch('a,b,c', [{ oldString: ',', newString: ';$&', replaceAll: true }]).newText).toBe('a;$&b;$&c');
  });

  it('counts non-overlapping occurrences and reports them', () => {
    expect(applyPatch('aaa', [{ oldString: 'aa', newString: 'b', replaceAll: true }]).results[0]).toMatchObject({ occurrences: 1, replaced: 1 });
    expect(applyPatch('aaaa', [{ oldString: 'aa', newString: 'b', replaceAll: true }]).newText).toBe('bb');
    expect(applyPatch('x x x', [{ oldString: 'x', newString: 'y', replaceAll: true }]).results[0]).toMatchObject({ occurrences: 3, replaced: 3 });
  });

  it('handles multiline edits, empty newString and empty edits', () => {
    const src = 'line1\nline2\nline3\n';
    expect(applyPatch(src, [{ oldString: 'line2\nline3', newString: 'B' }]).newText).toBe('line1\nB\n');
    expect(applyPatch(src, [{ oldString: 'line2\n', newString: '' }]).newText).toBe('line1\nline3\n');
    expect(applyPatch(src, [])).toEqual({ newText: src, results: [] });
  });

  it('is exact about line endings: an LF search does not match CRLF text', () => {
    // Honest failure beats a fuzzy match: the caller must re-read the file (the
    // error hint says exactly that), and the same edit written with CRLF applies.
    expect(() => applyPatch('a\r\nb\r\n', [{ oldString: 'a\nb', newString: 'X' }])).toThrow(/not found/);
    expect(applyPatch('a\r\nb\r\n', [{ oldString: 'a\r\nb', newString: 'X' }]).newText).toBe('X\r\n');
  });

  it('validates every edit before returning, so a late failure applies nothing', () => {
    expect(() => applyPatch('aaa bbb', [
      { oldString: 'aaa', newString: 'XXX' },
      { oldString: 'nope', newString: 'YYY' },
    ])).toThrow(/not found/);
    expect(() => applyPatch('x z', [
      { oldString: 'x', newString: 'y' },
      { oldString: 'q', newString: 'r' },
    ])).toThrow(/not found/);
    let err: unknown;
    try {
      applyPatch('x x', [{ oldString: 'x', newString: 'y' }]);
    } catch (e) {
      err = e;
    }
    expect((err as Error & { code: string }).code).toBe('BAD_ARGS');
    expect((err as Error).message).toMatch(/ambiguous \(2 matches/);
  });

  it('refuses an empty oldString (infinitely many positions)', () => {
    expect(() => applyPatch('abc', [{ oldString: '', newString: 'x' }])).toThrow(/empty/);
    // including an edit whose oldString was never supplied at all
    expect(() => applyPatch('abc', [{ oldString: 'a', newString: 'b' }, {} as { oldString: string; newString: string }])).toThrow(/empty \(edit 1\)/);
  });

  it('keeps unicode intact through the edit', () => {
    expect(applyPatch('日本語 🚩 tail', [{ oldString: ' 🚩 ', newString: '-' }]).newText).toBe('日本語-tail');
  });
});
