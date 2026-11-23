import { ControlError } from '../errors.js';
import { psCommand } from './windows.js';

// Pure command builders and parsers for the file-management tool family
// (file_glob / file_search / file_read / file_write / file_patch). Nothing here
// touches a transport: every function is synchronous and unit-testable with no
// host, and the registry runs the returned command through the audited
// runChecked path (safety gate -> ssh.exec).
//
// Injection-safety: every caller-supplied string that reaches a POSIX shell is
// wrapped with shq() and every one that reaches PowerShell is wrapped with
// psq(); the only interpolated non-string value is maxResults, validated to a
// safe integer first.

export type OS = 'linux' | 'windows';

export interface GlobItem {
  path: string;
  mtimeMs: number;
}

export interface SearchMatch {
  path: string;
  line: number;
  text: string;
}

// POSIX single-quote escaping: wrap in '...' and turn each embedded ' into '\''.
// Nothing inside single quotes is expanded by the shell, so a pattern like
// '$(reboot)' or '`reboot`' is passed as a literal argument, never executed.
export function shq(v: string): string {
  return `'${v.split("'").join(`'\\''`)}'`;
}

// PowerShell single-quoted string: the only escape inside one is to double the
// quote. Combined with -EncodedCommand (psCommand) this removes both the cmd.exe
// and the PowerShell quoting hazard.
function psq(v: string): string {
  return `'${v.split("'").join("''")}'`;
}

// A NUL byte cannot survive as a shell argument (and would truncate the argument
// at the exec boundary), so refuse it rather than run something different from
// what the caller asked for.
function needNoNul(value: string, what: string): string {
  if (value.includes('\0')) {
    throw new ControlError('BAD_ARGS', `${what} cannot contain a NUL byte`, { [what]: value.replace(/\0/g, '\\0') });
  }
  return value;
}

function needPattern(pattern: string): string {
  const p = needNoNul(pattern, 'pattern');
  if (p.length === 0) {
    throw new ControlError('BAD_ARGS', 'pattern must not be empty', {}, 'give a glob such as "*.log" or "src/**/*.ts" (file_glob), or a regex (file_search)');
  }
  return p;
}

// An empty include is NOT "no filter". On Linux it becomes `--include=`, which
// matches no file name at all (measured: grep exits 1 with no output for a search
// that finds the file with '--include=*.txt' or with no filter at all); on Windows
// it becomes `$_.Name -like ''`, which is never true. Both report "0 match(es)"
// for a tree that was never searched, so refuse it and say what to pass instead.
function needInclude(include: string | undefined): string | undefined {
  if (include === undefined) return undefined;
  const inc = needNoNul(include, 'include');
  if (inc.length === 0) {
    throw new ControlError('BAD_ARGS', 'include must not be empty', { include }, 'omit include to search every file, or give a file-name glob such as "*.ts"');
  }
  return inc;
}

// maxResults is the one value interpolated into a command line, so it must be a
// real integer before it gets there.
function needMaxResults(maxResults: number): number {
  if (!Number.isSafeInteger(maxResults) || maxResults < 1) {
    throw new ControlError('BAD_ARGS', 'maxResults must be an integer >= 1', { maxResults });
  }
  return maxResults;
}

// PowerShell's -like reads [ ] * ? as wildcards, but the ROOT it is compared
// against is a literal path: a directory really named 'logs[2024]' produced
// -like 'C:\logs[2024]\*.log', which does not match the very path it came from
// (measured in PowerShell: False, while 'C:\logs[[]2024[]]\*.log' is True), so the
// tool reported "no matches" for a tree that exists. about_Wildcards: wrapping a
// wildcard character in brackets makes it literal. One pass, so the brackets this
// adds are never re-escaped.
function likeLiteral(v: string): string {
  return v.replace(/[[\]*?]/g, (c) => `[${c}]`);
}

// -ErrorAction SilentlyContinue is what keeps a permission-denied directory in the
// middle of a recursive walk from aborting the whole query — and it also swallows
// "the root does not exist". Measured with powershell.exe -EncodedCommand and a
// missing root: exit 1 with NOTHING on stdout or stderr. file_search reads exit 1
// as grep's "no matches" convention and answers "0 match(es)" for a path that was
// never there; file_glob answers REMOTE_ERROR with no evidence in either stream.
// So test the root by name and exit 2, which both callers already map to
// REMOTE_ERROR, with the path in the message.
function winRootGuard(root: string): string {
  return (
    `if (-not (Test-Path -LiteralPath ${psq(root)})) {\n` +
    `  Write-Error ${psq(`root is missing or unreadable: ${root}`)}\n` +
    `  exit 2\n` +
    `}\n`
  );
}

// ------------------------------------------------------------------ builders --

export function buildGlobCommand(os: OS, o: { root: string; pattern: string; filesOnly: boolean; maxResults: number }): string {
  const pattern = needPattern(o.pattern);
  const max = needMaxResults(o.maxResults);
  const root = needNoNul(o.root, 'root');

  if (os === 'windows') {
    // -File always: the glob tool lists files. Newest-first and the cap happen
    // remotely, so a huge tree never streams back in full.
    // The pattern is RELATIVE to the root on both OSes: -like is applied to
    // FullName, so the root is prefixed and '/' is read as '\' — otherwise a
    // Linux-style 'src/**/*.ts' would never match a Windows full path and the
    // tool would report "no matches" for a pattern that works on Linux. In
    // -like, '*' spans separators exactly like find's -path, so '**' collapses
    // the same way.
    const baseW = root.replace(/[\\/]+$/, '');
    const fullW = `${likeLiteral(baseW)}\\${pattern.replace(/\*\*\//g, '*').replace(/\//g, '\\').replace(/\*+/g, '*')}`;
    return psCommand(
      winRootGuard(root) +
      `Get-ChildItem -LiteralPath ${psq(root)} -Recurse -File -ErrorAction SilentlyContinue` +
      ` | Where-Object { $_.FullName -like ${psq(fullW)} }` +
      ` | Sort-Object LastWriteTimeUtc -Descending` +
      ` | Select-Object -First ${max}` +
      ` | ForEach-Object { "{0}\`t{1}" -f $_.LastWriteTimeUtc.Ticks, $_.FullName }`,
    );
  }

  // GNU find's -path matches the WHOLE path and its '*' spans '/', so '**' is
  // equivalent to '*' here: 'a/**/b' collapses to 'a/*b' (zero or more
  // directories) and any run of stars collapses to one. Exactly one slash joins
  // root and pattern (a trailing '/' on root would make '//pattern', which -path
  // would not match).
  // A starting point whose first character is '-' is not a path to find: find parses
  // it as an option or predicate. Measured with GNU findutils: `find '-data' -type f
  // -path '-data/*'` → "unknown predicate `-data'" exit 1 (the directory exists but
  // cannot be listed), and `find '-printf' …` → "paths must precede expression: `f'".
  // A valid option spelling is worse than the error: '-P' is simply consumed as an
  // option, find then searches '.' — a different tree — and reports no matches.
  // find has no '--', so a leading './' is the portable guard; it goes into the
  // -path pattern too, because -path must match the paths find actually prints.
  const start = root.startsWith('-') ? `./${root}` : root;
  const base = start.replace(/\/+$/, '');
  const fullPath = `${base}/${pattern.replace(/\*\*\//g, '*').replace(/\*+/g, '*')}`;
  // %T@ prints epoch seconds (fractional); \t separates it from %p, \0 ends the
  // record so paths containing newlines survive.
  return `find ${shq(start)}${o.filesOnly ? ' -type f' : ''} -path ${shq(fullPath)} -printf ${shq('%T@\\t%p\\0')} 2>/dev/null`;
}

export function buildSearchCommand(os: OS, o: { root: string; pattern: string; include?: string; maxResults: number }): string {
  const pattern = needPattern(o.pattern);
  const max = needMaxResults(o.maxResults);
  const root = needNoNul(o.root, 'root');
  const include = needInclude(o.include);

  if (os === 'windows') {
    // Select-String takes a .NET regex — a different dialect from grep -E; the
    // tool description says so rather than pretending they are interchangeable.
    const nameFilter = include !== undefined ? `$_.Name -like ${psq(include)}` : '$true';
    return psCommand(
      winRootGuard(root) +
      `Get-ChildItem -LiteralPath ${psq(root)} -Recurse -File -ErrorAction SilentlyContinue` +
      ` | Where-Object { ${nameFilter} }` +
      ` | Select-String -Pattern ${psq(pattern)} -ErrorAction SilentlyContinue` +
      ` | Select-Object -First ${max}` +
      ` | ForEach-Object { "{0}:{1}:{2}" -f $_.Path, $_.LineNumber, $_.Line }`,
    );
  }

  // -I skips binary files; grep exits 1 for "no matches", which the caller treats
  // as success-with-no-results. Deliberately NOT piped to head: closing the pipe
  // early kills grep with SIGPIPE and hides the real outcome. Capping happens in
  // the parser.
  const inc = include === undefined ? '' : ` ${shq(`--include=${include}`)}`;
  // The pattern and the root are POSITIONAL operands, so one that begins with '-' is
  // parsed by grep as options instead. Measured with GNU grep, both on a tree whose
  // only file holds the single line "alpha":
  //   grep -rnI --color=never --exclude-dir=.git -E '-vn' ./a.log
  //     -> printed "a.log:1:alpha" and "-data/c.log:1:gamma": '-vn' became -v
  //        (invert) + -n, the file argument became the pattern, and -r searched the
  //        whole cwd — matches reported that were never asked for, in files that
  //        were never named.
  //   grep ... -E '-F<file>' ./a.log  -> "conflicting matchers specified", exit 2.
  // '-e' binds the pattern operand and '--' ends option parsing before the root;
  // each is added only when a value needs it, so the ordinary command line stays
  // byte-identical (and the existing suite's pinned strings still hold).
  const patArg = pattern.startsWith('-') ? `-e ${shq(pattern)}` : shq(pattern);
  const rootArg = root.startsWith('-') ? `-- ${shq(root)}` : shq(root);
  return `grep -rnI --color=never --exclude-dir=.git -E ${patArg}${inc} ${rootArg}`;
}

// ------------------------------------------------------------------- parsers --

// GNU find %T@ yields epoch seconds with a fraction, and some locales print the
// decimal separator as ','. Parse it exactly (sub-millisecond digits dropped)
// instead of going through float multiplication.
function parseEpochMillis(token: string): number | null {
  const m = /^(-?\d+)(?:[.,](\d+))?$/.exec(token.trim());
  if (!m) return null;
  const whole = Number(m[1]);
  const ms = Number((m[2] ?? '').padEnd(3, '0').slice(0, 3));
  if (!Number.isSafeInteger(whole * 1000)) return null;
  return whole < 0 ? whole * 1000 - ms : whole * 1000 + ms;
}

function newestFirstCap(items: GlobItem[], maxResults: number): GlobItem[] {
  items.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return items.slice(0, Math.max(0, maxResults));
}

// Parse NUL-delimited '<epoch-seconds>\t<path>' records from GNU find. Records
// that do not match are skipped (never guessed).
export function parseFindOutput(stdout: string, maxResults: number): GlobItem[] {
  const items: GlobItem[] = [];
  for (const rec of stdout.split('\0')) {
    if (!rec) continue;
    const tab = rec.indexOf('\t');
    if (tab <= 0) continue;
    const path = rec.slice(tab + 1);
    const mtimeMs = parseEpochMillis(rec.slice(0, tab));
    if (mtimeMs === null || !path) continue;
    items.push({ path, mtimeMs });
  }
  return newestFirstCap(items, maxResults);
}

// .NET Ticks are 100ns intervals since 0001-01-01. /10000 gives ms since 0001;
// subtract the 0001->1970 span in ms (62135596800000) to get Unix epoch ms.
// NOT 11644473600000 — that is the FILETIME span, whose epoch is 1601-01-01;
// pairing it with 0001-based Ticks yields dates ~1600 years in the future.
const WIN_TICKS_TO_UNIX_MS = 62135596800000;

// Parse '<ticks>\t<path>' lines from the PowerShell glob. The ticks field is what
// PowerShell's "{0}" -f [long] writes: bare decimal digits and nothing else, so
// require exactly that. Number() would also accept '  ', hex, exponent and sign
// forms, and coercing one of those (a truncated or interleaved stream, say) invents
// a timestamp — a whitespace-only field becomes 0, i.e. 1970-01-01.
export function parseWinGlobOutput(stdout: string, maxResults: number): GlobItem[] {
  const items: GlobItem[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    if (!raw) continue;
    const tab = raw.indexOf('\t');
    if (tab <= 0) continue;
    const path = raw.slice(tab + 1);
    if (!path) continue;
    const token = raw.slice(0, tab);
    if (!/^\d+$/.test(token)) continue;
    const ticks = Number(token);
    if (!Number.isFinite(ticks)) continue;
    items.push({ path, mtimeMs: Math.floor(ticks / 10000 - WIN_TICKS_TO_UNIX_MS) });
  }
  return newestFirstCap(items, maxResults);
}

// '<path>:<line>:<text>' — the text may itself contain ':', so the separator is the
// FIRST colon followed by digits and another colon (the same rule
// parseWinSearchOutput uses). Splitting on the first two colons instead dropped a
// real match for a file whose name contains ':' — POSIX allows it, so
// 'dir/a:b.log:12:x' is one row, and a dropped row is reported as one match fewer
// (or "0 match(es)"). Anything with no ':<digits>:' anywhere — grep's "Binary file
// X matches" notice, a stray colon — is still skipped, never guessed.
export function parseGrepOutput(stdout: string, maxResults: number): SearchMatch[] {
  const out: SearchMatch[] = [];
  for (const raw of stdout.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (!line) continue;
    for (let i = line.indexOf(':'); i >= 0; i = line.indexOf(':', i + 1)) {
      const m = /^(\d+):/.exec(line.slice(i + 1));
      if (!m) continue;
      const path = line.slice(0, i);
      if (!path) break;
      out.push({ path, line: Number(m[1]), text: line.slice(i + 1 + m[0].length) });
      break;
    }
  }
  return out.slice(0, Math.max(0, maxResults));
}

// Same shape as grep, but a Windows path legitimately contains a colon (the
// drive letter — ':' is otherwise illegal in a Windows file name), so the drive
// colon is skipped before looking for the ':<line>:' separator. An NTFS
// alternate-data-stream path could still confuse it; that is not claimed to be
// handled.
export function parseWinSearchOutput(stdout: string, maxResults: number): SearchMatch[] {
  const out: SearchMatch[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (!line) continue;
    const start = /^[A-Za-z]:[\\/]/.test(line) ? 2 : 0;
    for (let i = line.indexOf(':', start); i >= 0; i = line.indexOf(':', i + 1)) {
      const m = /^(\d+):/.exec(line.slice(i + 1));
      if (!m) continue;
      const path = line.slice(0, i);
      if (!path) break;
      out.push({ path, line: Number(m[1]), text: line.slice(i + 1 + m[0].length) });
      break;
    }
  }
  return out.slice(0, Math.max(0, maxResults));
}

// ------------------------------------------------------------------ text ops --

// offset is 1-based. A trailing newline yields a final empty line (what most
// editors show), and offset past the end yields an empty window rather than an
// error, so the caller can report it honestly.
export function sliceLines(
  text: string,
  offset: number,
  limit: number,
): { shown: string[]; firstLine: number; lastLine: number; totalLinesSeen: number; truncatedByLimit: boolean } {
  const off = Math.max(1, Math.trunc(offset) || 1);
  const lim = Math.max(1, Math.trunc(limit) || 1);
  const lines = text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
  const shown = lines.slice(off - 1, off - 1 + lim);
  return {
    shown,
    firstLine: off,
    lastLine: off + shown.length - 1,
    totalLinesSeen: lines.length,
    truncatedByLimit: off - 1 + shown.length < lines.length,
  };
}

// A NUL byte in the first 8 KiB is the usual "this is not text" signal; a text
// reader would return mojibake, so the caller refuses and points at file_download
// instead. An empty buffer is not binary.
export function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0x00) return true;
  return false;
}

export interface PatchEdit {
  oldString: string;
  newString: string;
  replaceAll?: boolean;
}

export interface PatchResult {
  index: number;
  occurrences: number;
  replaced: number;
  replaceAll: boolean;
}

function countOccurrences(hay: string, needle: string): number {
  let n = 0;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + needle.length)) n++;
  return n;
}

function replaceOccurrences(hay: string, needle: string, replacement: string, all: boolean): string {
  if (!all) {
    const i = hay.indexOf(needle);
    return i === -1 ? hay : hay.slice(0, i) + replacement + hay.slice(i + needle.length);
  }
  // split/join so a replacement containing $&-style tokens stays literal.
  return hay.split(needle).join(replacement);
}

// Mirror a classic editor: an oldString must occur exactly once unless
// replaceAll is set. Edits apply in order against the working copy (so edit #2
// sees edit #1's output) and EVERY edit is validated before any text is
// returned, so a bad edit late in the list never leaves a half-applied file.
export function applyPatch(text: string, edits: PatchEdit[]): { newText: string; results: PatchResult[] } {
  let working = text;
  const results: PatchResult[] = [];
  for (let i = 0; i < edits.length; i++) {
    const edit = edits[i];
    const oldString = edit?.oldString ?? '';
    if (oldString === '') {
      throw new ControlError('BAD_ARGS', `patch oldString must not be empty (edit ${i})`, { index: i }, 'match at least one character; an empty oldString has infinitely many positions');
    }
    const occurrences = countOccurrences(working, oldString);
    if (occurrences === 0) {
      throw new ControlError('BAD_ARGS', `patch oldString not found (edit ${i})`, { index: i }, 're-read the file with file_read and match the current text exactly, including whitespace');
    }
    const replaceAll = edit.replaceAll === true;
    if (!replaceAll && occurrences > 1) {
      throw new ControlError(
        'BAD_ARGS',
        `patch oldString is ambiguous (${occurrences} matches; use replaceAll or widen the context) (edit ${i})`,
        { index: i, occurrences },
        'widen oldString with surrounding lines until it matches once, or set replaceAll:true to replace every match',
      );
    }
    working = replaceOccurrences(working, oldString, edit.newString ?? '', replaceAll);
    results.push({ index: i, occurrences, replaced: replaceAll ? occurrences : 1, replaceAll });
  }
  return { newText: working, results };
}
