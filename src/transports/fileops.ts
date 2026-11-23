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

// maxResults is the one value interpolated into a command line, so it must be a
// real integer before it gets there.
function needMaxResults(maxResults: number): number {
  if (!Number.isSafeInteger(maxResults) || maxResults < 1) {
    throw new ControlError('BAD_ARGS', 'maxResults must be an integer >= 1', { maxResults });
  }
  return maxResults;
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
    const fullW = `${baseW}\\${pattern.replace(/\*\*\//g, '*').replace(/\//g, '\\').replace(/\*+/g, '*')}`;
    return psCommand(
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
  const base = root.replace(/\/+$/, '');
  const fullPath = `${base}/${pattern.replace(/\*\*\//g, '*').replace(/\*+/g, '*')}`;
  // %T@ prints epoch seconds (fractional); \t separates it from %p, \0 ends the
  // record so paths containing newlines survive.
  return `find ${shq(root)}${o.filesOnly ? ' -type f' : ''} -path ${shq(fullPath)} -printf ${shq('%T@\\t%p\\0')} 2>/dev/null`;
}

export function buildSearchCommand(os: OS, o: { root: string; pattern: string; include?: string; maxResults: number }): string {
  const pattern = needPattern(o.pattern);
  const max = needMaxResults(o.maxResults);
  const root = needNoNul(o.root, 'root');
  const include = o.include === undefined ? undefined : needNoNul(o.include, 'include');

  if (os === 'windows') {
    // Select-String takes a .NET regex — a different dialect from grep -E; the
    // tool description says so rather than pretending they are interchangeable.
    const nameFilter = include ? `$_.Name -like ${psq(include)}` : '$true';
    return psCommand(
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
  return `grep -rnI --color=never --exclude-dir=.git -E ${shq(pattern)}${inc} ${shq(root)}`;
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

// Parse '<ticks>\t<path>' lines from the PowerShell glob.
export function parseWinGlobOutput(stdout: string, maxResults: number): GlobItem[] {
  const items: GlobItem[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    if (!raw) continue;
    const tab = raw.indexOf('\t');
    if (tab <= 0) continue;
    const path = raw.slice(tab + 1);
    if (!path) continue;
    const ticks = Number(raw.slice(0, tab));
    if (!Number.isFinite(ticks)) continue;
    items.push({ path, mtimeMs: Math.floor(ticks / 10000 - WIN_TICKS_TO_UNIX_MS) });
  }
  return newestFirstCap(items, maxResults);
}

// '<path>:<line>:<text>' — the text may itself contain ':', so split on the
// first two colons only. Anything without a numeric second field (grep's
// "Binary file X matches", a path with a stray colon) is skipped, not guessed.
export function parseGrepOutput(stdout: string, maxResults: number): SearchMatch[] {
  const out: SearchMatch[] = [];
  for (const raw of stdout.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (!line) continue;
    const first = line.indexOf(':');
    const second = line.indexOf(':', first + 1);
    if (first <= 0 || second < 0) continue;
    const n = line.slice(first + 1, second);
    if (!/^\d+$/.test(n)) continue;
    out.push({ path: line.slice(0, first), line: Number(n), text: line.slice(second + 1) });
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
