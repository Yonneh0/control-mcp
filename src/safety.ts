import type { ErrCode } from './errors.js';

export interface GuardOptions {
  refuseSelfSevering: boolean;
  transport: 'ssh' | 'rdp';
  platform: 'windows' | 'linux';
}

export interface GuardVerdict {
  allowed: boolean;
  code?: ErrCode;
  reason?: string;
}

function norm(cmd: string): string {
  return cmd.toLowerCase().replace(/["'`]/g, '').replace(/\s+/g, ' ').trim();
}

// Split on shell separators so a mention in one segment cannot poison another.
const SEGMENT_RE = /[;&|]+|\r?\n/;

function segments(c: string): string[] {
  return c.split(SEGMENT_RE).map((s) => s.trim()).filter(Boolean);
}

// Each pattern is anchored to the start of its segment (after an optional
// interpreter/privilege prefix), so a mention inside an echo/findstr argument is
// not itself treated as running the service command. The prefix tolerates:
//   sudo / doas, with their flag args and a single value ("sudo -u root systemctl …")
//   powershell / pwsh with -Command or the -c abbreviation (and any leading flags)
//   bash / sh / zsh / dash with -c
//   cmd /c
// A nested payload is stripped one level here; the -EncodedCommand case is
// decoded before the scan in checkCommand (a base64 blob is opaque to these
// patterns, so it must be decoded rather than prefix-stripped).
const CMD_PREFIX =
  '(?:(?:sudo|doas)(?:\\s+-[\\w=-]+)*(?:\\s+[\\w./@-]+)?\\s+|' +
  '(?:pwsh|powershell)(?:\\.exe)?\\s+(?:-\\S+\\s+)*-(?:c|command)\\s+|' +
  '(?:bash|sh|zsh|dash)\\s+-c\\s+|' +
  'cmd(?:\\.exe)?\\s+/c\\s+)?';

// Windows service names: the sshd/OpenSSH variants, followed by a boundary that
// rejects a further word char, $, or dot (so sshd.socket is NOT matched but
// sshd@1 IS, because @ ends the name and still denotes the ssh server family).
const WINDOWS_SSHD = '(?:sshd|sshd\\$|openssh\\s+ssh\\s+server)(?![\\w$.])';
const WINDOWS_TERMSERVICE = '(?:termservice|terminalservices)(?![\\w$.])';
// taskkill /im targets the image file, so the .exe suffix is part of the token.
const WINDOWS_SSHD_EXE = '(?:sshd|openssh ssh server)\\.exe';

function windowsStopPatterns(service: string, startupNameLookahead: string): RegExp[] {
  return [
    // stop-service / restart-service with the service anywhere in the same segment
    new RegExp(`^${CMD_PREFIX}(?:stop|restart)-service\\s+(?:(?!-startup)[^\\s]+\\s+)*${service}`),
    // keep the historical start-form refusal too (operator policy, symmetric)
    new RegExp(`^${CMD_PREFIX}start-service\\s+(?:(?!-startup)[^\\s]+\\s+)*${service}`),
    // net.exe is the same controller as net; the .exe must not dodge the pattern.
    new RegExp(`^${CMD_PREFIX}net(?:\\.exe)?\\s+stop\\s+${service}`),
    new RegExp(`^${CMD_PREFIX}net(?:\\.exe)?\\s+start\\s+${service}`),
    new RegExp(`^${CMD_PREFIX}sc(?:\\.exe)?\\s+(?:stop|delete|config|start)\\s+${service}`),
    // Set-Service with -StartupType Disabled/Manual, either parameter order.
    new RegExp(`^${CMD_PREFIX}set-service(?=[^\\r\\n]*${startupNameLookahead})(?=[^\\r\\n]*(?:-startup[-\\s]*type\\s+(?:disabled|manual)|-startup\\s+disabled))`),
    // sc config start= disabled for the service
    new RegExp(`^${CMD_PREFIX}sc(?:\\.exe)?\\s+config\\s+${service}[^\\r\\n]*start\\s*=?\\s*(?:disabled|demand)`),
    new RegExp(`^${CMD_PREFIX}taskkill[^\\r\\n]*/im\\s+${WINDOWS_SSHD_EXE}`),
    // taskkill targeting the daemon by name without the .exe suffix, or via a
    // /fi image filter, and Stop-Process killing the daemon process — both sever
    // the exec path.
    new RegExp(`^${CMD_PREFIX}taskkill[^\\r\\n]*(?:sshd|openssh\\s+ssh\\s+server)(?![\\w$])`),
    new RegExp(`^${CMD_PREFIX}stop-process[^\\r\\n]*(?:sshd|openssh\\s+ssh\\s+server)(?![\\w$])`),
  ];
}

// A segment that is a bare stop-family verb with NO service argument. On its own
// such a command is a no-op (it errors for a missing target), but it is the sink
// of a pipeline like `Get-Service sshd | Stop-Service`, where the SOURCE segment
// names the transport service. Refused only when the command also names sshd /
// TermService, so `Get-Process chrome | Stop-Process` stays allowed.
const SINK_WINDOWS = [
  new RegExp(`^${CMD_PREFIX}(?:stop|restart|start)-service\\s*$`),
  new RegExp(`^${CMD_PREFIX}net(?:\\.exe)?\\s+(?:stop|start)\\s*$`),
  new RegExp(`^${CMD_PREFIX}sc(?:\\.exe)?\\s+(?:stop|delete|start)\\s*$`),
  new RegExp(`^${CMD_PREFIX}stop-process\\s*$`),
  new RegExp(`^${CMD_PREFIX}taskkill\\s*$`),
];

function linuxStopPatterns(): RegExp[] {
  // Unit names: sshd / ssh, optionally .service; never sshd.socket or sshdx.
  const unit = '(?:sshd|ssh)(?![\\w$])(?:\\.service)?(?![-.](?!service)[a-z])';
  return [
    // systemctl stop/restart/disable/kill/mask with flag tolerance (--now, …).
    // `mask` is included: a masked unit cannot start at next boot, the same
    // permanent-outage outcome as stopping it.
    new RegExp(`^${CMD_PREFIX}systemctl\\s+(?:stop|restart|disable|kill|mask)(?:\\s+--?[\\w=-]+)*\\s+${unit}`),
    new RegExp(`^${CMD_PREFIX}service\\s+${unit}\\s+(?:stop|restart|kill)`),
    // pkill/killall aimed at the daemon token. pkill's pattern must be the LAST
    // token so `-f "ssh session"` (a phrase, not the daemon) is not refused,
    // while `-f sshd` / `-9 sshd` (which do match the daemon) are.
    new RegExp(`^${CMD_PREFIX}pkill\\s+(?:-\\S+\\s+)*(?:sshd|ssh)(?![\\w$.])\\s*$`),
    new RegExp(`^${CMD_PREFIX}killall\\s+(?:-\\w+\\s+)*${unit}`),
  ];
}

const SINK_LINUX = [
  new RegExp(`^${CMD_PREFIX}systemctl\\s+(?:stop|restart|disable|kill|mask)\\s*$`),
  new RegExp(`^${CMD_PREFIX}pkill\\s*$`),
  new RegExp(`^${CMD_PREFIX}killall\\s*$`),
];

// A base64 blob is opaque to the segment patterns, so an -EncodedCommand payload
// must be decoded and screened too. A real payload is UTF-16LE text; anything
// else surfaces as replacement chars / control bytes, which we treat as
// undecodable and refuse (fail closed — we cannot prove it is safe).
function decodeEncodedPowerShell(b64: string): { ok: boolean; text: string } {
  try {
    const text = Buffer.from(b64, 'base64').toString('utf16le');
    if (text.length === 0) return { ok: false, text };
    let bad = 0;
    for (let i = 0; i < text.length; i++) {
      const cc = text.charCodeAt(i);
      if (cc === 0xfffd || cc < 9 || (cc > 13 && cc < 32)) bad++;
    }
    return { ok: bad / text.length < 0.15, text };
  } catch {
    return { ok: false, text: '' };
  }
}

function refuseWindows(transport: string): GuardVerdict {
  return {
    allowed: false,
    code: 'TRANSPORT_SEVERED_RISK',
    reason:
      `Refused: this command stops or reconfigures a transport-carrying service (sshd and/or TermService); the current transport is ${transport}. ` +
      'Windows Automatic services start only at boot, so a stopped sshd never self-heals and the box becomes unreachable. ' +
      'Pass override:"sever-transport" to run it anyway.',
  };
}

function refuseLinux(): GuardVerdict {
  return {
    allowed: false,
    code: 'TRANSPORT_SEVERED_RISK',
    reason:
      'Refused: this command stops the sshd that carries the current transport. ' +
      'Pass override:"sever-transport" to run it anyway.',
  };
}

// The screen that runs over a given command string (already one nesting level).
function scanCommand(cmd: string, opts: GuardOptions): GuardVerdict {
  const c = norm(cmd);
  // Loose "names a transport service anywhere" test, used only to enable the
  // pipeline-sink rules below (which require the bare stop verb to be fed a
  // service we care about by an earlier segment).
  const namesSvc = /(?:sshd|termservice|terminalservices|openssh\s+ssh\s+server)/.test(c);

  if (opts.platform === 'windows') {
    const sshPatterns = windowsStopPatterns(WINDOWS_SSHD, '(?:sshd|openssh\\s+ssh\\s+server)');
    const rdpPatterns = windowsStopPatterns(WINDOWS_TERMSERVICE, '(?:termservice|terminalservices)');
    // Both pattern sets always apply: a command that stops TermService severs an
    // RDP-driven session, and stopping sshd severs the exec path regardless of
    // which transport carried this call here.
    const patterns = [...sshPatterns, ...rdpPatterns];
    const segs = segments(c);
    for (const seg of segs) {
      for (const re of patterns) {
        if (re.test(seg)) return refuseWindows(opts.transport);
      }
    }
    if (namesSvc) {
      for (const seg of segs) {
        for (const re of SINK_WINDOWS) {
          if (re.test(seg)) return refuseWindows(opts.transport);
        }
      }
    }
  }

  if (opts.platform === 'linux' && opts.transport === 'ssh') {
    const patterns = linuxStopPatterns();
    const segs = segments(c);
    for (const seg of segs) {
      for (const re of patterns) {
        if (re.test(seg)) return refuseLinux();
      }
    }
    if (namesSvc) {
      for (const seg of segs) {
        for (const re of SINK_LINUX) {
          if (re.test(seg)) return refuseLinux();
        }
      }
    }
  }

  return { allowed: true };
}

export function checkCommand(cmd: string, opts: GuardOptions): GuardVerdict {
  if (!opts.refuseSelfSevering) return { allowed: true };

  // Decode -EncodedCommand / -enc payloads (base64, case-sensitive — hence we
  // scan the RAW command, not the lowercased norm() output) and screen them too.
  const encRe = /-(?:enc|encodedcommand)\s+"?([A-Za-z0-9+/=]{12,})"?/gi;
  let m: RegExpExecArray | null;
  while ((m = encRe.exec(cmd)) !== null) {
    const d = decodeEncodedPowerShell(m[1]);
    if (!d.ok) {
      return {
        allowed: false,
        code: 'TRANSPORT_SEVERED_RISK',
        reason:
          'Refused: a -EncodedCommand argument could not be decoded as UTF-16LE, so its contents cannot be screened for transport-severing commands. ' +
          'Pass override:"sever-transport" to run it anyway.',
      };
    }
    const inner = scanCommand(d.text, opts);
    if (!inner.allowed) return inner;
  }

  return scanCommand(cmd, opts);
}
