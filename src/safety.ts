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
// sudo/powershell -Command/cmd /c prefix via CMD_PREFIX), so a mention inside an
// echo/findstr argument is not itself treated as running the service command.
const CMD_PREFIX = '(?:sudo\\s+|powershell(?:\\.exe)?\\s+(?:-\\S+\\s+)*-command\\s+|cmd(?:\\.exe)?\\s+/c\\s+)?';

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
    new RegExp(`^${CMD_PREFIX}net\\s+stop\\s+${service}`),
    new RegExp(`^${CMD_PREFIX}net\\s+start\\s+${service}`),
    new RegExp(`^${CMD_PREFIX}sc(?:\\.exe)?\\s+(?:stop|delete|config|start)\\s+${service}`),
    // Set-Service with -StartupType Disabled/Manual, either parameter order.
    // Loose name form (no trailing boundary): "-startup-type" can follow the
    // token directly in dashed-option spelling.
    new RegExp(`^${CMD_PREFIX}set-service(?=[^\\r\\n]*${startupNameLookahead})(?=[^\\r\\n]*(?:-startup[-\\s]*type\\s+(?:disabled|manual)|-startup\\s+disabled))`),
    // sc config start= disabled for the service
    new RegExp(`^${CMD_PREFIX}sc(?:\\.exe)?\\s+config\\s+${service}[^\\r\\n]*start\\s*=?\\s*(?:disabled|demand)`),
    new RegExp(`^${CMD_PREFIX}taskkill[^\\r\\n]*/im\\s+${WINDOWS_SSHD_EXE}`),
    // taskkill targeting the daemon by name without the .exe suffix, or via a
    // /fi image filter, and Stop-Process killing the daemon process — both sever
    // the exec path but were previously unmatched.
    new RegExp(`^${CMD_PREFIX}taskkill[^\\r\\n]*(?:sshd|openssh\\s+ssh\\s+server)(?![\\w$])`),
    new RegExp(`^${CMD_PREFIX}stop-process[^\\r\\n]*(?:sshd|openssh\\s+ssh\\s+server)(?![\\w$])`),
  ];
}

function linuxStopPatterns(): RegExp[] {
  // Unit names: sshd / ssh, optionally .service; never sshd.socket or sshdx.
  const unit = '(?:sshd|ssh)(?![\\w$])(?:\\.service)?(?![-.](?!service)[a-z])';
  return [
    // systemctl stop/restart/disable/kill with flag tolerance (--now, --no-pager between)
    new RegExp(`^${CMD_PREFIX}systemctl\\s+(?:stop|restart|disable|kill)(?:\\s+--?[\\w=-]+)*\\s+${unit}`),
    new RegExp(`^${CMD_PREFIX}service\\s+${unit}\\s+(?:stop|restart|kill)`),
    // process kills aimed at the daemon itself (word-boundary token). Same unit
    // guard as systemctl/service forms so sshd-junk-style names are not refused.
    new RegExp(`^${CMD_PREFIX}pkill\\s+(?:-x\\s+)?${unit}`),
    new RegExp(`^${CMD_PREFIX}killall\\s+(?:-\\w+\\s+)*${unit}`),
  ];
}

export function checkCommand(cmd: string, opts: GuardOptions): GuardVerdict {
  if (!opts.refuseSelfSevering) return { allowed: true };
  const c = norm(cmd);

  if (opts.platform === 'windows') {
    const sshPatterns = windowsStopPatterns(WINDOWS_SSHD, '(?:sshd|openssh\\s+ssh\\s+server)');
    const rdpPatterns = windowsStopPatterns(WINDOWS_TERMSERVICE, '(?:termservice|terminalservices)');
    // Both pattern sets always apply: a command that stops TermService severs an
    // RDP-driven session, and stopping sshd severs the exec path regardless of
    // which transport carried this call here.
    const patterns = [...sshPatterns, ...rdpPatterns];
    for (const seg of segments(c)) {
      for (const re of patterns) {
        if (re.test(seg)) {
          return {
            allowed: false,
            code: 'TRANSPORT_SEVERED_RISK',
            reason:
              `Refused: this command stops or reconfigures a transport-carrying service (sshd and/or TermService); the current transport is ${opts.transport}. ` +
              'Windows Automatic services start only at boot, so a stopped sshd never self-heals and the box becomes unreachable. ' +
              'Pass override:"sever-transport" to run it anyway.',
          };
        }
      }
    }
  }

  if (opts.platform === 'linux' && opts.transport === 'ssh') {
    const patterns = linuxStopPatterns();
    for (const seg of segments(c)) {
      for (const re of patterns) {
        if (re.test(seg)) {
          return {
            allowed: false,
            code: 'TRANSPORT_SEVERED_RISK',
            reason:
              'Refused: this command stops the sshd that carries the current transport. ' +
              'Pass override:"sever-transport" to run it anyway.',
          };
        }
      }
    }
  }

  return { allowed: true };
}
