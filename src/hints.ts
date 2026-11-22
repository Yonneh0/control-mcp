// Actionable recovery guidance paired with every tool error, so a calling AI can
// self-correct from the failure alone. Every hint must be both actionable and
// true of how control-mcp actually behaves (verified on this LAN) — never a
// speculative guess. toolError() falls back to these when a call site supplies
// no more specific hint, so no error ever ships without a next step.
import type { ErrCode } from './errors.js';

export const DEFAULT_HINTS: Record<ErrCode, string> = {
  AUTH_FAILED:
    'the host answered but rejected the credential; confirm the user in config.toml is the account that accepts this key/password and that privateKeyPath/password/passwordEnv resolve. A blank-password Windows account is deliberately unreachable over the network. Re-check with host_status.',
  HOST_UNREACHABLE:
    'nothing answered this address; confirm the box is powered (wake its MAC from arp_table via wol_wake) and that address/alternateAddresses are right. A timeout means firewalled or down; a connection-refused means the host is up but nothing listens on that port. host_status gives a per-interface verdict.',
  CAPABILITY_UNAVAILABLE:
    'this action is not configured or not possible for the target; host_status explains why (RDP not declared, adb not installed, in-process MsRdpEx cannot hold a session). Configure the capability in config.toml or use the supported fallback named in the message.',
  TRANSPORT_SEVERED_RISK:
    'the self-sever guard stopped a command that would take down the service carrying this connection; only pass override:"sever-transport" if you have another way back (console, or the other transport), otherwise pick a command that does not stop sshd/TermService.',
  TIMEOUT:
    'the command outlived its timeout and the channel closed; the remote process may still be running. Raise timeoutMs, or start it detached (nohup, systemd-run, or schtasks) and poll for its result instead of blocking the call.',
  SESSION_GONE:
    'that shell session id is unknown or already closed (its channel died with the underlying connection); open a fresh one with shell_open and reuse the id it returns, or list live ones with shell_list.',
  BAD_ARGS:
    'arguments were rejected before any remote action ran; fix the field named in the message. Local paths must be absolute, remote paths must suit the host OS, and destructive options such as overwrite must be set explicitly. tools/list shows each exact schema.',
  REMOTE_ERROR:
    'the command reached the target and failed there; read stdout/stderr and the exit code in the result for the real cause — the failure is on the remote host, not in the transport.',
  INTERNAL:
    'unexpected control-mcp internal error; retry once, and if it persists check the control-mcp stderr log for the stack.',
};

// A short human hint for the command-outcome label so a model sees which knob
// to turn (timeoutMs) rather than a bare "killed by SIGTERM".
export function execOutcomeHint(signal: string | null, code: number | null): string | null {
  if (signal) return `the process was killed by ${signal}; raise timeoutMs or split the command if the work is legitimate`;
  if (code !== null && code !== 0) return `exit ${code} is the target program's own failure code; inspect stderr for the reason`;
  return null;
}
