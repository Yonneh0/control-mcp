export interface RdpProbeInput {
  declared: boolean;
  tcpOpen: boolean;
  sshAlive: boolean;
  hasCredential?: boolean;
  blankPasswordAccount?: boolean;
  limitBlankPasswordUse?: number;
  nlaRequired?: boolean;
}

export type RdpUnreason =
  | 'not-declared'
  | 'host-unreachable'
  | 'rdp-port-closed'
  | 'blank-password-policy'
  | 'nla-credential-missing';

export interface RdpVerdict {
  available: boolean;
  reason: string;
  code?: RdpUnreason;
  evidence?: Record<string, unknown>;
}

// The probe measures the outcome (network logon rejected for a blank password);
// LimitBlankPasswordUse is the registry switch normally behind it but may not be
// readable, so every clause branches on what was actually observed. Measured on
// this LAN 2026-11-22 with `cmd /c net use \\<ip>\IPC$ "" /user:<acct>`: n100's
// blank User returns exit 2 + "System error 1327 ... blank passwords aren't
// allowed" (the documented refusal); other nonzero codes are ambiguous and do
// not assert the blank-password story at all.
function blankPasswordReason(lbp: number | undefined, nlaRequired?: boolean): string {
  const policy = lbp === 1 ? 'LimitBlankPasswordUse=1 (Windows default)' : 'the network-logon path rejects blank passwords (typically LimitBlankPasswordUse)';
  const proof = lbp === 1
    ? 'Proof: probing `net use \\\\<ip>\\IPC$ "" /user:<acct>` over SSH fails with the blank-password error (System error 1327, "blank passwords aren\'t allowed") while LimitBlankPasswordUse=1 is set. '
    : 'Proof: probing `net use \\\\<ip>\\IPC$ "" /user:<acct>` over SSH is rejected for this account. ';
  const nla = nlaRequired ? 'NLA (UserAuthentication=1) then demands a credential that policy forbids; changing it needs console access. ' : '';
  return (
    'RDP is refused by policy: the target account has a blank password and ' + policy +
    ', so network logon is rejected ("blank passwords aren\'t allowed"). ' +
    proof + nla +
    'Not a transport problem: do not retry, set a password, or disable NLA.'
  );
}

export function classifyRdp(input: RdpProbeInput): RdpVerdict {
  const evidence = { ...input };
  if (!input.declared) {
    return {
      available: false,
      code: 'not-declared',
      reason: 'RDP is not declared for this host (capabilities.rdp=false); it was never enabled in control-mcp config.',
      evidence,
    };
  }
  if (!input.sshAlive && !input.tcpOpen) {
    return {
      available: false,
      code: 'host-unreachable',
      reason: 'No interface answered SSH and TCP/3389 is closed; the host appears down or firewalled.',
      evidence,
    };
  }
  if (!input.tcpOpen) {
    return {
      available: false,
      code: 'rdp-port-closed',
      reason: 'TCP/3389 refused or filtered, so the RDP listener is down (fDenyTSConnections=1, TermService stopped, or firewall).',
      evidence,
    };
  }
  if (input.blankPasswordAccount) {
    return { available: false, code: 'blank-password-policy', reason: blankPasswordReason(input.limitBlankPasswordUse, input.nlaRequired), evidence };
  }
  if (input.nlaRequired && input.hasCredential === false) {
    return {
      available: false,
      code: 'nla-credential-missing',
      reason: 'Server requires NLA (UserAuthentication=1) but no credential could be resolved for the RDP account.',
      evidence,
    };
  }
  const cred =
    input.hasCredential === true
      ? 'a credential path is configured (cmdkey / passwordEnv / credentialTarget) — not verified end-to-end over the network'
      : 'credential not verified — this is a network/availability verdict only';
  return { available: true, reason: `RDP listener open; ${cred}.` };
}

export interface InterfacePick {
  address: string;
  degraded: boolean;
}

export function pickInterface(
  primary: string,
  alternates: string[],
  reachable: Record<string, boolean>,
): InterfacePick | null {
  if (Object.hasOwn(reachable, primary) && reachable[primary]) return { address: primary, degraded: false };
  for (const alt of alternates) {
    if (Object.hasOwn(reachable, alt) && reachable[alt]) return { address: alt, degraded: true };
  }
  return null;
}
