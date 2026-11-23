import { describe, it, expect } from 'vitest';
import {
  classifySshState,
  rdpPolicyCommand,
  parseRdpPolicyLine,
  hasTermsrvTarget,
  magicPacket,
  parseArpWindows,
  parseArpLinux,
  ipToLong,
  longToIp,
} from '../src/transports/netprobe.js';

// windowsRdpPolicy interpolated a config-supplied `address` (schema: only min(1),
// no character validation) into a PowerShell `net use` string and a `new RegExp`,
// and `probeUser` into `/user:<user>`, with no escaping. Config is operator-
// trusted, but unescaped interpolation is the class of bug that bites when a value
// is copy-pasted wrong or a config is generated elsewhere — so the command builder
// is now a pure function with an allowlist guard that fails safe toward refusal.

describe('rdpPolicyCommand — allowlist guards (fail-safe toward refusal)', () => {
  const decode = (b64: string) => Buffer.from(b64, 'base64').toString('utf16le');

  it('builds the probe command for an ordinary address and user', () => {
    const b64 = rdpPolicyCommand('10.255.0.5', 'User');
    const ps = decode(b64);
    // The UNC segment and the user slot carry the values verbatim.
    expect(ps).toContain('\\\\10.255.0.5\\IPC$ "" /user:User');
    expect(ps).toContain('System error (\\d+)');
    expect(ps).toContain('LimitBlankPasswordUse');
    expect(ps).toContain('UserAuthentication');
    expect(ps).toContain('net use \\\\10.255.0.5\\IPC$ /delete');
  });

  it('accepts common hostname, domain-qualified and underscore forms', () => {
    for (const [address, user] of [
      ['msi.internal.example', 'User'],
      ['WORKSTATION-1', 'user.name'],
      ['10.255.0.4', 'DOMAIN\\admin'],
      ['host_2', 'svc-acct'],
    ] as const) {
      expect(() => rdpPolicyCommand(address, user)).not.toThrow();
    }
  });

  it('refuses an address carrying a shell/regex metacharacter', () => {
    // `$`, backtick, `'`, `"`, space, backslash, `;`, `(`, `)`, `|`, `&` and
    // control bytes all either expand inside PowerShell double quotes or make
    // the downstream RegExp throw — none belong in an address.
    for (const bad of ['10.0.0.1; reboot', 'a b', 'a`id`', "a'b", 'a$(id)', 'a\\b', 'a|b', 'a&b', 'a(b', 'a)b', 'a\nb']) {
      expect(() => rdpPolicyCommand(bad, 'User')).toThrow(/address/);
    }
  });

  it('refuses a username that could break out of the /user: argument', () => {
    // The pre-fix builder produced `... /user:x'; Get-Process 2>&1` verbatim —
    // a single-quoted PowerShell splice. Now it is refused before interpolation.
    for (const bad of ["x'; Get-Process", 'a`id`', 'a$(id)', 'a b', 'a$b', 'a|b', 'a;b', 'a\nb']) {
      expect(() => rdpPolicyCommand('10.0.0.1', bad)).toThrow(/user/);
    }
  });
});

describe('parseRdpPolicyLine — extraction is honest about missing fields', () => {
  it('extracts lbp/nla/netuse/err and the blank-password verdict', () => {
    expect(parseRdpPolicyLine('lbp=1 nla=1 netuse=2 err=1327')).toEqual({
      limitBlankPasswordUse: 1,
      nlaRequired: true,
      netuseCode: '2',
      netuseErr: '1327',
      blankPasswordAccount: true,
    });
  });

  it('a wrong NON-blank password (1326) is NOT a blank-password account', () => {
    expect(parseRdpPolicyLine('lbp=1 nla=1 netuse=2 err=1326').blankPasswordAccount).toBe(false);
  });

  it('a blank network logon that succeeded (exit 0, no error code) is not blank-rejected', () => {
    expect(parseRdpPolicyLine('lbp=0 nla=1 netuse=0 err=').blankPasswordAccount).toBe(false);
  });

  it('leaves unknown fields absent rather than guessed', () => {
    expect(parseRdpPolicyLine('')).toEqual({});
    expect(parseRdpPolicyLine('no machine output here')).toEqual({});
    expect(parseRdpPolicyLine('lbp=1').limitBlankPasswordUse).toBe(1);
    expect(parseRdpPolicyLine('lbp=1').blankPasswordAccount).toBeUndefined();
  });
});

describe('hasTermsrvTarget — a literal address never breaks the match', () => {
  const out = 'Target: Domain:target=termsrv/10.255.0.11\nType: Domain Password';
  it('finds an exact termsrv target', () => {
    expect(hasTermsrvTarget(out, '10.255.0.11')).toBe(true);
    expect(hasTermsrvTarget(out, 'TERMSRV/10.255.0.11'.split('/')[1])).toBe(true);
  });
  it('returns false for a different host', () => {
    expect(hasTermsrvTarget(out, '10.255.0.99')).toBe(false);
  });
  it('an address with regex metacharacters is matched literally, not thrown on', () => {
    // Pre-fix this built `new RegExp('...termsrv/1.2[abc]\\b')` and threw.
    expect(() => hasTermsrvTarget('', '1.2[abc]')).not.toThrow();
    expect(hasTermsrvTarget('', '1.2[abc]')).toBe(false);
  });
});

describe('magicPacket', () => {
  const expectValid = (mac: string) => {
    const b = magicPacket(mac);
    expect(b).not.toBeNull();
    expect(b!.length).toBe(102);
    expect(b!.subarray(0, 6).equals(Buffer.alloc(6, 0xff))).toBe(true);
    const body = b!.subarray(6).toString('hex');
    expect(body).toBe('aabbccddeeff'.repeat(16));
  };
  it('accepts common MAC spellings and builds the 102-byte packet', () => {
    for (const mac of ['AA:BB:CC:DD:EE:FF', 'aa-bb-cc-dd-ee-ff', 'AABBCCDDEEFF', 'aa bb cc dd ee ff', 'aabb.ccdd.eeff', 'Aa-Bb.Cc:Dd eE fF']) {
      expectValid(mac);
    }
  });
  it('rejects malformed MACs', () => {
    for (const mac of ['', '   ', 'not-a-mac', 'AABBCCDDEEF', 'AABBCCDDEEFFG', '12:34:56']) {
      expect(magicPacket(mac)).toBeNull();
    }
  });
});

describe('parseArpWindows / parseArpLinux', () => {
  it('parses Windows ARP rows and skips the header/interface lines', () => {
    const rows = parseArpWindows(
      'Interface: 10.0.0.5 --- 0xb\n  Internet Address      Physical Address      Type\n  10.0.0.1              aa-bb-cc-dd-ee-ff    dynamic\n  10.0.0.2              11-22-33-44-55-66   static\n  224.0.0.22            01-00-5e-00-00-16   static\n',
    );
    // All three are genuine ARP rows (224.0.0.22 is a real multicast entry);
    // only the interface/header lines are dropped.
    expect(rows.map((r) => r.address).sort()).toEqual(['10.0.0.1', '10.0.0.2', '224.0.0.22']);
    expect(rows.find((r) => r.address === '10.0.0.1')!.mac).toBe('AA-BB-CC-DD-EE-FF');
    expect(rows.every((r) => r.source === 'arp')).toBe(true);
  });
  it('parses Linux ARP incl. incomplete entries with a null MAC', () => {
    // net-tools format (leading "? (IP) at").
    const rows = parseArpLinux(
      '? (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n? (10.0.0.9) at <incomplete> on eth0\n',
    );
    expect(rows.length).toBe(2);
    expect(rows.find((r) => r.address === '10.0.0.1')!.mac).toBe('AA:BB:CC:DD:EE:FF');
    expect(rows.find((r) => r.address === '10.0.0.9')!.mac).toBeNull();
    expect(rows[0].iface).toBe('eth0');
  });
});

describe('ipToLong / longToIp', () => {
  it('round-trips valid addresses and rejects invalid octets/formats', () => {
    expect(ipToLong('10.0.0.5')).toBe(167772165);
    expect(longToIp(167772165)).toBe('10.0.0.5');
    expect(ipToLong('256.0.0.1')).toBeNull();
    expect(ipToLong('10.0.0')).toBeNull();
    expect(ipToLong('abc')).toBeNull();
  });
});
