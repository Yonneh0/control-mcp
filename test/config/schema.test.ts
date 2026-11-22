import { describe, it, expect } from 'vitest';
import { ConfigSchema, HostSchema } from '../../src/config/schema.js';
import { parseConfigText, resolveDefaultHost } from '../../src/config/loader.js';
import type { ControlConfig, HostConfig } from '../../src/config/schema.js';

const MIN_IN = {
  name: 'um780',
  address: '10.0.0.7',
  os: 'linux',
  ssh: { user: 'builder', privateKeyPath: '/home/builder/.ssh/id_ed25519' },
};

const MIN_OUT: HostConfig = {
  name: 'um780',
  address: '10.0.0.7',
  os: 'linux',
  ssh: { port: 22, user: 'builder', privateKeyPath: '/home/builder/.ssh/id_ed25519' },
  alternateAddresses: [],
  capabilities: { rdp: false },
};

const MIN_CFG: ControlConfig = {
  hosts: [MIN_OUT],
  safety: { refuseSelfSevering: true, firewallProfile: 'Any' },
};

const GHOST_DEFAULT_TOML = `defaultHost = "ghost"

[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
`;

// The first zod issue, joined the way the loader joins it. 'ACCEPTED' means the
// schema let the payload through, which is how a "this must parse" case reads.
function rejectedPath(fn: () => unknown): string {
  let failure: unknown;
  try {
    fn();
  } catch (caught) {
    failure = caught;
  }
  if (failure === undefined) {
    return 'ACCEPTED';
  }
  const issues = (failure as { issues?: unknown[] }).issues ?? [];
  const path = (issues[0] as { path?: unknown[] }).path ?? [];
  return path.map((part) => String(part)).join('.');
}

describe('HostSchema', () => {
  it('accepts a minimal host and fills the ssh port with 22', () => {
    expect(HostSchema.parse(MIN_IN)).toEqual(MIN_OUT);
  });

  it('defaults alternateAddresses to the empty list and capabilities.rdp to false', () => {
    const host = HostSchema.parse(MIN_IN);
    expect(host.alternateAddresses).toEqual([]);
    expect(host.capabilities).toEqual({ rdp: false });
  });

  it('applies the rdp defaults 3389 and 1920x1080 from a user-only rdp block', () => {
    const host = HostSchema.parse({ ...MIN_IN, rdp: { user: 'operator' } });
    expect(host.rdp).toEqual({ port: 3389, user: 'operator', width: 1920, height: 1080 });
  });

  it('treats the whole rdp block as optional', () => {
    expect(HostSchema.parse(MIN_IN).rdp).toBeUndefined();
  });

  it('accepts the optional ssh password next to a key', () => {
    const host = HostSchema.parse({ ...MIN_IN, ssh: { ...MIN_IN.ssh, password: 'rotate-monthly' } });
    expect(host.ssh.password).toBe('rotate-monthly');
    expect(host.ssh.port).toBe(22);
  });

  // privateKeyPath is no longer the required credential: any one of the three
  // satisfies the host, and the schema refuses only an ssh block with none.
  it('accepts an ssh block whose only credential is an environment variable', () => {
    const host = HostSchema.parse({
      ...MIN_IN,
      ssh: { user: 'builder', passwordEnv: 'CONTROL_MCP_PW_UM780' },
    });
    expect(host.ssh.passwordEnv).toBe('CONTROL_MCP_PW_UM780');
    expect(host.ssh.privateKeyPath).toBeUndefined();
    expect(host.ssh.port).toBe(22);
  });

  it('accepts an ssh block whose only credential is an inline password', () => {
    const host = HostSchema.parse({ ...MIN_IN, ssh: { user: 'builder', password: 'rotate-monthly' } });
    expect(host.ssh.password).toBe('rotate-monthly');
    expect(host.ssh.privateKeyPath).toBeUndefined();
  });

  // The passwordEnv rule is now SHARED between ssh and rdp (one PasswordEnvSchema),
  // so a lower-case value is rejected in the rdp block just as it is for ssh.
  it('refuses a lower-case passwordEnv in the rdp block, like ssh does', () => {
    expect(() => HostSchema.parse({ ...MIN_IN, rdp: { user: 'operator', passwordEnv: 'press_room_pw' } })).toThrow(/UPPER_SNAKE/);
  });

  it('accepts an UPPER_SNAKE passwordEnv in the rdp block and defaults the size', () => {
    const host = HostSchema.parse({ ...MIN_IN, rdp: { user: 'operator', passwordEnv: 'CONTROL_MCP_PW_PRESS_ROOM' } });
    expect(host.rdp?.passwordEnv).toBe('CONTROL_MCP_PW_PRESS_ROOM');
    expect(host.rdp?.width).toBe(1920);
  });

  it('keeps the rdp credential indirection fields', () => {
    const host = HostSchema.parse({
      ...MIN_IN,
      rdp: {
        user: 'operator',
        domain: 'CONTOSO',
        credentialTarget: 'TERMSRV/press-room',
        passwordEnv: 'CONTROL_MCP_PW_PRESS_ROOM',
      },
    });
    expect(host.rdp?.domain).toBe('CONTOSO');
    expect(host.rdp?.credentialTarget).toBe('TERMSRV/press-room');
    expect(host.rdp?.passwordEnv).toBe('CONTROL_MCP_PW_PRESS_ROOM');
    expect(host.rdp?.width).toBe(1920);
  });

  it('honours capabilities.rdp true and an empty capabilities block alike', () => {
    expect(HostSchema.parse({ ...MIN_IN, capabilities: { rdp: true } }).capabilities).toEqual({ rdp: true });
    // An empty block is not "no capability information": the nested default says
    // the same thing the outer default does.
    expect(HostSchema.parse({ ...MIN_IN, capabilities: {} }).capabilities).toEqual({ rdp: false });
  });

  it('preserves addresses and ports the operator actually chose', () => {
    const host = HostSchema.parse({
      ...MIN_IN,
      ssh: { ...MIN_IN.ssh, port: 2202 },
      alternateAddresses: ['10.0.0.9', 'um780.lan'],
      rdp: { user: 'operator', port: 3390, width: 1280, height: 720 },
    });
    expect(host.ssh.port).toBe(2202);
    expect(host.alternateAddresses).toEqual(['10.0.0.9', 'um780.lan']);
    expect(host.rdp).toEqual({ port: 3390, user: 'operator', width: 1280, height: 720 });
  });

  const HOST_REJECTS: Array<{ label: string; payload: unknown; path: string }> = [
    { label: 'name is empty', payload: { ...MIN_IN, name: '' }, path: 'name' },
    { label: 'address is absent', payload: { ...MIN_IN, address: undefined }, path: 'address' },
    { label: 'os is macos', payload: { ...MIN_IN, os: 'macos' }, path: 'os' },
    { label: 'os is Linux rather than linux', payload: { ...MIN_IN, os: 'Linux' }, path: 'os' },
    { label: 'ssh block is absent', payload: { ...MIN_IN, ssh: undefined }, path: 'ssh' },
    { label: 'ssh user is empty', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, user: '' } }, path: 'ssh.user' },
    { label: 'ssh privateKeyPath is empty', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, privateKeyPath: '' } }, path: 'ssh.privateKeyPath' },
    { label: 'ssh password is empty', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, password: '' } }, path: 'ssh.password' },
    { label: 'ssh passwordEnv is empty', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, passwordEnv: '' } }, path: 'ssh.passwordEnv' },
    { label: 'ssh passwordEnv is lower case', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, passwordEnv: 'um780_pw' } }, path: 'ssh.passwordEnv' },
    { label: 'ssh passwordEnv has a dash', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, passwordEnv: 'UM780-PW' } }, path: 'ssh.passwordEnv' },
    { label: 'ssh has no credential at all', payload: { ...MIN_IN, ssh: { user: 'builder' } }, path: 'ssh.privateKeyPath' },
    { label: 'ssh port is 0', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, port: 0 } }, path: 'ssh.port' },
    { label: 'ssh port is 65536', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, port: 65536 } }, path: 'ssh.port' },
    { label: 'ssh port is 22.5', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, port: 22.5 } }, path: 'ssh.port' },
    { label: 'ssh port is the string 22', payload: { ...MIN_IN, ssh: { ...MIN_IN.ssh, port: '22' } }, path: 'ssh.port' },
    { label: 'rdp block is present without a user', payload: { ...MIN_IN, rdp: {} }, path: 'rdp.user' },
    { label: 'rdp port is 0', payload: { ...MIN_IN, rdp: { user: 'operator', port: 0 } }, path: 'rdp.port' },
    { label: 'rdp port is 65536', payload: { ...MIN_IN, rdp: { user: 'operator', port: 65536 } }, path: 'rdp.port' },
    { label: 'rdp width is 639', payload: { ...MIN_IN, rdp: { user: 'operator', width: 639 } }, path: 'rdp.width' },
    { label: 'rdp width is 7681', payload: { ...MIN_IN, rdp: { user: 'operator', width: 7681 } }, path: 'rdp.width' },
    { label: 'rdp height is 479', payload: { ...MIN_IN, rdp: { user: 'operator', height: 479 } }, path: 'rdp.height' },
    { label: 'rdp height is 4321', payload: { ...MIN_IN, rdp: { user: 'operator', height: 4321 } }, path: 'rdp.height' },
    { label: 'capabilities.rdp is the string yes', payload: { ...MIN_IN, capabilities: { rdp: 'yes' } }, path: 'capabilities.rdp' },
    { label: 'alternateAddresses is a bare string', payload: { ...MIN_IN, alternateAddresses: '10.0.0.9' }, path: 'alternateAddresses' },
    { label: 'alternateAddresses carries a number', payload: { ...MIN_IN, alternateAddresses: ['10.0.0.9', 9] }, path: 'alternateAddresses.1' },
  ];

  it.each(HOST_REJECTS)('rejects $label and names $path', (row) => {
    expect(rejectedPath(() => HostSchema.parse(row.payload))).toBe(row.path);
  });

  // An ssh block nobody can authenticate with is the one config mistake that no
  // field-level rule can see, so superRefine says what to add.
  it('refuses an ssh block with no credential and names the three that would do', () => {
    expect(() => HostSchema.parse({ ...MIN_IN, ssh: { user: 'builder' } })).toThrow(/needs at least one of/);
    expect(() => HostSchema.parse({ ...MIN_IN, ssh: { user: 'builder' } })).toThrow(/privateKeyPath/);
  });

  describe('refuses keys it does not know', () => {
    it('refuses an unknown host-level key and blames the host object', () => {
      const payload = { ...MIN_IN, nickname: 'lathe bench' };
      expect(rejectedPath(() => HostSchema.parse(payload))).toBe('');
      // zod reports the offending key name, not a field path, so the operator
      // can still find the line they mistyped.
      expect(() => HostSchema.parse(payload)).toThrow(/nickname/);
    });

    it('refuses an unknown key inside ssh rather than ignoring it', () => {
      const payload = { ...MIN_IN, ssh: { ...MIN_IN.ssh, hostFingerprint: 'SHA256:abc' } };
      expect(rejectedPath(() => HostSchema.parse(payload))).toBe('ssh');
      expect(() => HostSchema.parse(payload)).toThrow(/hostFingerprint/);
    });

    it('refuses an unknown key inside rdp', () => {
      const payload = { ...MIN_IN, rdp: { user: 'operator', delegation: 'full' } };
      expect(rejectedPath(() => HostSchema.parse(payload))).toBe('rdp');
      expect(() => HostSchema.parse(payload)).toThrow(/delegation/);
    });
  });
});

describe('ConfigSchema', () => {
  it('accepts a one-host config and prefaults safety', () => {
    // safety is not marked optional; SafetySchema's .prefault({}) is what lets
    // a config file that never mentions [safety] still get both defaults.
    expect(ConfigSchema.parse({ hosts: [MIN_IN] })).toEqual(MIN_CFG);
    expect(ConfigSchema.parse({ hosts: [MIN_IN], safety: {} })).toEqual(MIN_CFG);
  });

  it('keeps safety values the operator chose', () => {
    const cfg = ConfigSchema.parse({ hosts: [MIN_IN], safety: { refuseSelfSevering: false, firewallProfile: 'Domain' } });
    expect(cfg.safety).toEqual({ refuseSelfSevering: false, firewallProfile: 'Domain' });
  });

  it('accepts a two-host config with an explicit defaultHost', () => {
    const cfg = ConfigSchema.parse({
      hosts: [MIN_IN, { ...MIN_IN, name: 'press-room', address: '192.168.4.20', os: 'windows' }],
      defaultHost: 'press-room',
    });
    expect(cfg.hosts.length).toBe(2);
    expect(cfg.hosts[1]).toEqual({
      name: 'press-room',
      address: '192.168.4.20',
      os: 'windows',
      ssh: { port: 22, user: 'builder', privateKeyPath: '/home/builder/.ssh/id_ed25519' },
      alternateAddresses: [],
      capabilities: { rdp: false },
    });
    expect(cfg.defaultHost).toBe('press-room');
    expect(cfg.safety).toEqual({ refuseSelfSevering: true, firewallProfile: 'Any' });
  });

  const CFG_REJECTS: Array<{ label: string; payload: unknown; path: string }> = [
    { label: 'hosts is an empty array', payload: { hosts: [] }, path: 'hosts' },
    { label: 'hosts is missing', payload: { defaultHost: 'um780' }, path: 'hosts' },
    { label: 'hosts is a single object instead of a list', payload: { hosts: MIN_IN }, path: 'hosts' },
    { label: 'the second host has os macos', payload: { hosts: [MIN_IN, { ...MIN_IN, os: 'macos' }] }, path: 'hosts.1.os' },
    { label: 'the first host has capabilities.rdp = 1', payload: { hosts: [{ ...MIN_IN, capabilities: { rdp: 1 } }] }, path: 'hosts.0.capabilities.rdp' },
    { label: 'the first host has an empty name', payload: { hosts: [{ ...MIN_IN, name: '' }] }, path: 'hosts.0.name' },
    { label: 'firewallProfile is Network', payload: { hosts: [MIN_IN], safety: { firewallProfile: 'Network' } }, path: 'safety.firewallProfile' },
    { label: 'refuseSelfSevering is the string true', payload: { hosts: [MIN_IN], safety: { refuseSelfSevering: 'true' } }, path: 'safety.refuseSelfSevering' },
    { label: 'an unknown key sits inside safety', payload: { hosts: [MIN_IN], safety: { selfSevering: true } }, path: 'safety' },
    { label: 'the first host has an ssh block with no credential', payload: { hosts: [{ ...MIN_IN, ssh: { user: 'builder' } }] }, path: 'hosts.0.ssh.privateKeyPath' },
    { label: 'the first host has a lower-case ssh passwordEnv', payload: { hosts: [{ ...MIN_IN, ssh: { ...MIN_IN.ssh, passwordEnv: 'um780_pw' } }] }, path: 'hosts.0.ssh.passwordEnv' },
    { label: 'an unknown key sits beside hosts', payload: { hosts: [MIN_IN], notes: 'lathe' }, path: '' },
    { label: 'an unknown key sits inside a host', payload: { hosts: [{ ...MIN_IN, nickname: 'lathe' }] }, path: 'hosts.0' },
  ];

  it.each(CFG_REJECTS)('rejects $label and blames $path', (row) => {
    expect(rejectedPath(() => ConfigSchema.parse(row.payload))).toBe(row.path);
  });

  it('refuses a key it does not know inside safety by name', () => {
    expect(() => ConfigSchema.parse({ hosts: [MIN_IN], safety: { selfSevering: true } })).toThrow(/selfSevering/);
  });

  // The schema's job is shape; the name it points at is a resolution concern, so
  // a defaultHost that matches nothing parses here and is refused one layer up.
  it('accepts a defaultHost that names no host, and the loader is what refuses it', () => {
    const cfg = ConfigSchema.parse({ hosts: [MIN_IN], defaultHost: 'ghost' });
    expect(cfg.defaultHost).toBe('ghost');
    // resolveDefaultHost echoes what it was given; it only refuses when nothing
    // was chosen at all.
    expect(resolveDefaultHost(cfg)).toBe('ghost');
    expect(() => parseConfigText(GHOST_DEFAULT_TOML, 'inline/ghost-default.toml')).toThrow(/does not match any host/);
  });
});
