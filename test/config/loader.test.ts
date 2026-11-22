import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { ConfigError, parseConfigText, resolveDefaultHost, getHost } from '../../src/config/loader.js';
import type { ControlConfig } from '../../src/config/schema.js';

function fixture(name: string): [string, string] {
  const url = new URL(`../fixtures/${name}`, import.meta.url);
  const path = fileURLToPath(url);
  return [readFileSync(path, 'utf8'), path];
}

function expectConfigError(fn: () => unknown): ConfigError {
  let failure: unknown;
  try {
    fn();
  } catch (caught) {
    failure = caught;
  }
  if (failure instanceof ConfigError) {
    return failure;
  }
  throw new Error(`expected a ConfigError, got: ${String(failure)}`);
}

const MIN_TOML = `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
`;

const MIN_PARSED: ControlConfig = {
  hosts: [
    {
      name: 'um780',
      address: '10.0.0.7',
      os: 'linux',
      ssh: { port: 22, user: 'builder', privateKeyPath: '/home/builder/.ssh/id_ed25519' },
      alternateAddresses: [],
      capabilities: { rdp: false },
    },
  ],
  safety: { refuseSelfSevering: true, firewallProfile: 'Any' },
};

const GOOD_PARSED: ControlConfig = {
  defaultHost: 'shop-floor',
  hosts: [
    {
      name: 'shop-floor',
      address: '10.0.0.7',
      os: 'linux',
      ssh: { port: 22, user: 'builder', privateKeyPath: '/home/builder/.ssh/id_ed25519' },
      alternateAddresses: ['10.0.0.9', '10.0.0.10'],
      capabilities: { rdp: false },
    },
    {
      name: 'press-room',
      address: '192.168.4.20',
      os: 'windows',
      ssh: { port: 22, user: 'operator', privateKeyPath: 'C:/Users/operator/.ssh/id_ed25519' },
      rdp: {
        port: 3389,
        user: 'operator',
        domain: 'CONTOSO',
        credentialTarget: 'TERMSRV/press-room',
        passwordEnv: 'CONTROL_MCP_PW_PRESS_ROOM',
        width: 1280,
        height: 720,
      },
      alternateAddresses: [],
      capabilities: { rdp: true },
    },
  ],
  safety: { refuseSelfSevering: true, firewallProfile: 'Any' },
};

const TWO_HOSTS_NO_DEFAULT = `[[hosts]]
name = "shop-floor"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"

[[hosts]]
name = "press-room"
address = "192.168.4.20"
os = "windows"

[hosts.ssh]
user = "operator"
privateKeyPath = "C:/Users/operator/.ssh/id_ed25519"
`;

// Only used for keys that do not collide with the host keys above it, because
// TOML refuses a key twice in the same table.
const AT_HOST_LEVEL = (extra: string): string => `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"
${extra}

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
`;

const AT_ROOT_LEVEL = (extra: string): string => `${extra}

${MIN_TOML}
`;

const MIN_NO_CREDENTIAL_TOML = `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
`;

describe('parseConfigText', () => {
  it('parses the fixture and applies every transport default', () => {
    const [text, path] = fixture('hosts.good.toml');
    expect(parseConfigText(text, path)).toEqual(GOOD_PARSED);
  });

  it('parses the smallest legal config, which has no [safety] section', () => {
    expect(parseConfigText(MIN_TOML, 'inline/min.toml')).toEqual(MIN_PARSED);
  });

  it('keeps an rdp block that carries domain, credentialTarget, and passwordEnv', () => {
    const cfg = parseConfigText(
      AT_HOST_LEVEL(`
[hosts.rdp]
user = "operator"
domain = "CONTOSO"
credentialTarget = "TERMSRV/um780"
passwordEnv = "CONTROL_MCP_PW_UM780"`),
      'inline/rdp-indirection.toml',
    );
    const rdp = cfg.hosts[0].rdp;
    expect(rdp).toBeDefined();
    expect(rdp?.domain).toBe('CONTOSO');
    expect(rdp?.credentialTarget).toBe('TERMSRV/um780');
    expect(rdp?.passwordEnv).toBe('CONTROL_MCP_PW_UM780');
    expect(rdp?.port).toBe(3389);
    expect(rdp?.width).toBe(1920);
  });

  // Any one of the three credentials is enough, so a config that keeps the
  // secret out of the file (and out of the process arguments) is accepted.
  it('accepts an ssh credential that comes only from an environment variable', () => {
    const cfg = parseConfigText(
      `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
passwordEnv = "CONTROL_MCP_PW_UM780"
`,
      'inline/env-credential.toml',
    );
    expect(cfg.hosts[0].ssh.passwordEnv).toBe('CONTROL_MCP_PW_UM780');
    expect(cfg.hosts[0].ssh.privateKeyPath).toBeUndefined();
    expect(cfg.hosts[0].ssh.port).toBe(22);
  });

  describe('refuses wrong shapes and names the offending key', () => {
    const WRONG_SHAPES: Array<{ label: string; toml: string; path: string }> = [
      {
        label: 'os is a number',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = 7

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
`,
        path: 'hosts.0.os',
      },
      {
        label: 'name is empty',
        toml: `[[hosts]]
name = ""
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
`,
        path: 'hosts.0.name',
      },
      {
        label: 'a host has no ssh table',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"
`,
        path: 'hosts.0.ssh',
      },
      {
        label: 'ssh user is empty',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = ""
privateKeyPath = "/home/builder/.ssh/id_ed25519"
`,
        path: 'hosts.0.ssh.user',
      },
      {
        label: 'ssh port is above the range',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
port = 70000
`,
        path: 'hosts.0.ssh.port',
      },
      {
        label: 'ssh password is empty',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
password = ""
`,
        path: 'hosts.0.ssh.password',
      },
      {
        label: 'ssh passwordEnv is lower case',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
privateKeyPath = "/home/builder/.ssh/id_ed25519"
passwordEnv = "um780_pw"
`,
        path: 'hosts.0.ssh.passwordEnv',
      },
      {
        label: 'ssh has no credential at all',
        toml: `[[hosts]]
name = "um780"
address = "10.0.0.7"
os = "linux"

[hosts.ssh]
user = "builder"
`,
        path: 'hosts.0.ssh.privateKeyPath',
      },
      { label: 'alternateAddresses is a bare string', toml: AT_HOST_LEVEL('alternateAddresses = "10.0.0.9"'), path: 'hosts.0.alternateAddresses' },
      { label: 'capabilities is a bare boolean', toml: AT_HOST_LEVEL('capabilities = true'), path: 'hosts.0.capabilities' },
      { label: 'capabilities.rdp is a string', toml: AT_HOST_LEVEL('[hosts.capabilities]\nrdp = "yes"'), path: 'hosts.0.capabilities.rdp' },
      { label: 'an rdp width is a string', toml: AT_HOST_LEVEL('\n[hosts.rdp]\nuser = "operator"\nwidth = "1920"'), path: 'hosts.0.rdp.width' },
      { label: 'hosts is an empty array', toml: 'hosts = []', path: 'hosts' },
    ];

    it.each(WRONG_SHAPES)('refuses $label and blames $path', (row) => {
      const error = expectConfigError(() => parseConfigText(row.toml, 'inline/table-driven.toml'));
      expect(error.path).toBe(row.path);
    });

    it('refuses an ssh block nobody can authenticate with and says what to add', () => {
      const error = expectConfigError(() => parseConfigText(MIN_NO_CREDENTIAL_TOML, 'inline/no-credential.toml'));
      expect(error.path).toBe('hosts.0.ssh.privateKeyPath');
      expect(error.message).toContain('needs at least one of');
    });

    it('refuses a config with no hosts at all', () => {
      const error = expectConfigError(() => parseConfigText('defaultHost = "um780"\n', 'inline/no-hosts.toml'));
      expect(error.path).toBe('hosts');
    });

    it('refuses an unknown root key and admits there is no field path to name', () => {
      const error = expectConfigError(() => parseConfigText(AT_ROOT_LEVEL('notes = "lathe"'), 'inline/extra-root-key.toml'));
      expect(error.path).toBeUndefined();
      expect(error.hint).toBe('Offending key: <root>');
      expect(error.message).toContain('notes');
    });

    it('refuses an unknown key inside a host and blames the host itself', () => {
      const error = expectConfigError(() => parseConfigText(AT_HOST_LEVEL('nickname = "lathe"'), 'inline/extra-host-key.toml'));
      expect(error.path).toBe('hosts.0');
      expect(error.message).toContain('nickname');
    });

    it('points at a wrong-typed port in the checked-in fixture', () => {
      const [text, path] = fixture('hosts.bad-type.toml');
      const error = expectConfigError(() => parseConfigText(text, path));
      expect(error.name).toBe('ConfigError');
      expect(error.path).toBe('hosts.0.ssh.port');
      expect(error.hint).toBe('Offending key: hosts.0.ssh.port');
    });

    it('refuses a defaultHost that names no host', () => {
      const error = expectConfigError(() => parseConfigText(AT_ROOT_LEVEL('defaultHost = "ghost"'), 'inline/ghost-default.toml'));
      expect(error.path).toBe('defaultHost');
      expect(error.message).toContain('does not match any host');
    });

    it('refuses broken TOML before it ever reaches the schema', () => {
      const error = expectConfigError(() => parseConfigText('[[hosts]\nname = "um780"\n', 'inline/broken.toml'));
      expect(error.message).toContain('TOML syntax error');
      expect(error.hint).toBe('Check for a missing quote or bracket.');
      expect(error.path).toBeUndefined();
    });
  });
});

describe('resolveDefaultHost', () => {
  it('returns the explicit defaultHost', () => {
    const [text, path] = fixture('hosts.good.toml');
    expect(resolveDefaultHost(parseConfigText(text, path))).toBe('shop-floor');
  });

  it('falls back to the only host when none was chosen', () => {
    expect(resolveDefaultHost(parseConfigText(MIN_TOML, 'inline/min.toml'))).toBe('um780');
  });

  it('refuses to guess between two hosts and names both ways out', () => {
    const cfg = parseConfigText(TWO_HOSTS_NO_DEFAULT, 'inline/two-hosts.toml');
    expect(() => resolveDefaultHost(cfg)).toThrow(/ambiguous/);
    const error = expectConfigError(() => resolveDefaultHost(cfg));
    expect(error.path).toBe('defaultHost');
    expect(error.message).toContain('shop-floor, press-room');
    expect(error.hint).toContain('Set defaultHost');
  });
});

describe('getHost', () => {
  it('resolves the host named by defaultHost', () => {
    const [text, path] = fixture('hosts.good.toml');
    const cfg = parseConfigText(text, path);
    expect(getHost(cfg)).toEqual(GOOD_PARSED.hosts[0]);
    expect(getHost(cfg, 'press-room')).toEqual(GOOD_PARSED.hosts[1]);
  });

  it('resolves a host by address as well as by name', () => {
    const [text, path] = fixture('hosts.good.toml');
    const host = getHost(parseConfigText(text, path), '192.168.4.20');
    expect(host.name).toBe('press-room');
    expect(host.rdp?.credentialTarget).toBe('TERMSRV/press-room');
  });

  it('refuses an unknown name and lists the candidates it does have', () => {
    const [text, path] = fixture('hosts.good.toml');
    const cfg = parseConfigText(text, path);
    expect(() => getHost(cfg, 'ghost')).toThrow(/Unknown host "ghost"/);
    const error = expectConfigError(() => getHost(cfg, 'ghost'));
    expect(error.path).toBe('hosts');
    // The hint now names addresses too, so a caller that passed an address can
    // learn which host owns it rather than only the host names.
    expect(error.hint).toContain('Known hosts');
    expect(error.hint).toContain('shop-floor');
    expect(error.hint).toContain('press-room');
    expect(error.hint).toContain('192.168.4.20');
  });

  it('inherits the ambiguity refusal when no host was named', () => {
    const cfg = parseConfigText(TWO_HOSTS_NO_DEFAULT, 'inline/two-hosts.toml');
    const error = expectConfigError(() => getHost(cfg));
    expect(error.message).toContain('ambiguous');
    expect(error.path).toBe('defaultHost');
  });
});
