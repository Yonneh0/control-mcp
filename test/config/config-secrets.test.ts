import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { homedir, tmpdir } from 'os';
import { isAbsolute, join, resolve, sep } from 'path';
import { ControlError } from '../../src/errors.js';
import { expandPath, readPasswordFromEnv, requirePrivateKey, describeSecret } from '../../src/config/secrets.js';
import type { ResolvedSecret } from '../../src/config/secrets.js';

// Every case here mutates process.env or the filesystem, so nothing may leak:
// withEnv restores each touched name to exactly what it was (including absent),
// and the temp directory is created per test and removed after it.
function withEnv(vars: Record<string, string | undefined>, fn: () => void): void {
  const saved = new Map<string, string | undefined>();
  for (const name of Object.keys(vars)) saved.set(name, process.env[name]);
  try {
    for (const [name, value] of Object.entries(vars)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fn();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

function expectControlError(fn: () => unknown): ControlError {
  let failure: unknown;
  try {
    fn();
  } catch (caught) {
    failure = caught;
  }
  if (failure instanceof ControlError) {
    return failure;
  }
  throw new Error(`expected a ControlError, got: ${String(failure)}`);
}

describe('expandPath', () => {
  it('expands a bare ~ to the home directory', () => {
    expect(expandPath('~')).toBe(homedir());
  });

  it('expands ~/keys/id under the home directory', () => {
    expect(expandPath('~/keys/id')).toBe(join(homedir(), 'keys', 'id'));
  });

  it('expands the Windows-shaped ~\\keys\\id under the home directory', () => {
    const expanded = expandPath('~\\keys\\id');
    expect(expanded.startsWith(join(homedir(), 'keys'))).toBe(true);
    // A POSIX path may legitimately contain a backslash, so the exact spelling
    // is only pinned where a backslash is a separator.
    if (process.platform === 'win32') expect(expanded).toBe(join(homedir(), 'keys', 'id'));
  });

  it('expands %USERPROFILE%\\keys\\id under the profile directory', () => {
    const home = homedir();
    withEnv({ USERPROFILE: home }, () => {
      const expanded = expandPath('%USERPROFILE%\\keys\\id');
      expect(expanded).not.toContain('%USERPROFILE%');
      expect(expanded.startsWith(resolve(home))).toBe(true);
      if (process.platform === 'win32') expect(expanded).toBe(join(home, 'keys', 'id'));
    });
  });

  it('expands an environment token in any position of a configured path', () => {
    const root = join(tmpdir(), 'control-mcp-secrets-root');
    withEnv({ CONTROL_MCP_TEST_ROOT: root }, () => {
      expect(expandPath(`%CONTROL_MCP_TEST_ROOT%${sep}id_ed25519`)).toBe(join(root, 'id_ed25519'));
      expect(expandPath(`%CONTROL_MCP_TEST_ROOT%`)).toBe(root);
    });
  });

  it('leaves an unset %VAR% token in place instead of collapsing the path', () => {
    withEnv({ CONTROL_MCP_NO_SUCH_ROOT: undefined }, () => {
      const expanded = expandPath('%CONTROL_MCP_NO_SUCH_ROOT%\\keys\\id');
      expect(expanded).toContain('%CONTROL_MCP_NO_SUCH_ROOT%');
      // Collapsing the unset name would have re-anchored 'keys' onto the cwd.
      expect(expanded).not.toBe(resolve(join('keys', 'id')));
    });
  });

  it('resolves a bare relative path against the server cwd, which is why configs should anchor paths', () => {
    expect(expandPath(join('keys', 'id_ed25519'))).toBe(join(process.cwd(), 'keys', 'id_ed25519'));
  });

  it('leaves an already absolute path alone', () => {
    const absolute = join(process.cwd(), 'keys', 'id_ed25519');
    expect(expandPath(absolute)).toBe(absolute);
  });
});

describe('readPasswordFromEnv', () => {
  it('returns the value with an env: source that never repeats the password', () => {
    withEnv({ CONTROL_MCP_PW_LANBOX: 's3cret' }, () => {
      const secret = readPasswordFromEnv('lanbox');
      if (!secret) throw new Error('expected a resolved secret');
      expect(secret.value).toBe('s3cret');
      expect(secret.source).toContain('CONTROL_MCP_PW_LANBOX');
      expect(secret.source).not.toContain('s3cret');
    });
  });

  it('honours an explicit envVar instead of the host-derived name', () => {
    withEnv({ CONTROL_MCP_PW_LANBOX: undefined, CONTROL_MCP_CUSTOM_PW: 's3cret' }, () => {
      const secret = readPasswordFromEnv('lanbox', 'CONTROL_MCP_CUSTOM_PW');
      if (!secret) throw new Error('expected a resolved secret');
      expect(secret.value).toBe('s3cret');
      expect(secret.source).toBe('env:CONTROL_MCP_CUSTOM_PW');
    });
  });

  it('returns undefined, not an empty string, for a genuinely unset variable', () => {
    withEnv({ CONTROL_MCP_PW_UNSET_HOST: undefined }, () => {
      expect(readPasswordFromEnv('unset-host')).toBeUndefined();
    });
  });

  it('refuses a variable that is set to an empty string instead of treating it as unset', () => {
    withEnv({ CONTROL_MCP_PW_EMPTY: '' }, () => {
      expect(() => readPasswordFromEnv('empty')).toThrow(/empty string/);
      const error = expectControlError(() => readPasswordFromEnv('empty'));
      expect(error.code).toBe('AUTH_FAILED');
      expect(error.message).toContain('CONTROL_MCP_PW_EMPTY');
      expect(error.message).toContain('is set to an empty string');
    });
  });

  it('reports an explicit empty envVar by the name the config used', () => {
    withEnv({ CONTROL_MCP_CUSTOM_PW: '' }, () => {
      const error = expectControlError(() => readPasswordFromEnv('lanbox', 'CONTROL_MCP_CUSTOM_PW'));
      expect(error.code).toBe('AUTH_FAILED');
      expect(error.message).toContain('CONTROL_MCP_CUSTOM_PW');
      expect(error.message).toContain('empty string');
    });
  });
});

describe('requirePrivateKey', () => {
  const MISSING = join(tmpdir(), 'control-mcp-secrets-missing', 'id_ed25519');

  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'control-mcp-secrets-'));
  });

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('refuses a key that does not exist with AUTH_FAILED saying not found', () => {
    expect(existsSync(MISSING)).toBe(false);
    const error = expectControlError(() => requirePrivateKey(MISSING, 'lanbox'));
    expect(error.code).toBe('AUTH_FAILED');
    expect(error.message).toContain('not found');
    expect(error.message).toContain('id_ed25519');
    if (!error.detail) throw new Error('expected the error to carry the path it rejected');
    expect(isAbsolute(String(error.detail.privateKeyPath))).toBe(true);
  });

  it('refuses a path whose parent exists but whose file does not, and names the expanded path', () => {
    const deep = join(dir, 'absent', 'id_ed25519');
    const error = expectControlError(() => requirePrivateKey(deep, 'lanbox'));
    expect(error.code).toBe('AUTH_FAILED');
    expect(error.message).toContain('not found');
    expect(error.message).toContain(deep);
  });

  it('refuses a directory with a message that says it is not a regular file', () => {
    const error = expectControlError(() => requirePrivateKey(dir, 'lanbox'));
    expect(error.code).toBe('AUTH_FAILED');
    expect(error.message).toContain('not a regular file');
  });

  it('returns the expanded absolute path for a readable key and never echoes its contents', () => {
    const keyPath = join(dir, 'id_ed25519');
    const secretKeyMaterial = '-----BEGIN OPENSSH PRIVATE KEY-----\nnever-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n';
    writeFileSync(keyPath, secretKeyMaterial);
    const resolvedPath = requirePrivateKey(keyPath, 'lanbox');
    expect(resolvedPath).toBe(keyPath);
    expect(isAbsolute(resolvedPath)).toBe(true);
    expect(resolvedPath).not.toContain('PRIVATE KEY');
  });

  // The unreadable-key branch (EACCES/EPERM) is covered by code inspection
  // rather than a test: forcing it needs an ACL change that a privileged CI
  // runner can silently satisfy, which would make the suite flaky in the
  // opposite direction.
});

describe('describeSecret', () => {
  const secret: ResolvedSecret = { value: 's3cret', source: 'env:CONTROL_MCP_PW_LANBOX' };

  it('names the source and nothing else', () => {
    expect(describeSecret(secret)).toBe('env:CONTROL_MCP_PW_LANBOX');
  });

  it('never leaks the value, directly or through JSON', () => {
    expect(describeSecret(secret)).not.toContain('s3cret');
    expect(JSON.stringify(describeSecret(secret))).not.toContain('s3cret');
    expect(JSON.stringify(secret)).toContain('s3cret');
  });

  it('describes a secret resolved from the environment without the password', () => {
    withEnv({ CONTROL_MCP_PW_LANBOX: 's3cret' }, () => {
      const resolved = readPasswordFromEnv('lanbox');
      if (!resolved) throw new Error('expected a resolved secret');
      expect(describeSecret(resolved)).toBe('env:CONTROL_MCP_PW_LANBOX');
      expect(describeSecret(resolved)).not.toContain('s3cret');
    });
  });
});
