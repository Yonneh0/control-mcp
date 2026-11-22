import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { ControlError } from '../errors.js';

// `%NAME%` indirection, the form a Windows operator reaches for first. Every
// MCP server process gets whatever environment the client that spawned it had,
// so `%USERPROFILE%\keys\id` survives a config file moving between machines and
// users, which an absolute path baked into the file does not.
const ENV_TOKEN = /%([A-Za-z_][A-Za-z0-9_]*)%/g;

// An unset name keeps its literal `%NAME%` rather than collapsing to an empty
// string: an empty expansion silently re-anchors the rest of the path onto the
// server's cwd, which produces a confusing path nobody typed and a failure that
// blames the wrong directory. Left in place, the path in the error is the path
// in the config, and the missing variable is visible in it.
function expandEnvTokens(p: string): string {
  return p.replace(ENV_TOKEN, (token: string, name: string) => process.env[name] ?? token);
}

/**
 * Expand a configured path into something the OS can open.
 *
 * Handles three anchored forms: a bare `~`, a `~/` or `~\` prefix, and any
 * number of `%VAR%` tokens taken from `process.env`.
 *
 * A bare relative path still resolves, but against the current working
 * directory of the MCP server process — which is whatever the launching client
 * happened to set it to and is not stable between launches. Callers should pass
 * an absolute path, or one anchored with `~` or `%VAR%`, so the expansion does
 * not depend on the launcher.
 */
export function expandPath(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return join(homedir(), expandEnvTokens(p.slice(2)));
  return resolve(expandEnvTokens(p));
}

export interface ResolvedSecret {
  // WARNING: plaintext credential. `value` is an ordinary enumerable string, so
  // JSON.stringify(secret), a structured log line, a thrown error's detail, or a
  // returned tool payload would all disclose it verbatim. Never put `value` in a
  // returned tool payload or a log line — use describeSecret() to talk about a
  // secret, and hand `value` only to the transport that authenticates with it.
  value: string;
  source: string;
}

/**
 * Log-safe rendering of a resolved secret: names where the credential came
 * from (`env:CONTROL_MCP_PW_LANBOX`, `config`, …) and never the credential
 * itself. Safe to embed in a tool payload or a log line.
 */
export function describeSecret(s: ResolvedSecret): string {
  return s.source;
}

export function readPasswordFromEnv(hostName: string, envVar?: string): ResolvedSecret | undefined {
  const candidates = envVar ? [envVar] : [`CONTROL_MCP_PW_${hostName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`];
  for (const name of candidates) {
    // Read the raw value rather than testing it for truthiness. An exported but
    // empty variable is a misconfiguration, not an absence: silently skipping it
    // makes the failure surface later as ssh2's "All authentication methods
    // failed", with no hint that the variable the operator just set is blank.
    const value = process.env[name];
    if (value === undefined) continue;
    if (value === '') {
      // The detail names the variable only; the (empty) value is never echoed.
      throw new ControlError(
        'AUTH_FAILED',
        `Environment variable "${name}" for host "${hostName}" is set to an empty string. Unset it to fall back to another credential, or set it to the real password.`,
        { envVar: name, host: hostName },
      );
    }
    return { value, source: `env:${name}` };
  }
  return undefined;
}

function errnoOf(caught: unknown): string | undefined {
  return caught instanceof Error ? (caught as Error & { code?: string }).code : undefined;
}

/**
 * Validate a configured private key path and return it expanded.
 *
 * Checks existence, then that it is a regular file, then that this process can
 * actually open it — the three ways a `privateKeyPath` is wrong, distinguished
 * here so the operator gets the path and the reason instead of ssh2 failing
 * later with an opaque parse or authentication error. The key contents are read
 * only to prove they can be read; they are discarded, never returned, and never
 * placed in an error message or detail.
 */
export function requirePrivateKey(privateKeyPath: string, hostName: string): string {
  const abs = expandPath(privateKeyPath);

  try {
    const stats = statSync(abs);
    if (!stats.isFile()) {
      throw new ControlError(
        'AUTH_FAILED',
        `SSH private key for host "${hostName}" exists but is not a regular file: ${abs}`,
        { privateKeyPath: abs },
        'Point privateKeyPath at a key file, not a directory or a special file.',
      );
    }
  } catch (caught) {
    if (caught instanceof ControlError) throw caught;
    const code = errnoOf(caught);
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      throw new ControlError(
        'AUTH_FAILED',
        `SSH private key for host "${hostName}" not found: ${abs}`,
        { privateKeyPath: abs },
        'Set privateKeyPath to an absolute path, or one anchored with ~ or %VAR%.',
      );
    }
    throw new ControlError(
      'AUTH_FAILED',
      `SSH private key for host "${hostName}" could not be inspected: ${abs} (${code ?? String(caught)})`,
      { privateKeyPath: abs },
    );
  }

  try {
    readFileSync(abs);
  } catch (caught) {
    const code = errnoOf(caught);
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      throw new ControlError(
        'AUTH_FAILED',
        `SSH private key for host "${hostName}" not found: ${abs}`,
        { privateKeyPath: abs },
        'Set privateKeyPath to an absolute path, or one anchored with ~ or %VAR%.',
      );
    }
    if (code === 'EACCES' || code === 'EPERM') {
      throw new ControlError(
        'AUTH_FAILED',
        `SSH private key for host "${hostName}" exists but is not readable (check file ACLs): ${abs}`,
        { privateKeyPath: abs },
        'Grant this process read access to the key file, or point privateKeyPath at a key it can open.',
      );
    }
    throw new ControlError(
      'AUTH_FAILED',
      `SSH private key for host "${hostName}" could not be read: ${abs} (${code ?? String(caught)})`,
      { privateKeyPath: abs },
    );
  }

  return abs;
}
