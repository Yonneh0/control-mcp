import { parse as parseToml } from 'smol-toml';
import { ConfigSchema, type ControlConfig, type HostConfig } from './schema.js';

export class ConfigError extends Error {
  path?: string;
  hint?: string;
  constructor(message: string, path?: string, hint?: string) {
    super(message);
    this.name = 'ConfigError';
    this.path = path;
    this.hint = hint;
  }
}

export function parseConfigText(text: string, sourcePath: string): ControlConfig {
  let raw: unknown;
  try {
    raw = parseToml(text);
  } catch (err) {
    const line = (err as { line?: number }).line;
    throw new ConfigError(
      `TOML syntax error in ${sourcePath}${line ? ` (line ${line})` : ''}: ${(err as Error).message}`,
      undefined,
      'Check for a missing quote or bracket.',
    );
  }

  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    // Report up to 5 problems in one round-trip so an author fixing a fresh
    // config does not pay one MCP call per typo. Only paths and zod's messages
    // (which expose types, never values) are shown, so a bad password is not
    // echoed back.
    const shown = parsed.error.issues.slice(0, 5);
    const lines = shown.map((i) => {
      const p = i.path.join('.');
      return p ? `- ${p}: ${i.message}` : `- ${i.message}`;
    });
    if (parsed.error.issues.length > shown.length) {
      lines.push(`- …and ${parsed.error.issues.length - shown.length} more`);
    }
    const first = shown[0];
    const firstPath = first.path.join('.');
    throw new ConfigError(
      `Invalid config at ${sourcePath}:\n${lines.join('\n')}`,
      firstPath || undefined,
      parsed.error.issues.length === 1
        ? `Offending key: ${firstPath || '<root>'}`
        : `First offending key: ${firstPath || '<root>'} (see the list above)`,
    );
  }

  const cfg = parsed.data;
  if (cfg.defaultHost && !cfg.hosts.some((h) => h.name === cfg.defaultHost)) {
    throw new ConfigError(
      `defaultHost "${cfg.defaultHost}" does not match any host in ${sourcePath}`,
      'defaultHost',
      'Names must match a [[hosts]] name entry.',
    );
  }
  return cfg;
}

export function resolveDefaultHost(cfg: ControlConfig): string {
  if (cfg.defaultHost) return cfg.defaultHost;
  if (cfg.hosts.length === 1) return cfg.hosts[0].name;
  const names = cfg.hosts.map((h) => h.name).join(', ');
  throw new ConfigError(
    `No defaultHost configured and ${cfg.hosts.length} hosts are defined (${names}); the call is ambiguous`,
    'defaultHost',
    'Set defaultHost in the config or pass host explicitly.',
  );
}

export function getHost(cfg: ControlConfig, name?: string): HostConfig {
  if (!name) {
    const defName = resolveDefaultHost(cfg);
    const def = cfg.hosts.find((h) => h.name === defName);
    if (!def) {
      throw new ConfigError(
        `defaultHost "${defName}" is not defined in the running config`,
        'defaultHost',
        `Configured hosts: ${cfg.hosts.map((h) => h.name).join(', ')}`,
      );
    }
    return def;
  }
  // Resolve by name, primary address, or any alternate; a caller may pass any of
  // the addresses host_list/host_status advertise. Gather every match rather than
  // taking the first, so a key that belongs to two hosts is refused, not guessed.
  const matches = cfg.hosts.filter(
    (h) => h.name === name || h.address === name || h.alternateAddresses.includes(name),
  );
  if (matches.length > 1) {
    throw new ConfigError(
      `"${name}" matches ${matches.length} hosts (${matches.map((h) => h.name).join(', ')}); it is ambiguous`,
      'hosts',
      'Pass the exact host name rather than a shared address.',
    );
  }
  if (matches.length === 0) {
    const listed = cfg.hosts.map((h) => `${h.name} (${[h.address, ...h.alternateAddresses].join(', ')})`).join(', ');
    throw new ConfigError(
      `Unknown host "${name}"`,
      'hosts',
      `Known hosts, with addresses: ${listed}`,
    );
  }
  return matches[0];
}
