import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { type ControlConfig } from './config/schema.js';
import { ConfigError, parseConfigText } from './config/loader.js';
import { CONTROL_MCP_CONFIG_PATH, registerTools } from './tools/registry.js';
import { SshTransport } from './transports/ssh.js';

const SHUTDOWN_BUDGET_MS = 5000;

function serverVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const raw = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
    return typeof raw.version === 'string' ? raw.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

// A bad config must not crash the server: log it and run with zero hosts, so
// host-scoped tools answer CAPABILITY_UNAVAILABLE/BAD_ARGS with the reason.
function loadServerConfig(): ControlConfig | null {
  const path = CONTROL_MCP_CONFIG_PATH;
  if (!existsSync(path)) {
    console.error(`control-mcp: no config file at ${path}; starting with zero hosts. Host tools will answer CAPABILITY_UNAVAILABLE until a valid config.toml exists there.`);
    return null;
  }
  try {
    return parseConfigText(readFileSync(path, 'utf8'), path);
  } catch (err: unknown) {
    if (err instanceof ConfigError) {
      console.error(`control-mcp: config error: ${err.message}${err.hint ? ` (offending key: ${err.hint})` : ''} -- starting with zero hosts.`);
    } else {
      console.error(`control-mcp: failed to read config: ${err instanceof Error ? err.message : String(err)} -- starting with zero hosts.`);
    }
    return null;
  }
}

async function main(): Promise<void> {
  const cfg = loadServerConfig();
  const server = new McpServer({ name: 'control-mcp', version: serverVersion() });
  const ssh = new SshTransport();
  // registerTools returns a dispose handle covering the EventMonitor timers it
  // owns; they must stop before closeAll or polls resurrect the connection cache.
  const disposeTools = registerTools(server, cfg, ssh);

  let shuttingDown = false;
  const cleanup = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error('control-mcp: shutting down, closing transports...');
    // Watchdog: if teardown hangs, end with a non-zero code so the failure is visible.
    const watchdog = setTimeout(() => process.exit(1), SHUTDOWN_BUDGET_MS);
    try {
      disposeTools();
    } catch (err: unknown) {
      console.error('control-mcp: tool disposal failed during shutdown:', err instanceof Error ? err.message : String(err));
    }
    try {
      ssh.closeAll();
    } catch (err: unknown) {
      console.error('control-mcp: ssh.closeAll failed during shutdown:', err instanceof Error ? err.message : String(err));
    }
    clearTimeout(watchdog);
    process.exit(0);
  };

  // Attach before connect(): a client that closes stdin during the handshake
  // must still find a listener, or the process idles forever.
  process.stdin.on('end', cleanup);
  process.stdin.on('close', cleanup);
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  await server.connect(new StdioServerTransport());
  console.error(`control-mcp ${serverVersion()} listening on stdio (hosts: ${cfg ? String(cfg.hosts.length) : '0'}); stdout is JSON-RPC only.`);
}

if (process.env.CONTROL_MCP_DISABLE_MAIN !== '1') {
  main().catch((err: unknown) => {
    console.error(`control-mcp fatal: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
