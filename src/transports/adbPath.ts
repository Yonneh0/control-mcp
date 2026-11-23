// Locating the adb binary WITHOUT requiring the user to put it on PATH.
//
// Historically control-mcp spawned the literal name 'adb', so it only worked
// when adb happened to be on the server process's PATH (on this workstation,
// via the WindowsApps alias). That is a poor failure story: platform-tools is
// almost always present under an SDK root but not on PATH. This module resolves
// a concrete binary by probing the usual places, with an explicit override, and
// falls back to the bare 'adb' (PATH resolution) as before. It is deliberately
// pure and dependency-injected so it can be unit-tested without a device or a
// real filesystem.
//
// Resolution order (first existing candidate wins):
//   1. CONTROL_MCP_ADB_PATH            — a full path to the adb binary
//   2. $ANDROID_HOME/platform-tools    and $ANDROID_SDK_ROOT/platform-tools
//   3. well-known SDK locations for the OS
//   4. the bare name 'adb' (let the OS resolve it via PATH)
//
// Nothing is installed or downloaded here; if no candidate exists we still
// return 'adb' and let the caller's spawn produce an ENOENT that maps to
// CAPABILITY_UNAVAILABLE with a fix-it hint.

import { existsSync } from 'node:fs';

export interface AdbBinResolution {
  // What to spawn: an absolute path, or the bare 'adb' meaning "resolve via PATH".
  bin: string;
  source: 'env' | 'sdk' | 'path';
  // Every absolute candidate probed, in order. Surfaced honestly so adb_status
  // can show what was looked for even when nothing was found.
  checked: string[];
}

// Path segments joined with the separator for the TARGET platform (from the
// `platform` argument, not the host running the code) so resolution is
// deterministic and testable. At runtime callers pass process.platform.
function joinP(platform: string, ...parts: string[]): string {
  const sep = platform === 'win32' ? '\\' : '/';
  return parts
    .map((p, i) => (i === 0 ? p.replace(/[\/\\]+$/, '') : p.replace(/^[\/\\]+|[\/\\]+$/g, '')))
    .join(sep);
}

// Ordered absolute-candidate list derived from env + platform. Pure.
export function adbCandidatePaths(
  env: NodeJS.ProcessEnv,
  platform: string,
  home: string,
): string[] {
  const exe = platform === 'win32' ? 'adb.exe' : 'adb';
  const out: string[] = [];
  const pushTools = (base: string | undefined): void => {
    if (base && base.trim()) out.push(joinP(platform, base, 'platform-tools', exe));
  };

  // 1. Explicit override wins outright (a full path to the binary itself).
  const override = env.CONTROL_MCP_ADB_PATH;
  if (override && override.trim()) out.push(override.trim());

  // 2. Standard SDK roots.
  pushTools(env.ANDROID_HOME);
  pushTools(env.ANDROID_SDK_ROOT);

  // 3. Well-known per-OS install locations.
  if (platform === 'win32') {
    if (env.LOCALAPPDATA) out.push(joinP(platform, env.LOCALAPPDATA, 'Android', 'Sdk', 'platform-tools', 'adb.exe'));
    if (env.PROGRAMFILES) out.push(joinP(platform, env.PROGRAMFILES, 'Android', 'platform-tools', 'adb.exe'));
    out.push('C:\\Android\\platform-tools\\adb.exe');
  } else {
    if (home) out.push(joinP(platform, home, 'Android', 'Sdk', 'platform-tools', exe));
    out.push(joinP(platform, '/opt/android-sdk', 'platform-tools', exe));
    out.push(joinP(platform, '/usr/lib/android-sdk', 'platform-tools', exe));
  }
  return out;
}

export function resolveAdbBin(
  env: NodeJS.ProcessEnv = process.env,
  exists: (p: string) => boolean = existsSync,
  platform: string = process.platform,
  home: string = process.env.HOME || process.env.USERPROFILE || '',
): AdbBinResolution {
  const override = env.CONTROL_MCP_ADB_PATH && env.CONTROL_MCP_ADB_PATH.trim() ? env.CONTROL_MCP_ADB_PATH.trim() : undefined;
  const checked: string[] = [];
  for (const cand of adbCandidatePaths(env, platform, home)) {
    checked.push(cand);
    if (exists(cand)) {
      return { bin: cand, source: override && cand === override ? 'env' : 'sdk', checked };
    }
  }
  // Nothing found on disk: return the bare name so the OS resolves it via PATH,
  // exactly as before. The caller's spawn ENOENT is then reported honestly.
  return { bin: 'adb', source: 'path', checked };
}
