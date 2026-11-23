import { describe, it, expect } from 'vitest';
import { adbCandidatePaths, resolveAdbBin } from '../src/transports/adbPath.js';

// Pure: inject env + exists + platform + home. No real FS, no device, no PATH.
const existsSet = (paths: string[]): ((p: string) => boolean) => (p) => paths.includes(p);

describe('adbCandidatePaths', () => {
  it('puts the explicit override first and appends SDK roots', () => {
    const c = adbCandidatePaths({ CONTROL_MCP_ADB_PATH: '/opt/custom/adb', ANDROID_HOME: '/home/u/Android/Sdk' }, 'linux', '/home/u');
    expect(c[0]).toBe('/opt/custom/adb');
    expect(c).toContain('/home/u/Android/Sdk/platform-tools/adb');
  });

  it('uses adb.exe on win32 and probes LOCALAPPDATA', () => {
    const c = adbCandidatePaths({ LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local', PROGRAMFILES: 'C:\\Program Files' }, 'win32', 'C:\\Users\\u');
    expect(c.every((p) => p.endsWith('adb.exe'))).toBe(true);
    expect(c).toContain('C:\\Users\\u\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe');
  });
});

describe('resolveAdbBin', () => {
  it('prefers an existing CONTROL_MCP_ADB_PATH and reports source=env', () => {
    const r = resolveAdbBin({ CONTROL_MCP_ADB_PATH: '/opt/custom/adb' }, existsSet(['/opt/custom/adb']), 'linux', '/home/u');
    expect(r.bin).toBe('/opt/custom/adb');
    expect(r.source).toBe('env');
  });

  it('falls back to an existing SDK-root binary and reports source=sdk', () => {
    const r = resolveAdbBin({ ANDROID_HOME: '/home/u/Android/Sdk' }, existsSet(['/home/u/Android/Sdk/platform-tools/adb']), 'linux', '/home/u');
    expect(r.bin).toBe('/home/u/Android/Sdk/platform-tools/adb');
    expect(r.source).toBe('sdk');
  });

  it('resolves a well-known win32 SDK location not derived from env roots', () => {
    const found = 'C:\\Users\\u\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe';
    const r = resolveAdbBin({ LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local' }, existsSet([found]), 'win32', 'C:\\Users\\u');
    expect(r.bin).toBe(found);
    expect(r.source).toBe('sdk');
  });

  it('with no candidate present returns the bare name (PATH resolution) and honestly lists what it checked', () => {
    const r = resolveAdbBin({ ANDROID_HOME: '/nope/Sdk' }, existsSet([]), 'linux', '/home/u');
    expect(r.bin).toBe('adb');
    expect(r.source).toBe('path');
    // The env path was still probed and is reported — never silently skipped.
    expect(r.checked).toContain('/nope/Sdk/platform-tools/adb');
  });

  it('when the override is set but missing, keeps searching and reports it in checked', () => {
    const sdk = '/home/u/Android/Sdk/platform-tools/adb';
    const r = resolveAdbBin({ CONTROL_MCP_ADB_PATH: '/absent/adb', ANDROID_HOME: '/home/u/Android/Sdk' }, existsSet([sdk]), 'linux', '/home/u');
    expect(r.bin).toBe(sdk);
    expect(r.source).toBe('sdk');
    expect(r.checked).toContain('/absent/adb');
  });
});
