import { describe, it, expect } from 'vitest';
import { outputPreview } from '../src/tools/registry.js';

// Regression for the S21 "I can't read it" failure: `adb_exec` built its tool
// TEXT line as just `adb exec <serial>: exit <code>` and left stdout only in
// structuredContent. Any caller that reads the text (the common case — many MCP
// clients render text only) therefore concluded a successful command produced
// nothing. The tool must append the same stdout/stderr preview that the SSH
// `exec` tool has, so an adb result is never less readable than an ssh one.
// These cases pass the ADB result shape (stdout/stderr/code, no `timedOut`) to
// pin that the shared helper works for it too.
describe('outputPreview carries stdout in the text line', () => {
  it('shows stdout on a successful adb-style result (no timedOut field)', () => {
    const t = outputPreview({ stdout: 'up 3 days, 4 min\nMem: 4.5G used', stderr: '', code: 0 });
    expect(t).toContain('stdout: up 3 days, 4 min');
  });
  it('leads with stderr on failure but still shows stdout', () => {
    const t = outputPreview({ stdout: 'partial out', stderr: 'dumpsys: not found', code: 1 });
    expect(t).toContain('stderr: dumpsys: not found');
    expect(t).toContain('stdout: partial out');
  });
  it('adds nothing when a clean exit produced no output', () => {
    expect(outputPreview({ stdout: '   ', stderr: '', code: 0 })).toBe('');
  });
  it('bounds very long output rather than dropping it', () => {
    const t = outputPreview({ stdout: 'x'.repeat(5000), stderr: '', code: 0 });
    expect(t).toContain('stdout: ');
    expect(t.length).toBeLessThan(1300);
  });
});
