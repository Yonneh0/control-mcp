import { describe, it, expect } from 'vitest';
import { parseBatteryDump, parseDataFreeMb, parsePowerDump } from '../src/transports/adb.js';

// NOTE: deviceState() itself is deliberately NOT tested here — it spawns real
// `adb -s <serial> shell dumpsys/settings/df` processes and needs a connected
// device, which the pure test suite never touches. These tests cover only the
// pure parsers over captured, realistic device output.

describe('parseBatteryDump', () => {
  const full = `Current Battery Service state:
  AC powered: true
  USB powered: false
  Wireless powered: false
  Max charging current: 500000
  time: 20261123_053012
  status: 2
  health: 2
  present: true
  plugged: 1
  level: 87
  scale: 100
  voltage: 4150
  temperature: 291
  technology: Li-ion`;

  it('reads level/status/plugged/temperature from a real dumpsys battery block', () => {
    expect(parseBatteryDump(full)).toEqual({
      level: 87,
      status: 'charging',
      plugged: 'ac',
      temperatureC: 29.1,
    });
  });

  it('leaves plugged null when the block has no plugged: line (not inferred from AC powered)', () => {
    const out = full.replace(/^  plugged: 1\n/m, '');
    expect(parseBatteryDump(out).plugged).toBeNull();
  });

  it('returns null level when the level line is absent (never defaults)', () => {
    const out = `Current Battery Service state:
  status: 3
  health: 2
  scale: 100
  temperature: 250`;
    expect(parseBatteryDump(out)).toEqual({ level: null, status: 'discharging', plugged: null, temperatureC: 25 });
  });

  it('maps every documented status and plugged code, and surfaces unknowns verbatim', () => {
    expect(parseBatteryDump('  status: 1').status).toBe('unknown');
    expect(parseBatteryDump('  status: 4').status).toBe('not-charging');
    expect(parseBatteryDump('  status: 5').status).toBe('full');
    expect(parseBatteryDump('  status: 9').status).toBe('9'); // unmapped code, not folded into 'unknown'
    expect(parseBatteryDump('  plugged: 0').plugged).toBe('none');
    expect(parseBatteryDump('  plugged: 2').plugged).toBe('usb');
    expect(parseBatteryDump('  plugged: 4').plugged).toBe('wireless');
    expect(parseBatteryDump('  plugged: 3').plugged).toBe('other');
  });

  it('clamps an out-of-range level and rejects non-numeric values with null', () => {
    expect(parseBatteryDump('  level: 150').level).toBe(100);
    expect(parseBatteryDump('  level: -3').level).toBe(0);
    expect(parseBatteryDump('  level: N/A').level).toBeNull();
  });

  it('never throws on garbage input', () => {
    expect(parseBatteryDump('??? not a battery dump')).toEqual({ level: null, status: null, plugged: null, temperatureC: null });
  });
});

describe('parsePowerDump', () => {
  const awake = `USER ACTIVITY [power] (current):
  mWakefulness=Awake
  mWakefulnessChanging=false
  mIsPowered=true
  mStayOn=false
  mScreenOn=true
  mScreenBrightnessBoostInProgress=false
Display Power: com.android.server.display.DisplayManagerService@1a2b3c4`;

  it('reads an Awake block with mWakefulness and mScreenOn', () => {
    const p = parsePowerDump(awake);
    expect(p.wakefulness).toBe('Awake');
    expect(p.screenOn).toBe(true);
    expect(p.doze).toBeNull();
  });

  it('reads a Dozing block (wakefulness, screen off, doze state)', () => {
    const dozing = `  mWakefulness=Dozing
  mScreenOn=false
Doze: dozing`;
    const p = parsePowerDump(dozing);
    expect(p.wakefulness).toBe('Dozing');
    expect(p.screenOn).toBe(false);
    expect(p.doze).toBe('dozing');
  });

  it('falls back to "Display Power: state=ON|OFF" when mScreenOn is absent', () => {
    expect(parsePowerDump('  mWakefulness=Asleep\nDisplay Power: state=OFF').screenOn).toBe(false);
    expect(parsePowerDump('Display Power: state=ON').screenOn).toBe(true);
    expect(parsePowerDump('Display Power: state=ON').wakefulness).toBeNull();
  });

  it('leaves screenOn null for a Display Power state that is not a boolean ON/OFF', () => {
    // DOZING/INTERACTIVE/DIM are not a screen on/off fact; no guessing.
    expect(parsePowerDump('Display Power: state=DOZING').screenOn).toBeNull();
  });

  it('reports null for every field when no marker is present (no fabrication)', () => {
    const none = `Power Manager State:
  mInteractive=true
  mBootCompleted=true
  mSendDreamingStateInDoze=true`;
    expect(parsePowerDump(none)).toEqual({ wakefulness: null, screenOn: null, doze: null });
  });

  it('captures mDozeState and ignores near-neighbour keys', () => {
    expect(parsePowerDump('  mDozeState=1').doze).toBe('1');
    // mWakefulnessChanging=false must not be read as the wakefulness value.
    expect(parsePowerDump('  mWakefulnessChanging=false').wakefulness).toBeNull();
  });

  it('never throws on garbage input', () => {
    expect(parsePowerDump('??? random')).toEqual({ wakefulness: null, screenOn: null, doze: null });
  });
});

describe('parseDataFreeMb', () => {
  const toybox = `Filesystem       1K-blocks    Used Available Use% Mounted on
/dev/block/dm-50 238685280 197788560  40896720  83% /data
/dev/fuse        238685280 197788560  40896720  83% /storage/emulated/0`;

  it('converts the 1K-block Available column of the /data row to MB', () => {
    // 40896720 KiB * 1024 = 41,878,241,280 B -> 41878 MB
    expect(parseDataFreeMb(toybox)).toBe(41878);
  });

  it('returns null when no /data row exists', () => {
    const out = `Filesystem       1K-blocks    Used Available Use% Mounted on
/dev/block/dm-0   655360   300000   355360  46% /`;
    expect(parseDataFreeMb(out)).toBeNull();
  });

  it('handles a human-readable suffixed value (5.2G = 5.2 * 1024^3 bytes)', () => {
    const out = `Filesystem      Size  Used Avail Use% Mounted on
/dev/block/dm-50  228G   189G  5.2G  84% /data`;
    // 5.2 * 1073741824 = 5,583,457,484.8 B -> 5583 MB
    expect(parseDataFreeMb(out)).toBe(5583);
  });

  it('handles suffixed M values and an exact 0', () => {
    expect(parseDataFreeMb('/dev/block/dm-50 100 90 2.1M  45% /data')).toBe(2); // 2,202,009.6 B
    expect(parseDataFreeMb('/dev/block/dm-50 100 100 0  100% /data')).toBe(0);
  });

  it('uses the single returned filesystem for `df /data` when the mount is labeled oddly (real S21)', () => {
    // Captured from a physical Galaxy S21: `df /data` returns one row whose mount
    // is a /storage path, not /data. With assumeTarget the Available column IS
    // the /data filesystem's free space; strict mode still returns null.
    const s21 = `Filesystem       1K-blocks     Used Available Use% Mounted on
/dev/block/dm-52 234947548 42807004 192009472  19% /storage/emulated/0/Android/obb`;
    expect(parseDataFreeMb(s21, true)).toBe(196618); // 192009472 KiB * 1024 / 1e6
    expect(parseDataFreeMb(s21)).toBeNull(); // strict: no /data label
  });

  it('null (not 0) for unparsable Available, headers only, and garbage', () => {
    expect(parseDataFreeMb('/dev/block/dm-50 100 90 -  90% /data')).toBeNull();
    expect(parseDataFreeMb('Filesystem       1K-blocks    Used Available Use% Mounted on')).toBeNull();
    expect(parseDataFreeMb('df: /data: Permission denied')).toBeNull();
    expect(parseDataFreeMb('')).toBeNull();
  });
});
