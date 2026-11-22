import { describe, it, expect } from 'vitest';
import {
  findUiNodes,
  knownKeyNames,
  parseLsLines,
  parseNowPlaying,
  parseUiHierarchy,
  resolveKeyCode,
  runUiPreset,
  UI_PRESETS,
} from '../src/transports/adb.js';

describe('parseUiHierarchy', () => {
  const xml = `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.foo" content-desc="" clickable="false" enabled="true" scrollable="false" bounds="[0,0][1080,2400]">
    <node index="0" text="" resource-id="com.foo:id/switch" class="android.widget.ImageButton" package="com.foo" content-desc="Switch to front camera" clickable="true" enabled="true" scrollable="false" bounds="[804,1888][1008,2092]" />
    <node index="1" text="Galaxy Bells" resource-id="" class="android.widget.TextView" package="com.foo" content-desc="" clickable="false" enabled="true" scrollable="false" bounds="[100,500][900,600]" />
  </node>
</hierarchy>`;

  it('parses every node with its key attributes', () => {
    const nodes = parseUiHierarchy(xml);
    expect(nodes).toHaveLength(3);
    const frame = nodes[0];
    expect(frame.className).toBe('android.widget.FrameLayout');
    expect(frame.bounds).toEqual({ x1: 0, y1: 0, x2: 1080, y2: 2400 });
    expect(frame.centerX).toBe(540);
    expect(frame.centerY).toBe(1200);
    expect(frame.clickable).toBe(false);
  });

  it('reads content-desc, resource-id and clickable on a leaf', () => {
    const btn = parseUiHierarchy(xml).find((n) => n.resourceId === 'com.foo:id/switch');
    expect(btn).toBeDefined();
    expect(btn!.desc).toBe('Switch to front camera');
    expect(btn!.clickable).toBe(true);
    expect(btn!.centerX).toBe(906);
    expect(btn!.centerY).toBe(1990);
  });

  it('tracks tree depth (parent 0, its children 1)', () => {
    const nodes = parseUiHierarchy(xml);
    expect(nodes[0].depth).toBe(0);
    expect(nodes[1].depth).toBe(1);
    expect(nodes[2].depth).toBe(1);
  });

  it('unescapes XML entities inside attribute values', () => {
    const esc = `<node text="a &gt; b &amp; c &lt; d" content-desc="" resource-id="" class="X" package="p" bounds="[0,0][1,1]" />`;
    const [n] = parseUiHierarchy(esc);
    expect(n.text).toBe('a > b & c < d');
  });

  it('drops nodes with no parsable bounds', () => {
    const bad = `<node text="ok" bounds="" class="X" package="p" /><node text="keep" bounds="[5,5][6,6]" class="X" package="p" />`;
    const nodes = parseUiHierarchy(bad);
    expect(nodes).toHaveLength(1);
    expect(nodes[0].text).toBe('keep');
  });
});

describe('findUiNodes', () => {
  const nodes = parseUiHierarchy(`
    <node text="Photo" resource-id="com.c:id/photo" content-desc="Take photo" class="android.widget.Button" clickable="true" bounds="[0,0][10,10]" />
    <node text="Photos" resource-id="com.c:id/grid" content-desc="" class="android.widget.TextView" clickable="false" bounds="[0,0][20,20]" />
    <node text="" resource-id="" content-desc="Switch to rear camera" class="android.widget.ImageButton" clickable="true" bounds="[30,30][40,40]" />`);

  it('substring (contains) matches case-insensitively', () => {
    const m = findUiNodes(nodes, { text: 'photo', contains: true });
    expect(m).toHaveLength(2); // Photo and Photos
  });

  it('exact match does not over-match', () => {
    const m = findUiNodes(nodes, { text: 'photo', contains: false });
    expect(m).toHaveLength(1);
    expect(m[0].text).toBe('Photo');
  });

  it('matches on content-desc and resource-id', () => {
    expect(findUiNodes(nodes, { desc: 'switch to rear', contains: true })).toHaveLength(1);
    expect(findUiNodes(nodes, { id: 'com.c:id/grid', contains: false })).toHaveLength(1);
  });

  it('returns nothing without a discriminator', () => {
    expect(findUiNodes(nodes, { contains: true })).toHaveLength(0);
  });
});

describe('resolveKeyCode / knownKeyNames', () => {
  it('resolves named keys case-insensitively', () => {
    expect(resolveKeyCode('home')).toBe(3);
    expect(resolveKeyCode('MEDIA_PLAY')).toBe(126);
    expect(resolveKeyCode(' back ')).toBe(4);
  });
  it('accepts a raw numeric code and rejects junk', () => {
    expect(resolveKeyCode('27')).toBe(27);
    expect(resolveKeyCode('not-a-key')).toBeNull();
  });
  it('knownKeyNames advertises the core navigation keys', () => {
    for (const k of ['home', 'back', 'recents', 'enter', 'media_play_pause']) {
      expect(knownKeyNames()).toContain(k);
    }
  });
});

describe('parseLsLines', () => {
  const out = `total 12
drwxr-xr-x 2 u0_a100 media_rw 4096 2026-11-22 18:10 Camera
-rw-rw---- 1 u0_a100 media_rw 889929 2026-11-22 18:10 photo.jpg
lrwxrwxrwx 1 shell shell 11 2026-11-22 18:10 link -> /data/link
-rw-r--r-- 1 shell shell 3 2026-11-22 18:10 name with spaces.txt`;

  it('skips the total line and classifies entries', () => {
    const e = parseLsLines(out);
    expect(e).toHaveLength(4);
    expect(e[0]).toMatchObject({ name: 'Camera', type: 'dir', size: 4096 });
    expect(e[1]).toMatchObject({ name: 'photo.jpg', type: 'file', size: 889929 });
    expect(e[1].mtime).toBe('2026-11-22 18:10');
  });

  it('detects symlinks and strips the arrow, preserving spaces in names', () => {
    const e = parseLsLines(out);
    expect(e[2]).toMatchObject({ name: 'link', type: 'link' });
    expect(e[3]).toMatchObject({ name: 'name with spaces.txt', type: 'file', size: 3 });
  });

  it('returns empty for non-ls output', () => {
    expect(parseLsLines('No such file or directory')).toHaveLength(0);
  });
});

describe('parseNowPlaying', () => {
  it('detects a playing session and decodes metadata', () => {
    const np = parseNowPlaying(`
      Sessions Stack - have 1 sessions:
        com.spotify.music /MediaSession (userId=0)
          ownerUid=10123 ownerPid=4567 packages=com.spotify.music
          PlaybackState {state=3, position=1000, actions=...}
          metadata: description=Midnight Drive; artist=The Testers; album=Dummy`);
    expect(np.active).toBe(true);
    expect(np.state).toBe('3');
    expect(np.title).toBe('Midnight Drive');
    expect(np.artist).toBe('The Testers');
    expect(np.package).toBe('com.spotify.music');
  });

  it('reports inactive when nothing is playing', () => {
    const np = parseNowPlaying('Sessions Stack - have 0 sessions:\n');
    expect(np.active).toBe(false);
    expect(np.title).toBeUndefined();
  });

  it('never throws on garbage input', () => {
    expect(() => parseNowPlaying('??? random \n stuff')).not.toThrow();
  });
});

describe('UI presets', () => {
  it('advertises the camera and navigation presets', () => {
    for (const p of ['home', 'back', 'recents', 'camera_front', 'camera_rear']) {
      expect(UI_PRESETS).toContain(p);
    }
  });

  it('rejects an empty serial before touching the device (fail-safe)', async () => {
    await expect(runUiPreset('', 'home')).rejects.toThrow(/serial/);
  });
});
