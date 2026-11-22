# control-mcp

A single Model Context Protocol (MCP) server for full remote control and
monitoring of machines on a LAN: SSH (command execution, persistent shell
sessions, SFTP), scripted RDP on Windows, `adb` for Android devices,
Wake-on-LAN, local network probing, and system-event monitoring. One config
file declares the hosts; **every tool answers honestly about what a host can
actually do** — a box that cannot be reached or driven says so with the evidence
it measured, never a fabricated success.

Honest, machine-checkable reporting is the whole product. If a capability is not
configured, not possible, or was not observed, the result says so — and every
refusal carries an actionable recovery hint so the calling agent can self-correct.

## Honesty model

Every tool result has a human summary and a machine-readable half:

- **success** — a one-line summary in `content[0].text` plus `structuredContent`
  with the measured fields (exit code, byte counts, verdicts, handles, timings).
- **refusal** — `isError: true`, `content[0].text` as `[CODE] message` followed by
  a second line `→ <hint>`, and `structuredContent: { code, message, detail, hint }`.

The recovery hint rides on the text line, so even single-block clients see it. A
call site supplies a specific hint when it can; otherwise the per-code table in
`src/hints.ts` fills one in, so **no error ships without a next step**.

| code | when it is raised |
|------|-------------------|
| `AUTH_FAILED` | the host answered and rejected the credential (or the configured private key file is missing) |
| `HOST_UNREACHABLE` | nothing answered: timeout / refused / unreachable at connect time |
| `CAPABILITY_UNAVAILABLE` | not configured or not possible for that target (no config at all, RDP not declared, adb not installed, no system log source) |
| `TRANSPORT_SEVERED_RISK` | the safety gate refused a command that would stop the service carrying the live transport |
| `TIMEOUT` | the operation outlived its timeout (adb path; `exec` reports a timeout inside its result instead) |
| `SESSION_GONE` | a shell session id is unknown, closed, or died with its connection |
| `BAD_ARGS` | rejected before any remote action ran (paths, ranges, missing `confirm`, unwatched hosts) |
| `REMOTE_ERROR` | the request reached the target and failed there (SFTP, a screencap without its IEND chunk, `PostMessageW` refused, log query) |
| `INTERNAL` | unexpected failure in control-mcp itself; the stack goes to stderr |

Nothing is asserted that was not observed:

- `exec` labels a killed command `timed out (TERM requested; the remote process may
  still be running)`, reports `exit code not reported` when the server sent no exit
  status, and reports a signal **only** when the server confirmed one.
- `admin_exec` states the effective privilege it actually measured (see below); an
  inconclusive probe says `not measured`, never a guess.
- `PostMessageW` returning `FALSE` is raised as `REMOTE_ERROR` rather than reported
  as a click that landed.
- A missing or invalid config does not crash the server: it starts with zero hosts,
  logs the offending path to stderr, and host-scoped tools answer
  `CAPABILITY_UNAVAILABLE` naming that path. The local tools (`net_ping`,
  `net_probe_tcp`, `wol_wake`, `arp_table`, `cdp_discover`) and the adb tools keep
  working with no config at all.

## Tools (51)

**Host discovery**
- `host_list` — configured hosts (name, address, os, alternate addresses, declared
  capabilities, ssh user, rdp-configured flag); never any secrets.
- `host_status` — probes one host over every configured interface: ping on each
  address, SSH handshake, TCP/3389, and (for a declared Windows RDP account) the
  live policy probe. Returns a per-interface verdict plus the RDP verdict with its
  reason. Run it before any RDP tool when a box is unclear.

**Commands**
- `exec` — one shell command over SSH; stdout/stderr/exit code/signal/truncation/
  timeout/duration, with a bounded output preview on the text line. Safety-gated.
- `admin_exec` — same connection, same gate, plus a measurement of the account's
  *effective* privilege (`whoami /groups` looking for the High mandatory label
  `S-1-16-12288` on Windows, `id -u` on Linux), reported in the result. There is
  **no** runas/UAC wrapper and elevation is not faked: an unprivileged account runs
  the command with the rights it has and access-denied comes back from the target.

**Shell sessions** (persistent, cwd/env kept)
- `shell_open` / `shell_run` / `shell_list` / `shell_close`. `shell_run` is
  sentinel-delimited and safety-gated like `exec`; a session with a command already
  in flight refuses a second one.

**Files** (SFTP)
- `file_upload` / `file_download` — byte counts in the result; `localPath` must be
  absolute; an existing destination is refused unless `overwrite: true`, on both
  ends. A missing local source is caught locally instead of being reported as a
  remote failure.
- `file_list` — name, size, type (from the mode bits), mode, mtime; capped to 500
  entries per call with the total reported.

**Local networking** (no host config needed)
- `net_ping` — reachability; requires an actual reply line, because `ping.exe`
  exits 0 for unresolvable targets too.
- `net_probe_tcp` — is something listening on `address:port`.
- `wol_wake` — magic packet, fanned out to every IPv4 interface's directed broadcast
  plus `255.255.255.255`, with a per-target sent/failed result.
- `arp_table` — this machine's ARP cache, for cross-checking MACs before waking.
- `cdp_discover` — raw-socket CDP listener on one adapter; raw sockets typically
  need an elevated control-mcp process, and a listener that cannot start answers
  `REMOTE_ERROR` rather than an empty scan.

**RDP** (Windows)
- `rdp_connect` (`connect` / `disconnect` / `status`) — creates the in-process
  MsRdpEx control and reports exactly what it achieved; see *RDP* below.
- `rdp_screenshot` — `PrintWindow` of the RDP window to an absolute PNG path.
- `rdp_click` / `rdp_key` / `rdp_type` — window messages (`WM_*`, `WM_CHAR`) posted
  to that window; coordinates are client-area relative.

Which window: the handle `rdp_connect` recorded for that host, otherwise a
machine-wide class lookup for the RDP host window class — used only when exactly
one such window exists. With several windows and none recorded for the host, the
tools refuse rather than guess which session to drive.

**System events**
- `monitor_start` / `monitor_stop` / `monitor_list` / `monitor_events` — poll and
  drain; see *Monitor* below.

**Android** (`adb`) — these mirror the browser-control model (*snapshot → find →
click-by-target → verify*) so the same muscle memory drives a real device, and
every screen action targets parsed `uiautomator` nodes rather than guessed
pixels.
- `adb_status` — is `adb` there, which version, which devices (honestly
  `available: false` when the CLI is not installed).
- Core — `adb_exec` (shell), `adb_screencap` (PNG signature **and** trailing IEND
  required), `adb_tap`, `adb_swipe`, `adb_type` (`[A-Za-z0-9 ._-]`, spaces as
  `%s`), `adb_key` (named keys `home`/`back`/`recents`/`media_*`/`dpad_*` or a
  numeric code), `adb_root` (a device refusing root is reported, not hidden).
- UI control — `adb_ui_dump` (structured element tree), `adb_ui_find` (by text /
  content-desc / resource-id / class), `adb_ui_tap` (tap a node **by selector**,
  self-correcting versus coordinate guessing), `adb_ui_set_text` (focus-by-
  selector + type; appends and cannot reliably clear — stated, not hidden).
- Navigation — `adb_current_app` (foreground package/activity), `adb_open_app`
  (launch by package), `adb_open_url` (http(s) only; `browserPackage` pins the
  handler so a rogue MIME registration cannot hijack the link).
- Presets — `adb_preset`: `home`, `back`, `recents`, `notification_shade`,
  `quick_settings`, `collapse_shade`, `camera_rear`, `camera_front` (the last
  opens the camera and performs the selector flip, then re-reads the hierarchy to
  **confirm** it landed rather than assuming it did).
- Files — `adb_ls`, `adb_pull`, `adb_push` (streamed; the local file is verified
  after a pull).
- Inventory & settings — `adb_apps` (all | system | third_party), `adb_settings`
  (get/put `system|secure|global`; a put **reads the value back** and reports
  whether it matched the write).
- Media & video — `adb_media` (control the active session via
  `cmd media_session dispatch` with a keyevent fallback), `adb_media_state`
  (now-playing, best-effort), `adb_screenrecord` (bounded silent clip, ≤180 s).
  Honest limits: `screenrecord` captures **no audio** on Android, and live video
  streaming needs a scrcpy bridge — neither is claimed.

> The Windows-desktop browser-equivalent — a real UIAutomation element tree over
> RDP instead of blind `rdp_click x,y` — is deliberate future work; the Android
> side is the complete model today.

**Power** (loud by design)
- `host_reboot` / `host_shutdown` — require `confirm: "yes"`, refuse any host that
  is localhost/loopback or shares an address with the machine running control-mcp,
  then issue `shutdown /r /t 5` / `shutdown /s /t 5` (Windows) or
  `systemctl reboot` / `systemctl poweroff` (Linux).

## Architecture

```
src/index.ts            stdio MCP server (stdout is JSON-RPC only; stderr is the log)
src/tools/registry.ts   the 51 tools + the audited pipeline: zod -> safety gate -> transport
src/config/             TOML config: schema (zod, .strict()), loader, secret resolution
src/transports/ssh.ts       ssh2 exec, persistent shell sessions (in-band sentinel), SFTP streaming
src/transports/netprobe.ts  ping / TCP probe / ARP / Wake-on-LAN / CDP raw-frame listener / RDP policy probe
src/transports/monitor.ts   event monitors: Windows Event Log + journald polling, per-host queues
src/transports/winsnapshot.ts PrintWindow -> PNG (koffi FFI: user32 + gdi32, hand-built PNG)
src/transports/wininput.ts  window enumeration + keyboard/mouse via PostMessageW (koffi FFI: user32)
src/transports/msrdpex.ts   MsRdpEx COM bridge (koffi); see RDP below for its honest limits
src/transports/adb.ts       Android devices via adb argv spawns (never through cmd.exe)
src/safety.ts         self-sever guard: refuses commands that stop the transport carrying them
src/capability.ts     per-host RDP verdict with measured evidence and human-readable reasons
src/errors.ts         ControlError + the two result builders (text line and structuredContent)
src/hints.ts          the per-code recovery-hint table every refusal falls back to
```

`registerTools()` returns a dispose handle: the event-monitor polls stop before the
SSH transport closes, so teardown cannot resurrect connections. The same guarded
pipeline wraps every tool, so a thrown `ControlError` always becomes a coded result
and anything unexpected becomes `INTERNAL`.

## Transports

**SSH** — the primary path on every host. Authentication is `privateKeyPath`
(`~` and `%VAR%` expanded; a missing or unreadable key file is `AUTH_FAILED` before
connect) or a password, resolved from `passwordEnv` / the `CONTROL_MCP_PW_<HOST>`
env convention first and falling back to an inline `password`. Connections are
cached per `host|address|user` with keepalives and evicted by identity on
error/close, so a reconnect cannot be clobbered by a dead client's handler; a closed
connection marks that host's shell sessions gone. Output is capped at 2 MiB per
stream with `truncated: true`. On timeout the channel asks the server for TERM and
the channel is destroyed — whether the server honored it is only visible through
the exit/close signal field, so it is not asserted. Shell sessions are `term: dumb`,
120×40, and command completion is detected by an in-band sentinel line the shell
itself prints (`CTL_MCP_<id>_END<exitcode>`, per-session nonce); only a full sentinel
line resolves, the echoed wrapper is cut out, and the exit code is appended as
`[exit N]`. Transfers stream with `fastPut` / `fastGet`.

**RDP** — declared per host by `capabilities.rdp = true` or a full `[hosts.rdp]`
block (either counts, and the gate and the verdict agree). When declared,
`host_status` measures the target instead of assuming: TCP/3389,
`LimitBlankPasswordUse`, NLA (`UserAuthentication`), and a live network-logon probe.
A stored Windows Credential Manager entry (`cmdkey`, target `TERMSRV/<address>`)
counts as a credential path, as do `credentialTarget` / `passwordEnv`.

`rdp_connect` creates the MsRdpEx control in-process. Whether it can actually reach
a live session (`Connected=1`) depends on the environment: MsRdpEx's Detours hooks
attach only inside real client processes, so a plain in-process host may be able to
create the control and its input window without ever establishing a session. When
that happens `rdp_connect` says so verbatim with the real last error, and `status`
keeps saying it. The recorded window handle is real, so `rdp_screenshot` /
`rdp_click` / `rdp_key` / `rdp_type` act on the local control window; with no live
session nothing reaches a remote desktop, and `connected=false` is in the same
result. A real scripted session is normally driven by launching the MsRdpEx-enabled
client on the target itself. The screen-capture surface for a *connected* session is
not bound, because with no reachable connected session it would be FFI that fails at
first use.

**ADB** — `adb` is invoked as argv arrays, never through `cmd.exe`. A missing binary
is `adb_status → available: false` and `CAPABILITY_UNAVAILABLE` on the operations
that need it; screencaps that lack a PNG signature or the trailing IEND chunk are
rejected instead of written as unopenable files; a killed child keeps its partial
output and reports the signal. UI tools parse `uiautomator` XML into a node tree so
taps/fills target elements, not coordinates; file ops stream via `adb pull`/`push`
and verify the local file; a settings write reads the value back. Actions use
explicit components and system services (`uiautomator`, `media_session dispatch`,
`monkey` launcher) rather than MIME `VIEW` intents, because on a real device any
installed app can register a MIME type and silently hijack a generic `VIEW` (an
audio `VIEW` here was swallowed by Termux and played nothing) — a lesson baked into
the design.

**Screen capture and input on Windows** — `winsnapshot.ts` renders a window with
`PrintWindow` (trying `PW_RENDERFULLCONTENT` first, which DWM-composited windows
need, falling back to plain 0), reads it back with `GetDIBits`, and writes a PNG
built by hand. `wininput.ts` enumerates windows and posts `WM_KEYDOWN` / `WM_CHAR` /
`WM_*BUTTONDOWN` messages to a specific handle; `PostMessageW` returning `FALSE` —
minimized window, locked workstation, a window that ignores messages — is raised as
`REMOTE_ERROR`.

## Configuration

Config lives at `%APPDATA%\control-mcp\config.toml` (Windows) and can be overridden
with the `CONTROL_MCP_CONFIG_PATH` environment variable — an explicit path wins,
otherwise the per-user default. `src/index.ts` and the tools resolve the same path,
so the override applies to the running server and to the paths quoted in error
messages.

A complete example (the addresses use the RFC 5737 documentation range
`192.0.2.0/24`; substitute your own):

```toml
# control-mcp config

[[hosts]]
name = "build-01"
address = "192.0.2.10"
os = "linux"                 # windows | linux

[hosts.ssh]
port = 22
user = "deploy"
privateKeyPath = "~/.ssh/id_ed25519"

[[hosts]]
name = "workstation"
address = "192.0.2.11"
os = "windows"
# alternateAddresses = ["192.0.2.41"]   # optional: extra addresses, probed too; a live alternate is used, marked degraded

[hosts.ssh]
port = 22
user = "operator"
privateKeyPath = "~/.ssh/id_ed25519"

[hosts.rdp]                  # omit entirely for non-RDP hosts
port = 3389
user = "operator"
credentialTarget = "TERMSRV/192.0.2.11"   # a Windows Credential Manager entry
# passwordEnv = "CONTROL_MCP_PW_WORKSTATION"   # alternative credential source
# domain = "WORKGROUP"
# width = 1920                            # 640..7680
# height = 1080                           # 480..4320

[hosts.capabilities]
rdp = true

[[hosts]]
name = "kiosk"
address = "192.0.2.12"
os = "windows"

[hosts.ssh]
port = 22
user = "kioskuser"
privateKeyPath = "~/.ssh/id_ed25519"

# Optional. Both keys have defaults, so [safety] may be omitted entirely.
[safety]
refuseSelfSevering = true     # consulted by the exec/shell safety gate
# firewallProfile = "Any"     # Any|Domain|Private|Public — accepted by the schema, not consulted by any tool
```

Rules the loader enforces:

- Every object schema is `.strict()`: an unknown key is a config error naming the
  offending key, and the server then starts with **zero** hosts rather than
  half-applying the file.
- At least one `[[hosts]]` entry. Host names are uniquely resolvable; two hosts may
  not share a name, address, or alternate.
- Each `ssh` block needs `privateKeyPath`, `password`, or `passwordEnv`;
  `passwordEnv` must be `UPPER_SNAKE_CASE` (same rule in the `rdp` block).
- `defaultHost` must name a configured host. If it is absent and more than one host
  is configured, every host-scoped call must pass `host` explicitly — omitting it
  returns `BAD_ARGS` with the known-host list instead of picking one.
- The `host` argument accepts a name or any configured address (primary or
  alternate).
- Secrets: prefer env (`passwordEnv`, or the `CONTROL_MCP_PW_<HOST>` naming
  convention) or Windows Credential Manager. An inline `password` is supported and
  never appears in tool results or logs; `host_list` reports only whether RDP is
  configured.

Environment variables control-mcp reads: `CONTROL_MCP_CONFIG_PATH` (config
location), `CONTROL_MCP_DISABLE_MAIN` (see *Build, typecheck, test*),
`CONTROL_MCP_HAS_CRED=1` (declare that a credential exists when it cannot be
resolved from config or `cmdkey`), plus the `CONTROL_MCP_PW_<HOST>` /
named-`passwordEnv` secret convention and `APPDATA`.

### Blank-password Windows accounts

An account with a blank password is **unreachable over the network by design**:
Windows' `LimitBlankPasswordUse` (the default) rejects blank-password network logon,
so RDP for that account cannot authenticate no matter how the transport is
configured, and NLA (`UserAuthentication=1`) then demands exactly the credential
policy forbids. control-mcp derives this from measurement, not assumption: when
`[hosts.rdp]` is declared for such a host, `host_status` probes network logon and
reports the refusal with the evidence. When no `[hosts.rdp]` block is present it
short-circuits to `not-declared` first. Either verdict is correct and expected —
**not** a bug and **not** a transport problem: do not retry with a different
transport; set a password or change NLA from the console.

## Prerequisites

- Node **≥ 20.6** (`package.json` engines). This repo is ESM (`"type": "module"`,
  `module`/`moduleResolution`: `Node16`), so every relative import in `src/` carries
  a `.js` specifier — the source compiles to `build/` and runs as written.
- pnpm for installs; `pnpm-lock.yaml` is the source of truth.
- Runtime dependencies: `@modelcontextprotocol/sdk` (stdio server), `ssh2`
  (SSH/SFTP transport), `koffi` (FFI to `user32`, `gdi32`, `ole32`, MsRdpEx),
  `smol-toml` (config), `zod` (schemas).
- **RDP control** requires MsRdpEx installed on *the machine running control-mcp*
  (`DLL_PATH_DEFAULT` points at the default Devolutions install location). Without
  it `rdp_connect` reports the load failure and its HRESULT; the rest of the server
  is unaffected. The koffi libraries load on first use, so importing these modules
  never touches FFI.
- **adb is optional.** Absent, `adb_status` answers `available: false` with the
  reason and the adb tools answer `CAPABILITY_UNAVAILABLE`; nothing else is affected.
- Local networking tools shell out to Windows built-ins (`ping.exe`, `arp.exe`,
  `cmdkey.exe`, `powershell`); `cdp_discover` additionally needs an elevated
  control-mcp process for its raw socket.

## Build, typecheck, test

```bash
pnpm install                                              # pnpm-lock.yaml is authoritative

node node_modules/typescript/bin/tsc -p tsconfig.json     # build: src -> build/
node node_modules/typescript/bin/tsc --noEmit -p tsconfig.test.json   # typecheck: src + test
```

`package.json` scripts: `build`, `typecheck` (`tsc --noEmit -p tsconfig.test.json`),
and `test` / `test:unit` / `test:e2e` (`cross-env CONTROL_MCP_DISABLE_MAIN=1 vitest
--run [path]`).

Tests must disable the entry point, because importing `src/index.ts` would otherwise
call `main()` and open the stdio server:

```bash
CONTROL_MCP_DISABLE_MAIN=1 node node_modules/vitest/vitest.mjs --run test/
```

What the suites cover: config schema/loader behavior against the TOML fixtures, the
safety guard's refusal *and* over-refusal tables, capability verdicts, monitor
semantics (baseline, dedupe, queue, drain), the error/hint pairing, the secrets
resolver (path expansion, empty-vs-unset env vars, unreadable keys), `wininput`
VK/lparam mapping, and the live SSH exec + shell sentinel protocol against a real
host — the live cases skip automatically when the host is unreachable.

A raw-stdio acceptance harness (`harness/`) drives the built server as an MCP client
and asserts a clean `initialize` handshake, tool-schema integrity, real tool results,
JSON-only stdout, and a clean exit on stdin EOF:

```bash
python harness/mcp_stdio_harness.py node build/index.js --call host_list '{}'
```

## Safety

`exec`, `admin_exec`, and `shell_run` pass every command through
`safety.checkCommand` before anything reaches a host. The guard refuses commands that
stop or reconfigure a transport-carrying service with `TRANSPORT_SEVERED_RISK`. On
Windows both pattern sets always apply — stopping `TermService` severs an RDP session
even when the command arrived over SSH, and stopping `sshd` kills the exec path —
because a stopped Automatic service does not self-heal and the box becomes
unreachable until someone touches it. Linux patterns apply on the SSH transport:
`systemctl stop|restart|disable|kill sshd|ssh`, `service ssh stop`, `pkill -x sshd`,
`killall sshd`.

Behavior as measured against the guard:

- **refused**: `Stop-Service sshd`, `net stop TermService`,
  `sc config sshd start= disabled`, `Set-Service -Name sshd -StartupType Disabled`,
  `taskkill /im sshd.exe /f`, `systemctl restart ssh`, `pkill -x sshd`, and service
  verbs behind a command prefix — `cmd /c "net start sshd"`,
  `powershell -Command "net start sshd"` (the prefix is stripped, so the verb is back
  at the start of the segment).
- **allowed**: `findstr sshd f.cmd`, `journalctl -u sshd`, `systemctl reboot`,
  `systemctl stop sshd.socket` — the service verbs must be at a segment start and the
  unit tokens are bounded, so mentions and neighboring units pass.

Parsing is per segment (`;`, `&`, `|`, newlines) after normalization that strips
quotes and collapses whitespace, with verbs anchored to segment start. It fails safe
toward refusing.

Escape hatch: `override: "sever-transport"` runs a refused command anyway. That is
genuinely dangerous — it is how you cut your own branch off the tree. Use it only
when you already have another way back (console access, the other transport, a
scheduled rescue); otherwise pick a command that does not stop sshd/TermService.
Every use logs an `AUDIT control-mcp: <tool> on host=<host> ran with
override=sever-transport: <command>` line to stderr. The gate is configurable:
`safety.refuseSelfSevering = false` turns it off (and the guard stays on when there
is no config at all).

Power operations are loud by design: `confirm: "yes"` is required, and any host
resolving to localhost/loopback or to an address of the machine running control-mcp
is refused outright — powering the control origin takes the server and every
transport with it.

Everything that can destroy data asks first: transfers refuse an existing destination
on either end without `overwrite: true`; `adb_type` refuses anything outside
`[A-Za-z0-9 ._-]` so no control character reaches a shell; the destination pre-check
quotes a POSIX remote path with POSIX escaping, so `/tmp/$(reboot)` is matched as a
literal filename rather than executed (SFTP paths never go through a shell at all); a
destination that cannot be pre-checked is not claimed absent — the transfer proceeds
and the failure to check is logged.

## Monitor

`monitor_start <host>` polls the host's own log over SSH: Windows via `Get-WinEvent`
on the System channel at levels 1–3 (critical/error/warning) rendered as compact
JSON, Linux via `journalctl -p 3 -n 20 --no-pager -o json` with a plain-text
fallback. Cadence is `intervalMs` — default 30 s, floor 5 s, one shared interval per
monitor.

It is **poll-based, never push**: nothing is installed on the targets and stdio MCP
has no push path here. Events are queued per host and `monitor_events` returns and
clears them; callers drain on their own cadence. Dedupe is by record identifier
(Windows `RecordId`, journal cursor), so the same log record is never emitted twice.
`monitor_start` primes with a first poll that only records identifiers and emits
nothing, so a fresh monitor reports only what happens while it is watched.

Honest edges: `monitor_stop` for a host that is not watched and `monitor_events` for
an unwatched host both answer `BAD_ARGS` instead of an empty result that would read
as "no events" — an empty drain only means something when the host is actually
monitored. Passing `intervalMs` re-creates the monitor, which resets **every**
watched host's baseline and drops queued, undrained events; the result says so and
names any host that failed to re-attach. Queues are capped at 500 events per host,
newest kept, oldest dropped. A poll that fails or returns unparseable output yields
no events and no error (and, importantly, does not mark the baseline taken — so it
re-baselines next time instead of replaying history); capability gaps are reported by
`start` as `CAPABILITY_UNAVAILABLE`.

## Contributing

Contributions are welcome — bug fixes, hardening, tests, and documentation. Please:

1. Open an issue first for anything non-trivial, and **feature requests are welcome**
   (label them `enhancement`). Describe the behavior you want and why; honesty gaps
   and self-correcting-error improvements are especially appreciated.
2. Branch from `main`, keep changes focused, and follow the invariants in
   [AGENTS.md](AGENTS.md) — especially the honesty contract, the per-error hint
   pattern, the `.strict()` config schema, and "no secrets in the repo, ever."
3. Run `pnpm typecheck` and the test suite before opening a PR, and add/adjust tests
   so the change is covered.

### Autonomous agents

This project welcomes **AI/agent-authored pull requests** — but only when a human
has reviewed and vouched for them. Every PR must name a human sponsor and explain,
in the PR body, *why the change is correct and safe* (what it fixes, how it was
tested, and the risk to the honesty contract). A PR with no human justification, or
one that merely asserts success without evidence, will be closed. See
[AGENTS.md](AGENTS.md) for the full, machine-readable guidance.

## License

Released under the MIT License. See [LICENSE](LICENSE).
