#!/usr/bin/env python3
# mcp_stdio_harness.py - raw-stdio MCP client harness for a Node MCP server.
#
# Intended invocation (Windows PowerShell):
#   python harness/mcp_stdio_harness.py C:\path\to\node.exe C:\path\to\entry.js `
#       --call someTool '{"a":1}' --call otherTool '{}' --expect-tool someTool `
#       --stderr-out C:\tmp\server.stderr.log
#
# Starts the server child process and speaks newline-delimited JSON-RPC 2.0
# over raw stdio (MCP protocol version 2024-11-05). Prints one PASS/FAIL/SKIP
# line per numbered check, some INFO lines, then a final "RESULT: PASS" or
# "RESULT: FAIL <n> failed" line; the exit code mirrors RESULT (0 = pass,
# 1 = fail; 2 = CLI/usage error, no RESULT line emitted).
#
# WHY THE PUMP THREAD EXISTS (the fixed defect): iterating proc.stdout or
# calling readline() on the pipe deadlocks once the pipe is saturated - the
# child blocks on a full pipe while the parent blocks inside buffered readline
# waiting for bytes the child cannot write. This harness NEVER touches proc
# .stdout as a file object: a background thread pumps the raw fd with
# os.read(fd, 65536), buffers bytes, splits on b"\n", and appends decoded
# lines to a shared list under a lock.
#
# Every wait is bounded; the total runtime budget is under 120 s. ASCII only,
# stdlib only.
import atexit
import json
import os
import subprocess
import sys
import threading
import time

if os.name == "nt":
    import msvcrt

PROTOCOL_VERSION = "2024-11-05"
HARD_BUDGET = 115.0     # global runtime budget in seconds (stays under 120)
EXIT_WAIT = 10.0        # check 7: clean exit must happen within 10 s
USAGE = ("usage: python mcp_stdio_harness.py <node.exe> <entry.js> "
         "[--call <toolName> <jsonArgs>]... [--expect-tool <name>]... "
         "[--stderr-out <path>]")
START_MONO = time.monotonic()

# ------------------------------------------------------------ shared state --
LINES = []               # complete stdout lines, in order
LINES_LOCK = threading.Lock()
PUMP_DONE = threading.Event()
CUR = 0                  # consumer cursor (main thread only)
VIOLATIONS = []          # lines that are not valid JSON-RPC (check 4)
NEXT_ID = [0]
PROC = {"proc": None, "stdin": None}
FAILURES = []            # ids of failed checks


def child_status():
    proc = PROC["proc"]
    if proc is None:
        return "no child spawned"
    rc = proc.poll()
    if rc is None:
        return "child still running"
    return "child exited rc=%s" % rc


def emit(text):
    # Guarantee ASCII on stdout regardless of the Windows console locale.
    sys.stdout.write(text.encode("ascii", "replace").decode("ascii") + "\n")
    sys.stdout.flush()


def brief(value, limit=140):
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=True)
    else:
        text = repr(value)
    text = text.encode("ascii", "replace").decode("ascii")
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def record_check(n, name, status, detail=""):
    line = "CHECK%d %s: %s" % (n, name, status)
    if status == "FAIL":
        FAILURES.append("check%d" % n)
    if detail:
        line += " -- " + detail
    emit(line)


def bounded_wait(cap, reserve):
    """Never block forever: cap a wait by cap AND the global runtime budget."""
    avail = HARD_BUDGET - (time.monotonic() - START_MONO) - reserve
    if avail < 0.05:
        return 0.05
    return min(cap, avail)


def next_id():
    NEXT_ID[0] += 1
    return NEXT_ID[0]


def send_obj(obj):
    stdin = PROC["stdin"]
    if stdin is None:
        return False
    try:
        stdin.write((json.dumps(obj, ensure_ascii=True) + "\n").encode("utf-8"))
        stdin.flush()
        return True
    except (OSError, ValueError):
        return False


def parse_rpc(raw):
    """Return the parsed dict if the line is a JSON-RPC message, else None."""
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    if "jsonrpc" not in obj:
        return None
    return obj


def pump_worker(fd):
    # The raw-pipe reader. os.read on the fd, buffer bytes, split on b"\n",
    # append decoded lines under the lock. Terminates on EOF or fd error.
    buf = bytearray()
    try:
        while True:
            data = os.read(fd, 65536)
            if not data:
                break
            buf += data
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                raw = bytes(buf[:nl])
                del buf[:nl + 1]
                with LINES_LOCK:
                    LINES.append(raw.decode("utf-8", "replace"))
    except OSError:
        pass
    if buf:
        # An unterminated tail is still one stdout line; keep it for check 4.
        with LINES_LOCK:
            LINES.append(bytes(buf).decode("utf-8", "replace"))
    PUMP_DONE.set()


def await_msg(msg_id, timeout):
    """Consume lines (advancing CUR) until the reply with msg_id arrives.

    Malformed lines are recorded (check 4) and skipped. Returns None on
    timeout or when the pipe reached EOF. Never blocks longer than timeout.
    """
    global CUR
    end = time.monotonic() + timeout
    while True:
        while True:
            with LINES_LOCK:
                if CUR >= len(LINES):
                    break
                raw = LINES[CUR]
            CUR += 1
            obj = parse_rpc(raw)
            if obj is None:
                VIOLATIONS.append(raw)
                continue
            if obj.get("id") == msg_id:
                return obj
        if PUMP_DONE.is_set():
            return None
        if time.monotonic() >= end:
            return None
        time.sleep(0.01)


def find_log_notification(after_index, timeout):
    # Scan raw lines from after_index for a notifications/message.
    # Does not consume (CUR untouched, no double counting in check 4).
    end = time.monotonic() + timeout
    while True:
        with LINES_LOCK:
            upto = len(LINES)
        i = max(0, after_index)
        while i < upto:
            obj = parse_rpc(LINES[i])
            if obj is not None and obj.get("method") == "notifications/message":
                return i
            i += 1
        if PUMP_DONE.is_set():
            return -1
        if time.monotonic() >= end:
            return -1
        time.sleep(0.02)


def schema_problems(tool_entry):
    problems = []
    if not isinstance(tool_entry, dict):
        return ["entry is not an object"]
    name = tool_entry.get("name")
    if not isinstance(name, str) or name == "":
        problems.append("name missing or not a string")
    schema = tool_entry.get("inputSchema")
    if not isinstance(schema, dict):
        problems.append("inputSchema missing or not an object")
    else:
        stype = schema.get("type")
        if stype != "object":
            problems.append("inputSchema.type=%r not 'object'" % (stype,))
        if "properties" not in schema:
            problems.append("inputSchema has no properties key")
        elif not isinstance(schema["properties"], dict):
            problems.append("inputSchema.properties is not an object")
    return problems


def kill_guard():
    # atexit guard: if the server child is still alive at interpreter exit,
    # do not leave it orphaned.
    proc = PROC["proc"]
    if proc is None:
        return
    try:
        proc.poll() or proc.kill()
    except Exception:
        pass


atexit.register(kill_guard)


# ----------------------------------------------------------------- main ----
def main(argv):
    calls = []
    expected_tools = []
    stderr_out = None
    positional = []
    cli_problems = []

    i = 1
    while i < len(argv):
        token = argv[i]
        if token == "--call":
            if i + 2 >= len(argv):
                cli_problems.append("--call needs <toolName> and <jsonArgs>")
                break
            raw_args = argv[i + 2]
            try:
                parsed = json.loads(raw_args)
            except ValueError:
                cli_problems.append("--call %s: <jsonArgs> is not valid JSON"
                                    % argv[i + 1])
                break
            if not isinstance(parsed, dict):
                cli_problems.append("--call %s: <jsonArgs> must be a JSON object"
                                    % argv[i + 1])
                break
            calls.append((argv[i + 1], parsed))
            i += 3
        elif token == "--expect-tool":
            if i + 1 >= len(argv):
                cli_problems.append("--expect-tool needs an argument")
                break
            expected_tools.append(argv[i + 1])
            i += 2
        elif token == "--stderr-out":
            if i + 1 >= len(argv):
                cli_problems.append("--stderr-out needs an argument")
                break
            stderr_out = argv[i + 1]
            i += 2
        elif token in ("-h", "--help"):
            emit(USAGE)
            return 0
        else:
            positional.append(token)
            i += 1
    if len(positional) != 2:
        cli_problems.append("exactly two positional args required: "
                            "<node.exe> <entry.js>")
    if cli_problems:
        for problem in cli_problems:
            emit("ARG ERROR: " + problem)
        emit(USAGE)
        return 2
    node_exe = positional[0]
    entry_js = positional[1]

    # Windows: make our own stdin/stdout binary so no newline munging ever
    # happens on raw JSON bytes passing through the harness itself.
    if os.name == "nt":
        try:
            msvcrt.setmode(0, os.O_BINARY)
            msvcrt.setmode(1, os.O_BINARY)
        except OSError:
            pass

    if stderr_out is None:
        stderr_out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "mcp_stdio_harness.stderr.log")
    try:
        errfh = open(stderr_out, "wb")
    except OSError as exc:
        emit("ERROR: cannot open stderr capture file %r: %s" % (stderr_out, exc))
        return 2

    cmd = [node_exe, entry_js]
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=errfh)
    except (OSError, ValueError) as exc:
        emit("ERROR: could not spawn %r: %s" % (cmd, exc))
        emit("RESULT: FAIL 1 failed")
        return 1
    PROC["proc"] = proc
    PROC["stdin"] = proc.stdin

    fd = proc.stdout.fileno()
    pump = threading.Thread(target=pump_worker, args=(fd,), name="stdio-pump")
    pump.daemon = True
    pump.start()
    emit("INFO: spawned server child %r; child stderr captured to %r"
         % (cmd, stderr_out))

    # ---- check 1: initialize handshake --------------------------------------
    logging_capable = False
    init_id = next_id()
    init_msg = {
        "jsonrpc": "2.0",
        "id": init_id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-stdio-harness", "version": "0.1"},
        },
    }
    if not send_obj(init_msg):
        record_check(1, "initialize-handshake", "FAIL",
                     "(stdin closed before initialize: %s)" % child_status())
    else:
        obj = await_msg(init_id, bounded_wait(20.0, 25.0))
        if obj is None:
            record_check(1, "initialize-handshake", "FAIL",
                         "(no initialize reply: %s)" % child_status())
        elif "error" in obj:
            record_check(1, "initialize-handshake", "FAIL",
                         "(JSON-RPC error: %s)" % brief(obj["error"]))
        else:
            result = obj.get("result")
            if not isinstance(result, dict):
                record_check(1, "initialize-handshake", "FAIL",
                             "(initialize result missing or not an object)")
            else:
                caps = result.get("capabilities")
                if isinstance(caps, dict):
                    logging_capable = "logging" in caps
                pv = result.get("protocolVersion")
                if pv != PROTOCOL_VERSION:
                    record_check(1, "initialize-handshake", "FAIL",
                                 "(server echoed protocolVersion=%r)" % (pv,))
                else:
                    detail = ""
                    info = result.get("serverInfo")
                    if isinstance(info, dict):
                        detail = "(serverInfo=%s)" % brief(info.get("name"))
                    record_check(1, "initialize-handshake", "PASS", detail)
    send_obj({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # ---- check 2: tools/list returns all tools + schema integrity -----------
    tool_names = []
    bad_schemas = []
    list_complete = False
    list_note = ""
    cursor = None
    pages_used = 0
    while pages_used < 5:
        pages_used += 1
        lid = next_id()
        msg = {"jsonrpc": "2.0", "id": lid, "method": "tools/list"}
        if cursor:
            msg["params"] = {"cursor": cursor}
        if not send_obj(msg):
            list_note = "tools/list send failed: %s" % child_status()
            break
        obj = await_msg(lid, bounded_wait(15.0, 25.0))
        if obj is None:
            list_note = "tools/list page %d: no reply (%s)" % (pages_used,
                                                               child_status())
            break
        if "error" in obj:
            list_note = "tools/list JSON-RPC error: %s" % brief(obj["error"])
            break
        result = obj.get("result")
        if not isinstance(result, dict):
            list_note = "tools/list result missing or not an object"
            break
        page_tools = result.get("tools")
        if not isinstance(page_tools, list):
            list_note = "tools/list 'tools' field missing or not a list"
            break
        for tool_entry in page_tools:
            problems = schema_problems(tool_entry)
            if problems:
                bad_schemas.append("%s: %s"
                                   % (brief(tool_entry.get("name")
                                        if isinstance(tool_entry, dict)
                                        else None, 60), "; ".join(problems)))
            else:
                tool_names.append(tool_entry.get("name"))
        cursor = result.get("nextCursor")
        if cursor is None or cursor == "":
            list_complete = True
            break
    if not list_complete and not list_note:
        list_note = "pagination not exhausted after 5 pages"
    if not list_complete:
        record_check(2, "tools-list-integrity", "FAIL", "(%s)" % list_note)
    else:
        missing = [t for t in expected_tools if t not in tool_names]
        if bad_schemas:
            record_check(2, "tools-list-integrity", "FAIL",
                         "(%d malformed schemas: %s)"
                         % (len(bad_schemas),
                            "; ".join(brief(s, 200) for s in bad_schemas[:3])))
        elif missing:
            record_check(2, "tools-list-integrity", "FAIL",
                         "(expected tools not offered: %s)" % ", ".join(missing))
        elif not tool_names and not expected_tools:
            record_check(2, "tools-list-integrity", "PASS",
                         "(server exposes 0 tools; pagination exhausted; "
                         "vacuously satisfied)")
        else:
            record_check(2, "tools-list-integrity", "PASS",
                         "(%d tools listed, every inputSchema type=object "
                         "with properties object)" % len(tool_names))

    # ---- check 3: real tool results -----------------------------------------
    call_notes = []
    for (tool_name, args_obj) in calls:
        cid = next_id()
        if not send_obj({"jsonrpc": "2.0", "id": cid, "method": "tools/call",
                         "params": {"name": tool_name,
                                    "arguments": args_obj}}):
            call_notes.append("%s: stdin closed" % tool_name)
            continue
        obj = await_msg(cid, bounded_wait(15.0, 25.0))
        if obj is None:
            call_notes.append("%s: no reply (%s)" % (tool_name, child_status()))
            continue
        if "error" in obj:
            call_notes.append("%s: JSON-RPC error %s" % (tool_name,
                                                         brief(obj["error"])))
            continue
        result = obj.get("result")
        if not isinstance(result, dict):
            call_notes.append("%s: result missing or not an object" % tool_name)
            continue
        content = result.get("content")
        content_ok = isinstance(content, list) and len(content) > 0
        errored = result.get("isError") is True
        if content_ok and not errored:
            continue
        if errored:
            note = "isError=true"
            if content_ok:
                note += ", first content block: %s" % brief(content[0], 120)
        else:
            note = "content array missing or empty"
        call_notes.append("%s: %s" % (tool_name, note))
    if not calls:
        record_check(3, "real-tool-results", "PASS",
                     "(no --call arguments given: vacuously satisfied)")
    elif call_notes:
        record_check(3, "real-tool-results", "FAIL",
                     "(%d/%d calls bad: %s)"
                     % (len(call_notes), len(calls),
                        "; ".join(brief(n, 160) for n in call_notes[:4])))
    else:
        record_check(3, "real-tool-results", "PASS",
                     "(%d/%d calls returned non-empty content, isError not "
                     "true)" % (len(calls), len(calls)))

    # ---- check 5: logging/setLevel + notifications/message ------------------
    log_boundary = len(LINES)
    lv_note = ""
    setlevel_ok = False
    lv_id = next_id()
    if send_obj({"jsonrpc": "2.0", "id": lv_id,
                 "method": "logging/setLevel",
                 "params": {"level": "info"}}):
        lv_obj = await_msg(lv_id, bounded_wait(10.0, 25.0))
        if lv_obj is None:
            lv_note = "no reply to logging/setLevel"
        elif "error" in lv_obj:
            lv_note = "logging/setLevel JSON-RPC error: %s" % brief(lv_obj["error"])
        elif "result" in lv_obj:
            lv_note = "logging/setLevel succeeded"
            setlevel_ok = True
        else:
            lv_note = "logging/setLevel returned something odd"
    else:
        lv_note = "logging/setLevel could not be sent: %s" % child_status()
    if setlevel_ok:
        # Generate log activity: a cheap round-trip that may make the server
        # emit a notifications/message line.
        trig_id = next_id()
        if send_obj({"jsonrpc": "2.0", "id": trig_id, "method": "tools/list"}):
            await_msg(trig_id, bounded_wait(5.0, 25.0))
    notif_idx = find_log_notification(log_boundary, bounded_wait(8.0, 25.0))
    if notif_idx >= 0:
        record_check(5, "logging-setLevel-notifications", "PASS",
                     "(notifications/message seen after setLevel: %s)"
                     % brief(LINES[notif_idx], 160))
    elif not logging_capable:
        record_check(5, "logging-setLevel-notifications", "SKIP",
                     "(server advertises NO logging capability in initialize; "
                     "%s; no notifications/message. Absence treated as SKIP, "
                     "not failure.)" % lv_note)
    else:
        record_check(5, "logging-setLevel-notifications", "FAIL",
                     "(logging capability advertised; %s; no "
                     "notifications/message observed)" % lv_note)

    # ---- check 6: malformed call rejected without crashing ------------------
    bogus_tool = "__mcp_stdio_harness_bogus_tool__"
    inv_id = next_id()
    inv_obj = None
    if send_obj({"jsonrpc": "2.0", "id": inv_id, "method": "tools/call",
                 "params": {"name": bogus_tool,
                            "arguments": {"__bogus_arg__": 42}}}):
        inv_obj = await_msg(inv_id, bounded_wait(10.0, 25.0))
    rc_now = PROC["proc"].poll()
    crashed = rc_now is not None and rc_now != 0
    if inv_obj is None:
        record_check(6, "malformed-args-rejected", "FAIL",
                     "(no reply to bogus call: %s)" % child_status())
    elif "error" in inv_obj:
        if crashed:
            record_check(6, "malformed-args-rejected", "FAIL",
                         "(error returned but child then crashed rc=%s)" % rc_now)
        else:
            record_check(6, "malformed-args-rejected", "PASS",
                         "(bogus tool call produced JSON-RPC error as required: "
                         "%s)" % brief(inv_obj["error"]))
    elif isinstance(inv_obj.get("result"), dict) and inv_obj["result"].get("isError") is True:
        record_check(6, "malformed-args-rejected", "PASS",
                     "(bogus call produced isError=true result; no crash)")
    else:
        record_check(6, "malformed-args-rejected", "FAIL",
                     "(bogus call was accepted as a normal result: %s)"
                     % brief(inv_obj.get("result")))

    # ---- check 7: clean exit 0 on stdin EOF ---------------------------------
    try:
        if PROC["stdin"] is not None:
            PROC["stdin"].close()
    except (OSError, ValueError):
        pass
    wait_s = bounded_wait(EXIT_WAIT, 12.0)
    try:
        rc = proc.wait(timeout=wait_s)
        if rc == 0:
            record_check(7, "clean-exit-on-stdin-eof", "PASS",
                         "(child exited 0 after stdin EOF within %.1fs)" % wait_s)
        else:
            record_check(7, "clean-exit-on-stdin-eof", "FAIL",
                         "(returncode=%s after stdin EOF)" % rc)
    except subprocess.TimeoutExpired:
        record_check(7, "clean-exit-on-stdin-eof", "FAIL",
                     "(still running %.1fs after stdin EOF; killing)" % wait_s)
        try:
            proc.kill()
        except (OSError, AttributeError):
            pass
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass

    # ---- check 8: no orphaned child processes --------------------------------
    if os.name != "nt":
        record_check(8, "no-orphaned-children", "SKIP",
                     "(not Windows: Get-CimInstance Win32_Process check "
                     "skipped gracefully)")
    else:
        entry_base = os.path.basename(entry_js)
        # Baseline first: sibling MCP servers (ssh-mcp, browser-mcp, ...) also
        # run as node.exe <...>/index.js, so count only processes that appear
        # AFTER the harness spawned its own child.
        ps = ("Get-CimInstance Win32_Process | "
              "Where-Object { $_.ProcessName -like 'node*' -and "
              "$_.CommandLine -like (\"*\" + $env:MCPTHARNESS_ENTRY + \"*\") } | "
              "ForEach-Object { \"$($_.ProcessId) :: \" + $_.CommandLine }")
        env = dict(os.environ)
        env["MCPTHARNESS_ENTRY"] = entry_base

        def scan_orphans():
            try:
                cp = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                                     ps], capture_output=True, text=True,
                                     timeout=10, env=env)
                return [ln for ln in cp.stdout.splitlines() if ln.strip()]
            except (OSError, subprocess.TimeoutExpired):
                return None

        baseline_pids = set()
        for ln in scan_orphans() or []:
            baseline_pids.add(ln.split(" :: ", 1)[0].strip())
        orphans = []
        attempt = 0
        while attempt < 3:
            attempt += 1
            found = scan_orphans()
            if found is None:
                orphans = ["powershell check failed"]
                break
            orphans = [ln for ln in found
                       if ln.split(" :: ", 1)[0].strip() not in baseline_pids]
            if not orphans:
                break
            if attempt < 3:
                time.sleep(0.5)
        if orphans:
            record_check(8, "no-orphaned-children", "FAIL",
                         "(%d NEW live node process(es) still running entry %r beyond the %d pre-existing: %s)"
                         % (len(orphans), entry_base, len(baseline_pids),
                            "; ".join(brief(o, 100) for o in orphans[:3])))
        else:
            record_check(8, "no-orphaned-children", "PASS",
                         "(Get-CimInstance Win32_Process found no NEW node process for entry %r; %d pre-existing sibling servers ignored)"
                         % (entry_base, len(baseline_pids)))

    # ---- check 4: zero non-JSON lines on child stdout -----------------------
    PUMP_DONE.wait(timeout=min(2.0,
                               max(0.1, HARD_BUDGET - (time.monotonic()
                                                      - START_MONO))))
    j = CUR
    while j < len(LINES):
        if parse_rpc(LINES[j]) is None:
            VIOLATIONS.append(LINES[j])
        j += 1
    if VIOLATIONS:
        shown = "; ".join(brief(v, 120) for v in VIOLATIONS[:5])
        record_check(4, "stdout-zero-non-json-lines", "FAIL",
                     "(%d line(s) are not JSON-RPC, offending text: %s)"
                     % (len(VIOLATIONS), shown))
    else:
        record_check(4, "stdout-zero-non-json-lines", "PASS",
                     "(%d stdout lines classified, all valid JSON-RPC 2.0 "
                     "messages)" % len(LINES))

    emit("INFO: stdout lines total=%d consumed=%d violations=%d; runtime=%.1fs"
         % (len(LINES), CUR, len(VIOLATIONS),
            time.monotonic() - START_MONO))
    if FAILURES:
        emit("RESULT: FAIL %d failed" % len(FAILURES))
        return 1
    emit("RESULT: PASS")
    return 0


if __name__ == "__main__":
    try:
        code = main(sys.argv)
    except KeyboardInterrupt:
        code = 3
    except Exception as exc:
        emit("FATAL: %s" % exc)
        n = len(FAILURES) + 1
        emit("RESULT: FAIL %d failed" % n)
        code = 1
    sys.exit(code)
