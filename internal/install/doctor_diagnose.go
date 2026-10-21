package install

import (
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// doctorGOOS is runtime.GOOS, swappable in tests of OS-specific diagnoses.
var doctorGOOS = runtime.GOOS

// latestPluginVersion fetches the newest scanner plugin release. A var so
// tests can stub the network call.
var latestPluginVersion = func() (string, error) {
	pi := newPluginInstaller()
	pi.httpClient.Timeout = 10 * time.Second
	return pi.LatestVersion()
}

// windowsToolHangFixedIn is the first scanner plugin release whose git
// subprocesses don't inherit the MCP stdin pipe. Before it, on Windows, a git
// child blocks on that pipe until the editor sends its next message, so every
// tool call stalls until git's 5s timeout or hangs outright.
const windowsToolHangFixedIn = "1.4.2"

const windowsToolHangHint = "This is a known bug in scanner plugin versions before v" + windowsToolHangFixedIn +
	" on Windows: the server's git calls inherit the editor's stdin pipe and block until the editor sends another message, " +
	"so every tool call, scans included, stalls for 5 seconds or hangs. Fixed in v" + windowsToolHangFixedIn +
	". Run: armis-cli mcp doctor --fix (installs the latest plugin), then restart your editor."

// serverStartRe matches the scanner's startup log line, which carries the
// plugin version. The initialize response's serverInfo.version is the MCP SDK
// version on older plugins, so it can't be used for this.
var serverStartRe = regexp.MustCompile(`Starting Armis AppSec MCP server (\S+)`)

// pluginVersionFromStderr returns the scanner plugin version the spawned
// server reported on startup, or "".
func pluginVersionFromStderr(stderr string) string {
	if m := serverStartRe.FindStringSubmatch(stderr); m != nil && m[1] != "unknown" {
		return m[1]
	}
	return ""
}

// versionBefore reports whether version is older than want. Unparseable
// versions are never "before", so a dev build doesn't trigger version advice.
func versionBefore(version, want string) bool {
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	w, err := semver.NewVersion(want)
	if err != nil {
		return false
	}
	return v.LessThan(w)
}

// hasWindowsToolHang reports whether a scanner plugin version has the
// Windows git/stdin hang.
func hasWindowsToolHang(component, version string) bool {
	return component == "scanner" && doctorGOOS == osWindows && versionBefore(version, windowsToolHangFixedIn)
}

// stuckToolCallHint explains a tool call that hung or was slow even though the
// server started and listed its tools. That combination rules out the usual
// suspects for a timeout (cold start, antivirus, the network), so it gets its
// own diagnosis instead of the generic timeout hint.
func stuckToolCallHint(component, version string) (string, FixAction) {
	if hasWindowsToolHang(component, version) {
		return windowsToolHangHint, FixReinstall
	}
	return "The server starts and lists its tools, but stalls while running " + debugConfigTool + ", which makes no network calls. " +
		"So this is not a slow start, antivirus, or the network: something local inside the server is blocking, and scans in your editor will stall the same way. " +
		"Send a support bundle (armis-cli mcp doctor --bundle): scanner/server.log and the stderr files show the last thing the server did.", FixNone
}

// isTimeout reports whether a session error is the doctor giving up waiting.
func isTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timed out")
}

// receivedToolCall reports whether the server's stderr shows it received a
// tools/call request (the MCP SDK logs each request type at INFO).
func receivedToolCall(stderr string) bool {
	return strings.Contains(stderr, "CallToolRequest")
}

// --- server.log analysis ---

// serverLogLineRe matches a server_log line: date, time, level, [pid], logger,
// message.
var serverLogLineRe = regexp.MustCompile(`^(\S+ \S+) \w+ \[(\d+)\] [^:]+: (.*)$`)

// toolDoneRe matches the scanner's per-call log line from @_logged_tool.
var toolDoneRe = regexp.MustCompile(`^tool (\w+) (?:ok|failed|crashed) in ([\d.]+)s`)

// toolLogStats summarizes the tool calls recorded in the scanner's server.log,
// i.e. what happened in the user's real editor sessions, not the doctor's.
type toolLogStats struct {
	calls      int     // tools/call requests received
	unfinished int     // calls whose process stopped or was replaced before answering
	slowDiag   int     // debug_config calls slower than slowToolCallThreshold
	maxDiag    float64 // slowest debug_config, in seconds
	lastStuck  string  // timestamp of the most recent unfinished or slow call
}

// analyzeServerLog counts tool calls per server process. A call is unfinished
// when its process logged a shutdown, or a later process started, while the
// call was still open. The last process in the log may still be running, so
// its open calls aren't counted.
func analyzeServerLog(log string) toolLogStats {
	var st toolLogStats
	type proc struct {
		open    int
		lastReq string
	}
	procs := make(map[string]*proc)
	var order []string
	closeProc := func(pid string) {
		if p := procs[pid]; p != nil && p.open > 0 {
			st.unfinished += p.open
			st.lastStuck = p.lastReq
			p.open = 0
		}
	}
	for _, line := range strings.Split(log, "\n") {
		m := serverLogLineRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		ts, pid, msg := m[1], m[2], m[3]
		p := procs[pid]
		if p == nil {
			// A new process: any earlier one with open calls was killed.
			for _, prev := range order {
				closeProc(prev)
			}
			p = &proc{}
			procs[pid] = p
			order = append(order, pid)
		}
		switch {
		case strings.Contains(msg, "CallToolRequest"):
			st.calls++
			p.open++
			p.lastReq = ts
		case msg == "MCP server stopped":
			closeProc(pid)
		default:
			d := toolDoneRe.FindStringSubmatch(msg)
			if d == nil {
				continue
			}
			p.open = max(p.open-1, 0)
			if d[1] != debugConfigTool {
				continue
			}
			secs, _ := strconv.ParseFloat(d[2], 64)
			st.maxDiag = max(st.maxDiag, secs)
			if time.Duration(secs*float64(time.Second)) > slowToolCallThreshold {
				st.slowDiag++
				st.lastStuck = ts
			}
		}
	}
	return st
}

// checkServerLogToolCalls reports stuck tool calls recorded in server.log.
// The doctor's own probe proves what happens now; the log proves what the
// user's editor saw, which is often the one the user is asking about.
func checkServerLogToolCalls(d *doctorRun, component, log, version string) {
	st := analyzeServerLog(log)
	if st.calls == 0 {
		return
	}
	if st.unfinished == 0 && st.slowDiag == 0 {
		d.report.add(component, "recent tool calls", StatusOK,
			fmt.Sprintf("server.log: %d recent tool calls, all finished", st.calls))
		return
	}
	var parts []string
	if st.unfinished > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d recent tool calls never finished", st.unfinished, st.calls))
	}
	if st.slowDiag > 0 {
		parts = append(parts, fmt.Sprintf("%s took up to %.2fs (should be well under a second)", debugConfigTool, st.maxDiag))
	}
	detail := "server.log: " + strings.Join(parts, "; ") + ", most recently at " + st.lastStuck
	hint, action := stuckToolCallHint(component, version)
	d.report.add(component, "recent tool calls", StatusWarn, detail).fix(action, hint)
}

// checkPluginVersion reports the installed scanner version, and when the
// network checks are on, whether a newer release exists. Being out of date is
// the first thing support asks about, and the answer for known bugs.
func checkPluginVersion(d *doctorRun, component, installed string) {
	if installed == "" {
		d.report.add(component, "plugin version", StatusWarn, "no installed version recorded").
			fix(FixReinstall, "Reinstall the plugin: armis-cli mcp doctor --fix")
		return
	}
	latest := ""
	if d.opts.Handshake {
		if v, err := latestPluginVersion(); err == nil {
			latest = v
		}
	}
	switch {
	case hasWindowsToolHang(component, installed):
		detail := "v" + installed
		if latest != "" {
			detail += " (latest is v" + latest + ")"
		}
		d.report.add(component, "plugin version", StatusWarn, detail).fix(FixReinstall, windowsToolHangHint)
	case latest != "" && versionBefore(installed, latest):
		d.report.add(component, "plugin version", StatusWarn, fmt.Sprintf("v%s (latest is v%s)", installed, latest)).
			fix(FixReinstall, "Update to the latest plugin: armis-cli mcp doctor --fix (or armis-cli mcp update), then restart your editor.")
	default:
		d.report.add(component, "plugin version", StatusOK, "v"+installed).short("v" + installed)
	}
}
