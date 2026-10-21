package install

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func stubGOOS(t *testing.T, goos string) {
	t.Helper()
	orig := doctorGOOS
	doctorGOOS = goos
	t.Cleanup(func() { doctorGOOS = orig })
}

func shortToolCallTimeout(t *testing.T) {
	t.Helper()
	orig := toolCallTimeout
	toolCallTimeout = 500 * time.Millisecond
	t.Cleanup(func() { toolCallTimeout = orig })
}

// A server that starts fast and lists its tools but hangs in debug_config was
// reported as a "slow start" with antivirus advice. It must be reported as a
// hung tool call, with the known Windows bug when the version matches.
func TestProbeHungToolCallIsNotSlowStart(t *testing.T) {
	shortToolCallTimeout(t)
	stubGOOS(t, osWindows)

	d := newDoctorRun(DoctorOptions{Handshake: true, Timeout: 10 * time.Second})
	d.probe("scanner", "", helperLaunch("toolhang"))
	d.probe("scanner", "VS Code", helperLaunch("toolhang"))

	checks := checkMap(d.report)
	start := wantStatus(t, checks, "scanner/live handshake", StatusOK)
	if !strings.Contains(start.Detail, "v1.4.1") {
		t.Errorf("handshake detail = %q, want the plugin version from stderr, not the SDK's 1.25.0", start.Detail)
	}
	call := wantStatus(t, checks, "scanner/tool call", StatusFail)
	if !strings.Contains(call.Detail, "received the call") {
		t.Errorf("tool call detail = %q, want stderr evidence", call.Detail)
	}
	if call.Fix != FixReinstall || !strings.Contains(call.Remediation, "known bug") {
		t.Errorf("tool call fix/hint = %q / %q, want FixReinstall with the known-bug hint", call.Fix, call.Remediation)
	}
	if strings.Contains(strings.ToLower(call.Remediation), "antivirus") && !strings.Contains(call.Remediation, "not a slow start") {
		t.Errorf("hint still blames antivirus: %q", call.Remediation)
	}
	dup := wantStatus(t, checks, "scanner/VS Code launch", StatusFail)
	if !strings.Contains(dup.Detail, "tool call") {
		t.Errorf("dedup detail = %q, want the reason it fails", dup.Detail)
	}
}

func TestProbeHungToolCallOtherOS(t *testing.T) {
	shortToolCallTimeout(t)
	stubGOOS(t, "linux")

	d := newDoctorRun(DoctorOptions{Handshake: true, Timeout: 10 * time.Second})
	d.probe("scanner", "", helperLaunch("toolhang"))
	call := wantStatus(t, checkMap(d.report), "scanner/tool call", StatusFail)
	if call.Fix != FixNone || !strings.Contains(call.Remediation, "not a slow start") {
		t.Errorf("tool call fix/hint = %q / %q", call.Fix, call.Remediation)
	}
}

func TestProbeSlowToolCallWarns(t *testing.T) {
	orig := slowToolCallThreshold
	slowToolCallThreshold = 50 * time.Millisecond
	t.Cleanup(func() { slowToolCallThreshold = orig })
	stubGOOS(t, osWindows)

	d := newDoctorRun(DoctorOptions{Handshake: true, Timeout: 10 * time.Second})
	d.probe("scanner", "", helperLaunch("toolslow"))
	call := wantStatus(t, checkMap(d.report), "scanner/tool call", StatusWarn)
	if call.Fix != FixReinstall || !strings.Contains(call.Detail, "should be well under a second") {
		t.Errorf("slow tool call = %+v", call)
	}
}

// customerServerLog is the scanner log from the support case that motivated
// the tool-call checks: two 5.06s debug_config calls (git's 5s timeout) and a
// call whose process was replaced before it answered.
const customerServerLog = `2026-10-21 14:24:44,526 INFO [45020] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3.14.4)
2026-10-21 14:24:44,656 INFO [45020] mcp.server.lowlevel.server: Processing request of type CallToolRequest
2026-10-21 14:24:49,714 INFO [45020] appsec-mcp: tool debug_config ok in 5.06s
2026-10-21 14:24:49,724 INFO [45020] appsec-mcp: MCP server stopped
2026-10-21 14:24:56,647 INFO [40500] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3.14.4)
2026-10-21 14:24:56,734 INFO [40500] mcp.server.lowlevel.server: Processing request of type CallToolRequest
2026-10-21 14:25:01,797 INFO [40500] appsec-mcp: tool debug_config ok in 5.06s
2026-10-21 14:25:01,806 INFO [40500] appsec-mcp: MCP server stopped
2026-10-21 14:37:34,100 INFO [42776] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3.14.4)
2026-10-21 14:37:34,174 INFO [42776] mcp.server.lowlevel.server: Processing request of type CallToolRequest
2026-10-21 14:37:47,351 INFO [48228] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3.14.4)
2026-10-21 14:37:47,410 INFO [48228] mcp.server.lowlevel.server: Processing request of type CallToolRequest
`

func TestAnalyzeServerLog(t *testing.T) {
	stubProcesses(t, []procInfo{{PID: 48228, PPID: 1}}, nil) // the last server still runs
	st := analyzeServerLog(strings.ReplaceAll(customerServerLog, "\n", "\r\n"))
	if st.calls != 4 || st.unfinished != 1 || st.slowDiag != 2 || st.maxDiag != 5.06 {
		t.Errorf("stats = %+v, want 4 calls, 1 unfinished (the last process may still run), 2 slow at 5.06s", st)
	}
	if st.lastStuck != "2026-10-21 14:37:34,174" {
		t.Errorf("lastStuck = %q", st.lastStuck)
	}

	healthy := analyzeServerLog("2026-10-21 14:24:44,656 INFO [1] mcp.server.lowlevel.server: Processing request of type CallToolRequest\n" +
		"2026-10-21 14:24:44,700 INFO [1] appsec-mcp: tool scan_diff ok in 42.10s\n" +
		"2026-10-21 14:24:49,724 INFO [1] appsec-mcp: MCP server stopped\n")
	if healthy.unfinished != 0 || healthy.slowDiag != 0 {
		t.Errorf("a slow scan is normal, got %+v", healthy)
	}
}

func TestAnalyzeServerLogLiveness(t *testing.T) {
	// Two editors, each with a server mid-call: neither is unfinished while both run.
	both := "2026-10-21 14:37:34,174 INFO [10] mcp.server.lowlevel.server: Processing request of type CallToolRequest\n" +
		"2026-10-21 14:37:35,000 INFO [20] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3)\n" +
		"2026-10-21 14:37:36,000 INFO [20] mcp.server.lowlevel.server: Processing request of type CallToolRequest\n"
	stubProcesses(t, []procInfo{{PID: 10}, {PID: 20}}, nil)
	if st := analyzeServerLog(both); st.unfinished != 0 {
		t.Errorf("running servers counted as unfinished: %+v", st)
	}
	// The older server is gone: its call never finished; the running one's isn't counted.
	stubProcesses(t, []procInfo{{PID: 20}}, nil)
	if st := analyzeServerLog(both); st.unfinished != 1 || st.lastStuck != "2026-10-21 14:37:34,174" {
		t.Errorf("want the dead server's call only: %+v", st)
	}
	// No process table: a later server means the earlier one was replaced.
	stubProcesses(t, nil, errors.New("no ps"))
	if st := analyzeServerLog(both); st.unfinished != 1 {
		t.Errorf("fallback: %+v", st)
	}
}

func TestAnalyzeServerLogSkipsDoctorProbes(t *testing.T) {
	stubProcesses(t, nil, nil)
	recordProbePID(31337)
	log := "2026-10-21 14:37:34,174 INFO [31337] mcp.server.lowlevel.server: Processing request of type CallToolRequest\n" +
		"2026-10-21 14:37:35,000 INFO [999] mcp.server.lowlevel.server: Processing request of type CallToolRequest\n"
	if st := analyzeServerLog(log); st.calls != 1 || st.unfinished != 1 {
		t.Errorf("probe pid should be ignored: %+v", st)
	}
}

func TestCheckServerLogToolCalls(t *testing.T) {
	stubProcesses(t, []procInfo{{PID: 48228, PPID: 1}}, nil)
	stubGOOS(t, osWindows)
	d := newDoctorRun(DoctorOptions{})
	checkServerLogToolCalls(d, "scanner", customerServerLog, "1.4.1")
	c := wantStatus(t, checkMap(d.report), "scanner/recent tool calls", StatusWarn)
	if !strings.Contains(c.Detail, "1 of 4 recent tool calls never finished") || !strings.Contains(c.Detail, "5.06s") {
		t.Errorf("detail = %q", c.Detail)
	}
	if c.Fix != FixReinstall {
		t.Errorf("fix = %q, want FixReinstall for the known Windows bug", c.Fix)
	}

	d = newDoctorRun(DoctorOptions{})
	checkServerLogToolCalls(d, "scanner", "no tool lines here\n", "1.4.1")
	if len(d.report.Checks) != 0 {
		t.Errorf("checks = %+v, want none without tool calls in the log", d.report.Checks)
	}
}

func TestCheckPluginVersion(t *testing.T) {
	tests := []struct {
		name, goos, installed, latest string
		latestErr                     error
		want                          CheckStatus
		wantFix                       FixAction
	}{
		{"windows hang version", osWindows, "1.4.1", "1.4.2", nil, StatusWarn, FixReinstall},
		{"windows hang version offline", osWindows, "1.4.1", "", errors.New("offline"), StatusWarn, FixReinstall},
		{"outdated", "linux", "1.4.1", "1.5.0", nil, StatusWarn, FixReinstall},
		{"current", osWindows, "1.4.2", "1.4.2", nil, StatusOK, FixNone},
		{"offline current", "linux", "1.4.1", "", errors.New("offline"), StatusOK, FixNone},
		{"dev build", "linux", "dev", "1.4.2", nil, StatusOK, FixNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubGOOS(t, tt.goos)
			orig := latestPluginVersion
			latestPluginVersion = func() (string, error) { return tt.latest, tt.latestErr }
			t.Cleanup(func() { latestPluginVersion = orig })

			d := newDoctorRun(DoctorOptions{Handshake: true})
			checkPluginVersion(d, "scanner", tt.installed)
			c := wantStatus(t, checkMap(d.report), "scanner/plugin version", tt.want)
			if c.Fix != tt.wantFix {
				t.Errorf("fix = %q, want %q", c.Fix, tt.wantFix)
			}
		})
	}
}

func TestPluginVersionFromStderr(t *testing.T) {
	if v := pluginVersionFromStderr("x\nINFO [1] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3.14.4 at C:\\py)\n"); v != "1.4.1" {
		t.Errorf("version = %q", v)
	}
	if v := pluginVersionFromStderr("Starting Armis AppSec MCP server unknown (python"); v != "" {
		t.Errorf("unknown version = %q, want empty", v)
	}
}

func TestCheckAuthSkipsCredentialsUnderSSO(t *testing.T) {
	called := false
	d := newDoctorRun(DoctorOptions{Handshake: true, AuthCheck: func(context.Context, string, string) error {
		called = true
		return nil
	}})
	t.Setenv("ARMIS_DEFAULT_AUTH_METHOD", "SSO")
	checkAuth(d, "scanner", map[string]string{"ARMIS_CLIENT_ID": "id", "ARMIS_CLIENT_SECRET": "s"})
	if called {
		t.Error("client credentials were validated although the server ignores them under SSO")
	}
	c := wantStatus(t, checkMap(d.report), "scanner/authentication", StatusInfo)
	if !strings.Contains(c.Detail, "shell only") {
		t.Errorf("detail = %q, want the shell-only source called out", c.Detail)
	}
}

func TestDedupeRemediations(t *testing.T) {
	long := strings.Repeat("a long hint ", 20)
	r := &DoctorReport{Checks: []DoctorCheck{
		{Name: "plugin version", Status: StatusWarn, Remediation: long, Fix: FixReinstall},
		{Name: "tool call", Status: StatusFail, Remediation: long, Fix: FixReinstall},
		{Name: "short", Status: StatusFail, Remediation: "Run: x"},
		{Name: "short again", Status: StatusFail, Remediation: "Run: x"},
	}}
	r.dedupeRemediations()
	if r.Checks[0].Remediation != long {
		t.Error("first occurrence lost its hint")
	}
	if !strings.Contains(r.Checks[1].Remediation, `"plugin version"`) || r.Checks[1].Fix != FixReinstall {
		t.Errorf("repeat = %+v, want a reference and the fix kept", r.Checks[1])
	}
	if r.Checks[3].Remediation != "Run: x" {
		t.Error("short hints should stay as they are")
	}
}
