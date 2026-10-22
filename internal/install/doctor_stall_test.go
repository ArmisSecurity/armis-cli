package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseProcessList(t *testing.T) {
	unix := "  100     1    05:12 /usr/bin/python server.py --flag\n  101   100       00:03 git diff HEAD --\nbad line\n"
	got := parseProcessList(unix, true)
	if len(got) != 2 || got[1].PID != 101 || got[1].PPID != 100 || got[1].Elapsed != "00:03" || got[1].Command != "git diff HEAD --" {
		t.Fatalf("unix parse = %+v", got)
	}
	if got[0].Command != "/usr/bin/python server.py --flag" {
		t.Errorf("command = %q", got[0].Command)
	}

	win := "200 4 1700000000000 C:\\Python\\python.exe server.py\r\n201 200 1700000005000 git status\r\n"
	got = parseProcessList(win, false)
	if len(got) != 2 || got[1].Command != "git status" || got[1].Elapsed != "" || got[1].Created != 1700000005000 {
		t.Fatalf("windows parse = %+v", got)
	}
}

func TestDescendants(t *testing.T) {
	all := []procInfo{
		{PID: 1, PPID: 0}, {PID: 10, PPID: 1}, {PID: 11, PPID: 10}, {PID: 12, PPID: 11},
		{PID: 20, PPID: 1}, {PID: 10, PPID: 12}, // a cycle must not loop forever
	}
	got := descendants(all, 10)
	var pids []int
	for _, p := range got {
		pids = append(pids, p.PID)
	}
	if len(pids) != 2 || pids[0] != 11 || pids[1] != 12 {
		t.Errorf("descendants(10) = %v, want [11 12]", pids)
	}
}

func TestDescendantsDropsPidReuseOrphans(t *testing.T) {
	all := []procInfo{
		{PID: 50, PPID: 4, Created: 2000},  // the server, which reused pid 50
		{PID: 60, PPID: 50, Created: 2500}, // real child
		{PID: 70, PPID: 60, Created: 3000}, // real grandchild
		{PID: 80, PPID: 50, Created: 1000}, // orphan of the dead former owner of pid 50
		{PID: 90, PPID: 80, Created: 1500}, // and its own child
		{PID: 100, PPID: 50},               // no start time: kept
	}
	var pids []int
	for _, p := range descendants(all, 50) {
		pids = append(pids, p.PID)
	}
	if len(pids) != 3 || pids[0] != 60 || pids[1] != 100 || pids[2] != 70 {
		t.Errorf("descendants(50) = %v, want [60 100 70]", pids)
	}
}

func TestStallInfoSummaryAndWaitingOn(t *testing.T) {
	st := &stallInfo{Snapshot: processSnapshot{Alive: true, Children: []procInfo{
		{PID: 5, Command: `"C:\Program Files\Git\cmd\git.exe" diff HEAD`, Elapsed: "00:09"},
	}}}
	if !st.waitingOn("git") || st.waitingOn("ssh") {
		t.Error("waitingOn(git) should match git.exe by base name only")
	}
	if s := st.summary(); !strings.Contains(s, `git.exe" diff HEAD`) {
		t.Errorf("summary = %q", s)
	}
	empty := &stallInfo{Snapshot: processSnapshot{Alive: true}}
	if !strings.Contains(empty.summary(), "no child processes") {
		t.Errorf("summary = %q", empty.summary())
	}
	if (*stallInfo)(nil).summary() != "" || (*stallInfo)(nil).waitingOn("git") {
		t.Error("nil stall must be inert")
	}
}

func TestPythonThreadTops(t *testing.T) {
	stderr := `INFO startup
Fatal Python error: Aborted

Thread 0x00007ff8 (most recent call first):
  File "/usr/lib/python3.14/subprocess.py", line 1946 in _try_wait
  File "/usr/lib/python3.14/subprocess.py", line 1264 in wait

Current thread 0x00001234 (most recent call first):
  File "/opt/armis/server.py", line 88 in <module>
`
	got := pythonThreadTops(stderr)
	want := []string{"subprocess.py:1946 in _try_wait", "server.py:88 in <module>"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("tops = %v, want %v", got, want)
	}
	if pythonThreadTops("no dump here") != nil {
		t.Error("stderr without a dump must give nil")
	}
}

func TestTraceLogCapsAndNilSafe(t *testing.T) {
	(*traceLog)(nil).add("->", []byte("x"))
	tl := newTraceLog()
	for i := 0; i < 200; i++ {
		tl.add("<-", []byte(strings.Repeat("x", 1500)))
	}
	if len(tl.String()) > maxTraceBytes+100 || !strings.Contains(tl.String(), "transcript truncated") {
		t.Errorf("transcript len = %d, want it capped", len(tl.String()))
	}
}

func TestStallHint(t *testing.T) {
	stubGOOS(t, "linux")
	git := &stallInfo{Snapshot: processSnapshot{Alive: true, Children: []procInfo{{PID: 7, Command: "git diff"}}}}
	h, action := stallHint("scanner", "1.4.2", git)
	if action != FixNone || !strings.Contains(h, "waiting on a process it started") || !strings.Contains(h, "credential helper") {
		t.Errorf("git stall hint = %q / %q", action, h)
	}
	h, _ = stallHint("scanner", "1.4.2", &stallInfo{Snapshot: processSnapshot{Alive: true}})
	if !strings.Contains(h, "not a slow start") {
		t.Errorf("no-child stall should fall back to the generic hint, got %q", h)
	}
	stubGOOS(t, osWindows)
	if _, action := stallHint("scanner", "1.4.1", git); action != FixReinstall {
		t.Errorf("known Windows bug should still win, got %q", action)
	}
}

func TestHandshakeStallRecordsChildProcess(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("uses sleep")
	}
	shortToolCallTimeout(t)
	out := runHandshake(handshakeRequest{
		Command: os.Args[0], Env: map[string]string{"ARMIS_TEST_MCP_HELPER": "toolhang-child"}, Timeout: 5 * time.Second,
	})
	if out.Err != nil || out.Result == nil {
		t.Fatalf("handshake = %+v", out)
	}
	if out.Stall == nil || !out.Stall.waitingOn("sleep") {
		t.Fatalf("stall = %+v, want the sleep child recorded", out.Stall)
	}
	if !strings.Contains(out.Transcript, `"method":"tools/call"`) || !strings.Contains(out.Transcript, "timed out waiting") {
		t.Errorf("transcript = %q, want the request and the timeout", out.Transcript)
	}
}

func TestProbeDeepScan(t *testing.T) {
	d := newDoctorRun(DoctorOptions{Handshake: true, Deep: true, Timeout: 10 * time.Second})
	d.deepFile = "/tmp/probe.py"
	d.probe("scanner", "", helperLaunch("deep"))
	checks := checkMap(d.report)
	scan := wantStatus(t, checks, "scanner/scan call", StatusOK)
	if !strings.Contains(scan.Detail, "scan_file succeeded") {
		t.Errorf("scan call = %+v", scan)
	}
	if tr := d.report.Artifacts["transcripts/scanner-live-handshake.txt"]; !strings.Contains(tr, "timings: initialize") {
		t.Errorf("transcript artifact missing or without timings: %q", tr)
	}
}

func TestProbeDeepScanHang(t *testing.T) {
	shortToolCallTimeout(t)
	orig := deepCallTimeout
	deepCallTimeout = 400 * time.Millisecond
	t.Cleanup(func() { deepCallTimeout = orig })
	stubGOOS(t, "linux")

	d := newDoctorRun(DoctorOptions{Handshake: true, Deep: true, Timeout: 10 * time.Second})
	d.deepFile = "/tmp/probe.py"
	d.probe("scanner", "", helperLaunch("deephang"))
	d.probe("scanner", "Cursor", helperLaunch("deephang"))
	checks := checkMap(d.report)
	wantStatus(t, checks, "scanner/tool call", StatusOK)
	scan := wantStatus(t, checks, "scanner/scan call", StatusFail)
	if !strings.Contains(scan.Detail, "never answered") || !strings.Contains(scan.Detail, "debug_config answered") {
		t.Errorf("scan call = %+v", scan)
	}
	// A second editor sharing the launch must inherit the scan_file failure.
	dup := wantStatus(t, checks, "scanner/Cursor launch", StatusFail)
	if !strings.Contains(dup.Detail, "scan call") {
		t.Errorf("duplicate launch detail = %q, want the scan call failure", dup.Detail)
	}
	if _, ok := d.report.Artifacts["stalls/scanner-live-handshake.txt"]; !ok {
		t.Error("stall artifact missing")
	}
}

func TestDeepProbeOffByDefault(t *testing.T) {
	d := newDoctorRun(DoctorOptions{Handshake: true})
	d.probe("scanner", "", helperLaunch("deep"))
	if _, ok := checkMap(d.report)["scanner/scan call"]; ok {
		t.Error("scan call ran without --deep")
	}
}

// --- watch ---

func stubProcesses(t *testing.T, procs []procInfo, err error) {
	t.Helper()
	orig := listProcesses
	listProcesses = func() ([]procInfo, error) { return procs, err }
	t.Cleanup(func() { listProcesses = orig })
}

func TestLogWatcherFlagsStuckCallWithChildren(t *testing.T) {
	stubProcesses(t, []procInfo{{PID: 42, PPID: 1}, {PID: 43, PPID: 42, Command: "git diff", Elapsed: "00:12"}}, nil)
	var out bytes.Buffer
	lw := newLogWatcher(&out, 10*time.Second)
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

	lw.handleLine("2026-10-21 12:00:00,100 INFO [42] mcp.server.lowlevel.server: Processing request of type CallToolRequest", t0)
	lw.tick(t0.Add(5 * time.Second))
	if strings.Contains(out.String(), "STUCK") {
		t.Fatal("reported stuck too early")
	}
	lw.tick(t0.Add(12 * time.Second))
	got := out.String()
	for _, want := range []string{"tool call received", "STUCK", "git diff", "pid 43"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// Not repeated on the next tick.
	n := strings.Count(got, "STUCK")
	lw.tick(t0.Add(13 * time.Second))
	if strings.Count(out.String(), "STUCK") != n {
		t.Error("stuck call re-reported immediately")
	}
	// Re-reported after the repeat interval.
	lw.tick(t0.Add(45 * time.Second))
	if strings.Count(out.String(), "STUCK") != n+1 {
		t.Error("stuck call not re-reported after the repeat interval")
	}

	lw.handleLine("2026-10-21 12:00:50,100 INFO [42] appsec-mcp: tool scan_file ok in 50.00s", t0.Add(50*time.Second))
	if !strings.Contains(out.String(), "reported as stuck") {
		t.Errorf("finish should mention it was stuck:\n%s", out.String())
	}
	if lw.sum.Calls != 1 || lw.sum.Finished != 1 || lw.sum.Stuck != 1 || lw.sum.SlowestTool != "scan_file" {
		t.Errorf("summary = %+v", lw.sum)
	}
}

func TestLogWatcherDeadServerAndReplacement(t *testing.T) {
	stubProcesses(t, []procInfo{{PID: 1, PPID: 0}}, nil) // pid 42 is gone
	var out bytes.Buffer
	lw := newLogWatcher(&out, time.Second)
	t0 := time.Now()
	lw.handleLine("2026-10-21 12:00:00,100 INFO [42] mcp.server.lowlevel.server: Processing request of type CallToolRequest", t0)
	lw.tick(t0.Add(2 * time.Second))
	if !strings.Contains(out.String(), "is not running") {
		t.Errorf("want dead-server report:\n%s", out.String())
	}
	lw.handleLine("2026-10-21 12:00:09,100 INFO [77] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3)", t0.Add(9*time.Second))
	if !strings.Contains(out.String(), "never finished: replaced by a new server process") ||
		!strings.Contains(out.String(), "server pid 77 started (plugin 1.4.1)") {
		t.Errorf("want replacement report:\n%s", out.String())
	}
}

func TestLogWatcherFailedToolAndTraceback(t *testing.T) {
	var out bytes.Buffer
	lw := newLogWatcher(&out, time.Minute)
	now := time.Now()
	lw.handleLine("2026-10-21 12:00:00,100 INFO [1] mcp.server.lowlevel.server: Processing request of type CallToolRequest", now)
	lw.handleLine("2026-10-21 12:00:01,100 ERROR [1] appsec-mcp: tool scan_file crashed in 1.00s", now)
	lw.handleLine("Traceback (most recent call last):", now)
	lw.handleLine("2026-10-21 12:00:02,000 INFO [1] appsec-mcp: unrelated", now)
	lw.handleLine("not part of a traceback", now)
	got := out.String()
	if !strings.Contains(got, "FAILED after 1.00s") || !strings.Contains(got, "Traceback (most recent call last):") {
		t.Errorf("output:\n%s", got)
	}
	if strings.Contains(got, "not part of a traceback") {
		t.Errorf("stray line printed:\n%s", got)
	}
	if lw.sum.Failed != 1 {
		t.Errorf("failed = %d", lw.sum.Failed)
	}
}

func TestWatchServerLogFollowsAppendsAndRotation(t *testing.T) {
	stubProcesses(t, nil, errors.New("no ps"))
	path := filepath.Join(t.TempDir(), "server.log")
	mustWrite(t, path, "2026-10-21 11:00:00,000 INFO [1] mcp.server.lowlevel.server: Processing request of type CallToolRequest\n")

	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan WatchSummary, 1)
	go func() {
		sum, _ := WatchServerLog(ctx, &out, WatchOptions{LogPath: path, PollInterval: 10 * time.Millisecond, StuckAfter: time.Hour})
		done <- sum
	}()

	waitFor(t, &out, "Watching")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	// A line split across two writes must be joined, not printed in halves.
	_, _ = f.WriteString("2026-10-21 12:00:00,100 INFO [2] mcp.server.lowlevel.server: Processing request of type Call")
	time.Sleep(50 * time.Millisecond)
	_, _ = f.WriteString("ToolRequest\n2026-10-21 12:00:00,200 INFO [2] appsec-mcp: tool debug_config ok in 0.10s\n")
	_ = f.Close()
	waitFor(t, &out, "debug_config ok in 0.10s")

	// Truncation restarts from the top.
	mustWrite(t, path, "2026-10-21 13:00:00,000 INFO [3] appsec-mcp: Starting Armis AppSec MCP server 1.5.0 (python 3)\n")
	waitFor(t, &out, "server pid 3 started (plugin 1.5.0)")

	cancel()
	sum := <-done
	if sum.Calls != 1 || sum.Finished != 1 {
		t.Errorf("summary = %+v, want the pre-existing call ignored and the appended one counted", sum)
	}
	if !strings.Contains(out.String(), "Earlier in this log: 1 tool calls") {
		t.Errorf("history line missing:\n%s", out.String())
	}
}

func TestWatchServerLogWaitsForMissingFile(t *testing.T) {
	var out syncBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := WatchServerLog(ctx, &out, WatchOptions{LogPath: filepath.Join(t.TempDir(), "nope.log"), PollInterval: 10 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Waiting for") {
		t.Errorf("output = %q", out.String())
	}
}

func TestFormatWatchSummary(t *testing.T) {
	if got := FormatWatchSummary(WatchSummary{}); !strings.Contains(got, "No tool calls") {
		t.Errorf("got %q", got)
	}
	got := FormatWatchSummary(WatchSummary{Calls: 3, Finished: 2, Failed: 1, Stuck: 1, SlowestTool: "scan_file", Slowest: 4.5})
	if !strings.Contains(got, "3 tool calls: 2 finished (1 failed), 1 reported stuck") || !strings.Contains(got, "scan_file, 4.50s") {
		t.Errorf("got %q", got)
	}
}

// syncBuffer is a bytes.Buffer safe for the watcher goroutine to write while
// the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitFor(t *testing.T, b *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in:\n%s", want, b.String())
}

func TestLogWatcherMatchesFinishedCallByDuration(t *testing.T) {
	stubProcesses(t, []procInfo{{PID: 42}}, nil)
	var out bytes.Buffer
	lw := newLogWatcher(&out, time.Second)
	t0 := time.Now()
	lw.handleLine("2026-10-21 12:00:00,100 INFO [42] mcp.server.lowlevel.server: Processing request of type CallToolRequest", t0) // hangs
	lw.handleLine("2026-10-21 12:00:10,000 INFO [42] mcp.server.lowlevel.server: Processing request of type CallToolRequest", t0)
	lw.handleLine("2026-10-21 12:00:10,200 INFO [42] appsec-mcp: tool debug_config ok in 0.20s", t0)
	open := lw.procs[42].open
	if len(open) != 1 || clock(open[0].logTime) != "12:00:00" {
		t.Fatalf("the hung call must stay open, got %d open:\n%s", len(open), out.String())
	}
}

func TestLogWatcherKeepsCallsOfRunningServer(t *testing.T) {
	stubProcesses(t, []procInfo{{PID: 42}, {PID: 77}}, nil) // both servers run
	var out bytes.Buffer
	lw := newLogWatcher(&out, time.Second)
	t0 := time.Now()
	lw.handleLine("2026-10-21 12:00:00,100 INFO [42] mcp.server.lowlevel.server: Processing request of type CallToolRequest", t0)
	lw.handleLine("2026-10-21 12:00:09,100 INFO [77] appsec-mcp: Starting Armis AppSec MCP server 1.4.1 (python 3)", t0)
	if strings.Contains(out.String(), "never finished") || lw.sum.Stuck != 0 || len(lw.procs[42].open) != 1 {
		t.Errorf("a running server's call was closed:\n%s", out.String())
	}
}

func TestExecutableBaseUnquotedWindowsPath(t *testing.T) {
	for cmd, want := range map[string]string{
		`C:\Program Files\Git\cmd\git.exe status`: "git.exe",
		`C:\Program Files\Git\cmd\git.exe`:        "git.exe",
		`"C:\Program Files\Git\cmd\git.exe" log`:  "git.exe",
		`/usr/bin/git status`:                     "git",
		`git`:                                     "git",
	} {
		if got := executableBase(cmd); got != want {
			t.Errorf("executableBase(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestAbortPythonTargetsPythonBelowWrapper(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("no SIGABRT on Windows")
	}
	// A non-Python wrapper with no Python below it gets no signal.
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	snap := processSnapshot{Alive: true, RootCommand: "/bin/sh run.sh", Children: []procInfo{{PID: 1 << 22, Command: "git status"}}}
	if abortPython(self, snap) {
		t.Error("signalled a wrapper that isn't Python")
	}
}
