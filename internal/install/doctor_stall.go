package install

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxTraceBytes bounds the JSON-RPC transcript kept per live session (CWE-770).
const maxTraceBytes = 128 << 10

// maxTraceLine bounds a single transcript line; tool results can be large.
const maxTraceLine = 2000

// abortDumpWait is how long the doctor gives a Python server to write its
// thread dump after SIGABRT before it kills the process. A var so tests can
// skip the wait.
var abortDumpWait = 500 * time.Millisecond

// traceLog records the JSON-RPC lines of a live session with timestamps, so a
// support bundle shows what was actually exchanged and when, not only the
// parsed outcome. A nil *traceLog discards everything.
type traceLog struct {
	start     time.Time
	buf       strings.Builder
	truncated bool
}

func newTraceLog() *traceLog { return &traceLog{start: time.Now()} }

// add records one line. dir is "->" for requests sent and "<-" for lines read.
func (t *traceLog) add(dir string, line []byte) {
	if t == nil {
		return
	}
	t.note(dir + " " + truncate(string(line), maxTraceLine))
}

// note records a line of commentary.
func (t *traceLog) note(msg string) {
	if t == nil || t.truncated {
		return
	}
	entry := fmt.Sprintf("+%7.3fs %s\n", time.Since(t.start).Seconds(), msg)
	if t.buf.Len()+len(entry) > maxTraceBytes {
		t.truncated = true
		t.buf.WriteString("... transcript truncated\n")
		return
	}
	t.buf.WriteString(entry)
}

func (t *traceLog) String() string {
	if t == nil {
		return ""
	}
	return t.buf.String()
}

// procInfo is one row of the OS process table.
type procInfo struct {
	PID, PPID int
	Elapsed   string // "" where the OS listing has no run time (Windows)
	Command   string
}

// listProcesses returns the OS process table. A var so tests can stub it.
var listProcesses = osListProcesses

func osListProcesses() ([]procInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if runtime.GOOS == osWindows {
		out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			`Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId) $($_.ParentProcessId) $($_.CommandLine)" }`).Output()
		if err != nil {
			return nil, fmt.Errorf("listing processes: %w", err)
		}
		return parseProcessList(string(out), false), nil
	}
	out, err := exec.CommandContext(ctx, "ps", "-A", "-o", "pid=,ppid=,etime=,command=").Output()
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}
	return parseProcessList(string(out), true), nil
}

// parseProcessList parses "pid ppid [etime] command" lines.
func parseProcessList(out string, withElapsed bool) []procInfo {
	want := 2
	if withElapsed {
		want = 3
	}
	var procs []procInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < want {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		p := procInfo{PID: pid, PPID: ppid}
		rest := line
		for i := 0; i < want; i++ {
			rest = strings.TrimSpace(strings.TrimPrefix(rest, fields[i]))
		}
		if withElapsed {
			p.Elapsed = fields[2]
		}
		p.Command = rest
		procs = append(procs, p)
	}
	return procs
}

// descendants returns every process below root, parents before children.
func descendants(all []procInfo, root int) []procInfo {
	byParent := make(map[int][]procInfo)
	for _, p := range all {
		byParent[p.PPID] = append(byParent[p.PPID], p)
	}
	var out []procInfo
	seen := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range byParent[cur] {
			if seen[c.PID] {
				continue
			}
			seen[c.PID] = true
			out = append(out, c)
			queue = append(queue, c.PID)
		}
	}
	return out
}

// processSnapshot is what was running under a server process at one moment.
type processSnapshot struct {
	Alive bool
	// RootCommand is the command line of the server process itself, "" when it
	// wasn't in the process table.
	RootCommand string
	Children    []procInfo
	Err         error
}

func snapshotProcesses(pid int) processSnapshot {
	all, err := listProcesses()
	if err != nil {
		return processSnapshot{Err: err}
	}
	snap := processSnapshot{Children: descendants(all, pid)}
	for _, p := range all {
		if p.PID == pid {
			snap.Alive = true
			snap.RootCommand = p.Command
			break
		}
	}
	return snap
}

// livePIDs returns the pids in the process table, or nil when it can't be
// read.
func livePIDs() map[int]bool {
	all, err := listProcesses()
	if err != nil {
		return nil
	}
	live := make(map[int]bool, len(all))
	for _, p := range all {
		live[p.PID] = true
	}
	return live
}

func (p procInfo) String() string {
	s := fmt.Sprintf("pid %d: %s", p.PID, truncate(p.Command, 200))
	if p.Elapsed != "" {
		s += " (running " + p.Elapsed + ")"
	}
	return s
}

// stallInfo is the evidence captured when a tool call stopped answering.
type stallInfo struct {
	Method   string
	Snapshot processSnapshot
	// Aborted is true when SIGABRT was sent so a Python server writes its
	// thread dump to stderr.
	Aborted bool
}

// captureStall records what the server was doing when it stopped answering:
// the child processes it was waiting on and, on unix, a thread dump. Call it
// before killing the process.
func captureStall(proc *os.Process, method string) *stallInfo {
	st := &stallInfo{Method: method, Snapshot: snapshotProcesses(proc.Pid)}
	// The doctor launches the server with PYTHONFAULTHANDLER=1, so SIGABRT
	// makes a Python process print every thread's traceback to stderr before it
	// dies. Only Python processes get it: anything else would just die, and may
	// leave a core dump or crash report.
	if runtime.GOOS != osWindows {
		st.Aborted = abortPython(proc, st.Snapshot)
		if st.Aborted {
			time.Sleep(abortDumpWait)
		}
	}
	return st
}

// abortPython sends SIGABRT to the server if it is a Python process, or, when
// a wrapper (shell script, uv run, node) launched it, to the Python processes
// below the wrapper. It reports whether any signal was sent.
func abortPython(proc *os.Process, snap processSnapshot) bool {
	if snap.Err != nil || snap.RootCommand == "" || isPython(snap.RootCommand) {
		return proc.Signal(syscall.SIGABRT) == nil
	}
	sent := false
	for _, c := range snap.Children {
		if !isPython(c.Command) {
			continue
		}
		if p, err := os.FindProcess(c.PID); err == nil && p.Signal(syscall.SIGABRT) == nil {
			sent = true
		}
	}
	return sent
}

func isPython(command string) bool {
	return strings.HasPrefix(executableBase(command), "python")
}

// killDescendants kills the processes the server had running when it stalled.
// Killing the server alone leaves them behind, still blocked.
func (s *stallInfo) killDescendants() {
	if s == nil {
		return
	}
	for _, c := range s.Snapshot.Children {
		if p, err := os.FindProcess(c.PID); err == nil {
			// armis:ignore cwe:404 reason:best-effort cleanup of a diagnostic subprocess's children
			_ = p.Kill()
		}
	}
}

// text renders the stall for the support bundle.
func (s *stallInfo) text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "No response to %s.\n", s.Method)
	switch {
	case s.Snapshot.Err != nil:
		fmt.Fprintf(&b, "Could not list processes: %v\n", s.Snapshot.Err)
	case len(s.Snapshot.Children) == 0:
		b.WriteString("The server had no child processes.\n")
	default:
		b.WriteString("Child processes of the server at that moment:\n")
		for _, c := range s.Snapshot.Children {
			b.WriteString("  " + c.String() + "\n")
		}
	}
	return b.String()
}

// summary is a one-line account of what the server was waiting on.
func (s *stallInfo) summary() string {
	if s == nil || s.Snapshot.Err != nil {
		return ""
	}
	if len(s.Snapshot.Children) == 0 {
		return "the server had no child processes, so it was blocked inside its own code"
	}
	parts := make([]string, 0, 3)
	for i, c := range s.Snapshot.Children {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(s.Snapshot.Children)-3))
			break
		}
		parts = append(parts, truncate(c.String(), 120))
	}
	return "the server was waiting on child process " + strings.Join(parts, "; ")
}

// waitingOn reports whether a child process of the stalled server runs name
// (matched on the executable's base name).
func (s *stallInfo) waitingOn(name string) bool {
	if s == nil {
		return false
	}
	for _, c := range s.Snapshot.Children {
		if executableBase(c.Command) == name || executableBase(c.Command) == name+".exe" {
			return true
		}
	}
	return false
}

// executableBase returns the lower-cased base name of the program in a command
// line, handling quoted Windows paths that contain spaces.
func executableBase(command string) string {
	command = strings.TrimSpace(command)
	exe := command
	if strings.HasPrefix(command, `"`) {
		if i := strings.Index(command[1:], `"`); i >= 0 {
			exe = command[1 : i+1]
		}
	} else if i := exeEnd(command); i >= 0 {
		exe = command[:i]
	} else if i := strings.IndexAny(command, " \t"); i >= 0 {
		exe = command[:i]
	}
	return strings.ToLower(filepath.Base(strings.ReplaceAll(exe, `\`, "/")))
}

// exeEnd returns the index just past a ".exe" that ends the program path in an
// unquoted command line, so "C:\Program Files\Git\cmd\git.exe status" isn't
// cut at the space in "Program Files". It returns -1 when there is none.
func exeEnd(command string) int {
	lower := strings.ToLower(command)
	for from := 0; ; {
		i := strings.Index(lower[from:], ".exe")
		if i < 0 {
			return -1
		}
		end := from + i + len(".exe")
		if end == len(lower) || lower[end] == ' ' || lower[end] == '\t' {
			return end
		}
		from = end
	}
}

var (
	pyFatalRe  = regexp.MustCompile(`Fatal Python error: Aborted`)
	pyThreadRe = regexp.MustCompile(`^(?:Current thread|Thread) 0x[0-9a-fA-F]+`)
	pyFrameRe  = regexp.MustCompile(`^\s+File "([^"]+)", line (\d+) in (\S+)`)
)

// pythonThreadTops extracts, from a faulthandler dump in stderr, the innermost
// frame of each thread ("subprocess.py:1946 in _try_wait"): where the server
// was stuck. It returns nil when stderr holds no dump.
func pythonThreadTops(stderr string) []string {
	i := pyFatalRe.FindStringIndex(stderr)
	if i == nil {
		return nil
	}
	var tops []string
	seen := make(map[string]bool)
	inThread := false
	for _, line := range strings.Split(stderr[i[0]:], "\n") {
		line = strings.TrimRight(line, "\r")
		if pyThreadRe.MatchString(line) {
			inThread = true
			continue
		}
		if !inThread {
			continue
		}
		if m := pyFrameRe.FindStringSubmatch(line); m != nil {
			top := fmt.Sprintf("%s:%s in %s", filepath.Base(strings.ReplaceAll(m[1], `\`, "/")), m[2], m[3])
			if !seen[top] {
				seen[top] = true
				tops = append(tops, top)
			}
			inThread = false
		}
	}
	return tops
}

// --- pids of servers the doctor itself stalled and killed ---

// probePIDsPath is where the doctor remembers the servers it killed after a
// stall. A var so tests can point it at a temp dir.
var probePIDsPath = func() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "armis-cli", "doctor-probe-pids")
}

const (
	// probePIDsTTL is how long a recorded pid is trusted: pids get reused.
	probePIDsTTL = 7 * 24 * time.Hour
	// probePIDsKeep bounds the file.
	probePIDsKeep = 100
)

// recordProbePID notes that the doctor killed server pid mid-call, so the
// unfinished call it left in server.log isn't reported later as a stall the
// user's editor hit.
func recordProbePID(pid int) {
	path := probePIDsPath()
	if path == "" {
		return
	}
	lines := readProbePIDLines(path)
	lines = append(lines, fmt.Sprintf("%d %d", pid, time.Now().Unix()))
	if len(lines) > probePIDsKeep {
		lines = lines[len(lines)-probePIDsKeep:]
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// loadProbePIDs returns the recently recorded probe server pids.
func loadProbePIDs() map[int]bool {
	path := probePIDsPath()
	if path == "" {
		return nil
	}
	pids := make(map[int]bool)
	for _, line := range readProbePIDLines(path) {
		var pid int
		var at int64
		if _, err := fmt.Sscanf(line, "%d %d", &pid, &at); err == nil && time.Since(time.Unix(at, 0)) < probePIDsTTL {
			pids[pid] = true
		}
	}
	return pids
}

func readProbePIDLines(path string) []string {
	b, err := readBoundedConfigFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
