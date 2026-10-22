package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ScannerLogPath is where the scanner plugin writes its server.log.
func ScannerLogPath() string {
	return filepath.Join(NewEditorInstaller().PluginDir(), "logs", "server.log")
}

const (
	// DefaultWatchStuckAfter is how long a tool call may stay open before the
	// watcher reports it as stuck.
	DefaultWatchStuckAfter = 10 * time.Second
	// watchRepeatEvery is how often an open stuck call is re-reported with a
	// fresh process snapshot.
	watchRepeatEvery = 30 * time.Second
	defaultWatchPoll = 500 * time.Millisecond
	// watchHistoryBytes is how much of the existing log is summarized on start.
	watchHistoryBytes = 64 << 10
)

// WatchOptions configures WatchServerLog.
type WatchOptions struct {
	// LogPath is the server.log to follow. Defaults to ScannerLogPath().
	LogPath string
	// StuckAfter is how long a call may stay open before it is reported.
	StuckAfter time.Duration
	// PollInterval is how often the file is checked for new lines.
	PollInterval time.Duration
}

// WatchSummary counts what the watcher saw.
type WatchSummary struct {
	Calls       int // tool calls received
	Finished    int // calls the server answered
	Failed      int // answered calls that failed or crashed
	Stuck       int // calls reported as stuck (some may have finished later)
	SlowestTool string
	Slowest     float64 // seconds
}

type watchCall struct {
	received time.Time
	logTime  string
	at       time.Time // logTime parsed; zero if it didn't parse
	reported time.Time // when it was last reported as stuck; zero if never
	stuck    bool
}

type watchProc struct {
	open []*watchCall
}

// logWatcher turns server.log lines into readable events and spots tool calls
// that stay open.
type logWatcher struct {
	w          io.Writer
	stuckAfter time.Duration
	procs      map[int]*watchProc
	order      []int
	sum        WatchSummary
	inProblem  bool // last printed line was a warning or error
}

func newLogWatcher(w io.Writer, stuckAfter time.Duration) *logWatcher {
	return &logWatcher{w: w, stuckAfter: stuckAfter, procs: make(map[int]*watchProc)}
}

func (lw *logWatcher) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(lw.w, format+"\n", args...)
}

// clock extracts HH:MM:SS from a log timestamp ("2026-10-21 19:32:47,128").
func clock(ts string) string {
	if i := strings.IndexByte(ts, ','); i >= 0 {
		ts = ts[:i]
	}
	if i := strings.IndexByte(ts, ' '); i >= 0 {
		ts = ts[i+1:]
	}
	return ts
}

// handleLine processes one complete log line read at time now.
func (lw *logWatcher) handleLine(line string, now time.Time) {
	line = strings.TrimRight(line, "\r")
	m := serverLogLineRe.FindStringSubmatch(line)
	if m == nil {
		// A traceback line continues the previous warning or error.
		if lw.inProblem && strings.TrimSpace(line) != "" {
			lw.printf("           %s", line)
		}
		return
	}
	ts, level, logger, msg := m[1], m[2], m[4], m[5]
	pid, _ := strconv.Atoi(m[3])
	lw.inProblem = false

	p := lw.procs[pid]
	if p == nil {
		// A new process. An earlier one that is gone was replaced, and any call
		// it had open was abandoned; one still running (another editor's
		// server) keeps its calls.
		lw.closeGone(ts)
		p = &watchProc{}
		lw.procs[pid] = p
		lw.order = append(lw.order, pid)
	}

	switch {
	case strings.Contains(msg, "CallToolRequest"):
		lw.sum.Calls++
		p.open = append(p.open, &watchCall{received: now, logTime: ts, at: parseLogTime(ts)})
		lw.printf("%s  → tool call received (server pid %d)", clock(ts), pid)
	case strings.Contains(logger, "mcp.server") && strings.Contains(msg, "Processing request of type"):
		// Other request types (initialize, tools/list) add only noise.
	case msg == "MCP server stopped":
		lw.printf("%s  server pid %d stopped", clock(ts), pid)
		lw.closeProc(pid, ts, "server stopped")
	default:
		if d := toolDoneRe.FindStringSubmatch(msg); d != nil {
			lw.toolDone(p, pid, ts, d[1], d[2], msg)
			return
		}
		if sm := serverStartRe.FindStringSubmatch(msg); sm != nil {
			lw.printf("%s  server pid %d started (plugin %s)", clock(ts), pid, sm[1])
			return
		}
		if level == "WARNING" || level == "ERROR" || level == "CRITICAL" {
			lw.inProblem = true
			lw.printf("%s  %s: %s", clock(ts), level, msg)
			return
		}
		lw.printf("%s    %s", clock(ts), msg)
	}
}

func (lw *logWatcher) toolDone(p *watchProc, pid int, ts, tool, secsText, msg string) {
	secs, _ := strconv.ParseFloat(secsText, 64)
	lw.sum.Finished++
	if secs > lw.sum.Slowest {
		lw.sum.Slowest, lw.sum.SlowestTool = secs, tool
	}
	note := ""
	if i := matchOpenCall(p.open, parseLogTime(ts), secs); i >= 0 {
		if p.open[i].stuck {
			note = " (it had been reported as stuck)"
		}
		p.open = append(p.open[:i], p.open[i+1:]...)
	}
	if strings.HasPrefix(strings.TrimPrefix(msg, "tool "+tool+" "), "ok") {
		lw.printf("%s  ← %s ok in %.2fs%s", clock(ts), tool, secs, note)
		return
	}
	lw.sum.Failed++
	lw.inProblem = true
	lw.printf("%s  ← %s FAILED after %.2fs%s: %s", clock(ts), tool, secs, note, msg)
}

// logTimeLayout is the server_log timestamp format.
const logTimeLayout = "2006-01-02 15:04:05,000"

// parseLogTime parses a log timestamp, returning the zero time if it can't.
func parseLogTime(ts string) time.Time {
	t, err := time.Parse(logTimeLayout, ts)
	if err != nil {
		return time.Time{}
	}
	return t
}

// matchOpenCall picks which open call a finished call belongs to. The log line
// for a finished call carries no request id, only how long the call took, so
// the match is the open call received closest to (finish time - duration).
// That keeps a fast call finishing from closing a slower one still stuck. It
// falls back to the oldest open call when the times can't be compared, and
// returns -1 when nothing is open.
func matchOpenCall(open []*watchCall, doneAt time.Time, secs float64) int {
	if len(open) == 0 {
		return -1
	}
	if doneAt.IsZero() {
		return 0
	}
	started := doneAt.Add(-time.Duration(secs * float64(time.Second)))
	best, bestGap := 0, time.Duration(-1)
	for i, c := range open {
		if c.at.IsZero() {
			return 0
		}
		gap := c.at.Sub(started).Abs()
		if bestGap < 0 || gap < bestGap {
			best, bestGap = i, gap
		}
	}
	return best
}

// closeGone closes the open calls of earlier server processes that are no
// longer running.
func (lw *logWatcher) closeGone(ts string) {
	var live map[int]bool
	listed := false
	for _, prev := range lw.order {
		if p := lw.procs[prev]; p == nil || len(p.open) == 0 {
			continue
		}
		if !listed {
			live, listed = livePIDs(), true
		}
		if live[prev] {
			continue
		}
		lw.closeProc(prev, ts, "replaced by a new server process")
	}
}

// closeProc reports calls still open when a server process ends.
func (lw *logWatcher) closeProc(pid int, ts, why string) {
	p := lw.procs[pid]
	if p == nil || len(p.open) == 0 {
		return
	}
	lw.printf("%s  ! %d tool call(s) on server pid %d never finished: %s", clock(ts), len(p.open), pid, why)
	for _, c := range p.open {
		if !c.stuck {
			lw.sum.Stuck++
		}
	}
	p.open = nil
}

// tick reports calls that have stayed open too long, with a snapshot of what
// the server process is running.
func (lw *logWatcher) tick(now time.Time) {
	for _, pid := range lw.order {
		p := lw.procs[pid]
		for _, c := range p.open {
			age := now.Sub(c.received)
			if age < lw.stuckAfter {
				continue
			}
			if c.stuck && now.Sub(c.reported) < watchRepeatEvery {
				continue
			}
			if !c.stuck {
				c.stuck = true
				lw.sum.Stuck++
			}
			c.reported = now
			lw.printf("%s  ! STUCK: tool call received at %s is still open after %s (server pid %d)",
				now.Format("15:04:05"), clock(c.logTime), age.Round(time.Second), pid)
			lw.reportProcesses(pid)
		}
	}
}

func (lw *logWatcher) reportProcesses(pid int) {
	snap := snapshotProcesses(pid)
	switch {
	case snap.Err != nil:
		lw.printf("             could not list processes: %v", snap.Err)
	case !snap.Alive:
		lw.printf("             server pid %d is not running: the editor killed it or it crashed", pid)
	case len(snap.Children) == 0:
		lw.printf("             the server has no child processes, so it is blocked inside its own code")
	default:
		lw.printf("             the server is waiting on:")
		for _, c := range snap.Children {
			lw.printf("               %s", c)
		}
	}
}

// WatchServerLog follows the scanner's server.log until ctx ends, printing
// each tool call as it happens and flagging calls that stay open, along with
// the child processes the server is waiting on at that moment. Run it, then
// reproduce the problem in the editor. It returns what it saw.
func WatchServerLog(ctx context.Context, w io.Writer, opts WatchOptions) (WatchSummary, error) {
	if opts.LogPath == "" {
		opts.LogPath = ScannerLogPath()
	}
	if opts.StuckAfter <= 0 {
		opts.StuckAfter = DefaultWatchStuckAfter
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultWatchPoll
	}
	lw := newLogWatcher(w, opts.StuckAfter)

	var offset int64
	var info os.FileInfo
	if st, err := os.Stat(opts.LogPath); err == nil {
		offset, info = st.Size(), st
		if b, err := readBoundedConfigFile(opts.LogPath); err == nil {
			if h := analyzeServerLog(tail(string(b), watchHistoryBytes)); h.calls > 0 {
				lw.printf("Earlier in this log: %d tool calls, %d never finished, %d slow %s calls.", h.calls, h.unfinished, h.slowDiag, debugConfigTool)
			}
		}
		lw.printf("Watching %s. Use the editor now; Ctrl-C to stop.", opts.LogPath)
	} else {
		lw.printf("Waiting for %s to appear. Use the editor now; Ctrl-C to stop.", opts.LogPath)
	}

	var pending string
	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return lw.sum, nil
		case now := <-ticker.C:
			st, err := os.Stat(opts.LogPath)
			if err != nil {
				continue
			}
			if info != nil && (!os.SameFile(info, st) || st.Size() < offset) {
				lw.printf("%s  log file was rotated or truncated; reading from its start", now.Format("15:04:05"))
				offset, pending = 0, ""
			}
			info = st
			if st.Size() > offset {
				chunk, err := readLogFrom(opts.LogPath, offset, st.Size()-offset)
				if err == nil {
					offset += int64(len(chunk))
					pending += string(chunk)
					for {
						i := strings.IndexByte(pending, '\n')
						if i < 0 {
							break
						}
						lw.handleLine(pending[:i], now)
						pending = pending[i+1:]
					}
				}
			}
			lw.tick(now)
		}
	}
}

// readLogFrom reads up to n bytes of path starting at offset.
func readLogFrom(path string, offset, n int64) ([]byte, error) {
	// armis:ignore cwe:22 reason:path is the plugin's own log file
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // the plugin's own log path
	if err != nil {
		return nil, fmt.Errorf("opening log: %w", err)
	}
	defer func() { _ = f.Close() }()
	const maxChunk = 1 << 20
	buf := make([]byte, min(n, maxChunk))
	got, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading log: %w", err)
	}
	return buf[:got], nil
}

// FormatWatchSummary renders the closing line of a watch session.
func FormatWatchSummary(s WatchSummary) string {
	if s.Calls == 0 {
		return "No tool calls were made while watching."
	}
	out := fmt.Sprintf("%d tool calls: %d finished (%d failed), %d reported stuck.", s.Calls, s.Finished, s.Failed, s.Stuck)
	if s.SlowestTool != "" {
		out += fmt.Sprintf(" Slowest: %s, %.2fs.", s.SlowestTool, s.Slowest)
	}
	return out
}
