// Package progress provides progress indicators for CLI operations.
package progress

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"
)

const (
	// DefaultSpinnerTimeout is the maximum time a spinner will run before auto-stopping.
	// This is a safety net to prevent indefinite goroutine leaks.
	DefaultSpinnerTimeout = 30 * time.Minute

	// spinnerFrameDelay is the delay between animation frames.
	spinnerFrameDelay = 100 * time.Millisecond

	// ANSI escape sequences for cursor visibility control.
	// These are standard VT100/xterm sequences supported by all modern terminals.
	cursorHide = "\033[?25l"
	cursorShow = "\033[?25h"
)

// IsCI returns true if running in a CI environment.
func IsCI() bool {
	ciEnvVars := []string{
		"CI",
		"CONTINUOUS_INTEGRATION",
		"GITHUB_ACTIONS",
		"GITLAB_CI",
		"CIRCLECI",
		"JENKINS_URL",
		"TRAVIS",
		"BITBUCKET_BUILD_NUMBER",
		"AZURE_PIPELINES",
	}

	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}
	return false
}

// fdWriter is an interface for writers that can provide a file descriptor.
// *os.File implements this interface.
type fdWriter interface {
	Fd() uintptr
}

// isTerminalWriter reports whether the given writer is connected to a terminal.
func isTerminalWriter(w io.Writer) bool {
	if f, ok := w.(fdWriter); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

// NewReader wraps a reader with a progress bar.
func NewReader(r io.Reader, size int64, description string, disabled bool) io.Reader {
	if disabled || IsCI() {
		return r
	}

	bar := progressbar.DefaultBytes(
		size,
		description,
	)

	reader := progressbar.NewReader(r, bar)
	return &reader
}

// NewWriter wraps a writer with a progress bar.
func NewWriter(w io.Writer, size int64, description string, disabled bool) io.Writer {
	if disabled || IsCI() {
		return w
	}

	bar := progressbar.DefaultBytes(
		size,
		description,
	)

	return io.MultiWriter(w, bar)
}

// Spinner displays an animated spinner with a message.
type Spinner struct {
	mu        sync.RWMutex
	message   string
	disabled  bool // Immutable after construction - safe to read without mutex
	stopChan  chan struct{}
	doneChan  chan struct{}
	startTime time.Time
	showTimer bool      // Immutable after construction - safe to read without mutex
	writer    io.Writer // Immutable after construction - safe to read without mutex

	// Fields for goroutine leak prevention
	ctx      context.Context    // Parent context for cancellation
	cancel   context.CancelFunc // Internal cancel function
	stopOnce sync.Once          // Ensures Stop() is idempotent
	started  bool               // Tracks if Start() was called
	timeout  time.Duration      // Maximum spinner lifetime (safety net)
}

// NewSpinner creates a new spinner with the given message.
// Uses DefaultSpinnerTimeout as a safety net to prevent goroutine leaks.
func NewSpinner(message string, disabled bool) *Spinner {
	return NewSpinnerWithTimeout(message, disabled, DefaultSpinnerTimeout)
}

// NewSpinnerWithTimeout creates a new spinner with a custom timeout.
// The timeout acts as a safety net - if Stop() is not called within this duration,
// the spinner will automatically stop to prevent goroutine leaks.
// A timeout of 0 means no automatic timeout (use with caution).
func NewSpinnerWithTimeout(message string, disabled bool, timeout time.Duration) *Spinner {
	return &Spinner{
		message:   message,
		disabled:  disabled,
		stopChan:  make(chan struct{}),
		doneChan:  make(chan struct{}),
		startTime: time.Now(),
		showTimer: true,
		writer:    os.Stderr,
		timeout:   timeout,
	}
}

// NewSpinnerWithContext creates a new spinner that respects context cancellation.
// When the context is canceled, the spinner automatically stops.
// This is the recommended way to create spinners in operations that use context.
func NewSpinnerWithContext(ctx context.Context, message string, disabled bool) *Spinner {
	s := NewSpinnerWithTimeout(message, disabled, DefaultSpinnerTimeout)
	s.ctx = ctx
	return s
}

// SetWriter sets the output writer for the spinner (useful for testing).
// Must be called before Start to avoid data races.
func (s *Spinner) SetWriter(w io.Writer) {
	s.writer = w
}

// Start begins the spinner animation.
// The spinner will automatically stop if:
// - Stop() is called
// - The context (if provided) is canceled
// - The timeout (if set) is reached
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return // Already started, no-op
	}
	s.started = true
	s.startTime = time.Now() // Reset start time on Start()
	// Recreate channels and reset stopOnce to ensure they are fresh. This guards against
	// future changes that might allow spinner reuse - closed channels cannot be reused in Go,
	// and an exhausted sync.Once would make subsequent Stop() calls no-ops.
	s.stopChan = make(chan struct{})
	s.doneChan = make(chan struct{})
	s.stopOnce = sync.Once{}

	// Capture values while holding mutex to avoid race conditions
	startTime := s.startTime
	message := s.message
	s.mu.Unlock()

	if s.disabled || IsCI() {
		_, _ = fmt.Fprintf(s.writer, "%s (started at %s)\n", message, startTime.Format("15:04:05"))
		return
	}

	// Create internal context with timeout if configured
	var ctx context.Context
	var cancel context.CancelFunc

	if s.ctx != nil {
		// Use provided context as parent
		if s.timeout > 0 {
			ctx, cancel = context.WithTimeout(s.ctx, s.timeout)
		} else {
			ctx, cancel = context.WithCancel(s.ctx)
		}
	} else {
		// No parent context
		if s.timeout > 0 {
			ctx, cancel = context.WithTimeout(context.Background(), s.timeout)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
	}

	// Set cancel under mutex to avoid race with Stop()
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	go func() {
		defer close(s.doneChan)
		defer cancel() // Ensure context is canceled when goroutine exits

		// Hide cursor during spinner animation on real terminals.
		// Skip for non-TTY writers (pipes, files, test buffers) to avoid garbage output.
		// Also skip when colors are disabled (--color=never) to avoid ANSI escapes.
		hideCursor := isTerminalWriter(s.writer) && cli.ColorsEnabled()
		if hideCursor {
			_, _ = fmt.Fprint(s.writer, cursorHide)
			defer func() { _, _ = fmt.Fprint(s.writer, cursorShow) }()
		}

		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		ticker := time.NewTicker(spinnerFrameDelay)
		defer ticker.Stop()

		// clearLine returns the line-clear sequence.
		// Always use \r\033[K (carriage return + erase to EOL) to prevent
		// trailing characters when messages shrink. The \033[K (CSI K) sequence
		// is cursor control, not color, and works on all VT100-compatible terminals.
		clearLine := func() string {
			return "\r\033[K"
		}

		for {
			select {
			case <-s.stopChan:
				// Explicit stop requested
				_, _ = fmt.Fprint(s.writer, clearLine())
				return
			case <-ctx.Done():
				// Context canceled or timeout reached
				_, _ = fmt.Fprint(s.writer, clearLine())
				return
			case <-ticker.C:
				elapsed := time.Since(startTime)
				s.mu.RLock()
				msg := s.message
				s.mu.RUnlock()
				styles := output.GetStyles()
				char := styles.SpinnerChar.Render(spinner[i%len(spinner)])
				text := styles.SpinnerText.Render(msg)
				if s.showTimer {
					timer := styles.SpinnerTimer.Render("[" + formatDuration(elapsed) + "]")
					_, _ = fmt.Fprintf(s.writer, "%s%s %s %s", clearLine(), char, text, timer)
				} else {
					_, _ = fmt.Fprintf(s.writer, "%s%s %s", clearLine(), char, text)
				}
				i++
			}
		}
	}()
}

// Stop stops the spinner animation.
// Stop is safe to call multiple times - subsequent calls are no-ops.
// Stop is also safe to call if Start() was never called.
func (s *Spinner) Stop() {
	if s.disabled || IsCI() {
		return
	}

	s.stopOnce.Do(func() {
		s.mu.RLock()
		started := s.started
		cancel := s.cancel
		s.mu.RUnlock()

		if !started {
			return // Start() was never called
		}

		// Cancel the internal context first (belt and suspenders)
		if cancel != nil {
			cancel()
		}

		// Close stopChan to signal the goroutine
		close(s.stopChan)

		// Wait for the goroutine to finish with a timeout
		// This prevents indefinite blocking if something goes wrong
		select {
		case <-s.doneChan:
			// Goroutine exited cleanly
		case <-time.After(5 * time.Second):
			// Timeout waiting for goroutine - don't block indefinitely
		}
	})
}

// Update updates the spinner message.
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// GetElapsed returns the elapsed time since the spinner started.
func (s *Spinner) GetElapsed() time.Duration {
	s.mu.RLock()
	startTime := s.startTime
	s.mu.RUnlock()
	return time.Since(startTime)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}
