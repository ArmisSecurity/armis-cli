// Package progress provides progress indicators for CLI operations.
package progress

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

const (
	// DefaultSpinnerTimeout is the maximum time a spinner will run before auto-stopping.
	// This is a safety net to prevent indefinite goroutine leaks.
	DefaultSpinnerTimeout = 30 * time.Minute

	// spinnerFrameDelay is the delay between animation frames.
	spinnerFrameDelay = 100 * time.Millisecond
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
		writer:    os.Stdout,
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
	// Recreate channels to ensure they are fresh. This guards against future changes
	// that might allow spinner reuse - closed channels cannot be reused in Go.
	s.stopChan = make(chan struct{})
	s.doneChan = make(chan struct{})
	s.mu.Unlock()

	if s.disabled || IsCI() {
		_, _ = fmt.Fprintf(s.writer, "%s (started at %s)\n", s.message, s.startTime.Format("15:04:05"))
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

	s.cancel = cancel

	go func() {
		defer close(s.doneChan)
		defer cancel() // Ensure context is canceled when goroutine exits

		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		ticker := time.NewTicker(spinnerFrameDelay)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopChan:
				// Explicit stop requested
				_, _ = fmt.Fprint(s.writer, "\r\033[K")
				return
			case <-ctx.Done():
				// Context canceled or timeout reached
				_, _ = fmt.Fprint(s.writer, "\r\033[K")
				return
			case <-ticker.C:
				elapsed := time.Since(s.startTime)
				s.mu.RLock()
				msg := s.message
				s.mu.RUnlock()
				if s.showTimer {
					_, _ = fmt.Fprintf(s.writer, "\r%s %s [%s]", spinner[i%len(spinner)], msg, formatDuration(elapsed))
				} else {
					_, _ = fmt.Fprintf(s.writer, "\r%s %s", spinner[i%len(spinner)], msg)
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
		s.mu.RUnlock()

		if !started {
			return // Start() was never called
		}

		// Cancel the internal context first (belt and suspenders)
		if s.cancel != nil {
			s.cancel()
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

// UpdateMessage updates the spinner message.
func (s *Spinner) UpdateMessage(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// Update updates the spinner message.
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// GetElapsed returns the elapsed time since the spinner started.
func (s *Spinner) GetElapsed() time.Duration {
	return time.Since(s.startTime)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}
