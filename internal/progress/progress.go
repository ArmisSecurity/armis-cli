// Package progress provides progress indicators for CLI operations.
package progress

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
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
	disabled  bool
	stopChan  chan bool
	doneChan  chan bool
	startTime time.Time
	showTimer bool
}

// NewSpinner creates a new spinner with the given message.
func NewSpinner(message string, disabled bool) *Spinner {
	return &Spinner{
		message:   message,
		disabled:  disabled,
		stopChan:  make(chan bool),
		doneChan:  make(chan bool),
		startTime: time.Now(),
		showTimer: true,
	}
}

// Start begins the spinner animation.
func (s *Spinner) Start() {
	if s.disabled || IsCI() {
		fmt.Printf("%s (started at %s)\n", s.message, s.startTime.Format("15:04:05"))
		return
	}

	go func() {
		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-s.stopChan:
				fmt.Print("\r\033[K")
				close(s.doneChan)
				return
			default:
				elapsed := time.Since(s.startTime)
				s.mu.RLock()
				msg := s.message
				s.mu.RUnlock()
				if s.showTimer {
					fmt.Printf("\r%s %s [%s]", spinner[i%len(spinner)], msg, formatDuration(elapsed))
				} else {
					fmt.Printf("\r%s %s", spinner[i%len(spinner)], msg)
				}
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// Stop stops the spinner animation.
func (s *Spinner) Stop() {
	if s.disabled || IsCI() {
		return
	}
	close(s.stopChan)
	<-s.doneChan
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
