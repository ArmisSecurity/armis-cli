package progress

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestIsCI(t *testing.T) {
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

	tests := []struct {
		name     string
		envVars  map[string]string
		expected bool
	}{
		{
			name:     "no CI env vars",
			envVars:  map[string]string{},
			expected: false,
		},
		{
			name: "CI env var set",
			envVars: map[string]string{
				"CI": "true",
			},
			expected: true,
		},
		{
			name: "GITHUB_ACTIONS env var set",
			envVars: map[string]string{
				"GITHUB_ACTIONS": "true",
			},
			expected: true,
		},
		{
			name: "GITLAB_CI env var set",
			envVars: map[string]string{
				"GITLAB_CI": "true",
			},
			expected: true,
		},
		{
			name: "JENKINS_URL env var set",
			envVars: map[string]string{
				"JENKINS_URL": "http://jenkins.example.com",
			},
			expected: true,
		},
		{
			name: "CIRCLECI env var set",
			envVars: map[string]string{
				"CIRCLECI": "true",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalEnv := make(map[string]string)
			for _, key := range ciEnvVars {
				if val, exists := os.LookupEnv(key); exists {
					originalEnv[key] = val
				}
				_ = os.Unsetenv(key)
			}

			t.Cleanup(func() {
				for _, key := range ciEnvVars {
					_ = os.Unsetenv(key)
				}
				for key, val := range originalEnv {
					_ = os.Setenv(key, val)
				}
			})

			for key, value := range tt.envVars {
				_ = os.Setenv(key, value)
			}

			result := IsCI()
			if result != tt.expected {
				t.Errorf("IsCI() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewReader(t *testing.T) {
	t.Run("returns reader when disabled", func(t *testing.T) {
		input := bytes.NewReader([]byte("test data"))
		result := NewReader(input, 9, "test", true)

		if result != input {
			t.Error("Expected same reader when disabled")
		}
	})

	t.Run("returns reader in CI environment", func(t *testing.T) {
		_ = os.Setenv("CI", "true")
		t.Cleanup(func() { _ = os.Unsetenv("CI") })

		input := bytes.NewReader([]byte("test data"))
		result := NewReader(input, 9, "test", false)

		if result != input {
			t.Error("Expected same reader in CI environment")
		}
	})

	t.Run("wraps reader when not disabled and not CI", func(t *testing.T) {
		for _, key := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
			_ = os.Unsetenv(key)
		}
		t.Cleanup(func() {
			for _, key := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
				_ = os.Unsetenv(key)
			}
		})

		input := bytes.NewReader([]byte("test data"))
		result := NewReader(input, 9, "test", false)

		if result == input {
			t.Error("Expected wrapped reader when not disabled and not CI")
		}

		data, err := io.ReadAll(result)
		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}
		if string(data) != "test data" {
			t.Errorf("Data mismatch: got %q, want %q", string(data), "test data")
		}
	})
}

func TestNewWriter(t *testing.T) {
	t.Run("returns writer when disabled", func(t *testing.T) {
		var buf bytes.Buffer
		result := NewWriter(&buf, 100, "test", true)

		if result != &buf {
			t.Error("Expected same writer when disabled")
		}
	})

	t.Run("returns writer in CI environment", func(t *testing.T) {
		_ = os.Setenv("CI", "true")
		t.Cleanup(func() { _ = os.Unsetenv("CI") })

		var buf bytes.Buffer
		result := NewWriter(&buf, 100, "test", false)

		if result != &buf {
			t.Error("Expected same writer in CI environment")
		}
	})
}

func TestSpinner(t *testing.T) {
	t.Run("creates spinner", func(t *testing.T) {
		spinner := NewSpinner("test message", false)

		if spinner.message != "test message" {
			t.Errorf("Expected message 'test message', got %q", spinner.message)
		}
		if spinner.disabled != false {
			t.Error("Expected disabled to be false")
		}
	})

	t.Run("disabled spinner does not animate", func(_ *testing.T) {
		spinner := NewSpinner("test", true)
		spinner.Start()
		time.Sleep(50 * time.Millisecond)
		spinner.Stop()
	})

	t.Run("spinner in CI mode", func(t *testing.T) {
		_ = os.Setenv("CI", "true")
		t.Cleanup(func() { _ = os.Unsetenv("CI") })

		var buf bytes.Buffer
		spinner := NewSpinner("test", false)
		spinner.SetWriter(&buf)
		spinner.Start()
		time.Sleep(50 * time.Millisecond)
		spinner.Stop()
	})

	t.Run("update message", func(t *testing.T) {
		spinner := NewSpinner("initial", true)
		spinner.Update("updated")

		if spinner.message != "updated" {
			t.Errorf("Expected message 'updated', got %q", spinner.message)
		}
	})

	t.Run("get elapsed time", func(t *testing.T) {
		spinner := NewSpinner("test", true)
		time.Sleep(100 * time.Millisecond)
		elapsed := spinner.GetElapsed()

		if elapsed < 100*time.Millisecond {
			t.Errorf("Expected elapsed time >= 100ms, got %v", elapsed)
		}
	})

	t.Run("concurrent update while running", func(t *testing.T) {
		// Ensure we're not in CI mode for this test
		ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
		originalEnv := make(map[string]string)
		for _, key := range ciEnvVars {
			if val, exists := os.LookupEnv(key); exists {
				originalEnv[key] = val
			}
			_ = os.Unsetenv(key)
		}
		t.Cleanup(func() {
			for _, key := range ciEnvVars {
				_ = os.Unsetenv(key)
			}
			for key, val := range originalEnv {
				_ = os.Setenv(key, val)
			}
		})

		var buf bytes.Buffer
		spinner := NewSpinner("initial", false)
		spinner.SetWriter(&buf)
		spinner.Start()

		// Concurrently update the message while the spinner is running
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					spinner.Update("message update")
					time.Sleep(10 * time.Millisecond)
				}
			}(i)
		}

		wg.Wait()
		spinner.Stop()
	})
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "zero duration",
			duration: 0,
			expected: "00:00",
		},
		{
			name:     "30 seconds",
			duration: 30 * time.Second,
			expected: "00:30",
		},
		{
			name:     "1 minute",
			duration: 60 * time.Second,
			expected: "01:00",
		},
		{
			name:     "1 minute 30 seconds",
			duration: 90 * time.Second,
			expected: "01:30",
		},
		{
			name:     "10 minutes 5 seconds",
			duration: 605 * time.Second,
			expected: "10:05",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		})
	}
}

func TestSpinnerStopIdempotent(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	spinner := NewSpinner("test", false)
	spinner.SetWriter(io.Discard)
	spinner.Start()

	// Stop should not panic when called multiple times
	spinner.Stop()
	spinner.Stop()
	spinner.Stop()
}

func TestSpinnerWithContextCancellation(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	spinner := NewSpinnerWithContext(ctx, "test", false)
	spinner.SetWriter(io.Discard)
	spinner.Start()

	// Cancel the context
	cancel()

	// Give the goroutine time to notice the cancellation
	time.Sleep(200 * time.Millisecond)

	// Stop should still work (idempotent)
	spinner.Stop()
}

func TestSpinnerAutoTimeout(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	// Use a very short timeout for testing
	spinner := NewSpinnerWithTimeout("test", false, 200*time.Millisecond)
	spinner.SetWriter(io.Discard)
	spinner.Start()

	// Wait for longer than the timeout
	time.Sleep(500 * time.Millisecond)

	// Stop should still work (idempotent) even after auto-timeout
	spinner.Stop()
}

func TestSpinnerStopBeforeStart(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	spinner := NewSpinner("test", false)
	spinner.SetWriter(io.Discard)

	// Should not panic - Stop before Start should be safe
	spinner.Stop()
}

func TestSpinnerDoubleStart(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	spinner := NewSpinner("test", false)
	spinner.SetWriter(io.Discard)

	spinner.Start()
	spinner.Start() // Second start should be no-op

	spinner.Stop()
}

func TestSpinnerConcurrentStop(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	spinner := NewSpinner("test", false)
	spinner.SetWriter(io.Discard)
	spinner.Start()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spinner.Stop()
		}()
	}
	wg.Wait()
}

func TestSpinnerNoGoroutineLeak(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	// Allow some time for any background goroutines to settle
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		spinner := NewSpinnerWithTimeout("test", false, time.Second)
		spinner.SetWriter(io.Discard)
		spinner.Start()
		time.Sleep(10 * time.Millisecond)
		spinner.Stop()
	}

	// Allow some time for goroutines to clean up
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	// Allow for some variance due to runtime behavior
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("Possible goroutine leak: started with %d, ended with %d",
			initialGoroutines, finalGoroutines)
	}
}

func TestSpinnerWithContextDeadline(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	spinner := NewSpinnerWithContext(ctx, "test", false)
	spinner.SetWriter(io.Discard)
	spinner.Start()

	// Wait for context deadline
	time.Sleep(400 * time.Millisecond)

	// Stop should still work after context deadline
	spinner.Stop()
}

func TestIsTerminalWriter(t *testing.T) {
	t.Run("bytes.Buffer is not a terminal", func(t *testing.T) {
		var buf bytes.Buffer
		if isTerminalWriter(&buf) {
			t.Error("bytes.Buffer should not be detected as terminal")
		}
	})

	t.Run("io.Discard is not a terminal", func(t *testing.T) {
		if isTerminalWriter(io.Discard) {
			t.Error("io.Discard should not be detected as terminal")
		}
	})

	t.Run("os.Stderr has Fd method", func(t *testing.T) {
		// Just verify it doesn't panic; actual result depends on test environment
		_ = isTerminalWriter(os.Stderr)
	})

	t.Run("pipe is not a terminal", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Failed to create pipe: %v", err)
		}
		defer func() { _ = r.Close() }()
		defer func() { _ = w.Close() }()

		// Pipe has Fd() but is not a terminal
		if isTerminalWriter(w) {
			t.Error("Pipe should not be detected as terminal")
		}
	})
}

func TestSpinnerNoCursorSequencesOnNonTTY(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	var buf bytes.Buffer
	spinner := NewSpinner("test", false)
	spinner.SetWriter(&buf)
	spinner.Start()
	time.Sleep(150 * time.Millisecond)
	spinner.Stop()

	output := buf.String()
	if bytes.Contains([]byte(output), []byte("\033[?25l")) {
		t.Error("cursor hide sequence should not be written to non-TTY writer")
	}
	if bytes.Contains([]byte(output), []byte("\033[?25h")) {
		t.Error("cursor show sequence should not be written to non-TTY writer")
	}
}

func TestSpinnerNoCursorSequencesOnPipe(t *testing.T) {
	// Ensure we're not in CI mode
	ciEnvVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"}
	originalEnv := make(map[string]string)
	for _, key := range ciEnvVars {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
		_ = os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range ciEnvVars {
			_ = os.Unsetenv(key)
		}
		for key, val := range originalEnv {
			_ = os.Setenv(key, val)
		}
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	spinner := NewSpinner("test", false)
	spinner.SetWriter(w)
	spinner.Start()
	time.Sleep(150 * time.Millisecond)
	spinner.Stop()
	_ = w.Close()

	output, _ := io.ReadAll(r)
	if bytes.Contains(output, []byte("\033[?25l")) {
		t.Error("cursor hide sequence should not be written to pipe")
	}
	if bytes.Contains(output, []byte("\033[?25h")) {
		t.Error("cursor show sequence should not be written to pipe")
	}
}
