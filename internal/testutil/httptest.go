// Package testutil provides utilities for testing.
package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// NewTestServer creates a new test HTTP server with automatic cleanup.
func NewTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// JSONResponse writes a JSON response with the given status code.
func JSONResponse(t *testing.T, w http.ResponseWriter, statusCode int, data interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		t.Fatalf("Failed to encode JSON response: %v", err)
	}
}

// ErrorResponse writes an error response with the given status code.
// Sets Content-Type to text/plain to prevent HTML interpretation.
func ErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(message))
}

// ContainsSubstring checks if a string contains a substring.
// This is a shared test helper to avoid duplication across test files.
func ContainsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// CaptureStderr redirects os.Stderr for the duration of f and returns
// whatever was written to it. Not safe to use alongside t.Parallel, since
// os.Stderr is a shared global.
func CaptureStderr(t *testing.T, f func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	// Drain the pipe concurrently so f() can't deadlock by filling the
	// pipe buffer before we get around to reading it, and so os.Stderr is
	// restored via defer even if f() calls t.Fatal (runtime.Goexit).
	outCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outCh <- buf.String()
	}()

	f()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}
	out := <-outCh
	if err := r.Close(); err != nil {
		t.Fatalf("failed to close pipe reader: %v", err)
	}
	return out
}
