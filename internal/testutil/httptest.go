// Package testutil provides utilities for testing.
package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
