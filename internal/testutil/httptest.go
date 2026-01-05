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
func ErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(message))
}
