package install

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateCredentialsWithURL(t *testing.T) {
	t.Run("success on valid credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/api/v1/auth/token" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}

			var req struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"` //nolint:gosec // G117: test struct for JSON decoding
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decoding request: %v", err)
			}
			if req.ClientID != "test-id" || req.ClientSecret != "test-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"eyJhbGciOiJIUzI1NiJ9.eyJjdXN0b21lcl9pZCI6InRlc3QifQ.abc","region":"us"}`))
		}))
		defer server.Close()

		err := validateCredentialsWithURL("test-id", "test-secret", server.URL)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("failure on invalid credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
		}))
		defer server.Close()

		err := validateCredentialsWithURL("bad-id", "bad-secret", server.URL)
		if err == nil {
			t.Fatal("expected error for invalid credentials")
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("error message should contain 'authentication failed', got: %v", err)
		}
		if !strings.Contains(err.Error(), "API Credentials") {
			t.Errorf("error message should contain help text, got: %v", err)
		}
	})

	t.Run("failure on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
		}))
		defer server.Close()

		err := validateCredentialsWithURL("id", "secret", server.URL)
		if err == nil {
			t.Fatal("expected error for server error")
		}
	})

	t.Run("failure on invalid URL", func(t *testing.T) {
		err := validateCredentialsWithURL("id", "secret", "not-a-url")
		if err == nil {
			t.Fatal("expected error for invalid URL")
		}
	})

	t.Run("failure on connection refused", func(t *testing.T) {
		// Start and immediately close a server to get a valid but unreachable address
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		addr := server.URL
		server.Close()

		err := validateCredentialsWithURL("id", "secret", addr)
		if err == nil {
			t.Fatal("expected error for unreachable server")
		}
	})
}
