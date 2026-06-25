package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAnnotateTransportError(t *testing.T) {
	t.Run("EOF gets proxy guidance and stays unwrappable to io.EOF", func(t *testing.T) {
		got := annotateTransportError(io.EOF)
		if !errors.Is(got, io.EOF) {
			t.Fatalf("annotated error must still unwrap to io.EOF, got %v", got)
		}
		msg := got.Error()
		for _, want := range []string{"proxy", "HTTPS_PROXY"} {
			if !strings.Contains(msg, want) {
				t.Errorf("expected EOF guidance to mention %q, got: %s", want, msg)
			}
		}
	})

	t.Run("wrapped EOF is also annotated", func(t *testing.T) {
		wrapped := fmt.Errorf("Post \"https://moose.armis.com\": %w", io.EOF)
		got := annotateTransportError(wrapped)
		if !strings.Contains(got.Error(), "proxy") {
			t.Errorf("expected wrapped EOF to be annotated, got: %s", got.Error())
		}
	})

	t.Run("non-EOF errors pass through unchanged", func(t *testing.T) {
		orig := errors.New("dial tcp: connection refused")
		got := annotateTransportError(orig)
		if got.Error() != orig.Error() {
			t.Errorf("non-EOF error should pass through unchanged, got: %s", got.Error())
		}
	})
}

func TestAuthClient_DoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHit atomic.Bool

	// Both servers use plain HTTP so they are mutually reachable.
	// NewAuthClient allows HTTP for 127.0.0.1 (httptest.NewServer binds there).
	// This ensures that if redirects *were* followed, the request would
	// actually reach redirectTarget's handler instead of failing TLS.
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer authServer.Close()

	client, err := NewAuthClient(authServer.URL, false)
	if err != nil {
		t.Fatalf("NewAuthClient failed: %v", err)
	}

	_, err = client.Authenticate(context.Background(), "test-id", "test-secret", nil)
	if err == nil {
		t.Fatal("expected error from redirect response, got nil")
	}

	// Assert the specific error type so the test fails if the error
	// changes for an unrelated reason (e.g., network, JSON parse).
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if authErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected status %d, got %d", http.StatusTemporaryRedirect, authErr.StatusCode)
	}

	if redirectTargetHit.Load() {
		t.Fatal("client followed redirect to target server — credentials would have been leaked")
	}
}

func TestAuthClient_SuccessfulAuth(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"test-token-123","region":"us-east-1"}`))
	}))
	defer authServer.Close()

	client, err := NewAuthClient(authServer.URL, false)
	if err != nil {
		t.Fatalf("NewAuthClient failed: %v", err)
	}

	result, err := client.Authenticate(context.Background(), "test-id", "test-secret", nil)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if result.Token != "test-token-123" {
		t.Errorf("expected token 'test-token-123', got %q", result.Token)
	}
	if result.Region != "us-east-1" {
		t.Errorf("expected region 'us-east-1', got %q", result.Region)
	}
}

func TestRegionalBaseURL(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"empty region falls back to production", "", ProductionBaseURL},
		{"eu1 maps to EU data plane", "eu1", "https://eu.moose.armis.com"},
		{"us1 (primary) uses production host", "us1", ProductionBaseURL},
		{"au1 has no data plane yet, uses production host", "au1", ProductionBaseURL},
		{"unknown region falls back to production", "mars1", ProductionBaseURL},
		{"injection attempt falls back to production", "eu1.evil.com", ProductionBaseURL},
		{"path injection falls back to production", "eu1/path", ProductionBaseURL},
		{"uppercase region falls back to production", "EU1", ProductionBaseURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RegionalBaseURL(tt.region); got != tt.want {
				t.Errorf("RegionalBaseURL(%q) = %q, want %q", tt.region, got, tt.want)
			}
		})
	}
}
