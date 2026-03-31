package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

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
