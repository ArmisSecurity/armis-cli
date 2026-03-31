package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAuthClient_DoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHit atomic.Bool

	// Second server: the redirect target that should never be reached
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	// Primary auth server: returns 307 redirect to the target
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer authServer.Close()

	client, err := NewAuthClient(authServer.URL, false)
	if err != nil {
		t.Fatalf("NewAuthClient failed: %v", err)
	}
	// Use the test server's TLS client to trust self-signed certs
	client.httpClient.Transport = authServer.Client().Transport

	_, err = client.Authenticate(context.Background(), "test-id", "test-secret", nil)
	if err == nil {
		t.Fatal("expected error from redirect response, got nil")
	}

	if redirectTargetHit.Load() {
		t.Fatal("client followed redirect to target server — credentials would have been leaked")
	}
}

func TestAuthClient_SuccessfulAuth(t *testing.T) {
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"test-token-123","region":"us-east-1"}`))
	}))
	defer authServer.Close()

	client, err := NewAuthClient(authServer.URL, false)
	if err != nil {
		t.Fatalf("NewAuthClient failed: %v", err)
	}
	client.httpClient.Transport = authServer.Client().Transport

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
