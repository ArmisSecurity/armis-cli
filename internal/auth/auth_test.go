package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// createMockJWT creates a mock JWT token with the given claims.
func createMockJWT(customerID string, exp int64) string {
	// JWT header (not validated by our code)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	// JWT payload
	claims := map[string]interface{}{
		"customer_id": customerID,
		"exp":         exp,
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Signature (not validated by our code)
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payload + "." + signature
}

// createMockJWTWithFloatExp creates a mock JWT with a floating-point exp claim.
// Some auth servers return fractional timestamps (e.g., 1769951069.169681).
func createMockJWTWithFloatExp(customerID string, exp float64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"customer_id": customerID,
		"exp":         exp,
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payload + "." + signature
}

func TestNewAuthProvider_LegacyAuth(t *testing.T) {
	t.Run("succeeds with token and tenant ID", func(t *testing.T) {
		config := AuthConfig{
			Token:    "test-token",
			TenantID: "tenant-123",
		}

		p, err := NewAuthProvider(config)
		if err != nil {
			t.Fatalf("NewAuthProvider failed: %v", err)
		}

		if !p.isLegacy {
			t.Error("Expected legacy mode")
		}

		header, err := p.GetAuthorizationHeader(context.Background())
		if err != nil {
			t.Fatalf("GetAuthorizationHeader failed: %v", err)
		}
		if header != "Basic test-token" {
			t.Errorf("Expected 'Basic test-token', got %q", header)
		}

		tid, err := p.GetTenantID(context.Background())
		if err != nil {
			t.Fatalf("GetTenantID failed: %v", err)
		}
		if tid != "tenant-123" {
			t.Errorf("Expected 'tenant-123', got %q", tid)
		}
	})

	t.Run("fails without tenant ID", func(t *testing.T) {
		config := AuthConfig{
			Token: "test-token",
		}

		_, err := NewAuthProvider(config)
		if err == nil {
			t.Error("Expected error for missing tenant ID")
		}
		if !strings.Contains(err.Error(), "tenant ID required") {
			t.Errorf("Expected tenant ID error, got: %v", err)
		}
	})

	t.Run("fails without any credentials", func(t *testing.T) {
		_, err := NewAuthProvider(AuthConfig{})
		if err == nil {
			t.Error("Expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "authentication required") {
			t.Errorf("Expected authentication error, got: %v", err)
		}
	})

	t.Run("fails with only client_id provided", func(t *testing.T) {
		config := AuthConfig{
			ClientID: "test-client",
			// ClientSecret missing
		}

		_, err := NewAuthProvider(config)
		if err == nil {
			t.Error("Expected error for partial JWT credentials")
		}
		if !strings.Contains(err.Error(), "both --client-id and --client-secret must be provided") {
			t.Errorf("Expected partial credentials error, got: %v", err)
		}
	})

	t.Run("fails with only client_secret provided", func(t *testing.T) {
		config := AuthConfig{
			ClientSecret: "test-secret",
			// ClientID missing
		}

		_, err := NewAuthProvider(config)
		if err == nil {
			t.Error("Expected error for partial JWT credentials")
		}
		if !strings.Contains(err.Error(), "both --client-id and --client-secret must be provided") {
			t.Errorf("Expected partial credentials error, got: %v", err)
		}
	})

	t.Run("GetRawToken returns raw token for Basic auth", func(t *testing.T) {
		config := AuthConfig{
			Token:    "my-raw-token",
			TenantID: "tenant-123",
		}

		p, err := NewAuthProvider(config)
		if err != nil {
			t.Fatalf("NewAuthProvider failed: %v", err)
		}

		rawToken, err := p.GetRawToken(context.Background())
		if err != nil {
			t.Fatalf("GetRawToken failed: %v", err)
		}
		if rawToken != "my-raw-token" {
			t.Errorf("Expected raw token 'my-raw-token', got %q", rawToken)
		}

		// Verify GetAuthorizationHeader includes prefix while GetRawToken doesn't
		header, _ := p.GetAuthorizationHeader(context.Background())
		if header == rawToken {
			t.Error("Expected GetAuthorizationHeader to include 'Basic ' prefix")
		}
		if header != "Basic my-raw-token" {
			t.Errorf("Expected 'Basic my-raw-token', got %q", header)
		}
	})
}

func TestNewAuthProvider_JWTAuth(t *testing.T) {
	t.Run("succeeds with valid credentials", func(t *testing.T) {
		mockJWT := createMockJWT("tenant-from-jwt", time.Now().Add(1*time.Hour).Unix())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/authenticate" {
				t.Errorf("Unexpected path: %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("Expected POST, got %s", r.Method)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
		}))
		defer server.Close()

		config := AuthConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AuthEndpoint: server.URL,
		}

		p, err := NewAuthProvider(config)
		if err != nil {
			t.Fatalf("NewAuthProvider failed: %v", err)
		}

		if p.isLegacy {
			t.Error("Expected JWT mode, got legacy")
		}

		header, err := p.GetAuthorizationHeader(context.Background())
		if err != nil {
			t.Fatalf("GetAuthorizationHeader failed: %v", err)
		}
		// Raw JWT (no Bearer prefix)
		if header != mockJWT {
			t.Errorf("Unexpected auth header: got %q, want %q", header, mockJWT)
		}

		tid, err := p.GetTenantID(context.Background())
		if err != nil {
			t.Fatalf("GetTenantID failed: %v", err)
		}
		if tid != "tenant-from-jwt" {
			t.Errorf("Expected 'tenant-from-jwt', got %q", tid)
		}

		// Also verify GetRawToken returns the same JWT
		rawToken, err := p.GetRawToken(context.Background())
		if err != nil {
			t.Fatalf("GetRawToken failed: %v", err)
		}
		if rawToken != mockJWT {
			t.Errorf("GetRawToken: expected %q, got %q", mockJWT, rawToken)
		}
	})

	t.Run("fails with invalid credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		config := AuthConfig{
			ClientID:     "bad-client",
			ClientSecret: "bad-secret",
			AuthEndpoint: server.URL,
		}

		_, err := NewAuthProvider(config)
		if err == nil {
			t.Error("Expected error for invalid credentials")
		}
		if !strings.Contains(err.Error(), "invalid credentials") {
			t.Errorf("Expected invalid credentials error, got: %v", err)
		}
	})

	t.Run("fails without auth endpoint", func(t *testing.T) {
		config := AuthConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			// No AuthEndpoint
		}

		_, err := NewAuthProvider(config)
		if err == nil {
			t.Error("Expected error for missing auth endpoint")
		}
		if !strings.Contains(err.Error(), "--auth-endpoint is required") {
			t.Errorf("Expected auth endpoint required error, got: %v", err)
		}
	})

	t.Run("JWT auth takes priority over Basic auth", func(t *testing.T) {
		mockJWT := createMockJWT("jwt-tenant", time.Now().Add(1*time.Hour).Unix())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
		}))
		defer server.Close()

		// Provide both JWT and Basic auth credentials
		config := AuthConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AuthEndpoint: server.URL,
			Token:        "basic-token",
			TenantID:     "basic-tenant",
		}

		p, err := NewAuthProvider(config)
		if err != nil {
			t.Fatalf("NewAuthProvider failed: %v", err)
		}

		// Should use JWT auth, not Basic
		if p.isLegacy {
			t.Error("Expected JWT mode when both credentials provided")
		}

		tid, err := p.GetTenantID(context.Background())
		if err != nil {
			t.Fatalf("GetTenantID failed: %v", err)
		}
		if tid != "jwt-tenant" {
			t.Errorf("Expected JWT tenant 'jwt-tenant', got %q", tid)
		}
	})
}

func TestAuthProvider_RefreshIfNeeded(t *testing.T) {
	refreshCount := 0

	// Create mock JWT that expires soon (< 5 min threshold)
	mockJWT := createMockJWT("tenant-123", time.Now().Add(3*time.Minute).Unix())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
	}))
	defer server.Close()

	config := AuthConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthEndpoint: server.URL,
	}

	p, err := NewAuthProvider(config)
	if err != nil {
		t.Fatalf("NewAuthProvider failed: %v", err)
	}

	initialCount := refreshCount

	// This should trigger refresh since token expires in < 5 minutes
	_, err = p.GetAuthorizationHeader(context.Background())
	if err != nil {
		t.Fatalf("GetAuthorizationHeader failed: %v", err)
	}

	if refreshCount <= initialCount {
		t.Error("Expected token refresh for expiring token")
	}
}

func TestAuthProvider_NoRefreshWhenValid(t *testing.T) {
	refreshCount := 0

	// Create mock JWT that expires in 1 hour (> 5 min threshold)
	mockJWT := createMockJWT("tenant-123", time.Now().Add(1*time.Hour).Unix())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
	}))
	defer server.Close()

	config := AuthConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthEndpoint: server.URL,
	}

	p, err := NewAuthProvider(config)
	if err != nil {
		t.Fatalf("NewAuthProvider failed: %v", err)
	}

	initialCount := refreshCount

	// Multiple calls should not trigger refresh
	for i := 0; i < 5; i++ {
		_, err = p.GetAuthorizationHeader(context.Background())
		if err != nil {
			t.Fatalf("GetAuthorizationHeader failed: %v", err)
		}
	}

	if refreshCount != initialCount {
		t.Errorf("Expected no refresh, but refreshCount changed from %d to %d", initialCount, refreshCount)
	}
}

func TestAuthProvider_ThreadSafe(t *testing.T) {
	mockJWT := createMockJWT("tenant-123", time.Now().Add(1*time.Hour).Unix())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Small delay to increase chance of race conditions
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
	}))
	defer server.Close()

	config := AuthConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthEndpoint: server.URL,
	}

	p, err := NewAuthProvider(config)
	if err != nil {
		t.Fatalf("NewAuthProvider failed: %v", err)
	}

	// Launch concurrent requests
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.GetAuthorizationHeader(context.Background())
			if err != nil {
				errors <- err
			}
			_, err = p.GetTenantID(context.Background())
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestParseJWTClaims(t *testing.T) {
	t.Run("valid JWT", func(t *testing.T) {
		token := createMockJWT("cust-123", 1700000000)

		result, err := parseJWTClaims(token)
		if err != nil {
			t.Fatalf("parseJWTClaims failed: %v", err)
		}

		if result.CustomerID != "cust-123" {
			t.Errorf("Expected customer_id 'cust-123', got %q", result.CustomerID)
		}

		expectedTime := time.Unix(1700000000, 0)
		if !result.ExpiresAt.Equal(expectedTime) {
			t.Errorf("Expected exp %v, got %v", expectedTime, result.ExpiresAt)
		}
	})

	t.Run("valid JWT with floating-point exp", func(t *testing.T) {
		// Some auth servers return fractional timestamps like 1769951069.169681
		token := createMockJWTWithFloatExp("cust-456", 1769951069.169681)

		result, err := parseJWTClaims(token)
		if err != nil {
			t.Fatalf("parseJWTClaims failed: %v", err)
		}

		if result.CustomerID != "cust-456" {
			t.Errorf("Expected customer_id 'cust-456', got %q", result.CustomerID)
		}

		// The fractional part should be truncated
		expectedTime := time.Unix(1769951069, 0)
		if !result.ExpiresAt.Equal(expectedTime) {
			t.Errorf("Expected exp %v, got %v", expectedTime, result.ExpiresAt)
		}
	})

	t.Run("missing customer_id", func(t *testing.T) {
		// Create JWT without customer_id
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		claims := map[string]interface{}{"exp": int64(1700000000)}
		claimsJSON, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
		token := header + "." + payload + ".signature"

		_, err := parseJWTClaims(token)
		if err == nil {
			t.Error("Expected error for missing customer_id")
		}
		if !strings.Contains(err.Error(), "customer_id") {
			t.Errorf("Expected customer_id error, got: %v", err)
		}
	})

	t.Run("missing exp", func(t *testing.T) {
		// Create JWT without exp
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
		claims := map[string]interface{}{"customer_id": "test"}
		claimsJSON, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
		token := header + "." + payload + ".signature"

		_, err := parseJWTClaims(token)
		if err == nil {
			t.Error("Expected error for missing exp")
		}
		if !strings.Contains(err.Error(), "exp") {
			t.Errorf("Expected exp error, got: %v", err)
		}
	})

	t.Run("invalid format - not enough parts", func(t *testing.T) {
		_, err := parseJWTClaims("not-a-jwt")
		if err == nil {
			t.Error("Expected error for invalid JWT format")
		}
		if !strings.Contains(err.Error(), "invalid JWT format") {
			t.Errorf("Expected format error, got: %v", err)
		}
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		token := "header.!!!invalid-base64!!!.signature"
		_, err := parseJWTClaims(token)
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})
}

func TestIsLegacy(t *testing.T) {
	t.Run("returns true for Basic auth", func(t *testing.T) {
		p, err := NewAuthProvider(AuthConfig{
			Token:    "test-token",
			TenantID: "tenant-123",
		})
		if err != nil {
			t.Fatalf("NewAuthProvider failed: %v", err)
		}

		if !p.IsLegacy() {
			t.Error("Expected IsLegacy() to return true for Basic auth")
		}
	})
}

func TestNewAuthClient(t *testing.T) {
	t.Run("succeeds with valid HTTPS endpoint", func(t *testing.T) {
		client, err := NewAuthClient("https://auth.example.com")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if client == nil {
			t.Error("Expected non-nil client")
		}
	})

	t.Run("succeeds with localhost HTTP", func(t *testing.T) {
		client, err := NewAuthClient("http://localhost:8080")
		if err != nil {
			t.Errorf("Unexpected error for localhost: %v", err)
		}
		if client == nil {
			t.Error("Expected non-nil client")
		}
	})

	t.Run("succeeds with 127.0.0.1 HTTP", func(t *testing.T) {
		client, err := NewAuthClient("http://127.0.0.1:8080")
		if err != nil {
			t.Errorf("Unexpected error for 127.0.0.1: %v", err)
		}
		if client == nil {
			t.Error("Expected non-nil client")
		}
	})

	t.Run("fails with non-localhost HTTP", func(t *testing.T) {
		_, err := NewAuthClient("http://auth.example.com")
		if err == nil {
			t.Error("Expected error for non-localhost HTTP")
		}
		if !strings.Contains(err.Error(), "HTTPS required") {
			t.Errorf("Expected HTTPS required error, got: %v", err)
		}
	})

	t.Run("fails with empty endpoint", func(t *testing.T) {
		_, err := NewAuthClient("")
		if err == nil {
			t.Error("Expected error for empty endpoint")
		}
		if !strings.Contains(err.Error(), "auth endpoint is required") {
			t.Errorf("Expected endpoint required error, got: %v", err)
		}
	})

	t.Run("fails with invalid URL", func(t *testing.T) {
		_, err := NewAuthClient("://invalid")
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
		if !strings.Contains(err.Error(), "invalid endpoint URL") {
			t.Errorf("Expected invalid URL error, got: %v", err)
		}
	})
}

func TestAuthProvider_DoubleCheckedLocking(t *testing.T) {
	// Test that concurrent refresh requests don't cause a thundering herd
	// of duplicate API calls due to the double-checked locking fix.
	var refreshCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&refreshCount, 1)
		// Simulate slow auth server to increase chance of concurrent requests
		time.Sleep(50 * time.Millisecond)
		// Return a token that expires in 1 hour (well beyond 5 minute threshold)
		// This ensures subsequent goroutines see a valid token after the first refresh
		mockJWT := createMockJWT("tenant-123", time.Now().Add(1*time.Hour).Unix())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
	}))
	defer server.Close()

	config := AuthConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthEndpoint: server.URL,
	}

	p, err := NewAuthProvider(config)
	if err != nil {
		t.Fatalf("NewAuthProvider failed: %v", err)
	}

	// Manually set credentials to expire soon to trigger refresh
	p.mu.Lock()
	p.credentials.ExpiresAt = time.Now().Add(3 * time.Minute)
	p.mu.Unlock()

	// Reset counter after initial auth
	atomic.StoreInt32(&refreshCount, 0)

	// Launch many concurrent requests that should all trigger refresh
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.GetAuthorizationHeader(context.Background())
			if err != nil {
				t.Errorf("GetAuthorizationHeader failed: %v", err)
			}
		}()
	}

	wg.Wait()

	// With double-checked locking, we should have at most a few refreshes
	// (ideally 1, but race conditions may allow 2-3)
	// Without it, we'd have ~50 refreshes
	finalCount := atomic.LoadInt32(&refreshCount)
	if finalCount > 5 {
		t.Errorf("Expected <= 5 refreshes with double-checked locking, got %d (thundering herd detected)", finalCount)
	}
}

func TestAuthProvider_ContextCancellation(t *testing.T) {
	// Test that context cancellation is properly propagated
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Server is slow, giving time for context to be cancelled
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		mockJWT := createMockJWT("tenant-123", time.Now().Add(1*time.Hour).Unix())
		_ = json.NewEncoder(w).Encode(map[string]string{"token": mockJWT})
	}))
	defer slowServer.Close()

	// Create an auth client directly for the test
	authClient, err := NewAuthClient(slowServer.URL)
	if err != nil {
		t.Fatalf("NewAuthClient failed: %v", err)
	}

	// Create provider with token that needs refresh
	p := &AuthProvider{
		config: AuthConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AuthEndpoint: slowServer.URL,
		},
		authClient: authClient,
		credentials: &JWTCredentials{
			Token:     "old-token",
			TenantID:  "tenant-123",
			ExpiresAt: time.Now().Add(-1 * time.Minute), // Expired
		},
	}

	// Create a context that will be cancelled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should fail due to context cancellation
	_, err = p.GetAuthorizationHeader(ctx)
	if err == nil {
		t.Error("Expected error due to context cancellation")
	}

	// The error should be related to context (deadline or cancellation)
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Logf("Got error: %v (context cancellation may manifest differently)", err)
	}
}
