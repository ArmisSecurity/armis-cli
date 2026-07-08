package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// makeDeviceJWT builds an unsigned JWT carrying the device-flow access-token
// claims (tenant_id/sub/role), distinct from the client-credentials customer_id.
func makeDeviceJWT(tenantID, sub, role string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]any{
		"tenant_id": tenantID,
		"sub":       sub,
		"role":      role,
		"iss":       "https://moose.armis.com",
		"exp":       exp,
	}
	cj, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(cj)
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + payload + "." + sig
}

func TestRequestDeviceCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/device" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm() //nolint:gosec // G120: test server; request body is a tiny fixed form
		if r.Form.Get("client_id") != "armis-cli" {
			t.Errorf("client_id = %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("tenant_id") != "tenant-1" {
			t.Errorf("tenant_id = %q, want tenant-1", r.Form.Get("tenant_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-code",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          "https://moose.armis.com/oauth2/device/verify",
			"verification_uri_complete": "https://moose.armis.com/oauth2/device/verify?user_code=WDJB-MJHT",
			"expires_in":                900,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	c, err := NewDeviceClient(srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	da, err := c.RequestDeviceCode(context.Background(), "armis-cli", "tenant-1", "")
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}
	if da.DeviceCode != "dev-code" || da.UserCode != "WDJB-MJHT" || da.Interval != 5 {
		t.Errorf("unexpected device authorization: %+v", da)
	}
}

func TestRequestDeviceCodeRequiresTenant(t *testing.T) {
	c, err := NewDeviceClient("https://moose.armis.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RequestDeviceCode(context.Background(), "armis-cli", "", ""); err == nil {
		t.Fatal("expected error when tenant_id is empty")
	}
}

func TestPollTokenPendingThenSuccess(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	jwt := makeDeviceJWT("tenant-1", "user@example.com", "admin", time.Now().Add(time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n < 2 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": errAuthorizationPending})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwt,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refresh-1",
		})
	}))
	defer srv.Close()

	c, err := NewDeviceClient(srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// interval=0 is clamped to the default; override to keep the test fast by
	// using a 1s minimum via a tiny interval value.
	tok, err := c.PollToken(ctx, "dev-code", "armis-cli", 1)
	if err != nil {
		t.Fatalf("PollToken: %v", err)
	}
	if tok.AccessToken != jwt || tok.RefreshToken != "refresh-1" {
		t.Errorf("unexpected tokens: %+v", tok)
	}
	if tok.TenantID != "tenant-1" || tok.Subject != "user@example.com" || tok.Role != "admin" {
		t.Errorf("claims not parsed: %+v", tok)
	}
}

func TestPollTokenAccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errAccessDenied})
	}))
	defer srv.Close()

	c, _ := NewDeviceClient(srv.URL, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.PollToken(ctx, "dev-code", "armis-cli", 1)
	if err == nil {
		t.Fatal("expected denial error")
	}
}

func TestPollTokenExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errExpiredToken})
	}))
	defer srv.Close()

	c, _ := NewDeviceClient(srv.URL, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.PollToken(ctx, "dev-code", "armis-cli", 1)
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestRefresh(t *testing.T) {
	jwt := makeDeviceJWT("tenant-9", "svc", "viewer", time.Now().Add(time.Hour).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() //nolint:gosec // G120: test server; request body is a tiny fixed form
		if r.Form.Get("grant_type") != grantTypeRefreshToken {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Errorf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwt,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer srv.Close()

	c, _ := NewDeviceClient(srv.URL, false)
	tok, err := c.Refresh(context.Background(), "old-refresh", "armis-cli")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.RefreshToken != "new-refresh" || tok.TenantID != "tenant-9" {
		t.Errorf("unexpected refreshed token: %+v", tok)
	}
}

func TestNewDeviceClientRejectsHTTP(t *testing.T) {
	if _, err := NewDeviceClient("http://moose.armis.com", false); err == nil {
		t.Fatal("expected HTTPS enforcement error")
	}
	// localhost http is allowed (tests / dev).
	if _, err := NewDeviceClient("http://localhost:8080", false); err != nil {
		t.Errorf("localhost http should be allowed: %v", err)
	}
}

func TestParseAccessTokenClaims(t *testing.T) {
	jwt := makeDeviceJWT("t", "s", "r", 1700000000)
	claims, err := parseAccessTokenClaims(jwt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.TenantID != "t" || claims.Subject != "s" || claims.Role != "r" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if claims.ExpiresAt.Unix() != 1700000000 {
		t.Errorf("exp = %v", claims.ExpiresAt.Unix())
	}
}
