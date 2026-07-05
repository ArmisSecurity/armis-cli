package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newOAuthTestProvider wires an SSO-mode provider against a mock token endpoint
// and an in-memory token store.
func newOAuthTestProvider(t *testing.T, srvURL string, stored *StoredToken) (*AuthProvider, *TokenStore) {
	t.Helper()
	store := &TokenStore{dir: t.TempDir()}
	if err := store.Save(srvURL, stored); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	dc, err := NewDeviceClient(srvURL, false)
	if err != nil {
		t.Fatalf("device client: %v", err)
	}
	p, err := NewProviderFromStored(store, dc, srvURL, stored)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	return p, store
}

func TestOAuthProviderUsesStoredTokenWithoutRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("token endpoint should not be called when token is fresh")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	stored := sampleToken()
	stored.AccessToken = makeDeviceJWT("tenant-1", "u", "admin", time.Now().Add(time.Hour).Unix())
	stored.ExpiresAt = time.Now().Add(time.Hour)

	p, _ := newOAuthTestProvider(t, srv.URL, stored)

	hdr, err := p.GetAuthorizationHeader(context.Background())
	if err != nil {
		t.Fatalf("GetAuthorizationHeader: %v", err)
	}
	if hdr != "Bearer "+stored.AccessToken {
		t.Errorf("unexpected header: %q", hdr)
	}
	if p.AuthMethod() != AuthMethodSSO {
		t.Errorf("AuthMethod = %q, want sso", p.AuthMethod())
	}
}

func TestOAuthProviderRefreshesNearExpiry(t *testing.T) {
	newJWT := makeDeviceJWT("tenant-1", "u", "admin", time.Now().Add(time.Hour).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() //nolint:gosec // G120: test server; request body is a tiny fixed form
		if r.Form.Get("grant_type") != grantTypeRefreshToken {
			t.Errorf("expected refresh grant, got %q", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  newJWT,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rotated-refresh",
		})
	}))
	defer srv.Close()

	stored := sampleToken()
	stored.AccessToken = "stale"
	stored.ExpiresAt = time.Now().Add(1 * time.Minute) // within the 5-min window

	p, store := newOAuthTestProvider(t, srv.URL, stored)

	hdr, err := p.GetAuthorizationHeader(context.Background())
	if err != nil {
		t.Fatalf("GetAuthorizationHeader: %v", err)
	}
	if hdr != "Bearer "+newJWT {
		t.Errorf("expected refreshed token in header, got %q", hdr)
	}

	// The rotated refresh token must be persisted for the next process.
	reloaded, _ := store.Load(srv.URL)
	if reloaded == nil || reloaded.RefreshToken != "rotated-refresh" {
		t.Errorf("rotated refresh token not persisted: %+v", reloaded)
	}
}

func TestOAuthProviderRefreshFailureSurfacesReloginHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errInvalidGrant})
	}))
	defer srv.Close()

	stored := sampleToken()
	stored.ExpiresAt = time.Now().Add(1 * time.Minute)

	p, _ := newOAuthTestProvider(t, srv.URL, stored)

	_, err := p.GetTenantID(context.Background())
	if err == nil {
		t.Fatal("expected error on failed refresh")
	}
	if want := "auth login"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q should mention %q", err.Error(), want)
	}
}
