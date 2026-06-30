package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/spf13/cobra"
)

// tenant7 is the tenant ID used across the login-flow tests.
const tenant7 = "tenant-7"

// deviceJWT builds an unsigned access token with the device-flow claims.
func deviceJWT(tenant, sub, role string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"tenant_id": tenant, "sub": sub, "role": role,
		"iss": "https://moose.armis.com", "exp": exp,
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))
}

// setupAuthTest isolates global state: it points ARMIS_API_URL at the mock
// server, redirects HOME to a temp dir so the token store writes there instead
// of the real ~/.armis, and clears credential globals. The browser opener is
// stubbed once in TestMain. Everything is restored via t.Cleanup / t.Setenv.
func setupAuthTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // token store resolves ~/.armis from HOME

	origGlobals := struct{ clientID, clientSecret, token, tenantID string }{
		clientID, clientSecret, token, tenantID,
	}
	t.Cleanup(func() {
		clientID = origGlobals.clientID
		clientSecret = origGlobals.clientSecret
		token = origGlobals.token
		tenantID = origGlobals.tenantID
		credFlagsExplicit = false
		noProgress = false
		loginOrg = ""
		loginClientID = auth.DefaultDeviceClientID
		logoutAll = false
	})
	clientID, clientSecret, token, tenantID = "", "", "", ""
	credFlagsExplicit = false
	noProgress = true
	loginClientID = auth.DefaultDeviceClientID

	t.Setenv("ARMIS_API_URL", serverURL)
}

func newCmdWithCtx() *cobra.Command {
	c := &cobra.Command{}
	c.SetContext(context.Background())
	return c
}

func TestAuthLoginStoresTokens(t *testing.T) {
	jwt := deviceJWT(tenant7, "alice@example.com", "admin", time.Now().Add(time.Hour).Unix())
	var mu sync.Mutex
	tokenCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/device":
			_ = r.ParseForm() //nolint:gosec // G120: test server; request body is a tiny fixed form
			if r.Form.Get("tenant_id") != tenant7 {
				t.Errorf("device request tenant_id = %q, want %s", r.Form.Get("tenant_id"), tenant7)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "dev-code",
				"user_code":                 "WDJB-MJHT",
				"verification_uri":          "https://moose.armis.com/oauth2/device/verify",
				"verification_uri_complete": "https://moose.armis.com/oauth2/device/verify?user_code=WDJB-MJHT",
				"expires_in":                900,
				"interval":                  1,
			})
		case "/oauth2/token":
			mu.Lock()
			tokenCalls++
			n := tokenCalls
			mu.Unlock()
			if n < 2 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": jwt, "token_type": "Bearer",
				"expires_in": 3600, "refresh_token": "refresh-7",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	setupAuthTest(t, srv.URL)
	tenantID = tenant7 // device authorization requires a tenant

	if err := runAuthLogin(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("runAuthLogin: %v", err)
	}

	stored, err := auth.NewTokenStore().Load(srv.URL)
	if err != nil || stored == nil {
		t.Fatalf("expected stored token, err=%v stored=%v", err, stored)
	}
	if stored.RefreshToken != "refresh-7" || stored.TenantID != tenant7 {
		t.Errorf("unexpected stored token: %+v", stored)
	}
	if stored.Subject != "alice@example.com" {
		t.Errorf("subject = %q", stored.Subject)
	}
}

func TestAuthLoginRequiresTenant(t *testing.T) {
	setupAuthTest(t, "https://moose.armis.com")
	tenantID = "" // no --tenant-id / ARMIS_TENANT_ID

	err := runAuthLogin(newCmdWithCtx(), nil)
	if err == nil {
		t.Fatal("expected error when tenant ID is missing")
	}
	if !strings.Contains(err.Error(), "tenant ID required") {
		t.Errorf("error %q should mention 'tenant ID required'", err.Error())
	}
}

func TestAuthWhoamiAfterLogin(t *testing.T) {
	jwt := deviceJWT(tenant7, "alice@example.com", "admin", time.Now().Add(2*time.Hour).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // no refresh expected; token is fresh
	}))
	defer srv.Close()
	setupAuthTest(t, srv.URL)

	// Seed a stored token directly.
	store := auth.NewTokenStore()
	if err := store.Save(srv.URL, &auth.StoredToken{
		AccessToken: jwt, RefreshToken: "r", ExpiresAt: time.Now().Add(2 * time.Hour),
		TenantID: tenant7, Subject: "alice@example.com", Role: "admin",
		Issuer: srv.URL, ClientID: "armis-cli",
	}); err != nil {
		t.Fatal(err)
	}

	if err := runAuthWhoami(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("runAuthWhoami: %v", err)
	}
}

func TestAuthLogout(t *testing.T) {
	const env = "https://moose.armis.com"
	setupAuthTest(t, env)
	store := auth.NewTokenStore()
	if err := store.Save(env, &auth.StoredToken{AccessToken: "a", RefreshToken: "r", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}

	if err := runAuthLogout(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("runAuthLogout: %v", err)
	}
	got, _ := store.Load(env)
	if got != nil {
		t.Errorf("expected token cleared, got %+v", got)
	}

	// Idempotent: logging out again is not an error.
	if err := runAuthLogout(newCmdWithCtx(), nil); err != nil {
		t.Errorf("second logout errored: %v", err)
	}
}

// TestAuthLogoutScoping: a plain logout removes only the current environment's
// token; --all removes them all.
func TestAuthLogoutScoping(t *testing.T) {
	const curEnv = "https://moose.armis.com"
	const otherEnv = "http://localhost:8001"
	setupAuthTest(t, curEnv) // current env resolves to curEnv via ARMIS_API_URL

	store := auth.NewTokenStore()
	for _, e := range []string{curEnv, otherEnv} {
		if err := store.Save(e, &auth.StoredToken{AccessToken: "a", RefreshToken: "r", TenantID: "t"}); err != nil {
			t.Fatal(err)
		}
	}

	// Plain logout clears only curEnv.
	logoutAll = false
	if err := runAuthLogout(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if got, _ := store.Load(curEnv); got != nil {
		t.Error("current env token should be cleared")
	}
	if got, _ := store.Load(otherEnv); got == nil {
		t.Error("other env token should survive a scoped logout")
	}

	// --all clears everything.
	logoutAll = true
	if err := runAuthLogout(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("logout --all: %v", err)
	}
	if got, _ := store.Load(otherEnv); got != nil {
		t.Error("--all should clear remaining tokens")
	}
}

// TestStoredTokenTakesPrecedence verifies the resolution order: a stored SSO
// token is used over env-var client credentials when no credential flags are set.
func TestStoredTokenTakesPrecedence(t *testing.T) {
	jwt := deviceJWT(tenant7, "alice@example.com", "admin", time.Now().Add(time.Hour).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setupAuthTest(t, srv.URL)

	store := auth.NewTokenStore()
	if err := store.Save(srv.URL, &auth.StoredToken{
		AccessToken: jwt, RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour),
		TenantID: tenant7, Subject: "alice@example.com", Issuer: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}

	// Env client credentials are present but should be ignored in favor of SSO.
	clientID = "env-client"
	clientSecret = "env-secret"

	provider, err := getAuthProvider(context.Background())
	if err != nil {
		t.Fatalf("getAuthProvider: %v", err)
	}
	if provider.AuthMethod() != auth.AuthMethodSSO {
		t.Errorf("AuthMethod = %q, want sso", provider.AuthMethod())
	}
}

func TestNoCredentialsErrorMentionsLogin(t *testing.T) {
	setupAuthTest(t, "https://moose.armis.com")
	// No stored token, no credentials.
	_, err := getAuthProvider(context.Background())
	if err == nil {
		t.Fatal("expected error with no credentials")
	}
	if !strings.Contains(err.Error(), "auth login") {
		t.Errorf("error %q should mention 'auth login'", err.Error())
	}
}

// TestShouldAutoLoginSSO pins the gating rules: SSO auto-login fires only when
// ARMIS_DEFAULT_AUTH_METHOD=SSO and no other credential is configured.
func TestShouldAutoLoginSSO(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		clientID string
		token    string
		explicit bool
		want     bool
	}{
		{name: "unset", env: "", want: false},
		{name: "sso, no creds", env: "SSO", want: true},
		{name: "sso lowercase", env: "sso", want: true},
		{name: "other value", env: "client-credentials", want: false},
		{name: "sso but client creds present", env: "sso", clientID: "id", want: false},
		{name: "sso but legacy token present", env: "sso", token: "tok", want: false},
		{name: "sso but explicit cred flags", env: "sso", explicit: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupAuthTest(t, "https://moose.armis.com")
			t.Setenv("ARMIS_DEFAULT_AUTH_METHOD", tt.env)
			clientID = tt.clientID
			token = tt.token
			credFlagsExplicit = tt.explicit

			if got := shouldAutoLoginSSO(); got != tt.want {
				t.Errorf("shouldAutoLoginSSO() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAutoLoginSSOTriggersDeviceFlow verifies that, with ARMIS_DEFAULT_AUTH_METHOD=SSO
// and no stored token or credentials, getAuthProvider runs the device flow,
// persists the token, and returns an SSO-backed provider.
func TestAutoLoginSSOTriggersDeviceFlow(t *testing.T) {
	jwt := deviceJWT(tenant7, "alice@example.com", "admin", time.Now().Add(time.Hour).Unix())
	var mu sync.Mutex
	tokenCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "dev-code",
				"user_code":                 "WDJB-MJHT",
				"verification_uri":          "https://moose.armis.com/oauth2/device/verify",
				"verification_uri_complete": "https://moose.armis.com/oauth2/device/verify?user_code=WDJB-MJHT",
				"expires_in":                900,
				"interval":                  1,
			})
		case "/oauth2/token":
			mu.Lock()
			tokenCalls++
			n := tokenCalls
			mu.Unlock()
			if n < 2 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": jwt, "token_type": "Bearer",
				"expires_in": 3600, "refresh_token": "refresh-7",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	setupAuthTest(t, srv.URL)
	t.Setenv("ARMIS_DEFAULT_AUTH_METHOD", "SSO")
	tenantID = tenant7 // device authorization requires a tenant

	provider, err := getAuthProvider(context.Background())
	if err != nil {
		t.Fatalf("getAuthProvider with SSO auto-login: %v", err)
	}
	if provider.AuthMethod() != auth.AuthMethodSSO {
		t.Errorf("AuthMethod = %q, want sso", provider.AuthMethod())
	}
	if stored, _ := auth.NewTokenStore().Load(srv.URL); stored == nil || stored.RefreshToken != "refresh-7" {
		t.Errorf("expected auto-login to persist token, got %+v", stored)
	}
}

func TestMain(m *testing.M) {
	// Ensure no test accidentally spawns a real browser: stub the opener to a
	// no-op (success) for the whole cmd test binary.
	auth.SetBrowserOpener(func(string) error { return nil })
	os.Exit(m.Run())
}
