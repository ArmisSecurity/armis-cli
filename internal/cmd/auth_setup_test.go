package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// setupSetupTest isolates global state used by `auth setup` and points the CLI
// at the mock server via a legacy API token (Basic auth), so getAuthProvider
// resolves without a stored session.
func setupSetupTest(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	orig := struct {
		clientID, clientSecret, token, tenantID, cfg string
		update, yes                                  bool
	}{clientID, clientSecret, token, tenantID, setupConfigInput, setupUpdate, setupYes}
	t.Cleanup(func() {
		clientID, clientSecret, token, tenantID = orig.clientID, orig.clientSecret, orig.token, orig.tenantID
		setupConfigInput, setupUpdate, setupYes = orig.cfg, orig.update, orig.yes
		credFlagsExplicit = false
	})

	clientID, clientSecret = "", ""
	token = "admin-token"    // Basic auth path
	tenantID = "acme"        // Basic auth requires a tenant for AuthProvider construction
	credFlagsExplicit = true // force the token path (skip stored-session lookup)
	setupConfigInput, setupUpdate, setupYes = "", false, false

	t.Setenv("ARMIS_API_URL", serverURL)
}

func validConfigJSON(tenant string) string {
	b, _ := json.Marshal(map[string]any{
		"tenant_id":          tenant,
		"idp_type":           "okta",
		"issuer":             "https://acme.okta.com",
		"oidc_client_id":     "client-abc",
		"oidc_client_secret": "s3cr3t",
		"group_claim":        "groups",
		// role → [groups]; several groups may grant the same role.
		"group_mapping": map[string][]string{
			"admin":     {"eng-admins"},
			"developer": {"core-developers", "contract-developers"},
		},
	})
	return string(b)
}

func TestAuthSetupCreateSuccess(t *testing.T) {
	var gotMethod, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "acme", "idp_type": "okta", "issuer": "https://acme.okta.com",
			"oidc_client_id": "client-abc", "group_claim": "groups",
			"group_mapping": map[string]string{}, "ema_enabled": false, "enabled": true,
			"created_at": "t", "updated_at": "t",
		})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)
	setupConfigInput = validConfigJSON("acme")
	setupYes = true

	if err := runAuthSetup(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("runAuthSetup: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Basic admin-token" {
		t.Errorf("Authorization = %q, want Basic admin-token", gotAuth)
	}
	if gotBody["ema_enabled"] != false {
		t.Errorf("ema_enabled = %v, want false", gotBody["ema_enabled"])
	}
	// The role→[groups] input is flattened to the backend's group→role map;
	// several groups can share a role.
	gm, _ := gotBody["group_mapping"].(map[string]any)
	if gm["eng-admins"] != "admin" ||
		gm["core-developers"] != "developer" ||
		gm["contract-developers"] != "developer" {
		t.Errorf("group_mapping = %v", gm)
	}
}

// A scripted create (--yes, non-interactive) that hits a 409 must NOT silently
// overwrite the existing config: it should only POST, then error, pointing the
// user at --update.
func TestAuthSetupConflictWithYesDoesNotOverwrite(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "already exists"})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)
	setupConfigInput = validConfigJSON("acme")
	setupYes = true // non-interactive: 409 must error, not fall through to PUT

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "--update") {
		t.Fatalf("expected --update error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(methods) != 1 || methods[0] != http.MethodPost {
		t.Errorf("expected a single POST (no PUT), got %v", methods)
	}
}

func TestAuthSetupUpdateFlagUsesPut(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "acme", "idp_type": "okta", "issuer": "https://acme.okta.com",
			"oidc_client_id": "client-abc", "group_claim": "groups",
			"group_mapping": map[string]string{}, "ema_enabled": false, "enabled": true,
			"created_at": "t", "updated_at": "t",
		})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)
	setupConfigInput = validConfigJSON("acme")
	setupUpdate = true
	setupYes = true

	if err := runAuthSetup(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("runAuthSetup: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/api/v1/oauth2/idp-configs/acme" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestAuthSetupConflictWithoutUpdateErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "already exists"})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)
	setupConfigInput = validConfigJSON("acme")
	setupYes = true // no --update, non-interactive → should error, not silently PUT

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil {
		t.Fatal("expected error on conflict without --update")
	}
	if !strings.Contains(err.Error(), "--update") {
		t.Errorf("error %q should suggest --update", err.Error())
	}
}

func TestAuthSetupValidationErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": []map[string]any{
				{"loc": []any{"body", "issuer"}, "msg": "field required"},
			},
		})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)
	setupConfigInput = validConfigJSON("acme")
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil {
		t.Fatal("expected 422 error")
	}
	if !strings.Contains(err.Error(), "issuer: field required") {
		t.Errorf("error %q should carry the server detail", err.Error())
	}
}

func TestAuthSetupRejectsUnknownRole(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	setupConfigInput = `{"tenant_id":"acme","idp_type":"okta","issuer":"https://acme.okta.com","oidc_client_id":"c","oidc_client_secret":"s","group_mapping":{"superuser":["eng"]}}`
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil {
		t.Fatal("expected error for unrecognized role")
	}
	if !strings.Contains(err.Error(), "unrecognized role") {
		t.Errorf("error %q should reject the bad role", err.Error())
	}
}

// A group listed under two roles is ambiguous and must be rejected.
func TestAuthSetupRejectsGroupInTwoRoles(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	setupConfigInput = `{"tenant_id":"acme","idp_type":"okta","issuer":"https://acme.okta.com","oidc_client_id":"c","oidc_client_secret":"s","group_mapping":{"admin":["eng"],"developer":["eng"]}}`
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "only one role") {
		t.Fatalf("expected single-role conflict error, got %v", err)
	}
}

func TestAuthSetupRequiresMappings(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	setupConfigInput = `{"tenant_id":"acme","idp_type":"okta","issuer":"https://acme.okta.com","oidc_client_id":"c","oidc_client_secret":"s","group_mapping":{}}`
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "at least one group") {
		t.Fatalf("expected 'at least one group' error, got %v", err)
	}
}

func TestAuthSetupMissingRequiredField(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	// Missing issuer and oidc_client_secret.
	setupConfigInput = `{"tenant_id":"acme","idp_type":"okta","oidc_client_id":"c","group_mapping":{"admin":["eng"]}}`
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "missing required field") {
		t.Fatalf("expected missing-field error, got %v", err)
	}
}

func TestAuthSetupRejectsUnknownJSONField(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	setupConfigInput = `{"tenant_id":"acme","typpo":"x"}`
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "invalid config JSON") {
		t.Fatalf("expected invalid-config error, got %v", err)
	}
}

func TestSameMapping(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]string
		want bool
	}{
		{"both empty", map[string]string{}, map[string]string{}, true},
		{"identical", map[string]string{"eng": "developer", "ops": "admin"}, map[string]string{"ops": "admin", "eng": "developer"}, true},
		{"different length", map[string]string{"eng": "developer"}, map[string]string{"eng": "developer", "ops": "admin"}, false},
		{"different role", map[string]string{"eng": "developer"}, map[string]string{"eng": "admin"}, false},
		{"different group", map[string]string{"eng": "developer"}, map[string]string{"dev": "developer"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameMapping(tc.a, tc.b); got != tc.want {
				t.Errorf("sameMapping = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthSetupRejectsTrailingContent(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	setupConfigInput = validConfigJSON("acme") + "garbage"
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "trailing content") {
		t.Fatalf("expected trailing-content error, got %v", err)
	}
}

func TestAuthSetupRejectsOversizeConfig(t *testing.T) {
	setupSetupTest(t, "https://moose.armis.com")
	dir := t.TempDir()
	path := dir + "/big.json"
	if err := os.WriteFile(path, []byte(strings.Repeat("a", maxConfigBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	setupConfigInput = path
	setupYes = true

	err := runAuthSetup(newCmdWithCtx(), nil)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected oversize error, got %v", err)
	}
}

func TestAuthSetupConfigFromFile(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "acme", "idp_type": "okta", "issuer": "https://acme.okta.com",
			"oidc_client_id": "client-abc", "group_claim": "groups",
			"group_mapping": map[string]string{}, "ema_enabled": false, "enabled": true,
			"created_at": "t", "updated_at": "t",
		})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)
	dir := t.TempDir()
	path := dir + "/idp.json"
	if err := os.WriteFile(path, []byte(validConfigJSON("acme")), 0o600); err != nil {
		t.Fatal(err)
	}
	setupConfigInput = path
	setupYes = true

	if err := runAuthSetup(newCmdWithCtx(), nil); err != nil {
		t.Fatalf("runAuthSetup: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
}

// Regression test for PPSC-1230: the post-setup hint must print the
// credential-derived tenant ID (from the admin's own credentials), not the IdP
// config's tenant slug — the two can differ (e.g. a human-readable slug like
// "acme-slug" typed into the form vs. the real tenant ID tied to the admin's
// credentials).
func TestAuthSetupPostSetupHintUsesDetectedTenant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "acme-slug", "idp_type": "okta", "issuer": "https://acme.okta.com",
			"oidc_client_id": "client-abc", "group_claim": "groups",
			"group_mapping": map[string]string{}, "ema_enabled": false, "enabled": true,
			"created_at": "t", "updated_at": "t",
		})
	}))
	defer srv.Close()

	setupSetupTest(t, srv.URL)                      // credential tenant (Basic auth) is "acme"
	setupConfigInput = validConfigJSON("acme-slug") // IdP config's tenant slug differs
	setupYes = true

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	err := runAuthSetup(newCmdWithCtx(), nil)
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if err != nil {
		t.Fatalf("runAuthSetup: %v", err)
	}
	if !strings.Contains(out, "ARMIS_TENANT_ID=acme\n") {
		t.Errorf("hint should print the credential-derived tenant ID: %q", out)
	}
	if strings.Contains(out, "ARMIS_TENANT_ID=acme-slug") {
		t.Errorf("hint must not print the IdP config's tenant slug: %q", out)
	}
}

// detectIdentity should pull the tenant (customer_id) and region claim straight
// from the client-credentials JWT, so `auth setup` can seed the tenant prompt
// and the post-setup hint without the admin supplying either.
func TestDetectIdentity(t *testing.T) {
	region = ""
	t.Setenv("ARMIS_API_URL", "")
	p := newRegionAuthProvider(t, "eu1")

	tenant, reg := detectIdentity(context.Background(), p)
	if tenant != "customer-123" {
		t.Errorf("tenant = %q, want customer-123", tenant)
	}
	if reg != "eu1" {
		t.Errorf("region = %q, want eu1", reg)
	}
}

func TestIsNonDefaultRegion(t *testing.T) {
	cases := map[string]bool{
		"":    false, // default host
		"us1": false, // primary data plane
		"au1": false, // no dedicated data plane yet — falls back to primary
		"eu1": true,  // dedicated EU data plane
	}
	for region, want := range cases {
		if got := isNonDefaultRegion(region); got != want {
			t.Errorf("isNonDefaultRegion(%q) = %v, want %v", region, got, want)
		}
	}
}

// The post-setup hint tells the admin which env vars to deploy. ARMIS_REGION is
// emitted only for a non-default region; the default region omits it.
func TestPrintPostSetupHint(t *testing.T) {
	capture := func(f func()) string {
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		f()
		_ = w.Close()
		os.Stderr = old
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		return buf.String()
	}

	t.Run("default region omits ARMIS_REGION", func(t *testing.T) {
		orig := setupDetectedRegion
		t.Cleanup(func() { setupDetectedRegion = orig })
		setupDetectedRegion = ""

		out := capture(func() { printPostSetupHint("acme") })
		if !strings.Contains(out, "ARMIS_TENANT_ID=acme") {
			t.Errorf("missing tenant env var: %q", out)
		}
		if !strings.Contains(out, "ARMIS_DEFAULT_AUTH_METHOD=SSO") {
			t.Errorf("missing auth-method env var: %q", out)
		}
		if strings.Contains(out, "ARMIS_REGION") {
			t.Errorf("default region should not emit ARMIS_REGION: %q", out)
		}
	})

	t.Run("non-default region emits ARMIS_REGION", func(t *testing.T) {
		orig := setupDetectedRegion
		t.Cleanup(func() { setupDetectedRegion = orig })
		setupDetectedRegion = "eu1"

		out := capture(func() { printPostSetupHint("acme") })
		if !strings.Contains(out, "ARMIS_REGION=eu1") {
			t.Errorf("missing ARMIS_REGION=eu1: %q", out)
		}
	})
}
