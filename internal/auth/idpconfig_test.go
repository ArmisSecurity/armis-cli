package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// staticAuthHeader is a trivial AuthHeaderProvider for tests.
type staticAuthHeader struct {
	value string
	err   error
}

func (s staticAuthHeader) GetAuthorizationHeader(context.Context) (string, error) {
	return s.value, s.err
}

func sampleCreateReq() *IdpConfigCreateRequest {
	return &IdpConfigCreateRequest{
		TenantID:         "tenant-7",
		IdpType:          "okta",
		Issuer:           "https://example.okta.com",
		OIDCClientID:     "client-abc",
		OIDCClientSecret: "s3cr3t",
		GroupClaim:       "groups",
		GroupMapping:     map[string]string{"eng-admins": "admin", "eng": "developer"},
		EMAEnabled:       false,
		Enabled:          true,
	}
}

func TestIdpConfigClientCreateSuccess(t *testing.T) {
	var gotBody IdpConfigCreateRequest
	var gotAuth, gotMethod, gotPath, gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "tenant-7", "idp_type": "okta",
			"issuer": "https://example.okta.com", "oidc_client_id": "client-abc",
			"group_claim": "groups", "group_mapping": map[string]string{"eng-admins": "admin"},
			"ema_enabled": false, "enabled": true,
			"created_at": "2026-07-02T00:00:00Z", "updated_at": "2026-07-02T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, err := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Basic abc123"}, false)
	if err != nil {
		t.Fatalf("NewIdpConfigClient: %v", err)
	}

	resp, err := c.Create(context.Background(), sampleCreateReq())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resp.TenantID != "tenant-7" {
		t.Errorf("resp.TenantID = %q, want tenant-7", resp.TenantID)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/oauth2/idp-configs" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Basic abc123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	// The secret must be transmitted in the body exactly once.
	if gotBody.OIDCClientSecret != "s3cr3t" {
		t.Errorf("body secret = %q, want s3cr3t", gotBody.OIDCClientSecret)
	}
	if gotBody.GroupMapping["eng-admins"] != "admin" || gotBody.GroupMapping["eng"] != "developer" {
		t.Errorf("group_mapping = %v", gotBody.GroupMapping)
	}
	if gotBody.EMAEnabled {
		t.Error("ema_enabled should be sent false")
	}
}

func TestIdpConfigClientGetSuccess(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	var gotBodyLen int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBodyLen = len(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "tenant-7", "idp_type": "okta",
			"issuer": "https://example.okta.com", "oidc_client_id": "client-abc",
			"group_claim": "groups", "group_mapping": map[string]string{"eng-admins": "admin"},
			"ema_enabled": false, "enabled": true,
			"created_at": "2026-07-02T00:00:00Z", "updated_at": "2026-07-02T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Basic x"}, false)
	resp, err := c.Get(context.Background(), "tenant-7")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/api/v1/oauth2/idp-configs/tenant-7" {
		t.Errorf("path = %q", gotPath)
	}
	// A GET must carry no body and no Content-Type header.
	if gotBodyLen != 0 {
		t.Errorf("GET body length = %d, want 0", gotBodyLen)
	}
	if gotContentType != "" {
		t.Errorf("GET Content-Type = %q, want empty", gotContentType)
	}
	if resp.OIDCClientID != "client-abc" || resp.GroupMapping["eng-admins"] != "admin" {
		t.Errorf("unexpected response %+v", resp)
	}
}

func TestIdpConfigClientGetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "IdP configuration not found"})
	}))
	defer srv.Close()

	c, _ := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Basic x"}, false)
	_, err := c.Get(context.Background(), "tenant-7")
	var ce *IdpConfigError
	if !errors.As(err, &ce) || ce.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 IdpConfigError, got %v", err)
	}
}

func TestIdpConfigClientCreateConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"detail": "IdP configuration already exists for this tenant",
		})
	}))
	defer srv.Close()

	c, _ := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Basic x"}, false)
	_, err := c.Create(context.Background(), sampleCreateReq())
	if err == nil {
		t.Fatal("expected conflict error")
	}
	var ce *IdpConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *IdpConfigError", err)
	}
	if ce.StatusCode != http.StatusConflict {
		t.Errorf("StatusCode = %d, want 409", ce.StatusCode)
	}
	if ce.Detail == "" {
		t.Error("expected detail message")
	}
}

func TestIdpConfigClientUpdateSuccess(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id": "tenant-7", "idp_type": "okta",
			"issuer": "https://example.okta.com", "oidc_client_id": "client-abc",
			"group_claim": "groups", "group_mapping": map[string]string{},
			"ema_enabled": false, "enabled": true,
			"created_at": "2026-07-02T00:00:00Z", "updated_at": "2026-07-02T01:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Bearer jwt"}, false)
	secret := "rotated"
	_, err := c.Update(context.Background(), "tenant-7", &IdpConfigUpdateRequest{
		OIDCClientSecret: &secret,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/api/v1/oauth2/idp-configs/tenant-7" {
		t.Errorf("path = %q", gotPath)
	}
	// Omitted (nil) fields must not appear in the update body.
	if _, present := gotBody["issuer"]; present {
		t.Error("nil issuer should be omitted from update body")
	}
	if gotBody["oidc_client_secret"] != "rotated" {
		t.Errorf("secret in body = %v", gotBody["oidc_client_secret"])
	}
}

func TestIdpConfigClientUpdateNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "IdP configuration not found"})
	}))
	defer srv.Close()

	c, _ := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Basic x"}, false)
	_, err := c.Update(context.Background(), "tenant-7", &IdpConfigUpdateRequest{})
	var ce *IdpConfigError
	if !errors.As(err, &ce) || ce.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 IdpConfigError, got %v", err)
	}
}

func TestIdpConfigClientValidationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		// FastAPI list-shaped validation error.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": []map[string]any{
				{"loc": []any{"body", "issuer"}, "msg": "field required", "type": "value_error.missing"},
			},
		})
	}))
	defer srv.Close()

	c, _ := NewIdpConfigClient(srv.URL, staticAuthHeader{value: "Basic x"}, false)
	_, err := c.Create(context.Background(), sampleCreateReq())
	var ce *IdpConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *IdpConfigError", err)
	}
	if ce.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("StatusCode = %d, want 422", ce.StatusCode)
	}
	if ce.Detail != "issuer: field required" {
		t.Errorf("Detail = %q, want 'issuer: field required'", ce.Detail)
	}
}

func TestNewIdpConfigClientRejectsInsecureURL(t *testing.T) {
	_, err := NewIdpConfigClient("http://example.com", staticAuthHeader{value: "x"}, false)
	if err == nil {
		t.Fatal("expected HTTPS-required error for non-localhost http URL")
	}
}

func TestNewIdpConfigClientAllowsLocalhost(t *testing.T) {
	if _, err := NewIdpConfigClient("http://localhost:8001", staticAuthHeader{value: "x"}, false); err != nil {
		t.Errorf("localhost http should be allowed: %v", err)
	}
}
