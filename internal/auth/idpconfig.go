// Package auth provides authentication for the Armis API.
// This file implements a client for the tenant↔IdP configuration admin API
// (PPSC-1035), used by `armis-cli auth setup` to register a tenant's IdP with
// the Moose OAuth2 authorization server. The endpoints are mounted under
// /api/v1/oauth2/idp-configs (api_controller/oauth2/admin_router.py).
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
)

// idpConfigsPath is the collection endpoint, relative to the API base URL.
const idpConfigsPath = "/api/v1/oauth2/idp-configs"

// IdpConfigCreateRequest mirrors the backend IdpConfigCreateRequest
// (api_controller/oauth2/models.py). The plaintext oidc_client_secret is sent
// once on the wire and stored server-side in Secrets Manager; it is never
// returned in a response.
type IdpConfigCreateRequest struct {
	TenantID         string            `json:"tenant_id"`
	IdpType          string            `json:"idp_type"`
	Issuer           string            `json:"issuer"`
	OIDCClientID     string            `json:"oidc_client_id"`
	OIDCClientSecret string            `json:"oidc_client_secret"` //nolint:gosec // G117: request field carrying the plaintext secret for the single registration call
	GroupClaim       string            `json:"group_claim"`
	GroupMapping     map[string]string `json:"group_mapping"`
	EMAEnabled       bool              `json:"ema_enabled"`
	Enabled          bool              `json:"enabled"`
}

// IdpConfigUpdateRequest mirrors the backend IdpConfigUpdateRequest: every field
// is optional and only provided (non-nil) fields are changed. Supplying
// oidc_client_secret rotates the secret. tenant_id is not part of the body —
// it addresses the resource via the URL path.
type IdpConfigUpdateRequest struct {
	IdpType          *string           `json:"idp_type,omitempty"`
	Issuer           *string           `json:"issuer,omitempty"`
	OIDCClientID     *string           `json:"oidc_client_id,omitempty"`
	OIDCClientSecret *string           `json:"oidc_client_secret,omitempty"` //nolint:gosec // G117: request field carrying the plaintext secret for a rotation call
	GroupClaim       *string           `json:"group_claim,omitempty"`
	GroupMapping     map[string]string `json:"group_mapping,omitempty"`
	EMAEnabled       *bool             `json:"ema_enabled,omitempty"`
	Enabled          *bool             `json:"enabled,omitempty"`
}

// IdpConfigResponse mirrors the backend IdpConfigResponse. It deliberately omits
// the OIDC client secret and its Secrets Manager ARN.
type IdpConfigResponse struct {
	TenantID     string            `json:"tenant_id"`
	IdpType      string            `json:"idp_type"`
	Issuer       string            `json:"issuer"`
	OIDCClientID string            `json:"oidc_client_id"`
	GroupClaim   string            `json:"group_claim"`
	GroupMapping map[string]string `json:"group_mapping"`
	EMAEnabled   bool              `json:"ema_enabled"`
	Enabled      bool              `json:"enabled"`
	CreatedAt    string            `json:"created_at"`
	UpdatedAt    string            `json:"updated_at"`
}

// IdpConfigError is a typed HTTP error from the admin API. It carries the status
// code and the FastAPI {"detail": "..."} message so callers can branch on the
// status (e.g. 409 → offer an update) and show the server's explanation.
type IdpConfigError struct {
	StatusCode int
	Detail     string
}

func (e *IdpConfigError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s (status %d)", e.Detail, e.StatusCode)
	}
	return fmt.Sprintf("unexpected response (status %d)", e.StatusCode)
}

// IdpConfigClient talks to the tenant↔IdP configuration admin API. It reuses an
// AuthHeaderProvider for the Authorization header, so it works with whichever
// credential path the CLI resolved (Basic API token or a Bearer JWT).
type IdpConfigClient struct {
	baseURL    string
	authHeader AuthHeaderProvider
	httpClient *http.Client
	debug      bool
}

// AuthHeaderProvider supplies the Authorization header for admin API requests.
// It matches the api.AuthHeaderProvider contract; *AuthProvider satisfies both.
type AuthHeaderProvider interface {
	GetAuthorizationHeader(ctx context.Context) (string, error)
}

// NewIdpConfigClient creates a client for the admin API at baseURL. HTTPS is
// enforced for non-localhost hosts and redirects are disabled, matching the
// hardening of DeviceClient/AuthClient — the request carries the admin's
// credential and must not be replayed to a redirect target.
func NewIdpConfigClient(baseURL string, authHeader AuthHeaderProvider, debug bool) (*IdpConfigClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("API base URL is required to register an IdP configuration")
	}
	if authHeader == nil {
		return nil, fmt.Errorf("an authorization provider is required")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// armis:ignore cwe:918 reason:baseURL is operator-controlled (ARMIS_API_URL) or the hardcoded RegionalBaseURL allowlist; this block IS the SSRF guard (rejects non-HTTPS non-localhost hosts)
	if err := requireSecureBaseURL(parsedURL); err != nil {
		return nil, err
	}

	return &IdpConfigClient{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		authHeader: authHeader,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: httpclient.ProxyAwareTransport(),
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		debug: debug,
	}, nil
}

// Get fetches an existing tenant's IdP configuration (GET /{tenant_id}). A 404 is
// returned as an *IdpConfigError with StatusCode 404 so the caller can treat
// "not configured yet" distinctly from a transport or authorization failure. The
// response never carries the OIDC client secret.
func (c *IdpConfigClient) Get(ctx context.Context, tenantID string) (*IdpConfigResponse, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required to fetch an IdP configuration")
	}
	path := idpConfigsPath + "/" + url.PathEscape(tenantID)
	return c.send(ctx, http.MethodGet, path, nil, http.StatusOK)
}

// Create registers a new IdP configuration (POST). A 409 is returned as an
// *IdpConfigError with StatusCode 409 so the caller can offer to update instead.
func (c *IdpConfigClient) Create(ctx context.Context, req *IdpConfigCreateRequest) (*IdpConfigResponse, error) {
	return c.send(ctx, http.MethodPost, idpConfigsPath, req, http.StatusCreated)
}

// Update replaces (rotates) an existing tenant's IdP configuration
// (PUT /{tenant_id}). Supplying OIDCClientSecret rotates the stored secret.
func (c *IdpConfigClient) Update(ctx context.Context, tenantID string, req *IdpConfigUpdateRequest) (*IdpConfigResponse, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required to update an IdP configuration")
	}
	path := idpConfigsPath + "/" + url.PathEscape(tenantID)
	return c.send(ctx, http.MethodPut, path, req, http.StatusOK)
}

// send marshals body to JSON, issues the request with the Authorization header,
// and decodes a success response (wantStatus) into an IdpConfigResponse. Any
// other status becomes an *IdpConfigError carrying the parsed {"detail": ...}.
func (c *IdpConfigClient) send(ctx context.Context, method, path string, body any, wantStatus int) (*IdpConfigResponse, error) {
	// GET requests carry no body; only marshal and set Content-Type when there is
	// one, so a read never sends a stray Content-Type header.
	var reqBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request: %w", err)
		}
		reqBody = bytes.NewReader(payload)
	}

	authz, err := c.authHeader.GetAuthorizationHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve credentials: %w", err)
	}

	endpoint := c.baseURL + path
	// armis:ignore cwe:918 reason:baseURL validated by NewIdpConfigClient (HTTPS enforced for non-localhost); path is built from a hardcoded constant plus a URL-escaped tenant id
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)
	if reqBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq) //nolint:gosec // endpoint built from validated config, not user input
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", annotateTransportError(err))
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != wantStatus {
		return nil, parseIdpConfigError(respBody, resp.StatusCode)
	}

	var out IdpConfigResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &out, nil
}

// parseIdpConfigError extracts the FastAPI {"detail": "..."} message. The detail
// field may be a plain string or, for 422 validation errors, a list of error
// objects; both are rendered into a readable message.
func parseIdpConfigError(body []byte, status int) *IdpConfigError {
	var asString struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &asString); err == nil && asString.Detail != "" {
		return &IdpConfigError{StatusCode: status, Detail: asString.Detail}
	}

	// 422 validation errors carry a list of {loc, msg, type} objects.
	var asList struct {
		Detail []struct {
			Loc []any  `json:"loc"`
			Msg string `json:"msg"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(body, &asList); err == nil && len(asList.Detail) > 0 {
		parts := make([]string, 0, len(asList.Detail))
		for _, d := range asList.Detail {
			field := lastLocField(d.Loc)
			if field != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", field, d.Msg))
			} else {
				parts = append(parts, d.Msg)
			}
		}
		return &IdpConfigError{StatusCode: status, Detail: strings.Join(parts, "; ")}
	}

	return &IdpConfigError{StatusCode: status}
}

// lastLocField returns the last string element of a FastAPI error "loc" array,
// which names the offending field (e.g. ["body", "issuer"] → "issuer").
func lastLocField(loc []any) string {
	for i := len(loc) - 1; i >= 0; i-- {
		if s, ok := loc[i].(string); ok && s != "body" {
			return s
		}
	}
	return ""
}
