// Package auth provides authentication for the Armis API.
// This file implements the OAuth2 Device Authorization Grant (RFC 8628) client
// used by `armis-cli auth login`. The server side is the Moose OAuth2
// authorization server (PPSC-1033), mounted at the issuer root.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
)

const (
	// DefaultDeviceClientID is the public client_id armis-cli identifies as in
	// the device flow. The CLI is a public client (no secret); security comes
	// from the device_code and refresh-token rotation, not this identifier.
	DefaultDeviceClientID = "armis-cli"

	// Grant types (RFC 8628 §3.4 / RFC 6749 §6).
	grantTypeDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	grantTypeRefreshToken = "refresh_token"

	// deviceEndpointPath / tokenEndpointPath are root-mounted on the issuer per
	// RFC 8628 / the backend router (api_controller/oauth2/router.py).
	deviceEndpointPath = "/oauth2/device"
	tokenEndpointPath  = "/oauth2/token" // #nosec G101 -- URL path, not a credential

	// Polling guardrails so a misbehaving server cannot make us hammer it.
	minPollInterval     = 1 * time.Second
	defaultPollInterval = 5 * time.Second
	maxPollInterval     = 60 * time.Second
)

// DeviceAuthorization is the RFC 8628 §3.2 device authorization response.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenResponse mirrors the backend TokenResponse (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

// oauthErrorResponse is the RFC 6749 §5.2 / RFC 8628 §3.5 error body.
type oauthErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthError is a typed OAuth2 protocol error so callers can branch on the code
// (e.g. authorization_pending vs. expired_token).
type OAuthError struct {
	Code        string
	Description string
	StatusCode  int
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// OAuth2 error codes we branch on (RFC 8628 §3.5).
const (
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errExpiredToken         = "expired_token"
	errAccessDenied         = "access_denied"
	errInvalidGrant         = "invalid_grant"
)

// DeviceClient talks to the OAuth2 device + token endpoints on the issuer.
type DeviceClient struct {
	baseURL    string
	httpClient *http.Client
	debug      bool
}

// NewDeviceClient creates a device-flow client for the given issuer base URL.
// HTTPS is enforced for non-localhost hosts and redirects are disabled, matching
// the hardening of the client-credentials AuthClient.
func NewDeviceClient(baseURL string, debug bool) (*DeviceClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("API base URL is required for device authentication")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// armis:ignore cwe:918 reason:baseURL is operator-controlled (ARMIS_API_URL) or the hardcoded RegionalBaseURL allowlist; this block IS the SSRF guard (rejects non-HTTPS non-localhost hosts)
	if parsedURL.Scheme != schemeHTTPS {
		host := parsedURL.Hostname()
		if host != "localhost" && host != "127.0.0.1" {
			return nil, fmt.Errorf("HTTPS required for non-localhost URLs")
		}
	}

	return &DeviceClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Honor OS proxy config (WinINET/PAC), matching AuthClient.
			Transport: httpclient.ProxyAwareTransport(),
			// Never follow redirects: the token endpoint carries the device_code
			// and refresh_token, which must not be replayed to a redirect target.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		debug: debug,
	}, nil
}

// RequestDeviceCode performs the RFC 8628 §3.1 device authorization request.
// tenantID identifies which Armis tenant to authenticate against and is required
// by the authorization server.
func (c *DeviceClient) RequestDeviceCode(ctx context.Context, clientID, tenantID, scope string) (*DeviceAuthorization, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required to start the device authorization")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("tenant_id", tenantID)
	if scope != "" {
		form.Set("scope", scope)
	}

	body, status, err := c.postForm(ctx, deviceEndpointPath, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, c.parseError(body, status)
	}

	var da DeviceAuthorization
	if err := json.Unmarshal(body, &da); err != nil {
		return nil, fmt.Errorf("failed to parse device authorization response: %w", err)
	}
	if da.DeviceCode == "" || da.UserCode == "" {
		return nil, fmt.Errorf("device authorization response missing required fields")
	}
	return &da, nil
}

// PollToken polls the token endpoint until the user approves, the device code
// expires, or the request is denied (RFC 8628 §3.4/§3.5). It honors the server's
// interval and backs off on slow_down. The provided context bounds the total
// wait (callers should set a deadline ~ the device code's expires_in).
func (c *DeviceClient) PollToken(ctx context.Context, deviceCode, clientID string, intervalSeconds int) (*StoredToken, error) {
	interval := time.Duration(intervalSeconds) * time.Second
	if interval < minPollInterval {
		interval = defaultPollInterval
	}
	if interval > maxPollInterval {
		interval = maxPollInterval
	}

	for {
		// Wait first: the spec requires waiting `interval` between polls, and the
		// authorization is never approved instantly anyway.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for authorization: %w", ctx.Err())
		case <-time.After(interval):
		}

		tok, err := c.exchangeDeviceCode(ctx, deviceCode, clientID)
		if err == nil {
			return tok, nil
		}

		var oerr *OAuthError
		if !asOAuthError(err, &oerr) {
			return nil, err // transport / parse error — give up
		}
		switch oerr.Code {
		case errAuthorizationPending:
			continue
		case errSlowDown:
			interval += 5 * time.Second
			if interval > maxPollInterval {
				interval = maxPollInterval
			}
			continue
		case errExpiredToken:
			return nil, fmt.Errorf("the login request expired before it was approved; run 'armis-cli auth login' again")
		case errAccessDenied:
			return nil, fmt.Errorf("the login request was denied")
		default:
			return nil, oerr
		}
	}
}

// exchangeDeviceCode does a single device_code token exchange.
func (c *DeviceClient) exchangeDeviceCode(ctx context.Context, deviceCode, clientID string) (*StoredToken, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeDeviceCode)
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)
	return c.tokenRequest(ctx, form, clientID)
}

// Refresh exchanges a refresh token for a fresh access/refresh token pair
// (RFC 6749 §6). The backend rotates the refresh token, so the returned
// StoredToken carries a new RefreshToken that callers must persist.
func (c *DeviceClient) Refresh(ctx context.Context, refreshToken, clientID string) (*StoredToken, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeRefreshToken)
	form.Set("refresh_token", refreshToken)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	return c.tokenRequest(ctx, form, clientID)
}

// tokenRequest posts to the token endpoint and converts a success response into
// a StoredToken, deriving identity fields from the access-token claims.
func (c *DeviceClient) tokenRequest(ctx context.Context, form url.Values, clientID string) (*StoredToken, error) {
	body, status, err := c.postForm(ctx, tokenEndpointPath, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, c.parseError(body, status)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	claims, err := parseAccessTokenClaims(tr.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	// Prefer the server-provided expires_in; fall back to the token's exp claim.
	expiresAt := claims.ExpiresAt
	if tr.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	return &StoredToken{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    expiresAt,
		TenantID:     claims.TenantID,
		Subject:      claims.Subject,
		Role:         claims.Role,
		Issuer:       claims.Issuer,
		Region:       claims.Region,
		ClientID:     clientID,
	}, nil
}

// postForm issues a form-encoded POST and returns the body and status code.
func (c *DeviceClient) postForm(ctx context.Context, path string, form url.Values) ([]byte, int, error) {
	endpoint := c.baseURL + path
	// armis:ignore cwe:918 reason:baseURL validated by NewDeviceClient (HTTPS enforced for non-localhost); path is a hardcoded constant
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // endpoint built from validated config, not user input
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", annotateTransportError(err))
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// parseError converts an OAuth2 error body into a typed *OAuthError. When the
// body is not the expected JSON shape it falls back to a status-based message.
func (c *DeviceClient) parseError(body []byte, status int) error {
	var oe oauthErrorResponse
	if err := json.Unmarshal(body, &oe); err == nil && oe.ErrorCode != "" {
		return &OAuthError{Code: oe.ErrorCode, Description: oe.ErrorDescription, StatusCode: status}
	}
	return &OAuthError{Code: "server_error", Description: fmt.Sprintf("unexpected response (status %d)", status), StatusCode: status}
}

// asOAuthError is errors.As specialized for *OAuthError.
func asOAuthError(err error, target **OAuthError) bool {
	for err != nil {
		if oe, ok := err.(*OAuthError); ok { //nolint:errorlint // direct type assert is intentional here
			*target = oe
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// accessTokenClaims are the Moose RS256 access-token claims (token_issuer.py).
// This is distinct from jwtClaims (client-credentials path), which reads the
// VIPR customer_id claim; the device-flow token uses tenant_id/sub/role.
type accessTokenClaims struct {
	TenantID  string
	Subject   string
	Role      string
	Issuer    string
	Region    string
	ExpiresAt time.Time
}

// parseAccessTokenClaims decodes (without verifying) the JWT payload. Signature
// verification is delegated to the backend, which validates every API request;
// the CLI only needs the claims for local display and refresh scheduling.
//
// armis:ignore cwe:287 reason:JWT signature verification delegated to server; CLI only extracts claims for caching/display
// armis:ignore cwe:327 reason:no cryptographic operations; base64-decodes JWT payload for claim extraction only
func parseAccessTokenClaims(token string) (*accessTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var data struct {
		TenantID string  `json:"tenant_id"`
		Sub      string  `json:"sub"`
		Role     string  `json:"role"`
		Iss      string  `json:"iss"`
		Region   string  `json:"region"`
		Exp      float64 `json:"exp"` // float64 tolerates fractional timestamps
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	var expiresAt time.Time
	if data.Exp > 0 {
		expiresAt = time.Unix(int64(data.Exp), 0)
	}
	return &accessTokenClaims{
		TenantID:  data.TenantID,
		Subject:   data.Sub,
		Role:      data.Role,
		Issuer:    data.Iss,
		Region:    data.Region,
		ExpiresAt: expiresAt,
	}, nil
}
