package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// maxResponseSize limits auth response body to prevent memory exhaustion attacks
	maxResponseSize = 1 << 20 // 1MB

	// ProductionBaseURL is the default Armis API endpoint (US region / primary).
	ProductionBaseURL = "https://moose.armis.com"
)

// RegionalBaseURL returns the Armis API base URL for the given region code.
//
// The data plane (/api/v1/ingest/*) is physically region-pinned: a JWT issued
// for one region is rejected by another region's endpoint with a 401. The auth
// endpoint (/api/v1/auth/token) auto-discovers the region server-side, so the
// 401 only surfaces on upload — which is why the base URL must encode the region.
//
// Region codes are the values issued in the JWT "region" claim (us1, eu1, au1).
// There are currently two production data planes:
//   - us1 (primary) -> https://moose.armis.com
//   - eu1           -> https://eu.moose.armis.com
//
// au1 is a valid auth region but has no dedicated data plane yet, so it
// falls through to the primary host rather than a fabricated one. Unknown or
// empty regions also fall back to the primary host, so callers may pass an
// unvalidated flag/env value directly. The explicit allowlist (rather than
// interpolating the region into the host) prevents an attacker-controlled
// region from redirecting credentials to an arbitrary host (CWE-918).
func RegionalBaseURL(region string) string {
	switch region {
	case "eu1":
		return "https://eu.moose.armis.com"
	default:
		// "", "us1", "au1", and anything unrecognized resolve to the primary host.
		return ProductionBaseURL
	}
}

// AuthError represents an authentication failure with HTTP status context.
// This allows callers to distinguish between different failure modes
// (e.g., invalid credentials vs. region-specific rejection vs. server error).
type AuthError struct {
	StatusCode int
	Message    string
}

func (e *AuthError) Error() string { return e.Message }

// AuthClient handles authentication with an external auth service.
type AuthClient struct {
	baseURL    string
	httpClient *http.Client
	debug      bool
}

// NewAuthClient creates a new authentication client for the given base URL.
// The base URL must be a valid HTTPS URL (HTTP allowed only for localhost).
// If debug is true, authentication failures will log detailed error information.
func NewAuthClient(baseURL string, debug bool) (*AuthClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("API base URL is required for authentication")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// armis:ignore cwe:522 reason:this code IS the credential protection check (HTTPS enforcement for non-localhost)
	if parsedURL.Scheme != "https" {
		host := parsedURL.Hostname()
		if host != "localhost" && host != "127.0.0.1" {
			return nil, fmt.Errorf("HTTPS required for non-localhost URLs")
		}
	}

	return &AuthClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Disable redirects to prevent leaking client credentials (CWE-601).
			// On 307/308 redirects, Go re-sends the POST body to the redirect target.
			// The auth endpoint should never redirect; if it does, return the response as-is.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		debug: debug,
	}, nil
}

// authRequest is the request body for the authenticate endpoint.
type authRequest struct {
	ClientID     string  `json:"client_id"`
	ClientSecret string  `json:"client_secret"`    //nolint:gosec // G117: This is a JSON field name for auth request, not a secret value
	Region       *string `json:"region,omitempty"` // Optional region hint from cache
}

// authResponse is the response from the authenticate endpoint.
type authResponse struct {
	Token  string `json:"token"`
	Region string `json:"region,omitempty"` // Discovered region for caching
	Error  string `json:"error,omitempty"`
}

// AuthResult contains the authentication response with token and discovered region.
type AuthResult struct {
	Token  string
	Region string
}

// Authenticate exchanges client credentials for a JWT token.
// Calls POST /api/v1/auth/token with client_id, client_secret, and optional region hint.
// Returns the token and the discovered/confirmed region for caching.
func (c *AuthClient) Authenticate(ctx context.Context, clientID, clientSecret string, regionHint *string) (*AuthResult, error) {
	// armis:ignore cwe:522 reason:CLI must marshal credentials to authenticate; sent over HTTPS only
	reqBody := authRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Region:       regionHint,
	}

	// armis:ignore cwe:522 cwe:770 reason:marshaling credentials is intentional for the auth token endpoint; sent over HTTPS; bounded by caller input
	jsonBody, err := json.Marshal(reqBody) //nolint:gosec // G117: ClientSecret is a credential field; marshaling is intentional for the auth token request
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	authEndpoint := c.baseURL + "/api/v1/auth/token"
	// armis:ignore cwe:918 reason:baseURL validated by NewAuthClient (HTTPS enforced for non-localhost); endpoint path is hardcoded
	req, err := http.NewRequestWithContext(ctx, "POST", authEndpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// armis:ignore cwe:918 reason:baseURL is user-configurable via ARMIS_API_URL but validated (HTTPS enforced for non-localhost, no redirects)
	// armis:ignore cwe:522 reason:credentials are sent over HTTPS (enforced above); this is the auth token exchange endpoint
	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: authEndpoint is constructed from validated config, not user input
	if err != nil {
		return nil, fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &AuthError{
			StatusCode: resp.StatusCode,
			Message:    "invalid credentials\n  Get credentials from the VIPR external API screen in the Armis Platform",
		}
	}

	if resp.StatusCode != http.StatusOK {
		// Log non-sensitive metadata when debug mode is enabled.
		// Response body is intentionally excluded to prevent credential leakage (CWE-522).
		if c.debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] Auth failed: status=%d, content-type=%q, response-length=%d bytes\n", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
		}
		// Don't include raw response body in error to prevent potential info leakage
		return nil, &AuthError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("authentication failed (status %d)", resp.StatusCode)}
	}

	var authResp authResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if authResp.Error != "" {
		// Don't include raw error content to prevent potential sensitive info leakage
		return nil, fmt.Errorf("authentication failed: server returned an error")
	}

	if authResp.Token == "" {
		return nil, fmt.Errorf("no token in response")
	}

	return &AuthResult{
		Token:  authResp.Token,
		Region: authResp.Region,
	}, nil
}
