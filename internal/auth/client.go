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
)

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

	// Require HTTPS for non-localhost
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
	reqBody := authRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Region:       regionHint,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	authEndpoint := c.baseURL + "/api/v1/auth/token"
	req, err := http.NewRequestWithContext(ctx, "POST", authEndpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

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
		return nil, &AuthError{StatusCode: resp.StatusCode, Message: "invalid credentials"}
	}

	if resp.StatusCode != http.StatusOK {
		// Log detailed error info when debug mode is enabled.
		// Truncate body to avoid exposing large amounts of potentially sensitive data.
		if c.debug {
			debugBody := string(body)
			const maxDebugLen = 512
			if len(debugBody) > maxDebugLen {
				debugBody = debugBody[:maxDebugLen] + "... (truncated)"
			}
			fmt.Fprintf(os.Stderr, "[DEBUG] Auth failed with status %d, response length: %d bytes\n%s\n", resp.StatusCode, len(body), debugBody)
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
