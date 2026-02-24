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

// AuthClient handles authentication with an external auth service.
type AuthClient struct {
	endpoint   string
	httpClient *http.Client
	debug      bool
}

// NewAuthClient creates a new authentication client for the given endpoint.
// The endpoint must be a valid HTTPS URL (HTTP allowed only for localhost).
// If debug is true, authentication failures will log detailed error information.
func NewAuthClient(endpoint string, debug bool) (*AuthClient, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("auth endpoint is required")
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Require HTTPS for non-localhost
	if parsedURL.Scheme != "https" {
		host := parsedURL.Hostname()
		if host != "localhost" && host != "127.0.0.1" {
			return nil, fmt.Errorf("HTTPS required for non-localhost endpoint")
		}
	}

	return &AuthClient{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		debug: debug,
	}, nil
}

// authRequest is the request body for the authenticate endpoint.
type authRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` //nolint:gosec // G117: This is a JSON field name for auth request, not a secret value
}

// authResponse is the response from the authenticate endpoint.
type authResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

// Authenticate exchanges client credentials for a JWT token.
// Calls POST /api/v1/authenticate with client_id and client_secret.
func (c *AuthClient) Authenticate(ctx context.Context, clientID, clientSecret string) (string, error) {
	reqBody := authRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	authEndpoint := c.endpoint + "/api/v1/authenticate"
	req, err := http.NewRequestWithContext(ctx, "POST", authEndpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: authEndpoint is constructed from validated config, not user input
	if err != nil {
		return "", fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body read-only

	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("invalid credentials")
	}

	if resp.StatusCode != http.StatusOK {
		// Log detailed error info when debug mode is enabled
		if c.debug {
			fmt.Fprintf(os.Stderr, "DEBUG: Auth failed with status %d, body: %s\n", resp.StatusCode, string(body))
		}
		// Don't include raw response body in error to prevent potential info leakage
		return "", fmt.Errorf("authentication failed (status %d)", resp.StatusCode)
	}

	var authResp authResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if authResp.Error != "" {
		// Don't include raw error content to prevent potential sensitive info leakage
		return "", fmt.Errorf("authentication failed: server returned an error")
	}

	if authResp.Token == "" {
		return "", fmt.Errorf("no token in response")
	}

	return authResp.Token, nil
}
