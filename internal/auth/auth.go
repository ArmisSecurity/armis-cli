// Package auth provides authentication for the Armis API.
// It supports both JWT authentication (using client credentials)
// and legacy Basic authentication (using static tokens).
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AuthConfig contains configuration for authentication.
type AuthConfig struct {
	// JWT auth credentials
	ClientID     string
	ClientSecret string //nolint:gosec // G117: This is a config field name, not a secret value
	BaseURL      string // Moose API base URL (dev or prod)
	Region       string // Optional region override - bypasses auto-discovery if set

	// Legacy Basic auth
	Token    string
	TenantID string

	// Debug mode for verbose logging
	Debug bool
}

// JWTCredentials contains the JWT token and extracted claims.
type JWTCredentials struct {
	Token     string
	TenantID  string // Extracted from customer_id claim
	ExpiresAt time.Time
	Region    string // Deployment region (e.g., "us1", "eu1", "au1")
}

// AuthProvider manages authentication tokens with automatic refresh.
// It supports both JWT authentication and legacy Basic authentication.
// For JWT auth, tokens are automatically refreshed when within 5 minutes of expiry.
type AuthProvider struct {
	config       AuthConfig
	credentials  *JWTCredentials
	authClient   *AuthClient
	mu           sync.RWMutex
	isLegacy     bool   // true if using Basic auth (--token)
	cachedRegion string // memoized region from disk cache (loaded once)
	regionLoaded bool   // true if cachedRegion has been loaded from disk
}

// NewAuthProvider creates an AuthProvider from configuration.
// If ClientID and ClientSecret are set, uses JWT auth with the specified base URL.
// Otherwise falls back to legacy Basic auth with Token.
func NewAuthProvider(config AuthConfig) (*AuthProvider, error) {
	p := &AuthProvider{
		config: config,
	}

	// Validate that client credentials are either both provided or both empty
	// to prevent silent fallback to Basic auth when JWT is partially configured
	hasClientID := config.ClientID != ""
	hasClientSecret := config.ClientSecret != ""
	if hasClientID != hasClientSecret {
		return nil, fmt.Errorf("both --client-id and --client-secret must be provided for JWT authentication")
	}

	// Determine auth mode: JWT credentials take priority
	if config.ClientID != "" && config.ClientSecret != "" {
		// JWT auth via moose
		p.isLegacy = false
		if config.BaseURL == "" {
			return nil, fmt.Errorf("base URL is required for JWT authentication")
		}
		authClient, err := NewAuthClient(config.BaseURL, config.Debug)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth client: %w", err)
		}
		p.authClient = authClient

		// Initial token exchange (use background context for initialization)
		if err := p.exchangeCredentials(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	} else if config.Token != "" {
		// Legacy Basic auth
		p.isLegacy = true
		if config.TenantID == "" {
			return nil, fmt.Errorf("tenant ID required: use --tenant-id flag or ARMIS_TENANT_ID environment variable")
		}
	} else {
		return nil, fmt.Errorf("authentication required: use --token flag or ARMIS_API_TOKEN environment variable")
	}

	return p, nil
}

// GetAuthorizationHeader returns the Authorization header value.
// For JWT auth: the raw JWT token (no "Bearer" prefix - backend expects raw JWT)
// For Basic auth: "Basic <token>" per RFC 7617
func (p *AuthProvider) GetAuthorizationHeader(ctx context.Context) (string, error) {
	if p.isLegacy {
		// #nosec G101 -- Basic auth scheme requires token in header per RFC 7617
		return "Basic " + p.config.Token, nil
	}

	// Refresh JWT if needed
	if err := p.refreshIfNeeded(ctx); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	// Raw JWT token (no Bearer prefix) - backend expects raw JWT per API contract
	return p.credentials.Token, nil
}

// GetTenantID returns the tenant ID for API requests.
// For JWT auth: extracted from customer_id claim
// For Basic auth: from config
func (p *AuthProvider) GetTenantID(ctx context.Context) (string, error) {
	if p.isLegacy {
		return p.config.TenantID, nil
	}

	if err := p.refreshIfNeeded(ctx); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.credentials.TenantID, nil
}

// GetRegion returns the deployment region from the JWT token.
// For JWT auth: extracted from region claim (may be empty for older tokens)
// For Basic auth: returns empty string (no region available)
func (p *AuthProvider) GetRegion(ctx context.Context) (string, error) {
	if p.isLegacy {
		return "", nil // Legacy auth doesn't have region
	}

	if err := p.refreshIfNeeded(ctx); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.credentials.Region, nil
}

// IsLegacy returns true if using legacy Basic auth.
func (p *AuthProvider) IsLegacy() bool {
	return p.isLegacy
}

// GetRawToken returns the raw JWT token (for JWT auth) or the raw token (for Basic auth).
// This is useful for displaying tokens to users or passing to external tools.
// Unlike GetAuthorizationHeader, this never includes prefixes like "Basic ".
//
// SECURITY NOTE: Exposing raw tokens is intentional here - this method exists
// specifically for the `auth` command to output tokens for piping to other tools.
// The token is only printed to stdout when explicitly requested by the user.
//
// #nosec G101 -- Intentional credential exposure for CLI output
func (p *AuthProvider) GetRawToken(ctx context.Context) (string, error) {
	if p.isLegacy {
		return p.config.Token, nil
	}

	// Refresh JWT if needed
	if err := p.refreshIfNeeded(ctx); err != nil {
		return "", fmt.Errorf("failed to refresh token: %w", err)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.credentials.Token, nil
}

// exchangeCredentials exchanges client credentials for a JWT token.
// Uses double-checked locking to prevent thundering herd of concurrent refreshes.
// Leverages region caching to avoid auto-discovery overhead on subsequent requests.
//
// Region selection priority:
//  1. --region flag (config.Region) - explicit override, bypasses cache and discovery
//  2. Cached region - from previous successful auth for this client_id
//  3. Auto-discovery - server tries regions until one succeeds
//
// Retry behavior: If auth fails with a cached region hint (not explicit --region),
// the cache is cleared and auth is retried without the hint. This handles stale
// cache gracefully without requiring user to re-run the command.
func (p *AuthProvider) exchangeCredentials(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: another goroutine may have refreshed while we waited for the lock
	if p.credentials != nil && time.Until(p.credentials.ExpiresAt) >= 5*time.Minute {
		return nil
	}

	// Load cached region once per process (memoize to avoid repeated disk I/O)
	if !p.regionLoaded {
		if region, ok := loadCachedRegion(p.config.ClientID); ok {
			p.cachedRegion = region
		}
		p.regionLoaded = true
	}

	// Determine region hint - explicit flag takes priority over cache
	var regionHint *string
	var usingCachedHint bool
	if p.config.Region != "" {
		// Explicit --region flag - don't retry on failure (user error)
		regionHint = &p.config.Region
	} else if p.cachedRegion != "" {
		// Cached region - will retry without hint on failure
		regionHint = &p.cachedRegion
		usingCachedHint = true
	}

	result, err := p.authClient.Authenticate(ctx, p.config.ClientID, p.config.ClientSecret, regionHint)
	if err != nil {
		// If auth failed with a cached region hint, clear cache and retry without hint
		// This handles stale cache (region changed) without requiring user to re-run
		if usingCachedHint {
			clearCachedRegion()
			p.cachedRegion = ""
			// Retry without region hint - let server auto-discover
			result, err = p.authClient.Authenticate(ctx, p.config.ClientID, p.config.ClientSecret, nil)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Cache the discovered region for future requests (skip if unchanged)
	if result.Region != "" && result.Region != p.cachedRegion {
		saveCachedRegion(p.config.ClientID, result.Region)
		p.cachedRegion = result.Region
	}

	// Parse JWT to extract claims
	claims, err := parseJWTClaims(result.Token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	p.credentials = &JWTCredentials{
		Token:     result.Token,
		TenantID:  claims.CustomerID,
		ExpiresAt: claims.ExpiresAt,
		Region:    claims.Region,
	}

	return nil
}

// refreshIfNeeded refreshes the token if within 5 minutes of expiry.
func (p *AuthProvider) refreshIfNeeded(ctx context.Context) error {
	p.mu.RLock()
	needsRefresh := p.credentials == nil ||
		time.Until(p.credentials.ExpiresAt) < 5*time.Minute
	p.mu.RUnlock()

	if !needsRefresh {
		return nil
	}

	return p.exchangeCredentials(ctx)
}

// jwtClaims represents the relevant claims from a JWT.
type jwtClaims struct {
	CustomerID string // maps to tenant_id
	ExpiresAt  time.Time
	Region     string // deployment region (optional)
}

// parseJWTClaims extracts claims from a JWT without signature verification.
// The JWT format is: header.payload.signature (base64url encoded)
// We only need to decode the payload to extract customer_id and exp.
//
// SECURITY NOTE: Signature verification is intentionally omitted because:
// 1. The CLI obtained this token directly from the auth service via HTTPS
// 2. The backend validates the signature server-side for all API requests
// 3. This function only extracts claims for local caching/refresh logic
//
// #nosec G104 -- JWT signature verification delegated to backend
func parseJWTClaims(token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (second part) - JWT uses base64url encoding without padding
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var data struct {
		CustomerID string  `json:"customer_id"`
		Exp        float64 `json:"exp"`    // float64 to handle servers that return fractional timestamps
		Region     string  `json:"region"` // optional deployment region
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	if data.CustomerID == "" {
		return nil, fmt.Errorf("customer_id claim missing from JWT")
	}
	if data.Exp == 0 {
		return nil, fmt.Errorf("exp claim missing from JWT")
	}

	// Convert float64 to Unix timestamp (truncate sub-second precision)
	expSec := int64(data.Exp)

	return &jwtClaims{
		CustomerID: data.CustomerID,
		ExpiresAt:  time.Unix(expSec, 0),
		Region:     data.Region, // may be empty for backward compatibility
	}, nil
}
