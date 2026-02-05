// Package testutil provides utilities for testing.
package testutil

import "context"

// TestAuthProvider is a simple auth provider for testing.
// It implements the AuthHeaderProvider interface.
type TestAuthProvider struct {
	Token string
}

// GetAuthorizationHeader returns a Basic auth header with the configured token.
func (t *TestAuthProvider) GetAuthorizationHeader(_ context.Context) (string, error) {
	return "Basic " + t.Token, nil
}

// NewTestAuthProvider creates a test auth provider with the given token.
func NewTestAuthProvider(token string) *TestAuthProvider {
	return &TestAuthProvider{Token: token}
}
