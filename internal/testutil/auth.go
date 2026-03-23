// Package testutil provides utilities for testing.
package testutil

import "context"

// TestAuthProvider is a simple auth provider for testing.
// It implements the AuthHeaderProvider interface.
//
// CWE-522 false positive: This is a test utility that uses fake/mock credentials.
// It is only used in unit tests and never handles real authentication tokens.
// #nosec CWE-522
type TestAuthProvider struct {
	Token string
}

// GetAuthorizationHeader returns a Basic auth header with the configured token.
// This is a test-only implementation with fake credentials.
func (t *TestAuthProvider) GetAuthorizationHeader(_ context.Context) (string, error) {
	return "Basic " + t.Token, nil // #nosec CWE-522 -- test utility with fake credentials
}

// NewTestAuthProvider creates a test auth provider with the given token.
func NewTestAuthProvider(token string) *TestAuthProvider {
	return &TestAuthProvider{Token: token}
}
