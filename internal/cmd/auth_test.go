package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// createMockJWT creates a mock JWT token with the given claims.
func createMockJWT(customerID string, exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"customer_id": customerID,
		"exp":         exp,
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payload + "." + signature
}

func TestRunAuth(t *testing.T) {
	tests := []struct {
		name           string
		clientID       string
		clientSecret   string
		setupServer    bool
		serverResponse int
		wantErr        bool
		errContains    string
	}{
		{
			name:         "missing client-id",
			clientID:     "",
			clientSecret: "test-secret",
			setupServer:  true,
			wantErr:      true,
			errContains:  "--client-id is required",
		},
		{
			name:         "missing client-secret",
			clientID:     "test-client",
			clientSecret: "",
			setupServer:  true,
			wantErr:      true,
			errContains:  "--client-secret is required",
		},
		{
			name:         "missing auth-endpoint",
			clientID:     "test-client",
			clientSecret: "test-secret",
			setupServer:  false, // No server = empty authEndpoint
			wantErr:      true,
			errContains:  "--auth-endpoint is required",
		},
		{
			name:           "successful authentication",
			clientID:       "test-client",
			clientSecret:   "test-secret",
			setupServer:    true,
			serverResponse: http.StatusOK,
			wantErr:        false,
		},
		{
			name:           "authentication failure - 401",
			clientID:       "test-client",
			clientSecret:   "test-secret",
			setupServer:    true,
			serverResponse: http.StatusUnauthorized,
			wantErr:        true,
			errContains:    "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values
			origClientID := clientID
			origClientSecret := clientSecret
			origAuthEndpoint := authEndpoint
			origToken := token
			origTenantID := tenantID

			// Restore after test
			defer func() {
				clientID = origClientID
				clientSecret = origClientSecret
				authEndpoint = origAuthEndpoint
				token = origToken
				tenantID = origTenantID
			}()

			// Clear legacy auth vars to ensure JWT path is taken
			token = ""
			tenantID = ""

			// Set test values
			clientID = tt.clientID
			clientSecret = tt.clientSecret

			if tt.setupServer {
				// Create mock auth server
				mockJWT := createMockJWT("customer-123", time.Now().Add(time.Hour).Unix())
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/api/v1/authenticate" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if r.Method != http.MethodPost {
						w.WriteHeader(http.StatusMethodNotAllowed)
						return
					}

					if tt.serverResponse != http.StatusOK {
						w.WriteHeader(tt.serverResponse)
						_, _ = w.Write([]byte(`{"error": "authentication failed"}`))
						return
					}

					w.Header().Set("Content-Type", "application/json")
					resp := map[string]string{"token": mockJWT}
					_ = json.NewEncoder(w).Encode(resp)
				}))
				defer server.Close()
				authEndpoint = server.URL
			} else {
				authEndpoint = ""
			}

			// Create a minimal cobra command with context
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())

			// Run the auth function
			err := runAuth(cmd, nil)

			// Check results
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q does not contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestRunAuth_InvalidEndpoint(t *testing.T) {
	// Save original values
	origClientID := clientID
	origClientSecret := clientSecret
	origAuthEndpoint := authEndpoint
	origToken := token
	origTenantID := tenantID

	defer func() {
		clientID = origClientID
		clientSecret = origClientSecret
		authEndpoint = origAuthEndpoint
		token = origToken
		tenantID = origTenantID
	}()

	// Clear legacy auth vars
	token = ""
	tenantID = ""

	// Set valid credentials but invalid endpoint
	clientID = "test-client"
	clientSecret = "test-secret"
	authEndpoint = "http://localhost:99999" // Invalid port

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runAuth(cmd, nil)

	if err == nil {
		t.Error("Expected error for invalid endpoint")
		return
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("Expected 'authentication failed' error, got: %v", err)
	}
}
