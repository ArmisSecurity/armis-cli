package install

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
)

const (
	validateTimeout    = 15 * time.Second
	validationHelpText = "Check that your Client ID and Secret are correct.\n" +
		"You can find them in the Armis platform under Settings > API Credentials."
)

// ValidateCredentials performs a token exchange to verify the credentials are valid.
// It respects ARMIS_API_URL and ARMIS_REGION env vars to select the correct endpoint.
// Returns nil on success, or a user-friendly error on failure.
func ValidateCredentials(clientID, clientSecret string) error {
	return validateCredentialsWithURL(clientID, clientSecret, resolveBaseURL())
}

func resolveBaseURL() string {
	if override := os.Getenv("ARMIS_API_URL"); override != "" {
		return override
	}
	if region := os.Getenv("ARMIS_REGION"); region != "" {
		return "https://moose." + region + ".armis.com"
	}
	return auth.ProductionBaseURL
}

func validateCredentialsWithURL(clientID, clientSecret, baseURL string) error {
	// armis:ignore cwe:295 reason:second param is debug flag, not TLS verification; http.Client validates certs by default
	client, err := auth.NewAuthClient(baseURL, false)
	if err != nil {
		return fmt.Errorf("failed to initialize auth client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()

	_, err = client.Authenticate(ctx, clientID, clientSecret, nil)
	if err != nil {
		var authErr *auth.AuthError
		if errors.As(err, &authErr) && authErr.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("authentication failed: %w\n%s", err, validationHelpText)
		}
		return fmt.Errorf("authentication failed: %w", err)
	}
	return nil
}
