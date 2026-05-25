package install

import (
	"context"
	"fmt"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
)

const (
	validateTimeout    = 15 * time.Second
	productionBaseURL  = "https://moose.armis.com"
	validationHelpText = "Check that your Client ID and Secret are correct.\n" +
		"You can find them in the Armis platform under Settings > API Credentials."
)

// ValidateCredentials performs a token exchange to verify the credentials are valid.
// Returns nil on success, or a user-friendly error on failure.
func ValidateCredentials(clientID, clientSecret string) error {
	return validateCredentialsWithURL(clientID, clientSecret, productionBaseURL)
}

func validateCredentialsWithURL(clientID, clientSecret, baseURL string) error {
	client, err := auth.NewAuthClient(baseURL, false)
	if err != nil {
		return fmt.Errorf("failed to initialize auth client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()

	_, err = client.Authenticate(ctx, clientID, clientSecret, nil)
	if err != nil {
		return fmt.Errorf("authentication failed: %w\n%s", err, validationHelpText)
	}
	return nil
}
