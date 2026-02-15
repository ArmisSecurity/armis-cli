package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate and print JWT token",
	Long: `Exchange client credentials for a JWT token and print it to stdout.

This command is useful for:
- Testing authentication configuration
- Obtaining tokens for use with other tools
- Debugging JWT-related issues

Requires --client-id, --client-secret, and --auth-endpoint flags or
their corresponding environment variables (ARMIS_CLIENT_ID,
ARMIS_CLIENT_SECRET, ARMIS_AUTH_ENDPOINT).`,
	Example: `  # Obtain JWT token using flags
  armis-cli auth --client-id MY_ID --client-secret MY_SECRET --auth-endpoint https://auth.example.com

  # Obtain token using environment variables
  export ARMIS_CLIENT_ID=MY_ID
  export ARMIS_CLIENT_SECRET=MY_SECRET
  export ARMIS_AUTH_ENDPOINT=https://auth.example.com
  armis-cli auth`,
	RunE: runAuth,
}

func init() {
	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, args []string) error {
	// Validate required flags for JWT auth
	if clientID == "" {
		return fmt.Errorf("--client-id is required (or set ARMIS_CLIENT_ID)")
	}
	if clientSecret == "" {
		return fmt.Errorf("--client-secret is required (or set ARMIS_CLIENT_SECRET)")
	}
	if authEndpoint == "" {
		return fmt.Errorf("--auth-endpoint is required (or set ARMIS_AUTH_ENDPOINT)")
	}

	provider, err := getAuthProvider()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	token, err := provider.GetRawToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Print the raw token without any prefix (useful for piping to other tools)
	fmt.Println(token)
	return nil
}
