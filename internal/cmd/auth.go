package cmd

import (
	"context"
	"fmt"
	"os"
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

Requires --client-id and --client-secret flags or their corresponding
environment variables (ARMIS_CLIENT_ID, ARMIS_CLIENT_SECRET).`,
	Example: `  # Obtain JWT token using flags
  armis-cli auth --client-id MY_ID --client-secret MY_SECRET

  # Obtain token using environment variables
  export ARMIS_CLIENT_ID=MY_ID
  export ARMIS_CLIENT_SECRET=MY_SECRET
  armis-cli auth`,
	RunE: runAuth,
}

func init() {
	// Hide auth command until backend JWT support is available
	authCmd.Hidden = true
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

	// Print the raw token without any prefix (useful for piping to other tools).
	// CWE-522: Token output is the intentional purpose of this command.
	// Warning is sent to stderr so it doesn't interfere with piped usage.
	fmt.Fprintln(os.Stderr, "Warning: token output below. Avoid storing in logs or shell history.")
	fmt.Println(token) // #nosec CWE-522 -- intentional token output for CLI auth command
	return nil
}
