package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// authCmd is the parent group for authentication commands.
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication with Armis Cloud",
	Long: `Authenticate the CLI with Armis Cloud.

The recommended path is browser-based SSO:

  armis-cli auth login     Sign in via your browser (OAuth2 Device Authorization)
  armis-cli auth whoami    Show the current identity, tenant, and token expiry
  armis-cli auth logout    Remove stored credentials

For CI/CD and service accounts, set ARMIS_CLIENT_ID / ARMIS_CLIENT_SECRET
(client-credentials) instead of logging in interactively.`,
}

// authTokenCmd preserves the original `armis-cli auth` behavior (print a raw
// JWT obtained via client credentials) as a hidden `auth token` subcommand, for
// testing auth configuration and piping tokens to other tools.
var authTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print a JWT access token to stdout",
	Long: `Exchange credentials for an access token and print it to stdout.

Uses the active credentials in resolution order: a stored SSO session
(from 'armis-cli auth login'), then client credentials (--client-id /
--client-secret or ARMIS_CLIENT_ID / ARMIS_CLIENT_SECRET).

This command is useful for:
- Testing authentication configuration
- Obtaining tokens for use with other tools
- Debugging token-related issues`,
	Example: `  # Print a token using environment variables
  export ARMIS_CLIENT_ID=MY_ID
  export ARMIS_CLIENT_SECRET=MY_SECRET
  armis-cli auth token`,
	RunE: runAuth,
}

func init() {
	// `auth token` stays hidden: it's a debug/scripting helper that prints a raw
	// token, not part of the user-facing login/logout/whoami surface.
	authTokenCmd.Hidden = true
	authCmd.AddCommand(authTokenCmd)
	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, _ []string) error {
	provider, err := getAuthProvider(cmd.Context())
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
	// armis:ignore cwe:522 reason:auth token command's purpose is to output the token for piping to other tools
	fmt.Println(token)
	return nil
}
