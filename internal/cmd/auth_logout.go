package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/spf13/cobra"
)

var logoutAll bool

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored Armis credentials",
	Long: `Remove the SSO tokens stored by 'armis-cli auth login'.

By default only the token for the current environment is removed (the
environment is the resolved API base URL, e.g. set via --dev / --region /
ARMIS_API_URL). Use --all to remove tokens for every environment.

This does not affect credentials supplied via environment variables or flags.`,
	Args: cobra.NoArgs,
	RunE: runAuthLogout,
}

func init() {
	authLogoutCmd.Flags().BoolVar(&logoutAll, "all", false, "Remove stored tokens for all environments")
	authCmd.AddCommand(authLogoutCmd)
}

func runAuthLogout(_ *cobra.Command, _ []string) error {
	store := auth.NewTokenStore()

	if logoutAll {
		envs := store.Environments()
		if err := store.ClearAll(); err != nil {
			return fmt.Errorf("failed to remove stored credentials: %w", err)
		}
		if len(envs) == 0 {
			fmt.Fprintln(os.Stderr, "No stored credentials to remove.")
			return nil
		}
		fmt.Fprintf(os.Stderr, "%s Signed out of %d environment(s).\n", output.IconSuccess, len(envs))
		return nil
	}

	env := getAPIBaseURL()

	// Report whether anything was actually stored, so logout is informative
	// rather than silently succeeding when not logged in.
	existing, _ := store.Load(env)
	if err := store.Clear(env); err != nil {
		return fmt.Errorf("failed to remove stored credentials: %w", err)
	}

	if existing == nil {
		fmt.Fprintf(os.Stderr, "No stored credentials to remove for %s.\n", env)
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s Signed out of %s.\n", output.IconSuccess, env)
	return nil
}
