package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/spf13/cobra"
)

var authWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the current Armis identity and auth method",
	Long: `Display the identity, tenant, token expiry, and authentication method for
the currently active credentials, resolved in the same order the scan commands
use: stored SSO session, then client credentials, then legacy token.`,
	Args: cobra.NoArgs,
	RunE: runAuthWhoami,
}

func init() {
	authCmd.AddCommand(authWhoamiCmd)
}

func runAuthWhoami(cmd *cobra.Command, _ []string) error {
	provider, err := getAuthProvider()
	if err != nil {
		// getAuthProvider already returns a self-describing message (the
		// no-credentials case lists the sign-in options); don't re-wrap it.
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	// Resolve the tenant; this also triggers a refresh if the token is stale,
	// surfacing an expired-session error here rather than on the next scan.
	tenant, err := provider.GetTenantID(ctx)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Environment: %s\n", getAPIBaseURL())
	fmt.Fprintf(os.Stderr, "Auth method: %s\n", describeAuthMethod(provider.AuthMethod()))
	if id := provider.Identity(); id != "" {
		fmt.Fprintf(os.Stderr, "Identity:    %s\n", id)
	}
	if tenant != "" {
		fmt.Fprintf(os.Stderr, "Tenant:      %s\n", tenant)
	}
	if region, rerr := provider.GetRegion(ctx); rerr == nil && region != "" {
		fmt.Fprintf(os.Stderr, "Region:      %s\n", region)
	}
	if exp := provider.Expiry(); !exp.IsZero() {
		fmt.Fprintf(os.Stderr, "Expires:     %s (%s)\n", exp.Format(time.RFC3339), humanizeUntil(time.Until(exp)))
	}
	return nil
}

// describeAuthMethod renders the auth method in user-facing terms.
func describeAuthMethod(m auth.AuthMethod) string {
	switch m {
	case auth.AuthMethodSSO:
		return "SSO (browser login)"
	case auth.AuthMethodClientCredentials:
		return "client credentials"
	case auth.AuthMethodBasic:
		return "API token (legacy)"
	default:
		return string(m)
	}
}

// humanizeUntil renders a duration-until-expiry as a short, friendly phrase.
func humanizeUntil(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	switch {
	case d < time.Minute:
		return "in less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("in %d minutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("in %d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("in %d days", int(d.Hours()/24))
	}
}
