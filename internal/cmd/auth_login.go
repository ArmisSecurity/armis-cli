package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/spf13/cobra"
)

var (
	loginOrg      string
	loginClientID string
)

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in to Armis Cloud via your browser",
	Long: `Authenticate with Armis Cloud using browser-based SSO (OAuth2 Device
Authorization Grant, RFC 8628).

The CLI requests a device code, opens your browser to the Armis sign-in page,
and waits while you authenticate with your corporate identity provider. On
success the access and refresh tokens are stored in a 0600 file under ~/.armis
and shared with the Armis MCP plugins.

A tenant is required: pass --tenant-id or set ARMIS_TENANT_ID.

If the browser cannot be opened automatically (for example over SSH), the CLI
prints a URL and a code to enter manually.`,
	Example: `  # Sign in interactively
  armis-cli auth login --tenant-id my-tenant

  # Skip org selection in the browser
  armis-cli auth login --tenant-id my-tenant --org my-company`,
	Args: cobra.NoArgs,
	RunE: runAuthLogin,
}

func init() {
	authLoginCmd.Flags().StringVar(&loginOrg, "org", "", "Organization slug hint to skip org selection in the browser")
	authLoginCmd.Flags().StringVar(&loginClientID, "client-id", auth.DefaultDeviceClientID, "OAuth2 client ID to authenticate as")
	authCmd.AddCommand(authLoginCmd)
}

func runAuthLogin(cmd *cobra.Command, _ []string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID required: use --tenant-id flag or ARMIS_TENANT_ID environment variable")
	}

	issuer := getAPIBaseURL()
	deviceClient, err := auth.NewDeviceClient(issuer, debug)
	if err != nil {
		return fmt.Errorf("failed to initialize login: %w", err)
	}

	// Step 1: request a device code. Use a short timeout for this single call.
	reqCtx, cancelReq := context.WithTimeout(cmd.Context(), 30*time.Second)
	da, err := deviceClient.RequestDeviceCode(reqCtx, loginClientID, tenantID, "")
	cancelReq()
	if err != nil {
		return fmt.Errorf("failed to start login: %w", err)
	}

	// Step 2: send the user to the verification page. The browser URL carries
	// the user_code, so the happy path needs no manual entry. --org is appended
	// as a hint for the verification page to preselect the organization.
	browseURL := withOrgHint(da.VerificationURIComplete, loginOrg)
	opened := auth.OpenBrowser(browseURL) == nil
	printVerificationInstructions(da, browseURL, opened)

	// Step 3: poll until approval, expiry, or denial. Bound the wait by the
	// device code's lifetime.
	pollCtx, cancelPoll := context.WithTimeout(cmd.Context(), time.Duration(da.ExpiresIn)*time.Second)
	defer cancelPoll()

	spinner := progress.NewSpinner("Waiting for you to finish signing in…", noProgress)
	spinner.Start()
	stored, err := deviceClient.PollToken(pollCtx, da.DeviceCode, loginClientID, da.Interval)
	spinner.Stop()
	if err != nil {
		return err
	}

	// Step 4: persist the tokens for reuse by the CLI and MCP plugins, keyed by
	// this environment (the API base URL) so multiple environments coexist.
	stored.Issuer = issuer
	store := auth.NewTokenStore()
	if err := store.Save(issuer, stored); err != nil {
		return fmt.Errorf("signed in, but failed to store credentials: %w", err)
	}

	printLoginSuccess(stored)
	return nil
}

// withOrgHint appends an `org` query parameter to the verification URL when an
// org slug was supplied. A parse failure returns the URL unchanged.
func withOrgHint(rawURL, org string) string {
	if org == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("org", org)
	u.RawQuery = q.Encode()
	return u.String()
}

// printVerificationInstructions tells the user where to authenticate, covering
// both the auto-opened-browser case and the manual fallback.
func printVerificationInstructions(da *auth.DeviceAuthorization, browseURL string, opened bool) {
	if opened {
		fmt.Fprintf(os.Stderr, "Opened your browser to complete sign-in.\n")
		fmt.Fprintf(os.Stderr, "If it didn't open, visit:\n\n    %s\n\n", browseURL)
		fmt.Fprintf(os.Stderr, "Verify this code is shown: %s\n\n", output.GetStyles().Bold.Render(da.UserCode))
		return
	}
	fmt.Fprintf(os.Stderr, "To sign in, open the following URL in your browser:\n\n")
	fmt.Fprintf(os.Stderr, "    %s\n\n", da.VerificationURI)
	fmt.Fprintf(os.Stderr, "and enter this code:  %s\n\n", output.GetStyles().Bold.Render(da.UserCode))
}

// printLoginSuccess confirms the signed-in identity and tenant.
func printLoginSuccess(stored *auth.StoredToken) {
	fmt.Fprintf(os.Stderr, "%s Signed in successfully.\n", output.IconSuccess)
	if stored.Subject != "" {
		fmt.Fprintf(os.Stderr, "  Identity: %s\n", stored.Subject)
	}
	if stored.TenantID != "" {
		fmt.Fprintf(os.Stderr, "  Tenant:   %s\n", stored.TenantID)
	}
}
