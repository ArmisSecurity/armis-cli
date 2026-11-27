package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/spf13/cobra"
)

var loginClientID string

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
prints a URL and a code to enter manually.

Client credentials need no login: every command signs in with them. Given
here (--client-id and --client-secret), or in a CI job's environment
(ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET), auth login checks them and exits,
as auth whoami does. In CI without them it fails at once, since nobody can
complete a browser sign-in there.`,
	Example: `  # Sign in interactively
  armis-cli auth login --tenant-id my-tenant

  # Check client credentials (a CI job needs no login step)
  armis-cli auth login --client-id "$ARMIS_CLIENT_ID" --client-secret "$ARMIS_CLIENT_SECRET"`,
	Args: cobra.NoArgs,
	RunE: runAuthLogin,
}

func init() {
	authLoginCmd.Flags().StringVar(&loginClientID, "client-id", auth.DefaultDeviceClientID,
		"OAuth2 client ID to authenticate as; with --client-secret, the client credentials' ID")
	authCmd.AddCommand(authLoginCmd)
}

func runAuthLogin(cmd *cobra.Command, _ []string) error {
	// Client credentials need no login. Given on the command line, or found in
	// a CI job's environment, they are checked instead of starting a browser
	// sign-in that nobody would complete. A developer machine with them in
	// its environment still signs in, for a session the MCP plugins share.
	ci, ciVar := progress.DetectCI()
	if cmd.Flags().Changed("client-secret") || (ci && clientSecret != "") {
		return checkClientCredentials(cmd)
	}
	if ci {
		return fmt.Errorf("auth login opens a browser sign-in, which a CI job cannot complete (CI detected from %s). "+
			"In CI, set ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET instead: every command signs in with them, with no "+
			"login step. To check them, run: armis-cli auth whoami", ciVar)
	}
	_, err := performDeviceLogin(cmd.Context(), loginClientID)
	return err
}

// checkClientCredentials signs in with auth login's client credentials, as
// auth whoami does, and says there is nothing to store. The client ID is
// --client-id's when given (auth login's own flag, which otherwise names the
// browser sign-in's OAuth client), and ARMIS_CLIENT_ID's otherwise.
func checkClientCredentials(cmd *cobra.Command) error {
	id := clientID
	if cmd.Flags().Changed("client-id") {
		id = loginClientID
	}
	if id == "" || clientSecret == "" {
		return fmt.Errorf("client credentials need both a client ID and a secret: pass --client-id and " +
			"--client-secret, or set ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET")
	}
	// These credentials, over any stored session.
	clientID, credFlagsExplicit = id, true
	provider, err := getAuthProvider(cmd.Context())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	tenant, err := provider.GetTenantID(ctx)
	if err != nil {
		return fmt.Errorf("the client credentials could not sign in: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s Client credentials are valid.\n", output.IconSuccess)
	if tenant != "" {
		fmt.Fprintf(os.Stderr, "  Tenant:   %s\n", tenant)
	}
	fmt.Fprintln(os.Stderr, "Every command signs in with them, so there is no session to store and no login step to run.")
	return nil
}

// performDeviceLogin runs the OAuth2 device-authorization flow end to end:
// request a device code, open (or print) the verification URL, poll until the
// user approves, and persist the resulting tokens. It returns the stored token
// on success. It is shared by the `auth login` command and the
// ARMIS_DEFAULT_AUTH_METHOD=SSO auto-login path in getAuthProvider.
//
// ctx bounds the whole interactive flow, so callers should pass a long-lived
// context (e.g. the command context), not a short per-request timeout.
func performDeviceLogin(ctx context.Context, clientID string) (*auth.StoredToken, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID required: use --tenant-id flag or ARMIS_TENANT_ID environment variable")
	}

	issuer := getAPIBaseURL()
	deviceClient, err := auth.NewDeviceClient(issuer, debug)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize login: %w", err)
	}

	// Step 1: request a device code. Use a short timeout for this single call.
	reqCtx, cancelReq := context.WithTimeout(ctx, 30*time.Second)
	da, err := deviceClient.RequestDeviceCode(reqCtx, clientID, tenantID, "")
	cancelReq()
	if err != nil {
		return nil, fmt.Errorf("failed to start login: %w", err)
	}

	// Step 2: send the user to the verification page. The browser URL carries
	// the user_code, so the happy path needs no manual entry.
	browseURL := da.VerificationURIComplete
	opened := auth.OpenBrowser(browseURL) == nil
	printVerificationInstructions(da, browseURL, opened)

	// Step 3: poll until approval, expiry, or denial. Bound the wait by the
	// device code's lifetime.
	pollCtx, cancelPoll := context.WithTimeout(ctx, time.Duration(da.ExpiresIn)*time.Second)
	defer cancelPoll()

	spinner := progress.NewSpinner("Waiting for you to finish signing in…", noProgress)
	spinner.Start()
	stored, err := deviceClient.PollToken(pollCtx, da.DeviceCode, clientID, da.Interval)
	spinner.Stop()
	if err != nil {
		return nil, err
	}

	// Step 4: persist the tokens for reuse by the CLI and MCP plugins, keyed by
	// this environment (the API base URL) so multiple environments coexist.
	stored.Issuer = issuer
	store := auth.NewTokenStore()
	if err := store.Save(issuer, stored); err != nil {
		return nil, fmt.Errorf("signed in, but failed to store credentials: %w", err)
	}

	printLoginSuccess(stored)
	return stored, nil
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
