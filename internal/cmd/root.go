// Package cmd implements the CLI commands for the Armis security scanner.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/update"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

const (
	devBaseURL        = "https://moose-dev.armis.com"
	productionBaseURL = auth.ProductionBaseURL

	// Theme values for terminal background detection
	themeAuto  = "auto"
	themeDark  = "dark"
	themeLight = "light"

	// versionDev is the version string used for development builds
	versionDev = "dev"
)

var (
	token         string
	useDev        bool
	format        string
	noProgress    bool
	failOn        []string
	exitCode      int
	tenantID      string
	pageLimit     int
	debug         bool
	noUpdateCheck bool
	colorFlag     string
	themeFlag     string

	// JWT authentication
	clientID     string
	clientSecret string
	region       string

	// credFlagsExplicit is set in PersistentPreRunE when the user passed
	// --client-id/--client-secret/--token explicitly. It lets those flags
	// override a stored SSO token in getAuthProvider.
	credFlagsExplicit bool

	version = versionDev
	commit  = "none"
	date    = "unknown"

	// updateResultCh receives version check results from background goroutine.
	updateResultCh <-chan *update.CheckResult

	// updateNotificationPrinted tracks if the notification has already been shown.
	// Protected by updateNotificationMu for thread safety.
	updateNotificationPrinted bool
	updateNotificationMu      sync.Mutex

	// skipUpdateNotification is set by PersistentPreRunE for meta-commands
	// (help, completion, etc.) where update notifications should be suppressed.
	skipUpdateNotification bool
)

var rootCmd = &cobra.Command{
	Use:   "armis-cli",
	Short: "Armis Security Scanner CLI",
	Long:  `Enterprise-grade CLI for static application security scanning integrated with Armis Cloud.`,
	Example: `  # Scan current directory for vulnerabilities
  armis-cli scan repo .

  # Scan with JSON output
  armis-cli scan repo . -f json

  # Scan container image
  armis-cli scan image nginx:latest

  # Scan with specific failure threshold
  armis-cli scan repo . --fail-on HIGH,CRITICAL`,
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// Show update notification after any command completes (like gh CLI)
		PrintUpdateNotification()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize colors based on --color flag
		mode := cli.ColorMode(colorFlag)
		switch mode {
		case cli.ColorModeAuto, cli.ColorModeAlways, cli.ColorModeNever:
			// valid
		default:
			return fmt.Errorf("invalid --color value %q: must be auto, always, or never", colorFlag)
		}
		cli.InitColors(mode)

		// Apply theme override for terminal background detection
		switch themeFlag {
		case themeAuto:
			// Let lipgloss auto-detect terminal background
		case themeDark:
			lipgloss.SetHasDarkBackground(true)
		case themeLight:
			lipgloss.SetHasDarkBackground(false)
		default:
			return fmt.Errorf("invalid --theme value %q: must be auto, dark, or light", themeFlag)
		}

		output.SyncColors()

		// Resolve credentials from environment when not explicitly provided via flags.
		// Using cmd.Flags().Changed() ensures that an explicit --flag="" can override
		// an env var (i.e. intentionally clear a credential).
		if !cmd.Flags().Changed("token") {
			token = os.Getenv("ARMIS_API_TOKEN")
		}
		if !cmd.Flags().Changed("tenant-id") {
			tenantID = os.Getenv("ARMIS_TENANT_ID")
		}
		if !cmd.Flags().Changed("client-id") {
			clientID = os.Getenv("ARMIS_CLIENT_ID")
		}
		if !cmd.Flags().Changed("client-secret") {
			clientSecret = os.Getenv("ARMIS_CLIENT_SECRET")
		}
		// Record whether the user explicitly passed credential flags. When they
		// did, those flags take precedence over any stored SSO token (an escape
		// hatch for forcing client-credentials/Basic auth without logging out).
		credFlagsExplicit = cmd.Flags().Changed("client-id") ||
			cmd.Flags().Changed("client-secret") ||
			cmd.Flags().Changed("token")
		if !cmd.Flags().Changed("region") {
			region = os.Getenv("ARMIS_REGION")
		}

		// Warn if the removed ARMIS_AUTH_ENDPOINT env var is set
		if os.Getenv("ARMIS_AUTH_ENDPOINT") != "" {
			cli.PrintWarning("ARMIS_AUTH_ENDPOINT is no longer supported. " +
				"The auth endpoint is now derived from the base URL. " +
				"Use ARMIS_API_URL to override the base URL, or --region to specify a region.")
		}

		// Skip update check if:
		// - explicitly disabled via flag or env var
		// - running in CI
		// - version is "dev" (development build)
		// - running meta-commands (help, completion, shell completion)
		isCompletionCmd := cmd.Name() == "completion" ||
			(cmd.Parent() != nil && cmd.Parent().Name() == "completion")
		isMetaCmd := cmd.Name() == "help" || cmd.Name() == "__complete" || isCompletionCmd
		if noUpdateCheck || os.Getenv("ARMIS_NO_UPDATE_CHECK") != "" ||
			progress.IsCI() || version == versionDev || isMetaCmd {
			// Set skipUpdateNotification for meta-commands so PrintUpdateNotification
			// won't show notifications even via cache fast-path
			if isMetaCmd {
				skipUpdateNotification = true
			}
			return nil
		}

		checker := update.NewChecker(version)
		updateResultCh = checker.CheckInBackground(context.Background())
		return nil
	},
}

// SetVersion sets the version information for the CLI.
func SetVersion(v, c, d string) {
	version = v
	commit = c
	date = d
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Set up styled help output on root command
	// The help function is inherited by all subcommands added later
	SetupHelp(rootCmd)

	// Append a help hint to flag-parse errors. SilenceUsage suppresses the full
	// usage dump, so without this an "unknown flag" error leaves the user with no
	// next step. Cobra walks up to the parent's FlagErrorFunc when a subcommand
	// has none, so registering it on rootCmd covers every subcommand. CommandPath()
	// yields the full path (e.g. "armis-cli scan repo"), unlike Name() (leaf only).
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return fmt.Errorf("%w\n\nRun '%s --help' for usage", err, cmd.CommandPath())
	})

	// Legacy Basic authentication
	rootCmd.PersistentFlags().StringVarP(&token, "token", "t", "", "API token for Basic authentication (env: ARMIS_API_TOKEN)")
	// Signal that Basic auth is the legacy path: MarkDeprecated prints a stderr
	// warning whenever --token is used and hides it from --help; the shorthand
	// (-t) needs its own call. Both error only on an unknown flag name, so the
	// returns are intentionally discarded. The flag still functions — auth is
	// unchanged; this is signposting toward JWT (--client-id / --client-secret).
	_ = rootCmd.PersistentFlags().MarkDeprecated("token", "use --client-id / --client-secret (JWT) instead; see ARMIS_CLIENT_ID + ARMIS_CLIENT_SECRET")
	_ = rootCmd.PersistentFlags().MarkShorthandDeprecated("token", "use --client-id / --client-secret (JWT) instead")
	rootCmd.PersistentFlags().StringVar(&tenantID, "tenant-id", "", "Tenant identifier for Armis Cloud (env: ARMIS_TENANT_ID)")

	// JWT authentication
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", "", "Client ID for JWT authentication (env: ARMIS_CLIENT_ID)")
	rootCmd.PersistentFlags().StringVar(&clientSecret, "client-secret", "", "Client secret for JWT authentication (env: ARMIS_CLIENT_SECRET)")
	rootCmd.PersistentFlags().StringVar(&region, "region", "", "Override Armis cloud region (auto-detected from credentials by default) (env: ARMIS_REGION)")

	// General options
	rootCmd.PersistentFlags().BoolVar(&useDev, "dev", false, "Use development environment instead of production")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Suppress progress output (for CI/scripts)")
	rootCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", []string{"CRITICAL"}, "Exit with error on findings at these severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	rootCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code when --fail-on triggers")
	rootCmd.PersistentFlags().IntVar(&pageLimit, "page-limit", getEnvOrDefaultInt("ARMIS_PAGE_LIMIT", 500), "Results page size for pagination (range: 1-1000)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug mode to print detailed API responses")
	rootCmd.PersistentFlags().BoolVar(&noUpdateCheck, "no-update-check", false, "Disable automatic update checking (env: ARMIS_NO_UPDATE_CHECK)")
	rootCmd.PersistentFlags().StringVar(&colorFlag, "color", "auto", "Control colored output: auto, always, never")
	rootCmd.PersistentFlags().StringVar(&themeFlag, "theme", getEnvOrDefault("ARMIS_THEME", themeAuto), "Terminal background theme: auto, dark, light (env: ARMIS_THEME)")

	// Tab-completion for enumerated flags. Without these, Cobra falls back to
	// (useless) file-path completion. The value lists reuse the same slices the
	// validators read, so the completion candidates can't drift from what's
	// actually accepted. --region is intentionally omitted (advisory-only).
	_ = rootCmd.RegisterFlagCompletionFunc("format", fixedCompletions(validFormats, map[string]string{
		"human": "Human-readable terminal output",
		"json":  "Machine-readable JSON",
		"sarif": "SARIF for code-scanning tools",
		"junit": "JUnit XML for CI test reports",
	}))
	_ = rootCmd.RegisterFlagCompletionFunc("fail-on", fixedCompletions(cmdutil.ValidSeverities, map[string]string{
		"INFO":     "Informational findings",
		"LOW":      "Low-severity findings",
		"MEDIUM":   "Medium-severity findings",
		"HIGH":     "High-severity findings",
		"CRITICAL": "Critical-severity findings",
	}))
	_ = rootCmd.RegisterFlagCompletionFunc("color", fixedCompletions(
		[]string{string(cli.ColorModeAuto), string(cli.ColorModeAlways), string(cli.ColorModeNever)},
		map[string]string{
			string(cli.ColorModeAuto):   "Enable colors when writing to a terminal (default)",
			string(cli.ColorModeAlways): "Always emit ANSI colors",
			string(cli.ColorModeNever):  "Never emit ANSI colors",
		}))
	_ = rootCmd.RegisterFlagCompletionFunc("theme", fixedCompletions([]string{themeAuto, themeDark, themeLight}, map[string]string{
		themeAuto:  "Auto-detect terminal background",
		themeDark:  "Optimize colors for a dark background",
		themeLight: "Optimize colors for a light background",
	}))
}

// fixedCompletions builds a Cobra completion function that offers a fixed set
// of values in the given order, attaching a "\tDescription" hint (rendered by
// zsh/fish) when one is present. It always returns ShellCompDirectiveNoFileComp
// so the shell does not fall back to file-path completion. Passing the
// validator's own slice as values keeps the completion set and the accepted set
// in lockstep.
func fixedCompletions(values []string, descriptions map[string]string) cobra.CompletionFunc {
	choices := make([]cobra.Completion, 0, len(values))
	for _, v := range values {
		if desc, ok := descriptions[v]; ok {
			choices = append(choices, cobra.CompletionWithDesc(v, desc))
		} else {
			choices = append(choices, v)
		}
	}
	return cobra.FixedCompletions(choices, cobra.ShellCompDirectiveNoFileComp)
}

// PrintUpdateNotification prints a version update notification if one is available.
// This function is safe to call multiple times - it will only print once per session.
// Call it at the END of commands (via PersistentPostRun or main.go fallback) to match
// the industry standard pattern used by gh, npm, and other popular CLIs.
func PrintUpdateNotification() {
	// Check skip conditions first.
	// skipUpdateNotification is set by PersistentPreRunE for meta-commands.
	if noUpdateCheck || os.Getenv("ARMIS_NO_UPDATE_CHECK") != "" ||
		progress.IsCI() || version == versionDev || skipUpdateNotification {
		return
	}

	// Check if already printed - if so, return early.
	updateNotificationMu.Lock()
	if updateNotificationPrinted {
		updateNotificationMu.Unlock()
		return
	}
	updateNotificationMu.Unlock()

	// Try synchronous cache check first (fast path when background goroutine hasn't completed).
	checker := update.NewChecker(version)
	if result := checker.CheckCached(); result != nil {
		printUpdateNotificationOnce(result)
		return
	}

	// Fallback: wait briefly for background check result (handles edge cases
	// where cache was just populated by the goroutine).
	if updateResultCh == nil {
		return
	}
	select {
	case result, ok := <-updateResultCh:
		if ok && result != nil {
			printUpdateNotificationOnce(result)
		}
	case <-time.After(100 * time.Millisecond):
		// Check hasn't completed yet -- silently skip.
		// The flag is NOT set here, so a subsequent call can still print
		// if the background check completes by then.
	}
}

// printUpdateNotificationOnce prints the notification and marks it as printed.
// This ensures the flag is only set when we actually print something.
func printUpdateNotificationOnce(result *update.CheckResult) {
	updateNotificationMu.Lock()
	if updateNotificationPrinted {
		updateNotificationMu.Unlock()
		return
	}
	updateNotificationPrinted = true
	updateNotificationMu.Unlock()

	msg := update.FormatNotification(result.CurrentVersion, result.LatestVersion, output.IconDependency)
	fmt.Fprint(os.Stderr, msg)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvOrDefaultInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intVal int
		if _, err := fmt.Sscanf(value, "%d", &intVal); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getAPIBaseURL returns the Armis API base URL, allowing override via ARMIS_API_URL env var for testing.
//
// Precedence: ARMIS_API_URL override > --dev > --region > production. The region
// must feed the upload endpoint as well as the token exchange; otherwise a
// region-scoped JWT is presented to the global host and rejected with a 401.
//
// This resolves the URL from explicit configuration only (it runs before
// authentication, so it cannot know the token's region). Use
// resolveDataPlaneURL once an AuthProvider exists to also honor the
// auto-discovered region.
func getAPIBaseURL() string {
	if override := os.Getenv("ARMIS_API_URL"); override != "" {
		return override // armis:ignore cwe:918 reason:ARMIS_API_URL is operator-configured; not reachable from external input
	}
	if useDev {
		return devBaseURL
	}
	// armis:ignore cwe:918 reason:RegionalBaseURL is a strict allowlist switch returning only hardcoded hosts; an unrecognized region falls through to the primary host, so region cannot redirect requests to an arbitrary host
	if region != "" {
		return auth.RegionalBaseURL(region) // armis:ignore cwe:918 reason:RegionalBaseURL allowlists hosts (hardcoded switch); unknown region falls back to primary host, so region cannot point requests at an attacker-chosen host
	}
	return productionBaseURL
}

// resolveDataPlaneURL returns the base URL for region-pinned data-plane calls
// (upload, status polling, results fetch).
//
// The data plane is physically region-pinned, but the auth endpoint
// auto-discovers the region server-side: a token exchange against the primary
// host succeeds even for a non-US customer and returns a region-scoped JWT. So
// when the user has not pinned a region explicitly, we read the region the auth
// service issued in that JWT and route the data plane to the matching host
// automatically — sparing EU (and future-region) customers from passing
// --region on every scan.
//
// Explicit configuration always wins: ARMIS_API_URL, --dev, and
// --region/ARMIS_REGION are honored ahead of the discovered region. When none
// of those are set and the region cannot be discovered (legacy Basic auth, or
// an older token without a region claim), it falls back to getAPIBaseURL.
func resolveDataPlaneURL(ctx context.Context, authProvider *auth.AuthProvider) string {
	if region == "" && !useDev && os.Getenv("ARMIS_API_URL") == "" {
		if discovered, err := authProvider.GetRegion(ctx); err == nil && discovered != "" {
			dataPlaneURL := auth.RegionalBaseURL(discovered)
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Auto-detected region %q from token; routing data plane to %s\n", discovered, dataPlaneURL)
			}
			return dataPlaneURL
		}
	}
	return getAPIBaseURL()
}

// getAuthProvider creates an AuthProvider based on the available credentials.
//
// Resolution order (PPSC-1037):
//  1. Stored SSO token (keychain / fallback file) from `armis-cli auth login`,
//     unless the user explicitly passed --client-id/--client-secret/--token,
//     which act as an escape hatch to force the credential path.
//  2. Client credentials (--client-id/--client-secret or ARMIS_CLIENT_ID/SECRET).
//  3. Legacy --token (Basic auth).
//  4. When ARMIS_DEFAULT_AUTH_METHOD=SSO and no credentials are configured,
//     trigger an interactive browser login (device flow) instead of erroring.
//  5. Otherwise an error pointing at `auth login` / env credentials.
//
// CI/CD is unaffected: with no stored token, resolution falls straight through
// to env-var client credentials exactly as before. The SSO auto-login in step 4
// only fires when no other credential is available, so it never overrides
// configured client credentials or a legacy token.
//
// ctx bounds any interactive login triggered here, so callers must pass a
// long-lived context (the command context), not a short per-request timeout.
func getAuthProvider(ctx context.Context) (*auth.AuthProvider, error) {
	if !credFlagsExplicit {
		if provider, ok := storedAuthProvider(); ok {
			return provider, nil
		}
	}

	// Opt-in: when the user has asked for SSO as the default auth method and no
	// other credentials are configured, sign in interactively rather than
	// failing. This makes `armis-cli scan ...` self-bootstrap a session on a
	// developer machine while leaving credentialed (CI) runs untouched.
	if shouldAutoLoginSSO() {
		if _, err := performDeviceLogin(ctx, auth.DefaultDeviceClientID); err != nil {
			return nil, err
		}
		if provider, ok := storedAuthProvider(); ok {
			return provider, nil
		}
		return nil, fmt.Errorf("signed in, but no stored session was found for %s", getAPIBaseURL())
	}

	provider, err := auth.NewAuthProvider(auth.AuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BaseURL:      getAPIBaseURL(),
		Region:       region,
		Token:        token,
		TenantID:     tenantID,
		Debug:        debug,
	})
	if err != nil {
		// Improve the no-credentials message to mention SSO login.
		return nil, augmentNoCredentialsError(err)
	}
	return provider, nil
}

// shouldAutoLoginSSO reports whether getAuthProvider should start an interactive
// device-flow login. It fires only when ARMIS_DEFAULT_AUTH_METHOD=SSO (case
// insensitive) and no other credentials are configured — no explicit credential
// flags, no client credentials, and no legacy token — so it never shadows a
// working CI/service-account setup.
func shouldAutoLoginSSO() bool {
	if !strings.EqualFold(os.Getenv("ARMIS_DEFAULT_AUTH_METHOD"), "sso") {
		return false
	}
	if credFlagsExplicit {
		return false
	}
	return clientID == "" && clientSecret == "" && token == ""
}

// storedAuthProvider builds an SSO-backed AuthProvider from a previously stored
// device-flow token, or returns ok=false when none is present (or it cannot be
// used), so callers fall through to credential-based auth.
func storedAuthProvider() (*auth.AuthProvider, bool) {
	// The environment key is the resolved API base URL, so each environment
	// (prod, dev, a local stack) has its own token entry. This is also where
	// the refresh grant is sent, so the token's own issuer is not consulted.
	env := getAPIBaseURL()

	store := auth.NewTokenStore()
	stored, err := store.Load(env)
	if err != nil || stored == nil {
		return nil, false
	}

	deviceClient, err := auth.NewDeviceClient(env, debug)
	if err != nil {
		return nil, false
	}
	provider, err := auth.NewProviderFromStored(store, deviceClient, env, stored)
	if err != nil {
		return nil, false
	}
	return provider, true
}

// augmentNoCredentialsError replaces the auth package's generic
// "authentication required" error with a CLI-friendly, browser-login-first list
// of options. Other errors pass through unchanged.
func augmentNoCredentialsError(err error) error {
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		return err
	}
	return fmt.Errorf("not authenticated — use one of the following options:\n" +
		"  - run 'armis-cli auth login' to sign in with your company IdP\n" +
		"  - or set ARMIS_CLIENT_ID / ARMIS_CLIENT_SECRET (or --client-id / --client-secret) for JWT auth\n" +
		"  - or set ARMIS_API_TOKEN (or --token) for legacy auth")
}

func getPageLimit() (int, error) {
	if err := validatePageLimit(pageLimit); err != nil {
		return 0, err
	}
	return pageLimit, nil
}

func validatePageLimit(limit int) error {
	if limit < 1 || limit > 1000 {
		return fmt.Errorf("page limit must be between 1 and 1000, got %d", limit)
	}
	return nil
}
