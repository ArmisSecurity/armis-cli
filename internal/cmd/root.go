// Package cmd implements the CLI commands for the Armis security scanner.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/progress"
	"github.com/ArmisSecurity/armis-cli/internal/update"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

const (
	devBaseURL        = "https://moose-dev.armis.com"
	productionBaseURL = "https://moose.armis.com"

	// Theme values for terminal background detection
	themeAuto  = "auto"
	themeDark  = "dark"
	themeLight = "light"
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
	authEndpoint string

	version = "dev"
	commit  = "none"
	date    = "unknown"

	// updateResultCh receives version check results from background goroutine.
	updateResultCh <-chan *update.CheckResult
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

		// Skip update check if:
		// - explicitly disabled via flag or env var
		// - running in CI
		// - version is "dev" (development build)
		// - running meta-commands (help, completion, shell completion)
		isCompletionCmd := cmd.Name() == "completion" ||
			(cmd.Parent() != nil && cmd.Parent().Name() == "completion")
		if noUpdateCheck || os.Getenv("ARMIS_NO_UPDATE_CHECK") != "" ||
			progress.IsCI() || version == "dev" ||
			cmd.Name() == "help" || cmd.Name() == "__complete" || isCompletionCmd {
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

	// Legacy Basic authentication
	rootCmd.PersistentFlags().StringVarP(&token, "token", "t", os.Getenv("ARMIS_API_TOKEN"), "API token for Basic authentication (env: ARMIS_API_TOKEN)")
	rootCmd.PersistentFlags().StringVar(&tenantID, "tenant-id", os.Getenv("ARMIS_TENANT_ID"), "Tenant identifier for Armis Cloud (env: ARMIS_TENANT_ID)")

	// JWT authentication
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", os.Getenv("ARMIS_CLIENT_ID"), "Client ID for JWT authentication (env: ARMIS_CLIENT_ID)")
	rootCmd.PersistentFlags().StringVar(&clientSecret, "client-secret", os.Getenv("ARMIS_CLIENT_SECRET"), "Client secret for JWT authentication (env: ARMIS_CLIENT_SECRET)")
	rootCmd.PersistentFlags().StringVar(&authEndpoint, "auth-endpoint", os.Getenv("ARMIS_AUTH_ENDPOINT"), "Authentication service endpoint URL (env: ARMIS_AUTH_ENDPOINT)")

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
}

// PrintUpdateNotification prints a version update notification if one is available.
// This should be called before any os.Exit() call to ensure the notification is displayed.
func PrintUpdateNotification() {
	if updateResultCh == nil {
		return
	}

	// Non-blocking read: only show if result is already available
	select {
	case result, ok := <-updateResultCh:
		if ok && result != nil {
			msg := update.FormatNotification(result.CurrentVersion, result.LatestVersion, output.IconDependency)
			fmt.Fprint(os.Stderr, msg)
		}
	default:
		// Check hasn't completed yet -- silently skip
	}
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

func getAPIBaseURL() string {
	// Allow override via environment variable (useful for testing)
	if override := os.Getenv("ARMIS_API_URL"); override != "" {
		return override
	}
	if useDev {
		return devBaseURL
	}
	return productionBaseURL
}

// getAuthProvider creates an AuthProvider based on the provided credentials.
// Priority: JWT auth (--client-id, --client-secret, --auth-endpoint) > Basic auth (--token)
func getAuthProvider() (*auth.AuthProvider, error) {
	return auth.NewAuthProvider(auth.AuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthEndpoint: authEndpoint,
		Token:        token,
		TenantID:     tenantID,
		Debug:        debug,
	})
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

// validSeverities contains the valid severity level strings for the --fail-on flag.
var validSeverities = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func validateFailOn(severities []string) error {
	validSet := make(map[string]bool)
	for _, s := range validSeverities {
		validSet[s] = true
	}

	for i, sev := range severities {
		// Normalize to uppercase for case-insensitive matching
		upper := strings.ToUpper(sev)
		if !validSet[upper] {
			return fmt.Errorf("invalid severity level %q: must be one of %v", sev, validSeverities)
		}
		// Update the slice with normalized value
		severities[i] = upper
	}
	return nil
}

func getFailOn() ([]string, error) {
	if err := validateFailOn(failOn); err != nil {
		return nil, err
	}
	return failOn, nil
}
