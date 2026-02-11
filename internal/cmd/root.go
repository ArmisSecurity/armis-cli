// Package cmd implements the CLI commands for the Armis security scanner.
package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/spf13/cobra"
)

const (
	devBaseURL        = "https://moose-dev.armis.com"
	productionBaseURL = "https://moose.armis.com"
)

var (
	token      string
	useDev     bool
	format     string
	noProgress bool
	failOn     []string
	exitCode   int
	tenantID   string
	pageLimit  int
	debug      bool

	// JWT authentication
	clientID     string
	clientSecret string
	authEndpoint string

	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:          "armis-cli",
	Short:        "Armis Security Scanner CLI",
	Long:         `Enterprise-grade CLI for static application security scanning integrated with Armis Cloud.`,
	Version:      version,
	SilenceUsage: true,
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
	// Legacy Basic authentication
	rootCmd.PersistentFlags().StringVar(&token, "token", os.Getenv("ARMIS_API_TOKEN"), "API token for Basic authentication (env: ARMIS_API_TOKEN)")
	rootCmd.PersistentFlags().StringVar(&tenantID, "tenant-id", os.Getenv("ARMIS_TENANT_ID"), "Tenant identifier for Armis Cloud (env: ARMIS_TENANT_ID)")

	// JWT authentication
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", os.Getenv("ARMIS_CLIENT_ID"), "Client ID for JWT authentication (env: ARMIS_CLIENT_ID)")
	rootCmd.PersistentFlags().StringVar(&clientSecret, "client-secret", os.Getenv("ARMIS_CLIENT_SECRET"), "Client secret for JWT authentication (env: ARMIS_CLIENT_SECRET)")
	rootCmd.PersistentFlags().StringVar(&authEndpoint, "auth-endpoint", os.Getenv("ARMIS_AUTH_ENDPOINT"), "Authentication service endpoint URL (env: ARMIS_AUTH_ENDPOINT)")

	// General options
	rootCmd.PersistentFlags().BoolVar(&useDev, "dev", false, "Use development environment instead of production")
	rootCmd.PersistentFlags().StringVar(&format, "format", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Disable progress indicators and spinners")
	rootCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", []string{"CRITICAL"}, "Fail build on severity levels (comma-separated): INFO, LOW, MEDIUM, HIGH, CRITICAL")
	rootCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code to return when build fails")
	rootCmd.PersistentFlags().IntVar(&pageLimit, "page-limit", getEnvOrDefaultInt("ARMIS_PAGE_LIMIT", 500), "Results page size for pagination (range: 1-1000)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug mode to print detailed API responses")
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
	if useDev {
		return devBaseURL
	}
	return productionBaseURL
}

func getToken() (string, error) {
	if token == "" {
		return "", fmt.Errorf("API token required: use --token flag or ARMIS_API_TOKEN environment variable")
	}
	return token, nil
}

func getTenantID() (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenant ID required: use --tenant-id flag or ARMIS_TENANT_ID environment variable")
	}
	return tenantID, nil
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

	for _, sev := range severities {
		if !validSet[sev] {
			return fmt.Errorf("invalid severity level %q: must be one of %v", sev, validSeverities)
		}
	}
	return nil
}

func getFailOn() ([]string, error) {
	if err := validateFailOn(failOn); err != nil {
		return nil, err
	}
	return failOn, nil
}
