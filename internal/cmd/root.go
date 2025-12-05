package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
)

const (
        devBaseURL        = "https://moose-dev.armis.com"
        productionBaseURL = ""
)

var (
        token      string
        useDev     bool
        apiBaseURL string
        format     string
        noProgress bool
        failOn     []string
        exitCode   int
        tenantID   string
        pageLimit  int
        debug      bool
        
        version = "dev"
        commit  = "none"
        date    = "unknown"
)

var rootCmd = &cobra.Command{
        Use:   "armis-cli",
        Short: "Armis Security Scanner CLI",
        Long:  `Enterprise-grade CLI for static application security scanning integrated with Armis Cloud.`,
        Version: version,
}

func SetVersion(v, c, d string) {
        version = v
        commit = c
        date = d
        rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
}

func Execute() error {
        return rootCmd.Execute()
}

func init() {
        rootCmd.PersistentFlags().StringVar(&token, "token", os.Getenv("ARMIS_API_TOKEN"), "API token for authentication (env: ARMIS_API_TOKEN)")
        rootCmd.PersistentFlags().BoolVar(&useDev, "dev", false, "Use development environment instead of production")
        rootCmd.PersistentFlags().StringVar(&format, "format", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
        rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Disable progress indicators and spinners")
        rootCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", []string{"CRITICAL"}, "Fail build on severity levels (comma-separated): INFO, LOW, MEDIUM, HIGH, CRITICAL")
        rootCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code to return when build fails")
        rootCmd.PersistentFlags().StringVar(&tenantID, "tenant-id", os.Getenv("ARMIS_TENANT_ID"), "Tenant identifier for Armis Cloud (env: ARMIS_TENANT_ID)")
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
