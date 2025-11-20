package cmd

import (
        "fmt"
        "os"

        "github.com/spf13/cobra"
)

var (
        token      string
        apiBaseURL string
        format     string
        noProgress bool
        failOn     []string
        exitCode   int
        tenantID   string
        pageLimit  int
)

var rootCmd = &cobra.Command{
        Use:   "armis",
        Short: "Armis Security Scanner CLI",
        Long:  `Enterprise-grade CLI for static application security scanning integrated with Armis Cloud.`,
}

func Execute() error {
        return rootCmd.Execute()
}

func init() {
        rootCmd.PersistentFlags().StringVar(&token, "token", "", "API token for authentication (can also use ARMIS_API_TOKEN env var)")
        rootCmd.PersistentFlags().StringVar(&apiBaseURL, "api-url", getEnvOrDefault("ARMIS_API_URL", "http://moose-dev-alb-1788264649.us-east-1.elb.amazonaws.com"), "Armis Cloud API base URL")
        rootCmd.PersistentFlags().StringVar(&format, "format", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
        rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Disable progress indicators")
        rootCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", []string{"CRITICAL"}, "Fail build on severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
        rootCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code to use when failing")
        rootCmd.PersistentFlags().StringVar(&tenantID, "tenant-id", getEnvOrDefault("ARMIS_TENANT_ID", ""), "Tenant identifier (required for repo and image scans)")
        rootCmd.PersistentFlags().IntVar(&pageLimit, "page-limit", getEnvOrDefaultInt("ARMIS_PAGE_LIMIT", 500), "Results page size for pagination")
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

func getToken() (string, error) {
        if token != "" {
                return token, nil
        }
        if envToken := os.Getenv("ARMIS_API_TOKEN"); envToken != "" {
                return envToken, nil
        }
        return "", fmt.Errorf("API token required: use --token flag or ARMIS_API_TOKEN environment variable")
}

func getTenantID() (string, error) {
        if tenantID != "" {
                return tenantID, nil
        }
        return "", fmt.Errorf("tenant ID required: use --tenant-id flag or ARMIS_TENANT_ID environment variable")
}
