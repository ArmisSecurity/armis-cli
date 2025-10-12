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
	rootCmd.PersistentFlags().StringVar(&apiBaseURL, "api-url", getEnvOrDefault("ARMIS_API_URL", "https://api.armis.cloud/v1"), "Armis Cloud API base URL")
	rootCmd.PersistentFlags().StringVar(&format, "format", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Disable progress indicators")
	rootCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", []string{"CRITICAL"}, "Fail build on severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	rootCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code to use when failing")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
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
