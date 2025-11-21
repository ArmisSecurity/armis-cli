package cmd

import (
        "context"
        "fmt"
        "os"
        "time"

        "github.com/silk-security/armis-cli/internal/api"
        "github.com/silk-security/armis-cli/internal/output"
        "github.com/silk-security/armis-cli/internal/scan/repo"
        "github.com/spf13/cobra"
)

var scanRepoCmd = &cobra.Command{
        Use:   "repo [path]",
        Short: "Scan a local repository",
        Long:  `Scan a local repository for security vulnerabilities, secrets, and license risks.`,
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
                repoPath := args[0]

                token, err := getToken()
                if err != nil {
                        return err
                }

                tid, err := getTenantID()
                if err != nil {
                        return err
                }

                limit, err := getPageLimit()
                if err != nil {
                        return err
                }

                baseURL := getAPIBaseURL()
                if baseURL == "" {
                        return fmt.Errorf("API base URL not configured: use --dev flag for development environment")
                }

                client := api.NewClient(baseURL, token, debug)
                timeoutDuration := time.Duration(timeout) * time.Minute
                scanner := repo.NewScanner(client, noProgress, tid, limit, includeTests, timeoutDuration)

                ctx := context.Background()
                result, err := scanner.Scan(ctx, repoPath)
                if err != nil {
                        return fmt.Errorf("scan failed: %w", err)
                }

                formatter, err := output.GetFormatter(format)
                if err != nil {
                        return err
                }

                if err := formatter.Format(result, os.Stdout); err != nil {
                        return fmt.Errorf("failed to format output: %w", err)
                }

                output.ExitIfNeeded(result, failOn, exitCode)
                return nil
        },
}

func init() {
        scanCmd.AddCommand(scanRepoCmd)
}
