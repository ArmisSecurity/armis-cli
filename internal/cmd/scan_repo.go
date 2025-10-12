package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/silk-security/Moose-CLI/internal/api"
	"github.com/silk-security/Moose-CLI/internal/output"
	"github.com/silk-security/Moose-CLI/internal/scan/repo"
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

		client := api.NewClient(apiBaseURL, token)
		scanner := repo.NewScanner(client, noProgress)

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
