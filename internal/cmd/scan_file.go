package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/silk-security/Moose-CLI/internal/api"
	"github.com/silk-security/Moose-CLI/internal/output"
	"github.com/silk-security/Moose-CLI/internal/scan/file"
	"github.com/spf13/cobra"
)

var scanFileCmd = &cobra.Command{
	Use:   "file [path]",
	Short: "Scan a single file",
	Long:  `Scan a single file for security vulnerabilities.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		token, err := getToken()
		if err != nil {
			return err
		}

		client := api.NewClient(apiBaseURL, token)
		scanner := file.NewScanner(client, noProgress)

		ctx := context.Background()
		result, err := scanner.Scan(ctx, filePath)
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
	scanCmd.AddCommand(scanFileCmd)
}
