package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/spf13/cobra"
)

var scanRepoCmd = &cobra.Command{
	Use:   "repo [path]",
	Short: "Scan a local repository",
	Long:  `Scan a local repository for security vulnerabilities, secrets, and license risks.`,
	Example: `  $ armis-cli scan repo .
  $ armis-cli scan repo . --format json
  $ armis-cli scan repo . --format sarif --fail-on HIGH,CRITICAL
  $ armis-cli scan repo . --sbom --sbom-output sbom.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		repoPath := args[0]

		authProvider, err := getAuthProvider()
		if err != nil {
			return err
		}

		tid, err := authProvider.GetTenantID(cmd.Context())
		if err != nil {
			return err
		}

		limit, err := getPageLimit()
		if err != nil {
			return err
		}

		failOnSeverities, err := getFailOn()
		if err != nil {
			return err
		}

		baseURL := getAPIBaseURL()
		client, err := api.NewClient(baseURL, authProvider, debug, time.Duration(uploadTimeout)*time.Minute)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}
		scanTimeoutDuration := time.Duration(scanTimeout) * time.Minute
		scanner := repo.NewScanner(client, noProgress, tid, limit, includeTests, scanTimeoutDuration, includeNonExploitable)

		// Configure SBOM/VEX options if any flags are set
		if generateSBOM || generateVEX {
			sbomVEXOpts := &scan.SBOMVEXOptions{
				GenerateSBOM: generateSBOM,
				GenerateVEX:  generateVEX,
				SBOMOutput:   sbomOutput,
				VEXOutput:    vexOutput,
			}
			scanner = scanner.WithSBOMVEXOptions(sbomVEXOpts)
		}

		// Handle --include-files flag for targeted file scanning
		// Security: Path traversal protection is enforced by ParseFileList which
		// validates all paths using SafeJoinPath to ensure they don't escape the
		// repository root. Invalid or traversal paths are rejected with an error.
		if len(includeFiles) > 0 {
			absPath, err := filepath.Abs(repoPath)
			if err != nil {
				return fmt.Errorf("failed to resolve path: %w", err)
			}
			fileList, err := repo.ParseFileList(absPath, includeFiles)
			if err != nil {
				return fmt.Errorf("invalid --include-files: %w", err)
			}
			scanner = scanner.WithIncludeFiles(fileList)
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		result, err := scanner.Scan(ctx, repoPath)
		if err != nil {
			return handleScanError(ctx, err)
		}

		formatter, err := output.GetFormatter(format)
		if err != nil {
			return err
		}

		opts := output.FormatOptions{
			GroupBy:    groupBy,
			RepoPath:   repoPath,
			Debug:      debug,
			SummaryTop: summaryTop,
		}

		if err := formatter.FormatWithOptions(result, os.Stdout, opts); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		PrintUpdateNotification()
		output.ExitIfNeeded(result, failOnSeverities, exitCode)
		return nil
	},
}

func init() {
	scanCmd.AddCommand(scanRepoCmd)
}
