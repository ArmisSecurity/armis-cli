package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/image"
	"github.com/ArmisSecurity/armis-cli/internal/util"
	"github.com/spf13/cobra"
)

var tarballPath string

var scanImageCmd = &cobra.Command{
	Use:   "image [image-name]",
	Short: "Scan a container image",
	Long:  `Scan a local or remote container image for security vulnerabilities.`,
	Example: `  $ armis-cli scan image nginx:latest
  $ armis-cli scan image myapp:v1.0 --format json
  $ armis-cli scan image --tarball ./image.tar
  $ armis-cli scan image alpine:3.18 --sbom --vex --fail-on HIGH,CRITICAL`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if tarballPath == "" && len(args) == 0 {
			return fmt.Errorf("missing target: specify an image name or use --tarball")
		}

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
		scanner := image.NewScanner(client, noProgress, tid, limit, includeTests, scanTimeoutDuration, includeNonExploitable)

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

		ctx, cancel := NewSignalContext()
		defer cancel()

		var result *model.ScanResult

		if tarballPath != "" {
			sanitizedPath, pathErr := util.SanitizePath(tarballPath)
			if pathErr != nil {
				return fmt.Errorf("invalid tarball path: %w", pathErr)
			}
			result, err = scanner.ScanTarball(ctx, sanitizedPath)
			if err != nil {
				return handleScanError(ctx, err)
			}
		} else {
			imageName := args[0]
			result, err = scanner.ScanImage(ctx, imageName)
			if err != nil {
				return handleScanError(ctx, err)
			}
		}

		formatter, err := output.GetFormatter(format)
		if err != nil {
			return err
		}

		opts := output.FormatOptions{
			GroupBy:    groupBy,
			RepoPath:   "",
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
	scanImageCmd.Flags().StringVar(&tarballPath, "tarball", "", "Path to a container image tarball")
	scanCmd.AddCommand(scanImageCmd)
}
