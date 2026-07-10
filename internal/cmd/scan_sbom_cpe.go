package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/sbomcpe"
	"github.com/spf13/cobra"
)

// sbomCpeOutput is the path to write the raw per-CPE JSON dump to. Empty →
// falls back to .armis/<artifact>-sbom-cpe.json (chosen by the driver).
var sbomCpeOutput string

var scanSbomCpeCmd = &cobra.Command{
	Use:   "sbom-cpe <path>",
	Short: "Scan a CycloneDX asset SBOM via CPE→NVD matching",
	Long: `Upload a CycloneDX SBOM (or a directory of SBOMs, or a pre-built tarball)
and scan each component against the National Vulnerability Database using
its CPE. Findings appear in the standard tenant findings view; the raw
per-component JSON (including CPE and low_confidence flags for synthesised
CPEs) is written to disk for triage.

Purl-only application SBOMs (npm/NuGet/pypi manifests) belong on the
regular scan flow — the CPE→NVD scanner returns a clear error if such an
SBOM is uploaded here.`,
	Example: `  # Single asset-inventory SBOM
  $ armis-cli scan sbom-cpe ./torizon-os-bom.json

  # Directory of SBOMs (each .json / .xml file is packed and scanned)
  $ armis-cli scan sbom-cpe ./sboms/

  # Pre-built tarball
  $ armis-cli scan sbom-cpe ./inventory.tar.gz

  # Write the raw per-CPE JSON dump to a specific path
  $ armis-cli scan sbom-cpe ./sbom.json --sbom-cpe-output ./results.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]

		// Fail fast on missing path before touching auth / network.
		// armis:ignore cwe:22 reason:os.Stat is a read-only existence check; SanitizePath happens inside the scan driver
		info, err := os.Stat(inputPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("path does not exist: %s", inputPath)
			}
			return fmt.Errorf("cannot access path %s: %w", inputPath, err)
		}
		_ = info // used implicitly — stat error is the only thing we care about here

		// SBOM-CPE scans never generate SBOM or VEX documents (the input IS
		// an SBOM). Emit a warning if the user passed those flags, matching
		// scan_image.go's warning style for the same class of misuse.
		if generateSBOM {
			return fmt.Errorf("--sbom is not supported for scan sbom-cpe (the input already is an SBOM)")
		}
		if generateVEX {
			return fmt.Errorf("--vex is not supported for scan sbom-cpe (use `armis-cli scan sbom` for SBOM → VEX)")
		}

		authProvider, err := getAuthProvider(cmd.Context())
		if err != nil {
			return err
		}
		if authProvider == nil {
			return fmt.Errorf("internal error: nil auth provider")
		}

		tid, err := authProvider.GetTenantID(cmd.Context())
		if err != nil {
			return err
		}

		limit, err := getPageLimit()
		if err != nil {
			return err
		}

		failOnSeverities, err := cmdutil.GetFailOn(failOn)
		if err != nil {
			return err
		}

		baseURL := resolveDataPlaneURL(cmd.Context(), authProvider)
		client, err := api.NewClient(baseURL, authProvider, debug, time.Duration(uploadTimeout)*time.Minute,
			clientOptionsForBaseURL(baseURL)...)
		if err != nil {
			return fmt.Errorf("failed to create API client: %w", err)
		}

		scanTimeoutDuration := time.Duration(scanTimeout) * time.Minute
		scanner := sbomcpe.NewScanner(
			client,
			noProgress,
			tid,
			limit,
			scanTimeoutDuration,
			includeNonExploitable,
		)
		if sbomCpeOutput != "" {
			scanner = scanner.WithRawOutput(sbomCpeOutput)
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		result, err := scanner.Scan(ctx, inputPath)
		if err != nil {
			return handleScanError(ctx, err)
		}

		outputCfg, err := cmdutil.ResolveOutput(cmd, outputFile, format, colorFlag)
		if err != nil {
			return err
		}
		defer outputCfg.Cleanup()

		formatter, err := output.GetFormatter(outputCfg.Format)
		if err != nil {
			return err
		}

		opts := output.FormatOptions{
			GroupBy:          groupBy,
			RepoPath:         "",
			Debug:            debug,
			SummaryTop:       summaryTop,
			FailOnSeverities: failOnSeverities,
		}
		if err := formatter.FormatWithOptions(result, outputCfg.Writer, opts); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		return output.CheckExit(result, failOnSeverities, exitCode)
	},
}

func init() {
	scanSbomCpeCmd.Flags().StringVar(&sbomCpeOutput, "sbom-cpe-output", "",
		"Path to write the raw per-CPE JSON dump. Default: .armis/<artifact>-sbom-cpe.json")
	scanCmd.AddCommand(scanSbomCpeCmd)
}
