package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/sbom"
	"github.com/spf13/cobra"
)

var scanSBOMCmd = &cobra.Command{
	Use:   "sbom [path]",
	Short: "Scan a pre-existing SBOM for vulnerabilities",
	Long: `Upload a pre-existing CycloneDX SBOM (single file, directory of SBOMs, or a
pre-built .tar/.tar.gz/.tgz) and get back the vulnerabilities it exposes.

The backend picks the right scanner automatically based on the SBOM contents:

  - SBOMs whose components carry an explicit CPE (asset / inventory SBOMs
    like Torizon) are matched against NVD directly.
  - SBOMs that identify components only via purl (npm / NuGet / PyPI-style
    application manifests) are matched via Trivy → deps.dev.

Findings are printed as a table (same shape as ` + "`scan repo` / `scan image`" + `);
pass ` + "`--vex-output`" + ` to also download the OpenVEX document the backend
generated alongside them.`,
	Example: `  # Single SBOM
  $ armis-cli scan sbom ./sbom.json

  # Directory of SBOMs
  $ armis-cli scan sbom ./sboms/

  # Pre-built tarball
  $ armis-cli scan sbom ./inventory.tar.gz

  # Also emit a VEX document
  $ armis-cli scan sbom ./sbom.json --vex-output ./out/vex.json

  # Custom path for the raw-findings JSON dump
  $ armis-cli scan sbom ./sbom.json --sbom-output ./out/findings.json`,
	// Path is optional and defaults to the current directory, matching scan repo.
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sbomPath := "."
		if len(args) > 0 {
			sbomPath = args[0]
		}

		// --sbom is a no-op here (you can't generate an SBOM from an SBOM).
		// --sbom-output is repurposed as the raw-findings dump path.
		if generateSBOM {
			cli.PrintWarning("--sbom is ignored for `scan sbom` (the SBOM is the input, not the output)")
		}

		// Validate path exists before making network calls. A directory, a
		// single SBOM file, and a pre-built tarball are all valid inputs, so we
		// only check existence here (the scanner classifies the path).
		// armis:ignore cwe:22 reason:os.Stat is read-only existence check; path is from direct CLI arg, sanitized again in scanner
		if _, err := os.Stat(sbomPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("path does not exist: %s", sbomPath)
			}
			return fmt.Errorf("cannot access path %s: %w", sbomPath, err)
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
		scanner := sbom.NewScanner(
			client,
			noProgress,
			tid,
			limit,
			scanTimeoutDuration,
			includeNonExploitable,
		)
		if sbomOutput != "" {
			scanner = scanner.WithRawOutput(sbomOutput)
		}
		// --vex opts into VEX generation; --vex-output implies --vex.
		if generateVEX || vexOutput != "" {
			scanner = scanner.WithVEXOutput(vexOutput)
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		// armis:ignore cwe:22 reason:sbomPath is from direct CLI argument; sanitized via util.SanitizePath in scanner.Scan
		result, err := scanner.Scan(ctx, sbomPath)
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
	scanCmd.AddCommand(scanSBOMCmd)
}
