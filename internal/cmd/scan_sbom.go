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
	Short: "Generate a VEX document from a pre-existing SBOM",
	Long: `Upload a pre-existing SBOM file and download the OpenVEX document the Armis
backend generates from it.

The <path> may be a single SBOM file (.json/.xml), a directory of SBOMs, or an
already-built .tar/.tar.gz/.tgz. An SBOM scan produces no findings — the result
is the generated VEX document (default: .armis/<artifact>-vex.json).`,
	Example: `  $ armis-cli scan sbom sbom.json
  $ armis-cli scan sbom ./sboms/
  $ armis-cli scan sbom sbom.json --vex-output out/vex.json`,
	// Path is optional and defaults to the current directory, matching scan repo.
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sbomPath := "."
		if len(args) > 0 {
			sbomPath = args[0]
		}

		// --sbom / --sbom-output are meaningless here: you can't generate an SBOM
		// from an SBOM. Warn (consistent with scan.PersistentPreRunE's style) and
		// ignore. --vex is always implied by this command.
		if generateSBOM {
			cli.PrintWarning("--sbom is ignored for `scan sbom` (the SBOM is the input, not the output)")
		}
		if sbomOutput != "" {
			cli.PrintWarning("--sbom-output is ignored for `scan sbom`")
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
		scanner := sbom.NewScanner(client, noProgress, tid, scanTimeoutDuration).
			WithVEXOutput(vexOutput)

		ctx, cancel := NewSignalContext()
		defer cancel()

		// armis:ignore cwe:22 reason:sbomPath is from direct CLI argument; sanitized via util.SanitizePath in scanner.Scan
		result, err := scanner.Scan(ctx, sbomPath)
		if err != nil {
			return handleScanError(ctx, err)
		}

		// Resolve output destination and format (handles file creation, format auto-detection, colors)
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

		// An SBOM scan produces no findings, so CheckExit never trips --fail-on;
		// call it anyway for symmetry with the other scan subcommands.
		return output.CheckExit(result, failOnSeverities, exitCode)
	},
}

func init() {
	scanCmd.AddCommand(scanSBOMCmd)
}
