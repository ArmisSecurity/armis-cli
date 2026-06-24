package cmd

import (
	"fmt"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	includeTests          bool
	scanTimeout           int
	uploadTimeout         int
	includeNonExploitable bool
	groupBy               string
	includeFiles          []string
	generateSBOM          bool
	generateVEX           bool
	sbomOutput            string
	vexOutput             string
	summaryTop            bool
	outputFile            string
)

// validFormats contains the valid output format strings.
var validFormats = []string{"human", "json", "sarif", "junit"}

// validGroupBy contains the valid group-by options.
var validGroupBy = []string{"none", "cwe", "severity", "file"}

// defaultFailOn returns the default --fail-on severity set. It returns a fresh
// slice on each call so the two flag registrations (scanCmd and scCheckCmd)
// never share backing storage — pflag parsing mutates a StringSlice's default
// in place, which would otherwise leak between the two flag instances.
func defaultFailOn() []string { return []string{"CRITICAL"} }

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan artifacts for security vulnerabilities",
	Long:  `Scan repositories and container images for security vulnerabilities, secrets, and license risks.`,
	Example: `  # Scan a repository
  armis-cli scan repo /path/to/repo

  # Scan a container image
  armis-cli scan image myapp:latest

  # Scan with SBOM generation
  armis-cli scan repo . --sbom --sbom-output sbom.json`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Call root command's PersistentPreRunE to initialize colors and update checking
		// We reference rootCmd directly since cmd.Parent() would return scanCmd for subcommands
		if rootCmd != nil && rootCmd.PersistentPreRunE != nil {
			if err := rootCmd.PersistentPreRunE(cmd, args); err != nil {
				return err
			}
		}

		// Validate format early to fail fast
		if _, err := output.GetFormatter(format); err != nil {
			return fmt.Errorf("invalid --format value %q: must be one of %v", format, validFormats)
		}

		// Validate group-by early
		validGroupBySet := make(map[string]bool)
		for _, g := range validGroupBy {
			validGroupBySet[g] = true
		}
		if !validGroupBySet[strings.ToLower(groupBy)] {
			return fmt.Errorf("invalid --group-by value %q: must be one of %v", groupBy, validGroupBy)
		}

		// Validate exit-code: must be between 1 and 255 (0 defeats --fail-on, >255 is invalid POSIX)
		if exitCode < 1 || exitCode > 255 {
			return fmt.Errorf("invalid --exit-code value %d: must be between 1 and 255", exitCode)
		}

		// Validate timeout values: must be positive and bounded
		if scanTimeout < 1 {
			return fmt.Errorf("invalid --scan-timeout value %d: must be at least 1 minute", scanTimeout)
		}
		const maxScanTimeout = 1440 // 24 hours
		if scanTimeout > maxScanTimeout {
			return fmt.Errorf("invalid --scan-timeout value %d: must not exceed %d minutes (24 hours)", scanTimeout, maxScanTimeout)
		}
		if uploadTimeout < 1 {
			return fmt.Errorf("invalid --upload-timeout value %d: must be at least 1 minute", uploadTimeout)
		}
		const maxUploadTimeout = 120 // 2 hours
		if uploadTimeout > maxUploadTimeout {
			return fmt.Errorf("invalid --upload-timeout value %d: must not exceed %d minutes", uploadTimeout, maxUploadTimeout)
		}

		// Validate --fail-on early so a typo (e.g. HIGHT) surfaces as a flag error
		// instead of silently defaulting once auth succeeds. ValidateFailOn also
		// normalizes the slice to uppercase in place, so the GetFailOn calls in the
		// subcommands' RunE become idempotent re-validation.
		if err := cmdutil.ValidateFailOn(failOn); err != nil {
			return err
		}

		// Warn early if SBOM/VEX output paths are given without their generation
		// flags. These are persistent flags shared by `scan repo` and `scan image`,
		// so surfacing the misuse here (before auth) keeps both commands consistent
		// and stops the warning from hiding behind an auth error in CI.
		if sbomOutput != "" && !generateSBOM {
			cli.PrintWarning("--sbom-output is ignored without --sbom flag")
		}
		if vexOutput != "" && !generateVEX {
			cli.PrintWarning("--vex-output is ignored without --vex flag")
		}

		return nil
	},
}

func init() {
	// Scan-output flags. These were previously root persistent flags but only
	// apply to the scan subtree, so they are scoped here to keep them out of the
	// --help of non-scan commands (hook, supply-chain, install, agent-detection).
	// Defaults and env bindings are preserved verbatim from their former root
	// registrations. `supply-chain check` re-registers the subset it consumes
	// locally (see supply_chain_check.go), since it is a sibling of scan.
	scanCmd.PersistentFlags().StringVarP(&format, "format", "f", getEnvOrDefault("ARMIS_FORMAT", "human"), "Output format: human, json, sarif, junit")
	scanCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Suppress progress output (for CI/scripts)")
	scanCmd.PersistentFlags().StringSliceVar(&failOn, "fail-on", defaultFailOn(), "Exit with error on findings at these severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL")
	scanCmd.PersistentFlags().IntVar(&exitCode, "exit-code", 1, "Exit code when --fail-on triggers")
	scanCmd.PersistentFlags().IntVar(&pageLimit, "page-limit", getEnvOrDefaultInt("ARMIS_PAGE_LIMIT", 500), "Results page size for pagination (range: 1-1000)")
	// Tab-completion for the relocated enumerated flags now lives with the flags.
	_ = scanCmd.RegisterFlagCompletionFunc("format", formatCompletions())
	_ = scanCmd.RegisterFlagCompletionFunc("fail-on", failOnCompletions())

	scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan (test files are excluded by default)")
	scanCmd.PersistentFlags().IntVar(&scanTimeout, "scan-timeout", 60, "Maximum time in minutes to wait for scan analysis to complete")
	scanCmd.PersistentFlags().IntVar(&uploadTimeout, "upload-timeout", 10, "Maximum time in minutes to wait for artifact upload to complete")
	scanCmd.PersistentFlags().BoolVar(&includeNonExploitable, "include-non-exploitable", false, "Show low/medium exploitability findings (hidden by default; high and ungraded findings always shown)")
	scanCmd.PersistentFlags().StringVar(&groupBy, "group-by", "none", "Group findings by: none, cwe, severity, file")
	_ = scanCmd.RegisterFlagCompletionFunc("group-by", fixedCompletions(validGroupBy, map[string]string{
		"none":     "No grouping (default)",
		"cwe":      "Group findings by CWE identifier",
		"severity": "Group findings by severity level",
		"file":     "Group findings by file path",
	}))
	scanCmd.PersistentFlags().BoolVar(&generateSBOM, "sbom", false, "Generate Software Bill of Materials (SBOM) in CycloneDX format")
	scanCmd.PersistentFlags().BoolVar(&generateVEX, "vex", false, "Generate Vulnerability Exploitability eXchange (VEX) document")
	scanCmd.PersistentFlags().StringVar(&sbomOutput, "sbom-output", "", "Output file path for SBOM (default: .armis/<artifact>-sbom.json)")
	scanCmd.PersistentFlags().StringVar(&vexOutput, "vex-output", "", "Output file path for VEX (default: .armis/<artifact>-vex.json)")
	scanCmd.PersistentFlags().BoolVar(&summaryTop, "summary-top", false, "Display summary at the top of output (before findings)")
	scanCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Write output to file (auto-detects format from extension: .json, .sarif, .xml)")
	if rootCmd != nil {
		rootCmd.AddCommand(scanCmd)
	}
}
