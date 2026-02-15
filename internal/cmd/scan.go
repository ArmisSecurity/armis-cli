package cmd

import (
	"fmt"
	"strings"

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
)

// validFormats contains the valid output format strings.
var validFormats = []string{"human", "json", "sarif", "junit"}

// validGroupBy contains the valid group-by options.
var validGroupBy = []string{"none", "cwe", "severity", "file"}

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

		// Validate timeout values: must be positive
		if scanTimeout < 1 {
			return fmt.Errorf("invalid --scan-timeout value %d: must be at least 1 minute", scanTimeout)
		}
		if uploadTimeout < 1 {
			return fmt.Errorf("invalid --upload-timeout value %d: must be at least 1 minute", uploadTimeout)
		}

		return nil
	},
}

func init() {
	scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan (test files are excluded by default)")
	scanCmd.PersistentFlags().IntVar(&scanTimeout, "scan-timeout", 60, "Maximum time in minutes to wait for scan analysis to complete")
	scanCmd.PersistentFlags().IntVar(&uploadTimeout, "upload-timeout", 10, "Maximum time in minutes to wait for artifact upload to complete")
	scanCmd.PersistentFlags().BoolVar(&includeNonExploitable, "include-non-exploitable", false, "Show non-exploitable findings (hidden by default)")
	scanCmd.PersistentFlags().StringVar(&groupBy, "group-by", "none", "Group findings by: none, cwe, severity, file")
	scanCmd.PersistentFlags().BoolVar(&generateSBOM, "sbom", false, "Generate Software Bill of Materials (SBOM) in CycloneDX format")
	scanCmd.PersistentFlags().BoolVar(&generateVEX, "vex", false, "Generate Vulnerability Exploitability eXchange (VEX) document")
	scanCmd.PersistentFlags().StringVar(&sbomOutput, "sbom-output", "", "Output file path for SBOM (default: .armis/<artifact>-sbom.json)")
	scanCmd.PersistentFlags().StringVar(&vexOutput, "vex-output", "", "Output file path for VEX (default: .armis/<artifact>-vex.json)")
	scanCmd.PersistentFlags().BoolVar(&summaryTop, "summary-top", false, "Display summary at the top of output (before findings)")
	if rootCmd != nil {
		rootCmd.AddCommand(scanCmd)
	}
}
