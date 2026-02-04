package cmd

import (
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

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan artifacts for security vulnerabilities",
	Long:  `Scan repositories and container images for security vulnerabilities, secrets, and license risks.`,
}

func init() {
	scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan (test files are excluded by default)")
	scanCmd.PersistentFlags().IntVar(&scanTimeout, "scan-timeout", 60, "Maximum time in minutes to wait for scan analysis to complete")
	scanCmd.PersistentFlags().IntVar(&uploadTimeout, "upload-timeout", 10, "Maximum time in minutes to wait for artifact upload to complete")
	scanCmd.PersistentFlags().BoolVar(&includeNonExploitable, "include-non-exploitable", false, "Include findings marked as non-exploitable (only exploitable findings shown by default)")
	scanCmd.PersistentFlags().StringVar(&groupBy, "group-by", "none", "Group findings by: none, cwe, severity, file")
	scanCmd.PersistentFlags().StringSliceVar(&includeFiles, "include-files", nil, "Comma-separated list of file paths to include in scan (relative to repository root)")
	scanCmd.PersistentFlags().BoolVar(&generateSBOM, "sbom", false, "Generate Software Bill of Materials (SBOM) in CycloneDX format")
	scanCmd.PersistentFlags().BoolVar(&generateVEX, "vex", false, "Generate Vulnerability Exploitability eXchange (VEX) document")
	scanCmd.PersistentFlags().StringVar(&sbomOutput, "sbom-output", "", "Output file path for SBOM (default: .armis/<artifact>-sbom.json)")
	scanCmd.PersistentFlags().StringVar(&vexOutput, "vex-output", "", "Output file path for VEX (default: .armis/<artifact>-vex.json)")
	scanCmd.PersistentFlags().BoolVar(&summaryTop, "summary-top", false, "Display summary at the top of output (before findings)")
	if rootCmd != nil {
		rootCmd.AddCommand(scanCmd)
	}
}
