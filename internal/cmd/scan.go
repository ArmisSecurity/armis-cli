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
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan artifacts for security vulnerabilities",
	Long:  `Scan repositories and container images for security vulnerabilities, secrets, and license risks.`,
}

func init() {
	scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan (test files are excluded by default)")
	scanCmd.PersistentFlags().IntVar(&scanTimeout, "scan-timeout", 20, "Maximum time in minutes to wait for scan analysis to complete")
	scanCmd.PersistentFlags().IntVar(&uploadTimeout, "upload-timeout", 10, "Maximum time in minutes to wait for artifact upload to complete")
	scanCmd.PersistentFlags().BoolVar(&includeNonExploitable, "include-non-exploitable", false, "Include findings marked as non-exploitable (only exploitable findings shown by default)")
	scanCmd.PersistentFlags().StringVar(&groupBy, "group-by", "none", "Group findings by: none, cwe, severity, file")
	if rootCmd != nil {
		rootCmd.AddCommand(scanCmd)
	}
}
