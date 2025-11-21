package cmd

import (
        "github.com/spf13/cobra"
)

var (
        includeTests bool
)

var scanCmd = &cobra.Command{
        Use:   "scan",
        Short: "Scan artifacts for security vulnerabilities",
        Long:  `Scan repositories and container images for security vulnerabilities, secrets, and license risks.`,
}

func init() {
        scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan")
        rootCmd.AddCommand(scanCmd)
}
