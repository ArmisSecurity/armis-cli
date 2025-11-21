package cmd

import (
        "github.com/spf13/cobra"
)

var (
        includeTests bool
        timeout      int
)

var scanCmd = &cobra.Command{
        Use:   "scan",
        Short: "Scan artifacts for security vulnerabilities",
        Long:  `Scan repositories and container images for security vulnerabilities, secrets, and license risks.`,
}

func init() {
        scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan")
        scanCmd.PersistentFlags().IntVar(&timeout, "timeout", 20, "Maximum time to wait for scan to complete (in minutes)")
        if rootCmd != nil {
                rootCmd.AddCommand(scanCmd)
        }
}
