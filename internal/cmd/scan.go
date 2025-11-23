package cmd

import (
        "github.com/spf13/cobra"
)

var (
        includeTests          bool
        timeout               int
        includeNonExploitable bool
        groupBy               string
)

var scanCmd = &cobra.Command{
        Use:   "scan",
        Short: "Scan artifacts for security vulnerabilities",
        Long:  `Scan repositories and container images for security vulnerabilities, secrets, and license risks.`,
}

func init() {
        scanCmd.PersistentFlags().BoolVar(&includeTests, "include-tests", false, "Include test files in the scan (default: false, test files are excluded)")
        scanCmd.PersistentFlags().IntVar(&timeout, "timeout", 20, "Maximum time in minutes to wait for scan completion (default: 20)")
        scanCmd.PersistentFlags().BoolVar(&includeNonExploitable, "include-non-exploitable", false, "Include findings marked as non-exploitable (default: false, only exploitable findings shown)")
        scanCmd.PersistentFlags().StringVar(&groupBy, "group-by", "none", "Group findings by: none, cwe, severity, file (default: none)")
        if rootCmd != nil {
                rootCmd.AddCommand(scanCmd)
        }
}
