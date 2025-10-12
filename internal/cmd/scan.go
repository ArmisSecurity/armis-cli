package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan artifacts for security vulnerabilities",
	Long:  `Scan repositories, container images, or files for security vulnerabilities, secrets, and license risks.`,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
