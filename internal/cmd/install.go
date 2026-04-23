package cmd

import (
	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Armis integrations",
	Long:  `Install Armis integrations for development tools.`,
	Example: `  # Install the Claude Code MCP plugin
  armis-cli install claude

  # Install the GitHub Copilot MCP server
  armis-cli install copilot`,
}

func init() {
	rootCmd.AddCommand(installCmd)
}
