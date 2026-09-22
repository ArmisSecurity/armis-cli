package cmd

import (
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Inspect and debug MCP server setup",
	Long: `Inspect and debug the MCP servers armis-cli install registered.

Use 'armis-cli mcp doctor' to check the scanner and knowledge MCP servers:
plugin files, credentials, editor registrations, and a live handshake.`,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
