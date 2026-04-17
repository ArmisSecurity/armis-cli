package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var installClaudeCmd = &cobra.Command{
	Use:   "claude",
	Short: "Install the Armis security scanner plugin for Claude Code",
	Long: `Download and install the Armis AppSec MCP plugin for Claude Code.

The plugin adds AI-powered vulnerability scanning directly into Claude Code:
  - scan_code: Scan code snippets for vulnerabilities
  - scan_file: Scan files on disk
  - scan_diff: Scan git changes before committing

After installation, set your credentials in the plugin's .env file
and restart Claude Code.

Source: https://github.com/ArmisSecurity/armis-appsec-mcp`,
	Example: `  # Install the Claude Code plugin
  armis-cli install claude

  # Check the installed plugin version
  armis-cli install claude --version`,
	RunE: runInstallClaude,
}

func init() {
	installCmd.AddCommand(installClaudeCmd)
	installClaudeCmd.Flags().Bool("version", false, "Print the installed plugin version and exit")
}

func runInstallClaude(cmd *cobra.Command, args []string) error {
	installer := install.NewClaudeInstaller()

	showVersion, _ := cmd.Flags().GetBool("version")
	if showVersion {
		v := installer.GetInstalledVersion()
		if v == "" {
			return fmt.Errorf("Armis AppSec plugin is not installed — run: armis-cli install claude")
		}
		fmt.Fprintf(os.Stderr, "Armis AppSec plugin v%s\n", v)
		return nil
	}

	fmt.Fprintln(os.Stderr, "Installing Armis AppSec plugin for Claude Code...")

	if err := installer.Install(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "Plugin v%s installed successfully!\n", installer.InstalledVersion())
	fmt.Fprintln(os.Stderr, "")

	if !installer.HasExistingEnv() {
		home, _ := os.UserHomeDir()
		envPath := home + "/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/latest/.env"
		fmt.Fprintln(os.Stderr, "Next steps:")
		fmt.Fprintf(os.Stderr, "  1. Set your credentials in %s:\n", envPath)
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_SECRET=<your-client-secret>")
		fmt.Fprintln(os.Stderr, "  2. Restart Claude Code")
	} else {
		cli.PrintWarning("Existing .env file preserved — credentials were not overwritten.")
		fmt.Fprintln(os.Stderr, "Restart Claude Code to pick up the updated plugin.")
	}

	return nil
}
