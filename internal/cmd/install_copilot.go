package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var installCopilotCmd = &cobra.Command{
	Use:   "copilot",
	Short: "Install the Armis security scanner MCP server for GitHub Copilot",
	Long: `Download and install the Armis AppSec MCP server for GitHub Copilot in VS Code.

The MCP server adds AI-powered vulnerability scanning to GitHub Copilot:
  - scan_code: Scan code snippets for vulnerabilities
  - scan_file: Scan files on disk
  - scan_diff: Scan git changes before committing

After installation, configure your Armis credentials as environment variables
or update the .env file in the plugin directory, then restart VS Code.

Source: https://github.com/ArmisSecurity/armis-appsec-mcp`,
	Example: `  # Install the GitHub Copilot MCP server
  armis-cli install copilot

  # Check the installed plugin version
  armis-cli install copilot --version`,
	RunE: runInstallCopilot,
}

func init() {
	installCmd.AddCommand(installCopilotCmd)
	installCopilotCmd.Flags().Bool("version", false, "Print the installed plugin version and exit")
}

func runInstallCopilot(cmd *cobra.Command, _ []string) error {
	installer := install.NewCopilotInstaller()

	showVersion, err := cmd.Flags().GetBool("version")
	if err != nil {
		return fmt.Errorf("reading --version flag: %w", err)
	}
	if showVersion {
		v := installer.GetInstalledVersion()
		if v == "" {
			return fmt.Errorf("Armis AppSec MCP server is not installed — run: armis-cli install copilot") //nolint:staticcheck // proper noun
		}
		fmt.Fprintf(os.Stderr, "Armis AppSec MCP server v%s\n", v)
		return nil
	}

	fmt.Fprintln(os.Stderr, "Installing Armis AppSec MCP server for GitHub Copilot...")

	if err := installer.Install(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "MCP server v%s installed successfully!\n", installer.InstalledVersion())
	fmt.Fprintln(os.Stderr, "")

	if !installer.HasExistingEnv() {
		envPath := installer.EnvFilePath()
		fmt.Fprintln(os.Stderr, "Next steps:")
		fmt.Fprintf(os.Stderr, "  1. Set your credentials in %s:\n", envPath)
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_SECRET=<your-client-secret>")
		fmt.Fprintln(os.Stderr, "  2. Restart VS Code")
	} else {
		cli.PrintWarning("Existing .env file preserved — credentials were not overwritten.")
		fmt.Fprintln(os.Stderr, "Restart VS Code to pick up the updated MCP server.")
	}

	return nil
}
