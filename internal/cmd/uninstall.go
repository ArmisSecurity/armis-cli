package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall [editor...]",
	Short: "Remove the Armis security scanner MCP server",
	Long: `Remove the Armis AppSec MCP server from your coding tools.

With no arguments, removes the plugin from all editors and deletes plugin files.
Specify editor names to remove from specific tools only (plugin files are kept).

Use --keep-credentials to preserve the .env file for easy reinstall.
Use --force to skip the confirmation prompt.`,
	Example: `  # Remove from all editors and delete plugin
  armis-cli uninstall

  # Remove from specific editors only (keep plugin)
  armis-cli uninstall cursor vscode

  # Remove all but preserve credentials
  armis-cli uninstall --keep-credentials

  # Skip confirmation
  armis-cli uninstall --force`,
	RunE: runUninstall,
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
	uninstallCmd.Flags().Bool("keep-credentials", false, "Preserve the .env credentials file")
	uninstallCmd.Flags().Bool("force", false, "Skip confirmation prompt")
}

func runUninstall(cmd *cobra.Command, args []string) error {
	keepCreds, err := cmd.Flags().GetBool("keep-credentials")
	if err != nil {
		return fmt.Errorf("reading --keep-credentials flag: %w", err)
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("reading --force flag: %w", err)
	}

	u := install.NewUninstaller()

	if len(args) > 0 {
		return uninstallTargets(u, args)
	}

	return uninstallAll(u, keepCreds, force)
}

func uninstallAll(u *install.Uninstaller, keepCreds, force bool) error {
	if !force {
		msg := "This will remove the Armis AppSec MCP server from all editors and delete plugin files."
		if keepCreds {
			msg += "\nCredentials (.env) will be preserved."
		}
		fmt.Fprintln(os.Stderr, msg)
		if !confirm("Continue?") {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
		fmt.Fprintln(os.Stderr, "")
	}

	deregistered, warnings := u.DeregisterAllEditors()
	for _, name := range deregistered {
		fmt.Fprintf(os.Stderr, "  ✓ Removed from %s\n", name)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
	}

	if err := u.DeregisterClaude(); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Claude Code: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Removed from Claude Code\n")
	}

	if err := u.RemovePluginFiles(keepCreds); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Plugin files: %v\n", err)
	} else if keepCreds {
		fmt.Fprintln(os.Stderr, "  ✓ Plugin files removed (credentials preserved)")
	} else {
		fmt.Fprintln(os.Stderr, "  ✓ Plugin files removed")
	}

	fmt.Fprintln(os.Stderr, "\nArmis AppSec MCP server uninstalled.")
	return nil
}

const (
	targetClaude  = "claude"
	targetCopilot = "copilot"
)

func uninstallTargets(u *install.Uninstaller, targets []string) error {
	for _, name := range targets {
		switch name {
		case targetClaude:
			if err := u.DeregisterClaude(); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ Claude Code\n")
			}
		case targetCopilot:
			if err := u.DeregisterEditor(install.EditorVSCode); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ VS Code: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ VS Code\n")
			}
		case "jetbrains":
			fmt.Fprintln(os.Stderr, "  ⚠ JetBrains: Remove .jb-mcp.json from your project root manually.")
		case "devin":
			fmt.Fprintln(os.Stderr, "  ⚠ Devin: Remove the MCP server via the Devin web UI.")
		case "openhands":
			fmt.Fprintln(os.Stderr, "  ⚠ OpenHands: Remove the MCP server via the OpenHands web UI.")
		case "aider":
			fmt.Fprintln(os.Stderr, "  ⚠ Aider: No MCP configuration to remove.")
		default:
			id := install.EditorID(name)
			e, ok := install.EditorByID(id)
			if !ok {
				fmt.Fprintf(os.Stderr, "  ✗ Unknown editor: %s\n", name)
				continue
			}
			if err := u.DeregisterEditor(id); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
			}
		}
	}

	// Update manifest if one exists
	manifest := install.ReadManifest(u.PluginDir())
	if manifest != nil {
		for _, name := range targets {
			switch name {
			case targetClaude:
				manifest.Claude = nil
			case targetCopilot:
				manifest.RemoveEditor(install.EditorVSCode)
			default:
				manifest.RemoveEditor(install.EditorID(name))
			}
		}
		if err := install.WriteManifest(manifest); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Could not update install manifest: %v\n", err)
		}
	}

	fmt.Fprintln(os.Stderr, "\nPlugin files kept (other editors may still use them).")
	return nil
}

func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 256))
	if !scanner.Scan() {
		return false
	}
	line := scanner.Text()
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}
