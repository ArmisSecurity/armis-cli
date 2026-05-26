package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/charmbracelet/lipgloss"
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
	styled := cli.ColorsEnabled()

	var titleStyle, separatorStyle, successMark, warnMark, dimStyle lipgloss.Style
	if styled {
		titleStyle = lipgloss.NewStyle().Bold(true).Foreground(brandAccent)
		separatorStyle = lipgloss.NewStyle().Foreground(brandSeparator)
		successMark = lipgloss.NewStyle().Foreground(brandSuccess)
		warnMark = lipgloss.NewStyle().Foreground(brandWarn)
		dimStyle = lipgloss.NewStyle().Foreground(brandMuted)
	}

	if !force {
		if styled {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "  %s\n", titleStyle.Render("Armis AppSec MCP Server Uninstall"))
			fmt.Fprintf(os.Stderr, "  %s\n", separatorStyle.Render("──────────────────────────────────"))
			fmt.Fprintln(os.Stderr, "")
			msg := "  This will remove the MCP server from all editors and delete plugin files."
			if keepCreds {
				msg += "\n  Credentials (.env) will be preserved."
			}
			fmt.Fprintln(os.Stderr, dimStyle.Render(msg))
			fmt.Fprintln(os.Stderr, "")
		} else {
			msg := "This will remove the Armis AppSec MCP server from all editors and delete plugin files."
			if keepCreds {
				msg += "\nCredentials (.env) will be preserved."
			}
			fmt.Fprintln(os.Stderr, msg)
		}
		prompt := "Continue?"
		if styled {
			prompt = "  Continue?"
		}
		if !confirm(prompt) {
			fmt.Fprintln(os.Stderr, "  Aborted.")
			return nil
		}
		fmt.Fprintln(os.Stderr, "")
	}

	// Remove native hook configs from all AI clients
	for _, hc := range install.AllHookClients {
		if err := install.RemoveNativeHook(hc); err != nil {
			if styled {
				fmt.Fprintf(os.Stderr, "  %s Hook removal (%s): %v\n", warnMark.Render("⚠"), hc.Name, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ⚠ Hook removal (%s): %v\n", hc.Name, err)
			}
		}
	}

	deregistered, warnings := u.DeregisterAllEditors()
	for _, name := range deregistered {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Removed from %s\n", successMark.Render("✓"), name)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Removed from %s\n", name)
		}
	}
	for _, w := range warnings {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", warnMark.Render("⚠"), w)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
		}
	}

	if err := u.DeregisterClaude(); err != nil {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Claude Code: %v\n", warnMark.Render("⚠"), err)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ Claude Code: %v\n", err)
		}
	} else {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Removed from Claude Code\n", successMark.Render("✓"))
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Removed from Claude Code\n")
		}
	}

	if err := u.RemovePluginFiles(keepCreds); err != nil {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Plugin files: %v\n", warnMark.Render("⚠"), err)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ Plugin files: %v\n", err)
		}
	} else if keepCreds {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Plugin files removed (credentials preserved)\n", successMark.Render("✓"))
		} else {
			fmt.Fprintln(os.Stderr, "  ✓ Plugin files removed (credentials preserved)")
		}
	} else {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s Plugin files removed\n", successMark.Render("✓"))
		} else {
			fmt.Fprintln(os.Stderr, "  ✓ Plugin files removed")
		}
	}

	fmt.Fprintln(os.Stderr, "")
	if styled {
		fmt.Fprintf(os.Stderr, "  %s Armis AppSec MCP server uninstalled.\n", successMark.Render("✓"))
	} else {
		fmt.Fprintln(os.Stderr, "Armis AppSec MCP server uninstalled.")
	}
	fmt.Fprintln(os.Stderr, "")
	return nil
}

const (
	targetClaude  = "claude"
	targetCopilot = "copilot"
)

func uninstallTargets(u *install.Uninstaller, targets []string) error {
	styled := cli.ColorsEnabled()

	var successMark, failMark, warnMark, dimStyle lipgloss.Style
	if styled {
		successMark = lipgloss.NewStyle().Foreground(brandSuccess)
		failMark = lipgloss.NewStyle().Foreground(brandError)
		warnMark = lipgloss.NewStyle().Foreground(brandWarn)
		dimStyle = lipgloss.NewStyle().Foreground(brandMuted)
	}

	printSuccess := func(msg string) {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", successMark.Render("✓"), msg)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", msg)
		}
	}
	printFail := func(msg string) {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", failMark.Render("✗"), msg)
		} else {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", msg)
		}
	}
	printWarn := func(msg string) {
		if styled {
			fmt.Fprintf(os.Stderr, "  %s %s\n", warnMark.Render("⚠"), msg)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", msg)
		}
	}

	for _, name := range targets {
		switch name {
		case targetClaude:
			if err := u.DeregisterClaude(); err != nil {
				printFail(fmt.Sprintf("Claude Code: %v", err))
			} else {
				printSuccess("Claude Code")
			}
		case targetCopilot:
			if err := u.DeregisterEditor(install.EditorVSCode); err != nil {
				printFail(fmt.Sprintf("VS Code: %v", err))
			} else {
				printSuccess("VS Code")
			}
		case "jetbrains":
			printWarn("JetBrains: Remove .jb-mcp.json from your project root manually.")
		case "devin":
			printWarn("Devin: Remove the MCP server via the Devin web UI.")
		case "openhands":
			printWarn("OpenHands: Remove the MCP server via the OpenHands web UI.")
		case "aider":
			printWarn("Aider: No MCP configuration to remove.")
		default:
			id := install.EditorID(name)
			e, ok := install.EditorByID(id)
			if !ok {
				printFail(fmt.Sprintf("Unknown editor: %s", name))
				continue
			}
			if err := u.DeregisterEditor(id); err != nil {
				printFail(fmt.Sprintf("%s: %v", e.Name, err))
			} else {
				printSuccess(e.Name)
			}
		}

		if hc, ok := install.HookClientByID(install.HookClientID(name)); ok {
			if err := install.RemoveNativeHook(hc); err != nil {
				printWarn(fmt.Sprintf("Hook config (%s): %v", hc.Name, err))
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
			printWarn(fmt.Sprintf("Could not update install manifest: %v", err))
		}
	}

	fmt.Fprintln(os.Stderr, "")
	if styled {
		fmt.Fprintln(os.Stderr, dimStyle.Render("  Plugin files kept (other editors may still use them)."))
	} else {
		fmt.Fprintln(os.Stderr, "Plugin files kept (other editors may still use them).")
	}
	fmt.Fprintln(os.Stderr, "")
	return nil
}

// armis:ignore cwe:253 reason:Scan() returns false on EOF/error which is correct default-deny behavior (returns false = no confirmation)
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
