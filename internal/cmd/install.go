package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install [editor...]",
	Short: "Install the Armis security scanner MCP server",
	Long: `Download and install the Armis AppSec MCP server for your coding tools.

With no arguments, installs the plugin and registers it in all detected editors.
Specify one or more editor names to target specific tools.

Supported editors:
  claude     Claude Code (uses plugin system)
  vscode     VS Code / GitHub Copilot
  copilot    Alias for vscode
  cursor     Cursor
  windsurf   Windsurf (Codeium)
  zed        Zed
  cline      Cline (VS Code extension)
  amazonq    Amazon Q Developer
  continue   Continue

Not auto-configurable (manual setup required):
  jetbrains  JetBrains IDEs (per-project .jb-mcp.json)
  devin      Devin (cloud-based, configure via web UI)
  aider      Aider (no MCP support)`,
	Example: `  # Install to all detected editors
  armis-cli install

  # Install to specific editors
  armis-cli install vscode cursor

  # Install to Claude Code only
  armis-cli install claude

  # Check installed version
  armis-cli install --version`,
	RunE: runInstall,
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().Bool("version", false, "Print the installed plugin version and exit")
}

func runInstall(cmd *cobra.Command, args []string) error {
	showVersion, err := cmd.Flags().GetBool("version")
	if err != nil {
		return fmt.Errorf("reading --version flag: %w", err)
	}

	if showVersion {
		return showInstalledVersions()
	}

	if len(args) == 0 {
		return installAll()
	}

	return installTargets(args)
}

func showInstalledVersions() error {
	ei := install.NewEditorInstaller()
	v := ei.GetInstalledVersion()

	ci := install.NewClaudeInstaller()
	cv := ci.GetInstalledVersion()

	if v == "" && cv == "" {
		return fmt.Errorf("Armis AppSec MCP server is not installed — run: armis-cli install") //nolint:staticcheck // proper noun
	}

	if cv != "" {
		fmt.Fprintf(os.Stderr, "Claude Code plugin: v%s\n", cv)
	}
	if v != "" {
		fmt.Fprintf(os.Stderr, "MCP server: v%s\n", v)
	}
	return nil
}

func installAll() error {
	ei := install.NewEditorInstaller()

	fmt.Fprintln(os.Stderr, "Downloading Armis AppSec MCP server...")
	if err := ei.FetchPlugin(); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "MCP server v%s downloaded.\n\n", ei.InstalledVersion())

	detected := install.DetectedEditors()
	var registered []string
	var failed []string

	for _, e := range detected {
		if err := e.Register(ei.PluginDir()); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
			failed = append(failed, e.Name)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
			registered = append(registered, e.Name)
		}
	}

	ci := install.NewClaudeInstaller()
	if err := ci.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", err)
		failed = append(failed, "Claude Code")
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Claude Code\n")
		registered = append(registered, "Claude Code")
	}

	fmt.Fprintln(os.Stderr, "")

	if len(registered) > 0 {
		fmt.Fprintf(os.Stderr, "Registered in: %s\n", strings.Join(registered, ", "))
	}
	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", strings.Join(failed, ", "))
	}
	if len(detected) == 0 && len(registered) <= 1 {
		fmt.Fprintln(os.Stderr, "No additional editors detected. Use 'armis-cli install <editor>' to target a specific tool.")
	}

	printCredentialStatus(ei)
	return nil
}

func installTargets(targets []string) error {
	hasClaude := false
	var editorIDs []install.EditorID

	for _, name := range targets {
		switch name {
		case "claude":
			hasClaude = true
		case "copilot":
			editorIDs = append(editorIDs, install.EditorVSCode)
		case "jetbrains":
			fmt.Fprintln(os.Stderr, "JetBrains: MCP servers are configured per-project.")
			fmt.Fprintln(os.Stderr, "After installing, copy .jb-mcp.json to your project root.")
			fmt.Fprintln(os.Stderr, "Run: armis-cli install --jetbrains-project /path/to/project")
			fmt.Fprintln(os.Stderr, "")
		case "devin":
			fmt.Fprintln(os.Stderr, "Devin: MCP servers are configured via the Devin web UI.")
			fmt.Fprintln(os.Stderr, "See: Settings → MCP Servers in your Devin dashboard.")
			return nil
		case "aider":
			fmt.Fprintln(os.Stderr, "Aider does not support MCP servers.")
			return nil
		default:
			id := install.EditorID(name)
			if _, ok := install.EditorByID(id); !ok {
				return fmt.Errorf("unknown editor %q — run 'armis-cli install --help' for supported editors", name)
			}
			editorIDs = append(editorIDs, id)
		}
	}

	needsSharedPlugin := len(editorIDs) > 0
	var ei *install.EditorInstaller

	if needsSharedPlugin {
		ei = install.NewEditorInstaller()
		fmt.Fprintln(os.Stderr, "Downloading Armis AppSec MCP server...")
		if err := ei.FetchPlugin(); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "MCP server v%s downloaded.\n\n", ei.InstalledVersion())

		for _, id := range editorIDs {
			e, _ := install.EditorByID(id)
			if err := e.Register(ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
			}
		}
		fmt.Fprintln(os.Stderr, "")
		printCredentialStatus(ei)
	}

	if hasClaude {
		ci := install.NewClaudeInstaller()
		fmt.Fprintln(os.Stderr, "Installing Armis AppSec plugin for Claude Code...")
		if err := ci.Install(); err != nil {
			return fmt.Errorf("Claude Code installation failed: %w", err) //nolint:staticcheck // proper noun
		}
		fmt.Fprintf(os.Stderr, "  ✓ Claude Code v%s\n", ci.InstalledVersion())
		fmt.Fprintln(os.Stderr, "")

		if ci.HasExistingEnv() {
			fmt.Fprintln(os.Stderr, "Credentials configured. Restart Claude Code to pick up the updated plugin.")
		} else {
			fmt.Fprintln(os.Stderr, "Next steps:")
			fmt.Fprintf(os.Stderr, "  1. Set your credentials in %s:\n", ci.EnvFilePath())
			fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_ID=<your-client-id>")
			fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_SECRET=<your-client-secret>")
			fmt.Fprintln(os.Stderr, "  2. Restart Claude Code")
		}
	}

	return nil
}

func printCredentialStatus(ei *install.EditorInstaller) {
	if ei.HasExistingEnv() {
		fmt.Fprintln(os.Stderr, "Credentials configured. Restart your editors to use the MCP server.")
	} else {
		fmt.Fprintln(os.Stderr, "Next steps:")
		fmt.Fprintf(os.Stderr, "  1. Set your credentials in %s:\n", ei.EnvFilePath())
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_SECRET=<your-client-secret>")
		fmt.Fprintln(os.Stderr, "  2. Restart your editors")
	}
}
