package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install [editor...]",
	Short: "Install the Armis security scanner MCP server",
	Long: `Download and install the Armis AppSec MCP server for your coding tools.

Requires Python 3.11+ on your PATH (the MCP server runs on it).

With no arguments, installs the plugin and registers it in all detected editors.
Specify one or more editor names to target specific tools.

Supported editors:
  claude          Claude Code (uses plugin system)
  claude-desktop  Claude Desktop app (macOS/Windows)
  codex           Codex CLI (registers MCP server + hooks)
  vscode          VS Code / GitHub Copilot Chat extension
  copilot         GitHub Copilot CLI
  cursor          Cursor
  windsurf        Windsurf (Codeium)
  zed             Zed
  cline           Cline (VS Code extension)
  amazonq         Amazon Q Developer
  continue        Continue
  antigravity     Antigravity (2.0, CLI, and IDE)
  roocode         Roo Code
  junie           Junie

Not auto-configurable (manual setup required):
  jetbrains  JetBrains IDEs (per-project .jb-mcp.json)
  devin      Devin (cloud-based, configure via web UI)
  openhands  OpenHands (cloud-based, configure via web UI)
  aider      Aider (no MCP support)`,
	Example: `  # Interactive setup (prompts for credentials and editors)
  armis-cli install
  armis-cli install --interactive

  # Non-interactive install (for CI/scripts, reads credentials from env)
  armis-cli install --non-interactive

  # Non-interactive install including Armis Knowledge
  armis-cli install --non-interactive --with-knowledge

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
	installCmd.Flags().Bool("force", false, "Force reinstall even if already up to date")
	installCmd.Flags().Bool("interactive", false, "Force interactive setup wizard (even without TTY)")
	installCmd.Flags().Bool("non-interactive", false, "Disable interactive prompts (for CI/scripts)")
	installCmd.Flags().Bool("with-knowledge", false, "Also install the Armis Knowledge plugin for the selected editors")
	installCmd.MarkFlagsMutuallyExclusive("interactive", "non-interactive")
}

func runInstall(cmd *cobra.Command, args []string) error {
	showVersion, err := cmd.Flags().GetBool("version")
	if err != nil {
		return fmt.Errorf("reading --version flag: %w", err)
	}

	if showVersion {
		return showInstalledVersions()
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("reading --force flag: %w", err)
	}

	interactive, err := cmd.Flags().GetBool("interactive")
	if err != nil {
		return fmt.Errorf("reading --interactive flag: %w", err)
	}
	nonInteractive, err := cmd.Flags().GetBool("non-interactive")
	if err != nil {
		return fmt.Errorf("reading --non-interactive flag: %w", err)
	}

	withKnowledge, err := cmd.Flags().GetBool("with-knowledge")
	if err != nil {
		return fmt.Errorf("reading --with-knowledge flag: %w", err)
	}

	// Interactive mode: explicit flag, or (no args + TTY + not --non-interactive)
	if interactive || (len(args) == 0 && !nonInteractive && cli.IsInteractive()) {
		return runInteractiveInstall(force)
	}

	if len(args) == 0 {
		return installAll(force, withKnowledge)
	}

	return installTargets(args, force, withKnowledge)
}

func showInstalledVersions() error {
	ei := install.NewEditorInstaller()
	v := ei.GetInstalledVersion()

	ci, err := install.NewClaudeInstaller()
	if err != nil {
		return fmt.Errorf("failed to initialize Claude installer: %w", err)
	}
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

	ki := install.NewKnowledgeMCPInstaller(knowledgeEnvForDev(useDev))
	if sha := ki.ShortSHA(); sha != "" {
		fmt.Fprintf(os.Stderr, "Knowledge bridge: %s (commit)\n", sha)
	}
	return nil
}

func installAll(force, withKnowledge bool) error {
	if err := install.CheckPython(); err != nil {
		return err
	}

	ei := install.NewEditorInstaller()

	fmt.Fprintln(os.Stderr, "Downloading Armis AppSec MCP server...")
	if err := ei.FetchPlugin(force); err != nil {
		if errors.Is(err, install.ErrAlreadyCurrent) {
			fmt.Fprintf(os.Stderr, "Armis AppSec MCP server v%s is already up to date.\n\n", ei.InstalledVersion())
		} else {
			return fmt.Errorf("download failed: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "MCP server v%s downloaded.\n\n", ei.InstalledVersion())
	}

	manifest := install.ReadManifest(ei.PluginDir())
	if manifest == nil {
		manifest = install.NewManifest(ei.PluginDir(), ei.InstalledVersion())
	} else {
		manifest.PluginVersion = ei.InstalledVersion()
	}

	detected := install.DetectedEditors()
	var registered []string
	var failed []string
	var kt knowledgeTargets

	for _, e := range detected {
		if err := e.Register(ei.PluginDir()); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
			failed = append(failed, e.Name)
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
			registered = append(registered, e.Name)
			manifest.AddEditor(e.ID, e.ConfigPath(), install.ConfigFormat(e.ID))
			kt.editors = append(kt.editors, e)
		}

		if hc, ok := install.HookClientByID(install.HookClientID(e.ID)); ok {
			if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ %s (hooks): %v\n", e.Name, err)
			}
		}
	}

	ci, ciErr := install.NewClaudeInstaller()
	if ciErr != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", ciErr)
		failed = append(failed, "Claude Code")
	} else if err := ci.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", err)
		failed = append(failed, "Claude Code")
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Claude Code\n")
		registered = append(registered, "Claude Code")
		manifest.SetClaude(ci.PluginCacheDir())
		kt.claude = true
	}

	if install.IsCodexDetected() {
		if err := install.RegisterCodexMCP(ei.PluginDir()); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Codex CLI (MCP): %v\n", err)
			failed = append(failed, "Codex CLI")
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (MCP)\n")
			registered = append(registered, "Codex CLI")
			manifest.SetCodex(install.CodexConfigPath())
			kt.codex = true
		}
		if hc, ok := install.HookClientByID(install.HookClientCodex); ok {
			if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ Codex CLI (hooks): %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (hooks)\n")
			}
		}
	}

	var kres knowledgeResult
	if withKnowledge {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Installing Armis Knowledge...")
		kres = installKnowledgeFor(kt, force, manifest)
	}

	if err := install.WriteManifest(manifest); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
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
	if withKnowledge {
		printKnowledgeResult(kres)
	}

	printCredentialStatus(ei)
	return nil
}

func installTargets(targets []string, force, withKnowledge bool) error {
	hasClaude := false
	var editorIDs []install.EditorID
	var kt knowledgeTargets

	hasCodex := false

	for _, name := range targets {
		switch name {
		case "claude":
			hasClaude = true
		case targetCodex:
			hasCodex = true
		case "copilot":
			editorIDs = append(editorIDs, install.EditorCopilotCLI)
		case "jetbrains":
			fmt.Fprintln(os.Stderr, "JetBrains: MCP servers are configured per-project (no automatic setup).")
			fmt.Fprintln(os.Stderr, "  1. Install the MCP server first: armis-cli install <editor>")
			fmt.Fprintln(os.Stderr, "  2. Create a .jb-mcp.json in your project root pointing at the installed")
			fmt.Fprintln(os.Stderr, "     server, then enable it in your IDE's AI Assistant MCP settings.")
			fmt.Fprintln(os.Stderr, "")
		case "devin":
			fmt.Fprintln(os.Stderr, "Devin: MCP servers are configured via the Devin web UI.")
			fmt.Fprintln(os.Stderr, "See: Settings → MCP Servers in your Devin dashboard.")
			fmt.Fprintln(os.Stderr, "")
		case "openhands":
			fmt.Fprintln(os.Stderr, "OpenHands: MCP servers are configured via the web UI.")
			fmt.Fprintln(os.Stderr, "See: Settings → MCP Servers in your OpenHands dashboard.")
			fmt.Fprintln(os.Stderr, "")
		case "aider":
			fmt.Fprintln(os.Stderr, "Aider does not support MCP servers.")
			fmt.Fprintln(os.Stderr, "")
		default:
			id := install.EditorID(name)
			if _, ok := install.EditorByID(id); !ok {
				return fmt.Errorf("unknown editor %q — run 'armis-cli install --help' for supported editors", name)
			}
			editorIDs = append(editorIDs, id)
		}
	}

	needsSharedPlugin := len(editorIDs) > 0 || hasCodex

	// Both the shared-plugin and Claude paths build a Python venv, so verify the
	// interpreter is present before downloading anything (advisory-only targets
	// like "jetbrains" skip the download and so skip this check).
	if needsSharedPlugin || hasClaude {
		if err := install.CheckPython(); err != nil {
			return err
		}
	}

	var ei *install.EditorInstaller

	if needsSharedPlugin {
		ei = install.NewEditorInstaller()
		fmt.Fprintln(os.Stderr, "Downloading Armis AppSec MCP server...")
		if err := ei.FetchPlugin(force); err != nil {
			if errors.Is(err, install.ErrAlreadyCurrent) {
				fmt.Fprintf(os.Stderr, "Armis AppSec MCP server v%s is already up to date.\n\n", ei.InstalledVersion())
			} else {
				return fmt.Errorf("download failed: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "MCP server v%s downloaded.\n\n", ei.InstalledVersion())
		}

		manifest := install.ReadManifest(ei.PluginDir())
		if manifest == nil {
			manifest = install.NewManifest(ei.PluginDir(), ei.InstalledVersion())
		} else {
			manifest.PluginVersion = ei.InstalledVersion()
		}

		for _, id := range editorIDs {
			e, ok := install.EditorByID(id)
			if !ok {
				continue
			}
			if err := e.Register(ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
				manifest.AddEditor(e.ID, e.ConfigPath(), install.ConfigFormat(e.ID))
				kt.editors = append(kt.editors, e)
			}

			if hc, ok := install.HookClientByID(install.HookClientID(id)); ok {
				if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
					fmt.Fprintf(os.Stderr, "  ⚠ %s (hooks): %v\n", e.Name, err)
				}
			}
		}

		if hasCodex {
			if err := install.RegisterCodexMCP(ei.PluginDir()); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Codex CLI (MCP): %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (MCP)\n")
				manifest.SetCodex(install.CodexConfigPath())
				kt.codex = true
			}
			if hc, ok := install.HookClientByID(install.HookClientCodex); ok {
				if err := install.InstallNativeHook(hc, ei.PluginDir()); err != nil {
					fmt.Fprintf(os.Stderr, "  ⚠ Codex CLI (hooks): %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (hooks)\n")
				}
			}
		}

		if err := install.WriteManifest(manifest); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "")
		printCredentialStatus(ei)
	}

	if hasClaude {
		ci, ciErr := install.NewClaudeInstaller()
		if ciErr != nil {
			return fmt.Errorf("Claude Code installation failed: %w", ciErr) //nolint:staticcheck // proper noun
		}
		fmt.Fprintln(os.Stderr, "Installing Armis AppSec plugin for Claude Code...")
		if err := ci.Install(); err != nil {
			return fmt.Errorf("Claude Code installation failed: %w", err) //nolint:staticcheck // proper noun
		}
		fmt.Fprintf(os.Stderr, "  ✓ Claude Code v%s\n", ci.InstalledVersion())
		fmt.Fprintln(os.Stderr, "")
		kt.claude = true

		pluginDir := install.NewEditorInstaller().PluginDir()
		manifest := install.ReadManifest(pluginDir)
		if manifest == nil {
			manifest = install.NewManifest(pluginDir, ci.InstalledVersion())
		}
		manifest.SetClaude(ci.PluginCacheDir())
		if err := install.WriteManifest(manifest); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
		}

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

	if withKnowledge {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Installing Armis Knowledge...")

		pluginDir := install.NewEditorInstaller().PluginDir()
		manifest := install.ReadManifest(pluginDir)
		kres := installKnowledgeFor(kt, force, manifest)
		if manifest != nil {
			if err := install.WriteManifest(manifest); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
			}
		}
		printKnowledgeResult(kres)
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

// printKnowledgeResult renders the knowledge install outcome. Failures print as
// warnings, never errors — knowledge must not fail a working scanner install.
func printKnowledgeResult(res knowledgeResult) {
	for _, w := range res.warnings {
		fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
	}
	if len(res.registered) > 0 {
		if res.shortSHA != "" {
			fmt.Fprintf(os.Stderr, "  ✓ Knowledge bridge (%s)\n", res.shortSHA)
		}
		fmt.Fprintf(os.Stderr, "  ✓ Knowledge registered in: %s\n", strings.Join(res.registered, ", "))
		fmt.Fprintln(os.Stderr, "")
		// The bridge reads these at startup and fails without them, so say so
		// whether or not credentials were configured during this run.
		if install.CredentialsPresent() {
			fmt.Fprintln(os.Stderr, "Knowledge reads ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET at runtime.")
		} else {
			fmt.Fprintln(os.Stderr, "Knowledge needs credentials exported before it can answer queries:")
			fmt.Fprintln(os.Stderr, "  export ARMIS_CLIENT_ID=<your-client-id>")
			fmt.Fprintln(os.Stderr, "  export ARMIS_CLIENT_SECRET=<your-client-secret>")
		}
	} else if !res.skipped {
		fmt.Fprintln(os.Stderr, "  ⚠ Knowledge was not registered in any editor.")
	}
}
