package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

Per-project setup:
  jetbrains  JetBrains AI Assistant (writes <project>/.jb-mcp.json; pass --project)

Not auto-configurable (manual setup required):
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

  # Machine-readable result for scripts and MDM rollouts (JSON on stdout,
  # progress on stderr; implies --non-interactive)
  armis-cli install --format json

  # Overwrite the client ID and secret in every managed .env with the values
  # from ARMIS_CLIENT_ID / ARMIS_CLIENT_SECRET
  armis-cli install --non-interactive --rotate-credentials

  # Install to specific editors
  armis-cli install vscode cursor

  # Install to Claude Code only
  armis-cli install claude

  # Register the MCP server for a JetBrains project
  armis-cli install jetbrains --project ~/code/my-repo

  # Pin the MCP server to one release (kept by 'mcp update' and 'mcp doctor --fix')
  armis-cli install --plugin-version 1.4.2

  # Drop the pin and follow the latest release again
  armis-cli install --plugin-version latest

  # Check installed version
  armis-cli install --version

  # Debug a broken or missing MCP setup
  armis-cli mcp doctor`,
	RunE: runInstall,
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().Bool("version", false, "Print the installed plugin version and exit")
	installCmd.Flags().Bool("force", false, "Force reinstall even if already up to date")
	installCmd.Flags().Bool("interactive", false, "Force interactive setup wizard (even without TTY)")
	installCmd.Flags().Bool("non-interactive", false, "Disable interactive prompts (for CI/scripts)")
	installCmd.Flags().Bool("with-knowledge", false, "Also install the Armis Knowledge plugin for the selected editors")
	installCmd.Flags().String("plugin-version", "", "Install this MCP server release (e.g. 1.4.2) and keep it on updates; \"latest\" clears the pin. Also read from ARMIS_MCP_VERSION")
	installCmd.Flags().String("project", "", "Project directory for the jetbrains target (writes <project>/.jb-mcp.json)")
	installCmd.Flags().Bool("rotate-credentials", false, "Overwrite the client ID and secret in every managed .env with ARMIS_CLIENT_ID/ARMIS_CLIENT_SECRET (implies --non-interactive)")
	installCmd.Flags().StringP("format", "f", agentFormatPlain, "Output format: plain, json (json writes one document to stdout and implies --non-interactive)")
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

	project, err := cmd.Flags().GetString("project")
	if err != nil {
		return fmt.Errorf("reading --project flag: %w", err)
	}

	rotate, err := cmd.Flags().GetBool("rotate-credentials")
	if err != nil {
		return fmt.Errorf("reading --rotate-credentials flag: %w", err)
	}
	formatStr, err := cmd.Flags().GetString("format")
	if err != nil {
		return fmt.Errorf("reading --format flag: %w", err)
	}
	format, err := parseOutputFormat(formatStr)
	if err != nil {
		return err
	}

	opts := installOptions{force: force, withKnowledge: withKnowledge, format: format, jetbrainsProject: project}

	// A script reading stdout needs a document even when the flags are rejected.
	failEarly := func(err error) error { return finishInstall(opts, newInstallReport(), err) }

	pluginVersion, err := cmd.Flags().GetString("plugin-version")
	if err != nil {
		return failEarly(fmt.Errorf("reading --plugin-version flag: %w", err))
	}
	if err := install.SetVersionPin(pluginVersion); err != nil {
		return failEarly(err)
	}
	if pluginVersion == "" {
		if err := install.ValidatePinEnv(); err != nil {
			return failEarly(err)
		}
	}

	if rotate {
		creds, err := rotationCredentialsFromEnv()
		if err != nil {
			return failEarly(err)
		}
		opts.rotateTo = creds
	}

	// Both flags take their credentials from the environment, so neither can
	// run the wizard that asks for them.
	scripted := opts.json() || rotate
	if interactive && scripted {
		return failEarly(fmt.Errorf("--interactive cannot be combined with --format json or --rotate-credentials"))
	}

	// Interactive mode: explicit flag, or (no args + TTY + not --non-interactive)
	if interactive || (len(args) == 0 && !nonInteractive && !scripted && cli.IsInteractive()) {
		return runInteractiveInstall(force)
	}

	if len(args) == 0 {
		return installAll(opts)
	}

	return installTargets(args, opts)
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

func installAll(opts installOptions) error {
	rep := newInstallReport()
	var tracker credentialTracker
	err := installAllInto(opts, rep, &tracker)
	return finishInstall(opts, rep, err)
}

func installAllInto(opts installOptions, rep *installReport, tracker *credentialTracker) error {
	if err := install.CheckPython(); err != nil {
		return err
	}

	ei := install.NewEditorInstaller()
	sharedEnv := tracker.watch(ei.EnvFilePath())

	fmt.Fprintln(os.Stderr, "Downloading Armis AppSec MCP server...")
	alreadyCurrent := false
	if err := ei.FetchPlugin(opts.force); err != nil {
		if errors.Is(err, install.ErrAlreadyCurrent) {
			alreadyCurrent = true
			fmt.Fprintf(os.Stderr, "Armis AppSec MCP server v%s is already up to date.\n\n", ei.InstalledVersion())
		} else {
			return fmt.Errorf("download failed: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "MCP server v%s downloaded.\n\n", ei.InstalledVersion())
	}
	sharedEnv.managed = true
	rep.setPlugin(ei.InstalledVersion(), ei.PluginDir(), alreadyCurrent)

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
		if registerEditorReported(rep, e, ei.PluginDir(), manifest, &kt) {
			registered = append(registered, e.Name)
		} else {
			failed = append(failed, e.Name)
		}
		installEditorHookReported(rep, e, ei.PluginDir())
	}

	claude := rep.client(targetClaude, "Claude Code")
	var claudeEnv *trackedEnv
	ci, ciErr := install.NewClaudeInstaller()
	if ciErr == nil {
		ci.SetForce(opts.force)
		claudeEnv = tracker.watch(ci.EnvFilePath())
		ciErr = ci.Install()
	}
	switch {
	case errors.Is(ciErr, install.ErrClaudeNotInstalled):
		claude.Status = reportSkip
		claude.Detail = ciErr.Error()
	case ciErr != nil:
		fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", ciErr)
		claude.fail(ciErr)
		failed = append(failed, "Claude Code")
	default:
		fmt.Fprintf(os.Stderr, "  ✓ Claude Code\n")
		claude.ok(ci.PluginCacheDir())
		claudeEnv.managed = true
		registered = append(registered, "Claude Code")
		manifest.SetClaude(ci.PluginCacheDir())
		kt.claude = true
	}

	if install.IsCodexDetected() {
		if registerCodexReported(rep, ei.PluginDir(), manifest, &kt) {
			registered = append(registered, "Codex CLI")
		} else {
			failed = append(failed, "Codex CLI")
		}
	}

	var kres knowledgeResult
	if opts.withKnowledge {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Installing Armis Knowledge...")
		kres = installKnowledgeTracked(kt, opts.force, manifest, rep, tracker)
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
	if opts.withKnowledge {
		printKnowledgeResult(kres)
	}

	rotateErr := settleCredentials(opts, rep, tracker)

	printInstallSummary(os.Stderr, installSummary{targets: kt, knowledge: kres.registered})
	printCredentialStatus(ei)
	return errors.Join(rep.failedTargetsError(), rotateErr)
}

// installKnowledgeTracked runs the knowledge install and records its outcome
// and .env file in the report and tracker.
func installKnowledgeTracked(kt knowledgeTargets, force bool, manifest *install.Manifest, rep *installReport, tracker *credentialTracker) knowledgeResult {
	res := installKnowledgeFor(kt, force, manifest)
	rep.setKnowledge(res)
	if res.shortSHA != "" {
		tracker.track(res.envFile, res.envExisted).managed = true
	}
	return res
}

// settleCredentials applies --rotate-credentials, then stores the per-file
// outcome in the report.
func settleCredentials(opts installOptions, rep *installReport, tracker *credentialTracker) error {
	creds, err := tracker.finish(opts.rotateTo)
	rep.Credentials = creds
	return err
}

func installTargets(targets []string, opts installOptions) error {
	rep := newInstallReport()
	var tracker credentialTracker
	err := installTargetsInto(targets, opts, rep, &tracker)
	return finishInstall(opts, rep, err)
}

func installTargetsInto(targets []string, opts installOptions, rep *installReport, tracker *credentialTracker) error {
	hasJetBrains := false
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
			if opts.jetbrainsProject != "" {
				hasJetBrains = true
				break
			}
			fmt.Fprintln(os.Stderr, "JetBrains: MCP servers are configured per-project.")
			fmt.Fprintln(os.Stderr, "  Run: armis-cli install jetbrains --project <path-to-project>")
			fmt.Fprintln(os.Stderr, "  This writes <project>/.jb-mcp.json pointing at the installed server;")
			fmt.Fprintln(os.Stderr, "  then enable it in your IDE's AI Assistant MCP settings.")
			fmt.Fprintln(os.Stderr, "")
			c := rep.client(name, "JetBrains")
			c.Status = reportWarn
			c.Detail = "per-project setup: run armis-cli install jetbrains --project <path-to-project>"
		case "devin":
			fmt.Fprintln(os.Stderr, "Devin: MCP servers are configured via the Devin web UI.")
			fmt.Fprintln(os.Stderr, "See: Settings → MCP Servers in your Devin dashboard.")
			fmt.Fprintln(os.Stderr, "")
			c := rep.client(name, "Devin")
			c.Status = reportWarn
			c.Detail = "configure the MCP server in the Devin web UI"
		case "openhands":
			fmt.Fprintln(os.Stderr, "OpenHands: MCP servers are configured via the web UI.")
			fmt.Fprintln(os.Stderr, "See: Settings → MCP Servers in your OpenHands dashboard.")
			fmt.Fprintln(os.Stderr, "")
			c := rep.client(name, "OpenHands")
			c.Status = reportWarn
			c.Detail = "configure the MCP server in the OpenHands web UI"
		case "aider":
			fmt.Fprintln(os.Stderr, "Aider does not support MCP servers.")
			fmt.Fprintln(os.Stderr, "")
			c := rep.client(name, "Aider")
			c.Status = reportSkip
			c.Detail = "Aider does not support MCP servers"
		default:
			id := install.EditorID(name)
			if _, ok := install.EditorByID(id); !ok {
				return fmt.Errorf("unknown editor %q — run 'armis-cli install --help' for supported editors", name)
			}
			editorIDs = append(editorIDs, id)
		}
	}

	var jetbrainsCfg string
	if hasJetBrains {
		cfg, cfgErr := jetbrainsConfigPath(opts.jetbrainsProject)
		if cfgErr != nil {
			return cfgErr
		}
		jetbrainsCfg = cfg
	}

	needsSharedPlugin := len(editorIDs) > 0 || hasCodex || hasJetBrains
	var kres knowledgeResult

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
		sharedEnv := tracker.watch(ei.EnvFilePath())
		fmt.Fprintln(os.Stderr, "Downloading Armis AppSec MCP server...")
		alreadyCurrent := false
		if err := ei.FetchPlugin(opts.force); err != nil {
			if errors.Is(err, install.ErrAlreadyCurrent) {
				alreadyCurrent = true
				fmt.Fprintf(os.Stderr, "Armis AppSec MCP server v%s is already up to date.\n\n", ei.InstalledVersion())
			} else {
				return fmt.Errorf("download failed: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "MCP server v%s downloaded.\n\n", ei.InstalledVersion())
		}
		sharedEnv.managed = true
		rep.setPlugin(ei.InstalledVersion(), ei.PluginDir(), alreadyCurrent)

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
			registerEditorReported(rep, e, ei.PluginDir(), manifest, &kt)
			installEditorHookReported(rep, e, ei.PluginDir())
		}

		if hasJetBrains {
			jb := rep.client("jetbrains", "JetBrains")
			if err := install.RegisterJetBrains(ei.PluginDir(), jetbrainsCfg); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ JetBrains (%s): %v\n", jetbrainsCfg, err)
				jb.fail(err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ JetBrains (%s)\n", jetbrainsCfg)
				jb.ok(jetbrainsCfg)
			}
		}

		if hasCodex {
			registerCodexReported(rep, ei.PluginDir(), manifest, &kt)
		}

		if err := install.WriteManifest(manifest); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "")
		printCredentialStatus(ei)
	}

	if hasClaude {
		installClaudeTarget(opts.force, &kt, rep, tracker)
	}

	if opts.withKnowledge {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Installing Armis Knowledge...")

		pluginDir := install.NewEditorInstaller().PluginDir()
		manifest := install.ReadManifest(pluginDir)
		kres = installKnowledgeTracked(kt, opts.force, manifest, rep, tracker)
		if manifest != nil {
			if err := install.WriteManifest(manifest); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ Could not write install manifest: %v\n", err)
			}
		}
		printKnowledgeResult(kres)
	}

	rotateErr := settleCredentials(opts, rep, tracker)

	printInstallSummary(os.Stderr, installSummary{targets: kt, knowledge: kres.registered})
	failedErr := rep.failedTargetsError()
	return errors.Join(failedErr, rotateErr)
}

// jetbrainsConfigPath resolves project to a real directory and returns the
// .jb-mcp.json inside it. A .jb-mcp.json that is a symlink or not a regular
// file is refused, so the write cannot be redirected elsewhere.
func jetbrainsConfigPath(project string) (string, error) {
	abs, err := filepath.Abs(project)
	if err != nil {
		return "", fmt.Errorf("--project %q: %w", project, err)
	}
	dir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("--project %q is not a directory", project)
	}
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("--project %q is not a directory", project)
	}
	cfg := filepath.Join(dir, ".jb-mcp.json")
	if info, lerr := os.Lstat(cfg); lerr == nil && !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s exists but is not a regular file", cfg)
	}
	return cfg, nil
}

// installClaudeTarget installs the Claude Code plugin, records it in the
// manifest and the report, and reports whether the install succeeded.
func installClaudeTarget(force bool, kt *knowledgeTargets, rep *installReport, tracker *credentialTracker) bool {
	claude := rep.client(targetClaude, "Claude Code")
	ci, ciErr := install.NewClaudeInstaller()
	if ciErr != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", ciErr)
		claude.fail(ciErr)
		return false
	}
	ci.SetForce(force)
	claudeEnv := tracker.watch(ci.EnvFilePath())
	fmt.Fprintln(os.Stderr, "Installing Armis AppSec plugin for Claude Code...")
	if err := ci.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Claude Code: %v\n", err)
		claude.fail(err)
		return false
	}
	fmt.Fprintf(os.Stderr, "  ✓ Claude Code v%s\n", ci.InstalledVersion())
	fmt.Fprintln(os.Stderr, "")
	claude.ok(ci.PluginCacheDir())
	claudeEnv.managed = true
	rep.setPlugin(ci.InstalledVersion(), ci.PluginCacheDir(), ci.AlreadyCurrent())
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
		fmt.Fprintln(os.Stderr, "Run 'armis-cli mcp doctor' to verify the setup works.")
	} else {
		fmt.Fprintln(os.Stderr, "Next steps:")
		fmt.Fprintf(os.Stderr, "  1. Set your credentials in %s:\n", ci.EnvFilePath())
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "     ARMIS_CLIENT_SECRET=<your-client-secret>")
		fmt.Fprintln(os.Stderr, "  2. Restart Claude Code")
	}
	return true
}

func printCredentialStatus(ei *install.EditorInstaller) {
	if ei.HasExistingEnv() {
		fmt.Fprintln(os.Stderr, "Credentials configured. Restart your editors to use the MCP server.")
		fmt.Fprintln(os.Stderr, "Run 'armis-cli mcp doctor' to verify the setup works.")
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
			state := ""
			if res.upToDate {
				state = ", up to date"
			}
			fmt.Fprintf(os.Stderr, "  ✓ Knowledge bridge (%s%s)\n", res.shortSHA, state)
		}
		fmt.Fprintf(os.Stderr, "  ✓ Knowledge registered in: %s\n", strings.Join(res.registered, ", "))
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Armis Knowledge is a second MCP server (armis-knowledge) next to armis-appsec.")
		// Editors launch servers without the user's shell exports, so the
		// bridge only sees credentials stored in its own .env.
		ki := install.NewKnowledgeMCPInstaller(knowledgeEnvForDev(useDev))
		if ki.HasCredentials() {
			fmt.Fprintf(os.Stderr, "Knowledge reads its credentials from %s.\n", ki.EnvFilePath())
		} else {
			fmt.Fprintf(os.Stderr, "Knowledge needs credentials in %s (editors do not inherit shell exports):\n", ki.EnvFilePath())
			fmt.Fprintln(os.Stderr, "  ARMIS_CLIENT_ID=<your-client-id>")
			fmt.Fprintln(os.Stderr, "  ARMIS_CLIENT_SECRET=<your-client-secret>")
		}
	} else if !res.skipped {
		fmt.Fprintln(os.Stderr, "  ⚠ Knowledge was not registered in any editor.")
	}
	if len(res.warnings) > 0 {
		fmt.Fprintln(os.Stderr, "Run 'armis-cli mcp doctor' to see what's wrong.")
	}
}
