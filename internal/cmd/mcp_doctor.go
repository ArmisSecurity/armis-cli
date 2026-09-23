package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/auth"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	mcpDoctorFormat      string
	mcpDoctorNoHandshake bool
	mcpDoctorTimeout     time.Duration
	mcpDoctorFix         bool
	mcpDoctorBundle      bool
	mcpDoctorBundlePath  string
)

var mcpDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose the installed MCP servers and their editor registrations",
	Long: `Diagnose everything 'armis-cli install' may have set up: the scanner and
knowledge MCP servers' plugin files, venv, and credentials; whether each
registered editor's config still contains the entry; Claude Code's plugin
registry; and Codex CLI's config.toml.

Unless --no-handshake is set, it also:
  - launches each server exactly as each editor's config says and runs a live
    MCP session (initialize, tools/list, and a diagnostic tool call)
  - checks that the client credentials are accepted by the Armis API
  - checks that the server's own Python runtime can reach the Armis API,
    which catches proxy and TLS-inspection problems the CLI itself doesn't hit

For VS Code (GitHub Copilot) it additionally checks VS Code Insiders and
VSCodium, per-profile and workspace configs, duplicate entries, settings and
Windows Group Policy that disable MCP or Agent mode, and VS Code's own MCP log
for the server.

Every failing check prints how to fix it. --fix repairs what the CLI can
(stale or missing registrations, a broken venv, a system proxy the server
isn't using) and re-runs the checks.
--bundle writes a zip with the full diagnostics, credentials removed, to send
to support.

Exits non-zero if any check fails.`,
	Example: `  # Full diagnostic, including live handshake
  armis-cli mcp doctor

  # Diagnose and repair what can be repaired automatically
  armis-cli mcp doctor --fix

  # Write a support bundle (armis-mcp-doctor-<timestamp>.zip)
  armis-cli mcp doctor --bundle

  # Structural checks only, skip spawning servers and network checks
  armis-cli mcp doctor --no-handshake

  # Machine-readable output
  armis-cli mcp doctor --format json`,
	Args: cobra.NoArgs,
	RunE: runMCPDoctor,
}

func init() {
	mcpCmd.AddCommand(mcpDoctorCmd)
	mcpDoctorCmd.Flags().StringVarP(&mcpDoctorFormat, "format", "f", agentFormatPlain, "Output format: plain, json")
	mcpDoctorCmd.Flags().BoolVar(&mcpDoctorNoHandshake, "no-handshake", false, "Skip spawning MCP servers and the network checks")
	mcpDoctorCmd.Flags().DurationVar(&mcpDoctorTimeout, "timeout", install.DefaultHandshakeTimeout, "Timeout for each live handshake")
	mcpDoctorCmd.Flags().BoolVar(&mcpDoctorFix, "fix", false, "Repair fixable problems (re-register editors, rebuild the venv), then re-check")
	mcpDoctorCmd.Flags().BoolVar(&mcpDoctorBundle, "bundle", false, "Write a support bundle zip (credentials removed) for Armis support")
	mcpDoctorCmd.Flags().StringVar(&mcpDoctorBundlePath, "bundle-path", "", "Where to write the support bundle (implies --bundle; default: ./armis-mcp-doctor-<timestamp>.zip)")
}

func runMCPDoctor(cmd *cobra.Command, _ []string) error {
	switch mcpDoctorFormat {
	case agentFormatPlain, agentFormatJSON:
	default:
		return fmt.Errorf("invalid --format value %q: must be plain or json", mcpDoctorFormat)
	}

	opts := install.DoctorOptions{
		Handshake: !mcpDoctorNoHandshake,
		Timeout:   mcpDoctorTimeout,
		AuthCheck: doctorAuthCheck,
	}
	stderr := cmd.ErrOrStderr()

	report := install.RunDoctor(opts)
	if mcpDoctorFormat == agentFormatPlain {
		printMCPDoctorPlain(stderr, report, !mcpDoctorFix)
	}

	if mcpDoctorFix {
		fixed, err := applyDoctorFixes(stderr, report)
		if err != nil {
			return err
		}
		if fixed {
			_, _ = fmt.Fprintln(stderr, "\nRe-running checks...")
			report = install.RunDoctor(opts)
			if mcpDoctorFormat == agentFormatPlain {
				printMCPDoctorPlain(stderr, report, false)
			}
		}
	}

	if mcpDoctorFormat == agentFormatJSON {
		if err := printMCPDoctorJSON(cmd, report); err != nil {
			return err
		}
	}

	if mcpDoctorBundle || mcpDoctorBundlePath != "" {
		path := mcpDoctorBundlePath
		if path == "" {
			path = install.DefaultBundleName()
		}
		if err := install.WriteSupportBundle(report, path, version); err != nil {
			return fmt.Errorf("writing support bundle: %w", err)
		}
		_, _ = fmt.Fprintf(stderr, "\nSupport bundle written to %s — attach it to your support request. It contains no credentials.\n", path)
	}

	if report.HasFailures() {
		return fmt.Errorf("mcp doctor found failing checks — see output above")
	}
	return nil
}

// doctorAuthCheck exchanges client credentials for a token against the same
// API base URL the rest of the CLI uses.
func doctorAuthCheck(ctx context.Context, id, secret string) error {
	_, err := auth.NewAuthProviderWithContext(ctx, auth.AuthConfig{
		ClientID:     id,
		ClientSecret: secret,
		BaseURL:      getAPIBaseURL(),
		Region:       region,
	})
	return err
}

// applyDoctorFixes performs the repairs the report calls for and reports
// whether anything was attempted.
func applyDoctorFixes(out io.Writer, report *install.DoctorReport) (bool, error) {
	for _, c := range report.Checks {
		if c.Component == install.ComponentInstall && c.Name == "manifest" && c.Status == install.StatusFail {
			_, _ = fmt.Fprintln(out, "\nNothing is installed yet, so there is nothing to repair. Run: armis-cli install")
			return false, nil
		}
	}

	fixes := report.Fixes()
	if report.HasBlockedRegistration() {
		_, _ = fmt.Fprintln(out, "\nSkipping editor re-registration: at least one editor's config file couldn't be parsed, and rewriting it would drop the other servers configured there. Fix the syntax (see the hint above), then re-run --fix.")
	}
	if len(fixes) == 0 {
		if report.HasProblems() {
			_, _ = fmt.Fprintln(out, "\nNone of the remaining problems can be fixed automatically — follow the → hints above.")
		}
		return false, nil
	}

	for _, f := range fixes {
		switch f {
		case install.FixSetProxy:
			desc, err := report.ApplyEnvFix()
			if err != nil {
				return true, fmt.Errorf("repair failed: %w", err)
			}
			_, _ = fmt.Fprintf(out, "\nConfigured the MCP server's proxy: %s\nRestart VS Code (or your editor) so the server picks it up.\n", desc)
		case install.FixReinstall, install.FixReregister:
			force := f == install.FixReinstall
			if force {
				_, _ = fmt.Fprintln(out, "\nReinstalling the MCP server and re-registering editors...")
			} else {
				_, _ = fmt.Fprintln(out, "\nRe-registering editors...")
			}
			if err := mcpDoctorUpdate(force, false); err != nil {
				return true, fmt.Errorf("repair failed: %w", err)
			}
		}
	}
	return true, nil
}

// mcpDoctorUpdate is performMCPUpdate, swappable in tests.
var mcpDoctorUpdate = performMCPUpdate

func printMCPDoctorJSON(cmd *cobra.Command, report *install.DoctorReport) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func printMCPDoctorPlain(out io.Writer, report *install.DoctorReport, suggestFix bool) {
	if len(report.Checks) == 0 {
		_, _ = fmt.Fprintln(out, "No checks produced any output.")
		return
	}

	accessible := !cli.ColorsEnabled()
	width := 20
	for _, c := range report.Checks {
		width = max(width, len(c.Name))
	}
	var lastComponent string
	var passed, warned, failed int
	for _, c := range report.Checks {
		if c.Component != lastComponent {
			_, _ = fmt.Fprintf(out, "%s:\n", c.Component)
			lastComponent = c.Component
		}
		_, _ = fmt.Fprintf(out, "  %s %-*s %s\n", statusSymbol(c.Status, accessible), width, c.Name, c.Detail)
		if c.Remediation != "" && c.Status != install.StatusOK {
			printRemediation(out, c.Remediation)
		}
		switch c.Status {
		case install.StatusOK:
			passed++
		case install.StatusWarn:
			warned++
		case install.StatusFail:
			failed++
		}
	}

	_, _ = fmt.Fprintf(out, "\n%d passed, %d warnings, %d failed\n", passed, warned, failed)
	if suggestFix && len(report.Fixes()) > 0 {
		_, _ = fmt.Fprintln(out, "Some of these can be repaired automatically: armis-cli mcp doctor --fix")
	}
	if warned+failed > 0 {
		_, _ = fmt.Fprintln(out, "Still stuck? Run 'armis-cli mcp doctor --bundle' and send the zip to Armis support.")
	}
}

// printRemediation prints a check's hint under it, indenting continuation
// lines so multi-line hints (steps, JSON snippets) stay readable.
func printRemediation(out io.Writer, remediation string) {
	lines := strings.Split(strings.TrimRight(remediation, "\n"), "\n")
	for i, line := range lines {
		prefix := "        "
		if i == 0 {
			prefix = "      → "
		}
		_, _ = fmt.Fprintln(out, prefix+line)
	}
}

// statusSymbol renders a check's status, matching the color/theme handling
// (cli.ColorsEnabled) and ASCII fallback used by the rest of the install/
// uninstall output (see install_interactive.go, uninstall.go) so `mcp doctor`
// doesn't diverge from the CLI's centralized styling.
func statusSymbol(s install.CheckStatus, accessible bool) string {
	if accessible {
		switch s {
		case install.StatusOK:
			return "[OK]"
		case install.StatusWarn:
			return "[WARN]"
		case install.StatusInfo:
			return "[INFO]"
		default:
			return "[FAIL]"
		}
	}
	switch s {
	case install.StatusOK:
		return lipgloss.NewStyle().Foreground(cmdutil.BrandSuccess).Render("✓")
	case install.StatusWarn:
		return lipgloss.NewStyle().Foreground(cmdutil.BrandWarn).Render("⚠")
	case install.StatusInfo:
		return "ℹ"
	default:
		return lipgloss.NewStyle().Foreground(cmdutil.BrandError).Render("✗")
	}
}
