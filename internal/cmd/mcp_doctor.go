package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/install"
	"github.com/spf13/cobra"
)

var (
	mcpDoctorFormat      string
	mcpDoctorNoHandshake bool
	mcpDoctorTimeout     time.Duration
)

var mcpDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose the installed MCP servers and their editor registrations",
	Long: `Diagnose everything 'armis-cli install' may have set up: the scanner and
knowledge MCP servers' plugin files and credentials, whether each registered
editor's config still contains the entry, Claude Code's plugin registry, and
Codex CLI's config.toml — then, unless --no-handshake is set, spawns each
server and performs a live MCP "initialize" handshake to confirm it actually
starts and responds.

Exits non-zero if any check fails.`,
	Example: `  # Full diagnostic, including live handshake
  armis-cli mcp doctor

  # Structural checks only, skip spawning the servers
  armis-cli mcp doctor --no-handshake

  # Machine-readable output
  armis-cli mcp doctor --format json`,
	Args: cobra.NoArgs,
	RunE: runMCPDoctor,
}

func init() {
	mcpCmd.AddCommand(mcpDoctorCmd)
	mcpDoctorCmd.Flags().StringVarP(&mcpDoctorFormat, "format", "f", agentFormatPlain, "Output format: plain, json")
	mcpDoctorCmd.Flags().BoolVar(&mcpDoctorNoHandshake, "no-handshake", false, "Skip spawning MCP servers for a live handshake check")
	mcpDoctorCmd.Flags().DurationVar(&mcpDoctorTimeout, "timeout", install.DefaultHandshakeTimeout, "Timeout for the live handshake check")
}

func runMCPDoctor(cmd *cobra.Command, _ []string) error {
	switch mcpDoctorFormat {
	case agentFormatPlain, agentFormatJSON:
	default:
		return fmt.Errorf("invalid --format value %q: must be plain or json", mcpDoctorFormat)
	}

	report := install.RunDoctor(install.DoctorOptions{
		Handshake: !mcpDoctorNoHandshake,
		Timeout:   mcpDoctorTimeout,
	})

	switch mcpDoctorFormat {
	case agentFormatJSON:
		if err := printMCPDoctorJSON(cmd, report); err != nil {
			return err
		}
	default:
		printMCPDoctorPlain(cmd, report)
	}

	if report.HasFailures() {
		return fmt.Errorf("mcp doctor found failing checks — see output above")
	}
	return nil
}

func printMCPDoctorJSON(cmd *cobra.Command, report *install.DoctorReport) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func printMCPDoctorPlain(cmd *cobra.Command, report *install.DoctorReport) {
	out := cmd.OutOrStdout()

	if len(report.Checks) == 0 {
		fmt.Fprintln(out, "No checks produced any output.")
		return
	}

	var lastComponent string
	for _, c := range report.Checks {
		if c.Component != lastComponent {
			fmt.Fprintf(out, "%s:\n", c.Component)
			lastComponent = c.Component
		}
		fmt.Fprintf(out, "  %s %-20s %s\n", statusSymbol(c.Status), c.Name, c.Detail)
	}
}

func statusSymbol(s install.CheckStatus) string {
	switch s {
	case install.StatusOK:
		return "✓"
	case install.StatusWarn:
		return "⚠"
	default:
		return "✗"
	}
}
