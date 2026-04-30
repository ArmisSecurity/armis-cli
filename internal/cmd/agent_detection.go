package cmd

import (
	"fmt"

	"github.com/ArmisSecurity/armis-cli/internal/agentdetect"
	"github.com/spf13/cobra"
)

const (
	agentFormatPlain = "plain"
	agentFormatJSON  = "json"
)

var agentDetectFormat string

var agentDetectionCmd = &cobra.Command{
	Use:   "agent-detection",
	Short: "Detect AI coding agents installed on this system",
	Long: `Detect AI coding agents (Claude Code, Cursor, Copilot, Windsurf, Google Antigravity)
across user profiles and check if Armis AppSec MCP is enabled.

When run as root (macOS/Linux) or SYSTEM (Windows), scans all local user profiles.
When run as a standard user, scans only the current user's home directory.`,
	Example: `  # Detect agents for current user
  armis-cli agent-detection

  # Detect agents with JSON output
  armis-cli agent-detection --format json

  # Detect agents across all users (requires root/admin)
  sudo armis-cli agent-detection`,
	RunE: runAgentDetection,
}

func init() {
	agentDetectionCmd.Flags().StringVarP(&agentDetectFormat, "format", "f", agentFormatPlain, "Output format: plain, json")
	rootCmd.AddCommand(agentDetectionCmd)
}

func runAgentDetection(cmd *cobra.Command, _ []string) error {
	switch agentDetectFormat {
	case agentFormatPlain, agentFormatJSON:
	default:
		return fmt.Errorf("invalid --format value %q: must be plain or json", agentDetectFormat)
	}

	platform := agentdetect.NewPlatform()
	scanner := agentdetect.NewScanner(platform)

	result, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("agent detection failed: %w", err)
	}

	switch agentDetectFormat {
	case agentFormatJSON:
		return agentdetect.FormatJSON(result, cmd.OutOrStdout())
	default:
		return agentdetect.FormatPlain(result, cmd.OutOrStdout())
	}
}
