package cmd

import (
	"fmt"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/agentdetect"
	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/spf13/cobra"
)

var agentDetectionCollectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Detect agents and report to Armis Cloud inventory",
	Long: `Detect installed AI coding agents and report the results to the
Armis Cloud agent inventory API. A separate report is sent for each user.

When run as root (macOS/Linux) or SYSTEM (Windows), scans all local user profiles.
When run as a standard user, scans only the current user's home directory.`,
	Example: `  # Report detected agents for the current user
  armis-cli agent-detection collect

  # Report agents across all users (requires root/admin)
  sudo armis-cli agent-detection collect`,
	RunE: runAgentDetectionCollect,
}

func init() {
	agentDetectionCmd.AddCommand(agentDetectionCollectCmd)
}

func runAgentDetectionCollect(cmd *cobra.Command, _ []string) error {
	ctx, cancel := NewSignalContext()
	defer cancel()

	authProvider, err := getAuthProvider()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	tid, err := authProvider.GetTenantID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tenant ID: %w", err)
	}

	client, err := api.NewClient(getAPIBaseURL(), authProvider, debug, 0)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	machineName, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}

	platform := agentdetect.NewPlatform()
	scanner := agentdetect.NewScanner(platform)
	result, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("agent detection failed: %w", err)
	}

	var reportErrors []error
	for _, userResult := range result.Users {
		payload := buildInventoryPayload(tid, machineName, userResult)

		if err := client.ReportAgentInventory(ctx, payload); err != nil {
			cli.PrintWarningf("failed to report agents for user %s: %v", userResult.User, err)
			reportErrors = append(reportErrors, err)
			continue
		}

		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Reported %d agent(s) for user %s\n",
			len(userResult.Agents), userResult.User)
	}

	if len(reportErrors) > 0 {
		return fmt.Errorf("failed to report for %d user(s)", len(reportErrors))
	}
	return nil
}

func buildInventoryPayload(tenantID, machineName string, userResult agentdetect.UserResult) api.AgentInventoryPayload {
	entries := make([]api.AgentInventoryEntry, 0, len(userResult.Agents))
	for _, agent := range userResult.Agents {
		entry := api.AgentInventoryEntry{
			Name:              agent.Name,
			ArmisMCPInstalled: agent.MCPInstalled,
		}
		if agent.Version != "" {
			v := agent.Version
			entry.Version = &v
		}
		entries = append(entries, entry)
	}
	return api.AgentInventoryPayload{
		TenantID:    tenantID,
		MachineName: machineName,
		User:        userResult.User,
		Agents:      entries,
	}
}
