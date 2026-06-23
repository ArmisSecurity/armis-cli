package agentdetect

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/output"
)

// FormatPlain writes the plain-text grouped-by-user format using lipgloss styles.
func FormatPlain(result *ScanResult, w io.Writer) error {
	s := output.GetStyles()

	for i, userResult := range result.Users {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		header := s.Bold.Render("user:") + " " + userResult.User
		if _, err := fmt.Fprintln(w, header); err != nil {
			return err
		}
		if len(userResult.Agents) == 0 {
			line := s.MutedText.Render("No agents detected")
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
			continue
		}
		// armis:ignore cwe:770 reason:bounded by API response page size (max 1000 agents per user)
		agents := make([]string, 0, len(userResult.Agents))
		for _, agent := range userResult.Agents {
			mcpStatus := s.ErrorText.Render("MCP:false")
			if agent.MCPInstalled {
				mcpStatus = s.SuccessText.Render("MCP:true")
			}
			agents = append(agents, fmt.Sprintf("%s(%s)", agent.Name, mcpStatus))
		}
		if _, err := fmt.Fprintln(w, strings.Join(agents, ", ")); err != nil {
			return err
		}
	}

	// MCP:false renders in red above; tell the user how to fix it rather than
	// leaving the red status with no next step. Shown once, after all users.
	if anyMCPMissing(result) {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		hint := s.MutedText.Render("Run 'armis-cli install' to enable Armis AppSec MCP for detected agents.")
		if _, err := fmt.Fprintln(w, hint); err != nil {
			return err
		}
	}
	return nil
}

// anyMCPMissing reports whether at least one detected agent lacks the Armis MCP.
func anyMCPMissing(result *ScanResult) bool {
	for _, u := range result.Users {
		for _, agent := range u.Agents {
			if !agent.MCPInstalled {
				return true
			}
		}
	}
	return false
}

// FormatJSON writes the flat JSON array of all detected agents.
func FormatJSON(result *ScanResult, w io.Writer) error {
	flat := result.FlatResults()
	if flat == nil {
		flat = []DetectedAgent{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(flat)
}
