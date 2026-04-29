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
	return nil
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
