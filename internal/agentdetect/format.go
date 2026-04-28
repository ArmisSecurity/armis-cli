package agentdetect

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FormatPlain writes the plain-text grouped-by-user format.
func FormatPlain(result *ScanResult, w io.Writer) error {
	for i, userResult := range result.Users {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "user: %s\n", userResult.User); err != nil {
			return err
		}
		agents := make([]string, 0, len(userResult.Agents))
		for _, agent := range userResult.Agents {
			agents = append(agents, fmt.Sprintf("%s(MCP:%t)", agent.Name, agent.MCPInstalled))
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
