package agentdetect

import (
	"encoding/json"
	"os"
	"strings"
)

const armisMCPIdentifier = "armis-appsec-mcp"

// mcpServerConfig is used to unmarshal MCP config files that have a top-level "mcpServers" key.
// Used by Windsurf, Cursor, GitHub Copilot, and Google Antigravity.
type mcpServerConfig struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
}

// HasArmisMCP checks if a standard MCP config file (mcp.json, mcp_config.json) contains
// an armis-appsec-mcp server entry. configPath must resolve under resolvedHome.
func HasArmisMCP(resolvedHome, configPath string) bool {
	if !isUnderDir(resolvedHome, configPath) {
		return false
	}
	data, err := os.ReadFile(configPath) //nolint:gosec // path validated by isUnderDir
	if err != nil {
		return false
	}
	return hasArmisMCPInData(data)
}

// claudeSettings represents the relevant fields in Claude Code's settings.json.
type claudeSettings struct {
	MCPServers     map[string]json.RawMessage `json:"mcpServers"`
	EnabledPlugins map[string]bool            `json:"enabledPlugins"`
}

// HasArmisMCPInClaudeSettings checks if Claude Code's settings.json contains
// an armis-appsec-mcp entry in either mcpServers or enabledPlugins.
// settingsPath must resolve under resolvedHome.
func HasArmisMCPInClaudeSettings(resolvedHome, settingsPath string) bool {
	if !isUnderDir(resolvedHome, settingsPath) {
		return false
	}
	data, err := os.ReadFile(settingsPath) //nolint:gosec // path validated by isUnderDir
	if err != nil {
		return false
	}
	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	for key := range settings.MCPServers {
		if strings.Contains(strings.ToLower(key), armisMCPIdentifier) {
			return true
		}
	}
	for key, enabled := range settings.EnabledPlugins {
		if enabled && strings.Contains(strings.ToLower(key), armisMCPIdentifier) {
			return true
		}
	}
	return false
}

// hasArmisMCPInData checks raw JSON data for the armis MCP identifier.
// Works for both standard MCP configs and Claude Code settings by checking
// if any key in mcpServers contains the armis identifier.
func hasArmisMCPInData(data []byte) bool {
	var config mcpServerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return false
	}
	for key := range config.MCPServers {
		if strings.Contains(strings.ToLower(key), armisMCPIdentifier) {
			return true
		}
	}
	return false
}
