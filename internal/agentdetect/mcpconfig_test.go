package agentdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasArmisMCP(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "armis MCP present",
			content: `{
				"mcpServers": {
					"armis-appsec-mcp": {
						"command": "npx",
						"args": ["armis-appsec-mcp"]
					}
				}
			}`,
			expected: true,
		},
		{
			name: "armis MCP absent",
			content: `{
				"mcpServers": {
					"some-other-server": {
						"command": "npx",
						"args": ["other"]
					}
				}
			}`,
			expected: false,
		},
		{
			name:     "empty mcpServers",
			content:  `{"mcpServers": {}}`,
			expected: false,
		},
		{
			name:     "no mcpServers key",
			content:  `{"other": "value"}`,
			expected: false,
		},
		{
			name:     "invalid JSON",
			content:  `not json at all`,
			expected: false,
		},
		{
			name:     "empty file",
			content:  ``,
			expected: false,
		},
		{
			name: "armis MCP with mixed case key",
			content: `{
				"mcpServers": {
					"Armis-AppSec-MCP": {
						"command": "npx"
					}
				}
			}`,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			path := filepath.Join(dir, "mcp.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got := HasArmisMCP(dir, path)
			if got != tt.expected {
				t.Errorf("HasArmisMCP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasArmisMCP_MissingFile(t *testing.T) {
	dir := resolvedTempDir(t)
	got := HasArmisMCP(dir, filepath.Join(dir, "mcp.json"))
	if got {
		t.Error("HasArmisMCP() should return false for missing file")
	}
}

func TestHasArmisMCPInClaudeSettings(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "claude settings with armis MCP",
			content: `{
				"mcpServers": {
					"armis-appsec-mcp": {
						"command": "/usr/local/bin/armis-appsec-mcp"
					}
				}
			}`,
			expected: true,
		},
		{
			name: "claude settings without armis MCP",
			content: `{
				"mcpServers": {},
				"permissions": {}
			}`,
			expected: false,
		},
		{
			name: "claude settings with enabledPlugins",
			content: `{
				"enabledPlugins": {
					"armis-appsec@armis-appsec-mcp": true
				}
			}`,
			expected: true,
		},
		{
			name: "claude settings with disabled plugin",
			content: `{
				"enabledPlugins": {
					"armis-appsec@armis-appsec-mcp": false
				}
			}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got := HasArmisMCPInClaudeSettings(dir, path)
			if got != tt.expected {
				t.Errorf("HasArmisMCPInClaudeSettings() = %v, want %v", got, tt.expected)
			}
		})
	}
}
