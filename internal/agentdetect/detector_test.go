package agentdetect

import (
	"os"
	"path/filepath"
	"testing"
)

type mockPlatform struct {
	users             []UserHome
	vsCodeExtDir      string
	jetBrainsPlugDirs []string
	vsCodeConfigDir   string
	cursorAppExists   bool
	junieBinPaths     []string
	zedConfigDir      string
	isRoot            bool
}

func (m *mockPlatform) UserHomeDirs() ([]UserHome, error)     { return m.users, nil }
func (m *mockPlatform) VSCodeExtensionsDir(_ string) string   { return m.vsCodeExtDir }
func (m *mockPlatform) JetBrainsPluginDirs(_ string) []string { return m.jetBrainsPlugDirs }
func (m *mockPlatform) VSCodeUserConfigDir(_ string) string   { return m.vsCodeConfigDir }
func (m *mockPlatform) CursorAppExists(_ string) bool         { return m.cursorAppExists }
func (m *mockPlatform) JunieBinaryPaths(_ string) []string    { return m.junieBinPaths }
func (m *mockPlatform) ZedConfigDir(_ string) string          { return m.zedConfigDir }
func (m *mockPlatform) IsRoot() bool                          { return m.isRoot }

func newMockPlatform(homeDir string) *mockPlatform {
	return &mockPlatform{
		users:           []UserHome{{Username: "testuser", HomeDir: homeDir}},
		vsCodeExtDir:    filepath.Join(homeDir, ".vscode", "extensions"),
		vsCodeConfigDir: filepath.Join(homeDir, ".config", "Code", "User"),
	}
}

// --- Claude Code Detector ---

func TestClaudeCodeDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string)
		expected bool
	}{
		{
			name: "claude dir exists",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".claude"))
			},
			expected: true,
		},
		{
			name: "claude.json exists",
			setup: func(t *testing.T, home string) {
				mustWriteFile(t, filepath.Join(home, ".claude.json"), "{}")
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string) {},
			expected: false,
		},
	}

	d := &claudeCodeDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			tt.setup(t, home)
			p := newMockPlatform(home)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClaudeCodeDetector_CheckMCP(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "MCP enabled",
			content:  `{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`,
			expected: true,
		},
		{
			name:     "MCP not configured",
			content:  `{"mcpServers":{}}`,
			expected: false,
		},
	}

	d := &claudeCodeDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			settingsDir := filepath.Join(home, ".claude")
			mustMkdirAll(t, settingsDir)
			mustWriteFile(t, filepath.Join(settingsDir, "settings.json"), tt.content)
			p := newMockPlatform(home)
			if got := d.CheckMCP(home, home, p); got != tt.expected {
				t.Errorf("CheckMCP() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// --- Windsurf Detector ---

func TestWindsurfDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "windsurf dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".windsurf"))
			},
			expected: true,
		},
		{
			name: "vscode extension exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				extDir := filepath.Join(home, ".vscode", "extensions")
				mustMkdirAll(t, filepath.Join(extDir, "codeium.windsurf-1.0.0"))
				p.vsCodeExtDir = extDir
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &windsurfDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWindsurfDetector_CheckMCP(t *testing.T) {
	d := &windsurfDetector{}
	home := resolvedTempDir(t)
	mcpDir := filepath.Join(home, ".codeium", "windsurf")
	mustMkdirAll(t, mcpDir)
	mustWriteFile(t, filepath.Join(mcpDir, "mcp_config.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

func TestWindsurfDetector_Version(t *testing.T) {
	d := &windsurfDetector{}
	home := resolvedTempDir(t)
	extDir := filepath.Join(home, ".vscode", "extensions", "codeium.windsurf-1.2.3")
	mustMkdirAll(t, extDir)
	mustWriteFile(t, filepath.Join(extDir, "package.json"), `{"version":"1.2.3"}`)
	p := newMockPlatform(home)
	p.vsCodeExtDir = filepath.Join(home, ".vscode", "extensions")
	if got := d.DetectVersion(home, home, p); got != "1.2.3" {
		t.Errorf("DetectVersion() = %q, want %q", got, "1.2.3")
	}
}

// --- Google Antigravity Detector ---

func TestAntigravityDetector_Detect(t *testing.T) {
	d := &antigravityDetector{}

	t.Run("directory exists", func(t *testing.T) {
		home := resolvedTempDir(t)
		mustMkdirAll(t, filepath.Join(home, ".gemini", "antigravity"))
		p := newMockPlatform(home)
		if !d.Detect(home, home, p) {
			t.Error("Detect() should return true when .gemini/antigravity exists")
		}
	})

	t.Run("directory missing", func(t *testing.T) {
		home := resolvedTempDir(t)
		p := newMockPlatform(home)
		if d.Detect(home, home, p) {
			t.Error("Detect() should return false when .gemini/antigravity is missing")
		}
	})
}

func TestAntigravityDetector_CheckMCP(t *testing.T) {
	d := &antigravityDetector{}
	home := resolvedTempDir(t)
	mcpDir := filepath.Join(home, ".gemini", "antigravity")
	mustMkdirAll(t, mcpDir)
	mustWriteFile(t, filepath.Join(mcpDir, "mcp_config.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

// --- GitHub Copilot Detector ---

func TestCopilotDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "vscode extension exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				extDir := filepath.Join(home, ".vscode", "extensions")
				mustMkdirAll(t, filepath.Join(extDir, "github.copilot-1.0.0"))
				p.vsCodeExtDir = extDir
			},
			expected: true,
		},
		{
			name: "config dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".config", "github-copilot"))
			},
			expected: true,
		},
		{
			name: "jetbrains plugin exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				pluginDir := filepath.Join(home, "jb-plugins")
				mustMkdirAll(t, filepath.Join(pluginDir, "github-copilot-1.0"))
				p.jetBrainsPlugDirs = []string{pluginDir}
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &copilotDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCopilotDetector_CheckMCP(t *testing.T) {
	d := &copilotDetector{}

	t.Run("mcpServers format", func(t *testing.T) {
		home := resolvedTempDir(t)
		configDir := filepath.Join(home, ".config", "Code", "User")
		mustMkdirAll(t, configDir)
		mustWriteFile(t, filepath.Join(configDir, "mcp.json"),
			`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
		p := newMockPlatform(home)
		p.vsCodeConfigDir = configDir
		if !d.CheckMCP(home, home, p) {
			t.Error("CheckMCP() should return true for mcpServers format")
		}
	})

	t.Run("vscode servers format", func(t *testing.T) {
		home := resolvedTempDir(t)
		configDir := filepath.Join(home, ".config", "Code", "User")
		mustMkdirAll(t, configDir)
		mustWriteFile(t, filepath.Join(configDir, "mcp.json"),
			`{"servers":{"armis-appsec":{"type":"stdio","command":"python3"}}}`)
		p := newMockPlatform(home)
		p.vsCodeConfigDir = configDir
		if !d.CheckMCP(home, home, p) {
			t.Error("CheckMCP() should return true for VS Code servers format")
		}
	})
}

// --- Cursor Detector ---

func TestCursorDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "cursor dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".cursor"))
			},
			expected: true,
		},
		{
			name: "cursor app exists",
			setup: func(_ *testing.T, _ string, p *mockPlatform) {
				p.cursorAppExists = true
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &cursorDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCursorDetector_CheckMCP(t *testing.T) {
	d := &cursorDetector{}
	home := resolvedTempDir(t)
	cursorDir := filepath.Join(home, ".cursor")
	mustMkdirAll(t, cursorDir)
	mustWriteFile(t, filepath.Join(cursorDir, "mcp.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

// --- Cline Detector ---

func TestClineDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "cline dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".cline"))
			},
			expected: true,
		},
		{
			name: "vscode extension exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				extDir := filepath.Join(home, ".vscode", "extensions")
				mustMkdirAll(t, filepath.Join(extDir, "saoudrizwan.claude-dev-2.0.0"))
				p.vsCodeExtDir = extDir
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &clineDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClineDetector_CheckMCP(t *testing.T) {
	d := &clineDetector{}
	home := resolvedTempDir(t)
	configDir := filepath.Join(home, ".config", "Code", "User")
	settingsDir := filepath.Join(configDir, "globalStorage",
		"saoudrizwan.claude-dev", "settings")
	mustMkdirAll(t, settingsDir)
	mustWriteFile(t, filepath.Join(settingsDir, "cline_mcp_settings.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	p.vsCodeConfigDir = configDir
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

func TestClineDetector_Version(t *testing.T) {
	d := &clineDetector{}
	home := resolvedTempDir(t)
	extDir := filepath.Join(home, ".vscode", "extensions", "saoudrizwan.claude-dev-2.1.0")
	mustMkdirAll(t, extDir)
	mustWriteFile(t, filepath.Join(extDir, "package.json"), `{"version":"2.1.0"}`)
	p := newMockPlatform(home)
	p.vsCodeExtDir = filepath.Join(home, ".vscode", "extensions")
	if got := d.DetectVersion(home, home, p); got != "2.1.0" {
		t.Errorf("DetectVersion() = %q, want %q", got, "2.1.0")
	}
}

// --- Roo Code Detector ---

func TestRooCodeDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "roo-cline dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".roo-cline"))
			},
			expected: true,
		},
		{
			name: "vscode extension exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				extDir := filepath.Join(home, ".vscode", "extensions")
				mustMkdirAll(t, filepath.Join(extDir, "rooveterinaryinc.roo-cline-1.5.0"))
				p.vsCodeExtDir = extDir
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &rooCodeDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRooCodeDetector_CheckMCP(t *testing.T) {
	d := &rooCodeDetector{}
	home := resolvedTempDir(t)
	rooDir := filepath.Join(home, ".roo-cline")
	mustMkdirAll(t, rooDir)
	mustWriteFile(t, filepath.Join(rooDir, "mcp_settings.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

func TestRooCodeDetector_Version(t *testing.T) {
	d := &rooCodeDetector{}
	home := resolvedTempDir(t)
	extDir := filepath.Join(home, ".vscode", "extensions", "rooveterinaryinc.roo-cline-1.5.0")
	mustMkdirAll(t, extDir)
	mustWriteFile(t, filepath.Join(extDir, "package.json"), `{"version":"1.5.0"}`)
	p := newMockPlatform(home)
	p.vsCodeExtDir = filepath.Join(home, ".vscode", "extensions")
	if got := d.DetectVersion(home, home, p); got != "1.5.0" {
		t.Errorf("DetectVersion() = %q, want %q", got, "1.5.0")
	}
}

// --- Aider Detector ---

func TestAiderDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string)
		expected bool
	}{
		{
			name: "aider dir exists",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".aider"))
			},
			expected: true,
		},
		{
			name: "aider config file exists",
			setup: func(t *testing.T, home string) {
				mustWriteFile(t, filepath.Join(home, ".aider.conf.yml"), "model: gpt-4")
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string) {},
			expected: false,
		},
	}

	d := &aiderDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			tt.setup(t, home)
			p := newMockPlatform(home)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// --- Devin Detector ---

func TestDevinDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string)
		expected bool
	}{
		{
			name: "devin dir exists",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".devin"))
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string) {},
			expected: false,
		},
	}

	d := &devinDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			tt.setup(t, home)
			p := newMockPlatform(home)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// --- OpenHands Detector ---

func TestOpenHandsDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string)
		expected bool
	}{
		{
			name: "openhands dir exists",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".openhands"))
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string) {},
			expected: false,
		},
	}

	d := &openHandsDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			tt.setup(t, home)
			p := newMockPlatform(home)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// --- Amazon Q Detector ---

func TestAmazonQDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "aws amazonq dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".aws", "amazonq"))
			},
			expected: true,
		},
		{
			name: "vscode extension exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				extDir := filepath.Join(home, ".vscode", "extensions")
				mustMkdirAll(t, filepath.Join(extDir, "amazonwebservices.amazon-q-vscode-1.0.0"))
				p.vsCodeExtDir = extDir
			},
			expected: true,
		},
		{
			name: "jetbrains plugin exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				pluginDir := filepath.Join(home, "jb-plugins")
				mustMkdirAll(t, filepath.Join(pluginDir, "amazon-q-1.0"))
				p.jetBrainsPlugDirs = []string{pluginDir}
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &amazonQDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAmazonQDetector_Version(t *testing.T) {
	d := &amazonQDetector{}
	home := resolvedTempDir(t)
	extDir := filepath.Join(home, ".vscode", "extensions", "amazonwebservices.amazon-q-vscode-1.3.0")
	mustMkdirAll(t, extDir)
	mustWriteFile(t, filepath.Join(extDir, "package.json"), `{"version":"1.3.0"}`)
	p := newMockPlatform(home)
	p.vsCodeExtDir = filepath.Join(home, ".vscode", "extensions")
	if got := d.DetectVersion(home, home, p); got != "1.3.0" {
		t.Errorf("DetectVersion() = %q, want %q", got, "1.3.0")
	}
}

// --- Junie Detector ---

func TestJunieDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "junie config dir exists",
			setup: func(t *testing.T, home string, _ *mockPlatform) {
				mustMkdirAll(t, filepath.Join(home, ".junie"))
			},
			expected: true,
		},
		{
			name: "jetbrains plugin exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				pluginDir := filepath.Join(home, "jb-plugins")
				mustMkdirAll(t, filepath.Join(pluginDir, "junie-1.0"))
				p.jetBrainsPlugDirs = []string{pluginDir}
			},
			expected: true,
		},
		{
			name: "binary exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				binDir := filepath.Join(home, ".local", "bin")
				mustMkdirAll(t, binDir)
				binPath := filepath.Join(binDir, "junie")
				mustWriteFile(t, binPath, "")
				p.junieBinPaths = []string{binPath}
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &junieDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestJunieDetector_CheckMCP(t *testing.T) {
	d := &junieDetector{}
	home := resolvedTempDir(t)
	mcpDir := filepath.Join(home, ".junie", "mcp")
	mustMkdirAll(t, mcpDir)
	mustWriteFile(t, filepath.Join(mcpDir, "mcp.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

func TestAmazonQDetector_CheckMCP(t *testing.T) {
	d := &amazonQDetector{}
	home := resolvedTempDir(t)
	mcpDir := filepath.Join(home, ".aws", "amazonq")
	mustMkdirAll(t, mcpDir)
	mustWriteFile(t, filepath.Join(mcpDir, "mcp.json"),
		`{"mcpServers":{"armis-appsec":{"command":"python3"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

// --- Zed Detector ---

func TestZedDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string, p *mockPlatform)
		expected bool
	}{
		{
			name: "zed config dir exists",
			setup: func(t *testing.T, home string, p *mockPlatform) {
				zedDir := filepath.Join(home, "zed-config")
				mustMkdirAll(t, zedDir)
				p.zedConfigDir = zedDir
			},
			expected: true,
		},
		{
			name: "zed not supported on platform",
			setup: func(_ *testing.T, _ string, p *mockPlatform) {
				p.zedConfigDir = ""
			},
			expected: false,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string, _ *mockPlatform) {},
			expected: false,
		},
	}

	d := &zedDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			p := newMockPlatform(home)
			tt.setup(t, home, p)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestZedDetector_CheckMCP(t *testing.T) {
	d := &zedDetector{}
	home := resolvedTempDir(t)
	zedDir := filepath.Join(home, "zed-config")
	mustMkdirAll(t, zedDir)
	mustWriteFile(t, filepath.Join(zedDir, "settings.json"),
		`{"context_servers":{"armis-appsec-mcp":{"command":{"path":"python3"}}}}`)
	p := newMockPlatform(home)
	p.zedConfigDir = zedDir
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is in context_servers")
	}
}

// --- Continue Detector ---

func TestContinueDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string)
		expected bool
	}{
		{
			name: "continue dir exists",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".continue"))
			},
			expected: true,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string) {},
			expected: false,
		},
	}

	d := &continueDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			tt.setup(t, home)
			p := newMockPlatform(home)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestContinueDetector_CheckMCP(t *testing.T) {
	d := &continueDetector{}

	t.Run("armis MCP in standard install file", func(t *testing.T) {
		home := resolvedTempDir(t)
		mcpDir := filepath.Join(home, ".continue", "mcpServers")
		mustMkdirAll(t, mcpDir)
		mustWriteFile(t, filepath.Join(mcpDir, "armis-appsec.json"),
			`{"mcpServers":{"armis-appsec":{"command":"python3"}}}`)
		p := newMockPlatform(home)
		if !d.CheckMCP(home, home, p) {
			t.Error("CheckMCP() should return true when armis MCP config exists")
		}
	})

	t.Run("armis MCP in custom filename", func(t *testing.T) {
		home := resolvedTempDir(t)
		mcpDir := filepath.Join(home, ".continue", "mcpServers")
		mustMkdirAll(t, mcpDir)
		mustWriteFile(t, filepath.Join(mcpDir, "my-servers.json"),
			`{"mcpServers":{"armis-appsec":{"command":"python3"}}}`)
		p := newMockPlatform(home)
		if !d.CheckMCP(home, home, p) {
			t.Error("CheckMCP() should return true when armis MCP is in any JSON file")
		}
	})

	t.Run("non-json file ignored", func(t *testing.T) {
		home := resolvedTempDir(t)
		mcpDir := filepath.Join(home, ".continue", "mcpServers")
		mustMkdirAll(t, mcpDir)
		mustWriteFile(t, filepath.Join(mcpDir, "armis-appsec.json.bak"),
			`{"mcpServers":{"armis-appsec":{"command":"python3"}}}`)
		p := newMockPlatform(home)
		if d.CheckMCP(home, home, p) {
			t.Error("CheckMCP() should ignore .bak files")
		}
	})

	t.Run("json file without armis MCP", func(t *testing.T) {
		home := resolvedTempDir(t)
		mcpDir := filepath.Join(home, ".continue", "mcpServers")
		mustMkdirAll(t, mcpDir)
		mustWriteFile(t, filepath.Join(mcpDir, "other.json"),
			`{"mcpServers":{"some-other-server":{"command":"node"}}}`)
		p := newMockPlatform(home)
		if d.CheckMCP(home, home, p) {
			t.Error("CheckMCP() should return false when no armis MCP entry exists")
		}
	})
}

// --- Gemini CLI Detector ---

func TestGeminiCLIDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, home string)
		expected bool
	}{
		{
			name: "gemini settings.json exists",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".gemini"))
				mustWriteFile(t, filepath.Join(home, ".gemini", "settings.json"), "{}")
			},
			expected: true,
		},
		{
			name: "gemini dir exists but no settings.json",
			setup: func(t *testing.T, home string) {
				mustMkdirAll(t, filepath.Join(home, ".gemini"))
			},
			expected: false,
		},
		{
			name:     "nothing exists",
			setup:    func(_ *testing.T, _ string) {},
			expected: false,
		},
	}

	d := &geminiCLIDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := resolvedTempDir(t)
			tt.setup(t, home)
			p := newMockPlatform(home)
			if got := d.Detect(home, home, p); got != tt.expected {
				t.Errorf("Detect() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGeminiCLIDetector_CheckMCP(t *testing.T) {
	d := &geminiCLIDetector{}
	home := resolvedTempDir(t)
	mustMkdirAll(t, filepath.Join(home, ".gemini"))
	mustWriteFile(t, filepath.Join(home, ".gemini", "settings.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)
	p := newMockPlatform(home)
	if !d.CheckMCP(home, home, p) {
		t.Error("CheckMCP() should return true when armis MCP is configured")
	}
}

func TestRegistryReturnsAllAgents(t *testing.T) {
	registry := Registry()
	expected := map[AgentName]bool{
		AgentClaudeCode:        false,
		AgentWindsurf:          false,
		AgentGoogleAntigravity: false,
		AgentGitHubCopilot:     false,
		AgentCursor:            false,
		AgentCline:             false,
		AgentRooCode:           false,
		AgentAider:             false,
		AgentDevin:             false,
		AgentOpenHands:         false,
		AgentAmazonQ:           false,
		AgentJunie:             false,
		AgentZed:               false,
		AgentContinue:          false,
		AgentGeminiCLI:         false,
	}
	for _, d := range registry {
		expected[d.Name()] = true
	}
	for name, found := range expected {
		if !found {
			t.Errorf("Registry() missing detector for %s", name)
		}
	}
}

// --- Path Traversal Tests ---

func TestIsUnderDir_RejectsTraversal(t *testing.T) {
	home := resolvedTempDir(t)
	mustMkdirAll(t, filepath.Join(home, "legit"))

	tests := []struct {
		name     string
		target   string
		expected bool
	}{
		{
			name:     "child directory",
			target:   filepath.Join(home, "legit"),
			expected: true,
		},
		{
			name:     "dotdot traversal",
			target:   filepath.Join(home, "legit", "..", "..", "etc", "passwd"),
			expected: false,
		},
		{
			name:     "nonexistent path",
			target:   filepath.Join(home, "does-not-exist"),
			expected: false,
		},
		{
			name:     "path outside home",
			target:   "/tmp",
			expected: false,
		},
		{
			name:     "home itself is not strictly under",
			target:   home,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUnderDir(home, tt.target); got != tt.expected {
				t.Errorf("isUnderDir(%q, %q) = %v, want %v", home, tt.target, got, tt.expected)
			}
		})
	}
}

func TestIsUnderDir_RejectsSymlinkEscape(t *testing.T) {
	home := resolvedTempDir(t)
	outside := resolvedTempDir(t)
	mustWriteFile(t, filepath.Join(outside, "secret.txt"), "sensitive data")

	link := filepath.Join(home, "escape-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if isUnderDir(home, filepath.Join(link, "secret.txt")) {
		t.Error("isUnderDir should reject symlink pointing outside home")
	}
}

func TestDirExists_RejectsTraversal(t *testing.T) {
	home := resolvedTempDir(t)
	outside := resolvedTempDir(t)

	if dirExists(home, outside) {
		t.Error("dirExists should reject path outside home")
	}
}

func TestFileExists_RejectsTraversal(t *testing.T) {
	home := resolvedTempDir(t)
	outside := resolvedTempDir(t)
	mustWriteFile(t, filepath.Join(outside, "file.txt"), "data")

	if fileExists(home, filepath.Join(outside, "file.txt")) {
		t.Error("fileExists should reject path outside home")
	}
}

func TestHasArmisMCP_RejectsTraversal(t *testing.T) {
	home := resolvedTempDir(t)
	outside := resolvedTempDir(t)
	mustWriteFile(t, filepath.Join(outside, "mcp.json"),
		`{"mcpServers":{"armis-appsec-mcp":{"command":"npx"}}}`)

	if HasArmisMCP(home, filepath.Join(outside, "mcp.json")) {
		t.Error("HasArmisMCP should reject config path outside home")
	}
}

func TestResolvePath_NonexistentReturnsError(t *testing.T) {
	_, err := resolvePath("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("resolvePath should return error for nonexistent path")
	}
}
