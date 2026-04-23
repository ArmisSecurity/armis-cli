package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewCopilotInstaller(t *testing.T) {
	ci := NewCopilotInstaller()
	if ci.installDir == "" {
		t.Fatal("installDir should not be empty")
	}
	if ci.plugin == nil {
		t.Fatal("plugin should not be nil")
	}
}

func TestCopilotHasExistingEnv(t *testing.T) {
	dir := t.TempDir()
	ci := &CopilotInstaller{installDir: dir, plugin: newPluginInstaller()}

	if ci.HasExistingEnv() {
		t.Error("HasExistingEnv() should return false when .env doesn't exist")
	}

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("PLACEHOLDER=test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ci.HasExistingEnv() {
		t.Error("HasExistingEnv() should return true when .env exists")
	}
}

func TestCopilotEnvFilePath(t *testing.T) {
	dir := filepath.Join("home", "test", ".armis", "plugins", "armis-appsec-mcp")
	ci := &CopilotInstaller{installDir: dir, plugin: newPluginInstaller()}
	got := ci.EnvFilePath()
	want := filepath.Join(dir, ".env")
	if got != want {
		t.Errorf("EnvFilePath() = %q, want %q", got, want)
	}
}

func TestCopilotInstalledVersion(t *testing.T) {
	ci := &CopilotInstaller{plugin: newPluginInstaller()}
	if v := ci.InstalledVersion(); v != "" {
		t.Errorf("InstalledVersion() = %q, want empty", v)
	}
	ci.plugin.installedVersion = "2.0.0"
	if v := ci.InstalledVersion(); v != "2.0.0" {
		t.Errorf("InstalledVersion() = %q, want %q", v, "2.0.0")
	}
}

func TestCopilotRegisterMCPServer(t *testing.T) {
	dir := t.TempDir()
	installDir := filepath.Join(dir, "plugin")
	if err := os.MkdirAll(installDir, 0o750); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(dir, "vscode-user")
	if err := os.MkdirAll(mcpDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mcpFile := filepath.Join(mcpDir, "mcp.json")

	pi := newPluginInstaller()
	pi.installedVersion = "1.5.0"
	ci := &CopilotInstaller{installDir: installDir, plugin: pi}

	origFunc := userMCPConfigPathOverride
	userMCPConfigPathOverride = func() string { return mcpFile }
	defer func() { userMCPConfigPathOverride = origFunc }()

	if err := ci.registerMCPServer(); err != nil {
		t.Fatalf("registerMCPServer() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(mcpFile))
	if err != nil {
		t.Fatal(err)
	}

	var config mcpConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}

	server, ok := config.Servers["armis-appsec"]
	if !ok {
		t.Fatal("armis-appsec server not registered")
	}
	if server.Type != "stdio" {
		t.Errorf("server type = %q, want %q", server.Type, "stdio")
	}
	if server.Command != venvPython(installDir) {
		t.Errorf("server command = %q, want %q", server.Command, venvPython(installDir))
	}
	expectedScript := filepath.Join(installDir, "server.py")
	if len(server.Args) != 1 || server.Args[0] != expectedScript {
		t.Errorf("server args = %v, want [%q]", server.Args, expectedScript)
	}

	versionData, err := os.ReadFile(filepath.Clean(filepath.Join(installDir, ".installed-version")))
	if err != nil {
		t.Fatal(err)
	}
	if string(versionData) != "1.5.0" {
		t.Errorf("version file = %q, want %q", string(versionData), "1.5.0")
	}
}

func TestCopilotRegisterMCPServerPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	installDir := filepath.Join(dir, "plugin")
	if err := os.MkdirAll(installDir, 0o750); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(dir, "vscode-user")
	if err := os.MkdirAll(mcpDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mcpFile := filepath.Join(mcpDir, "mcp.json")

	existing := mcpConfig{
		Servers: map[string]mcpServer{
			"other-server": {
				Type:    "stdio",
				Command: "node",
				Args:    []string{"server.js"},
			},
		},
	}
	b, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(mcpFile, b, 0o600); err != nil {
		t.Fatal(err)
	}

	pi := newPluginInstaller()
	pi.installedVersion = "1.0.0"
	ci := &CopilotInstaller{installDir: installDir, plugin: pi}

	origFunc := userMCPConfigPathOverride
	userMCPConfigPathOverride = func() string { return mcpFile }
	defer func() { userMCPConfigPathOverride = origFunc }()

	if err := ci.registerMCPServer(); err != nil {
		t.Fatalf("registerMCPServer() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(mcpFile))
	if err != nil {
		t.Fatal(err)
	}

	var config mcpConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}

	if _, ok := config.Servers["other-server"]; !ok {
		t.Error("existing server was lost")
	}
	if _, ok := config.Servers["armis-appsec"]; !ok {
		t.Error("armis-appsec server not registered")
	}
}

func TestCopilotGetInstalledVersion(t *testing.T) {
	dir := t.TempDir()
	installDir := filepath.Join(dir, "plugin")
	if err := os.MkdirAll(installDir, 0o750); err != nil {
		t.Fatal(err)
	}

	mcpDir := filepath.Join(dir, "vscode-user")
	if err := os.MkdirAll(mcpDir, 0o750); err != nil {
		t.Fatal(err)
	}
	mcpFile := filepath.Join(mcpDir, "mcp.json")

	ci := &CopilotInstaller{installDir: installDir, plugin: newPluginInstaller()}

	origFunc := userMCPConfigPathOverride
	userMCPConfigPathOverride = func() string { return mcpFile }
	defer func() { userMCPConfigPathOverride = origFunc }()

	if v := ci.GetInstalledVersion(); v != "" {
		t.Errorf("GetInstalledVersion() = %q, want empty when not installed", v)
	}

	config := mcpConfig{
		Servers: map[string]mcpServer{
			"armis-appsec": {Type: "stdio", Command: "python"},
		},
	}
	b, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(mcpFile, b, 0o600); err != nil {
		t.Fatal(err)
	}

	if v := ci.GetInstalledVersion(); v != "unknown" {
		t.Errorf("GetInstalledVersion() = %q, want %q when no version file", v, "unknown")
	}

	versionFile := filepath.Join(installDir, ".installed-version")
	if err := os.WriteFile(versionFile, []byte("3.0.0"), 0o600); err != nil {
		t.Fatal(err)
	}

	if v := ci.GetInstalledVersion(); v != "3.0.0" {
		t.Errorf("GetInstalledVersion() = %q, want %q", v, "3.0.0")
	}
}

func TestUserMCPConfigPath(t *testing.T) {
	userMCPConfigPathOverride = nil
	path := userMCPConfigPath()
	if path == "" {
		t.Fatal("userMCPConfigPath() returned empty string")
	}

	switch runtime.GOOS {
	case "darwin":
		if !filepath.IsAbs(path) {
			t.Errorf("expected absolute path, got %q", path)
		}
	case "linux":
		if !filepath.IsAbs(path) {
			t.Errorf("expected absolute path, got %q", path)
		}
	}
}

func TestVenvPython(t *testing.T) {
	got := venvPython("/some/dir")
	switch runtime.GOOS {
	case "windows":
		want := filepath.Join("/some/dir", ".venv", "Scripts", "python.exe")
		if got != want {
			t.Errorf("venvPython() = %q, want %q", got, want)
		}
	default:
		want := filepath.Join("/some/dir", ".venv", "bin", "python")
		if got != want {
			t.Errorf("venvPython() = %q, want %q", got, want)
		}
	}
}
