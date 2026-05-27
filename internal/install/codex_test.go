package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterCodexMCP_MissingFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	pluginDir := filepath.Join(dir, "plugins", "armis-appsec-mcp")
	setupFakeVenv(t, pluginDir)

	if err := RegisterCodexMCP(pluginDir); err != nil {
		t.Fatalf("RegisterCodexMCP() error: %v", err)
	}

	content, err := os.ReadFile(configFile) //nolint:gosec // test file with controlled path
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	got := string(content)
	if !strings.Contains(got, "[mcp_servers.armis_scanner]") {
		t.Errorf("missing section header in:\n%s", got)
	}
	if !strings.Contains(got, `command = "`+venvPython(pluginDir)+`"`) {
		t.Errorf("missing command in:\n%s", got)
	}
	if !strings.Contains(got, filepath.Join(pluginDir, "server.py")) {
		t.Errorf("missing server.py path in:\n%s", got)
	}
}

func TestRegisterCodexMCP_ExistingConfig(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	existing := `model = "gpt-5-codex"
model_reasoning_effort = "medium"

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
`
	if err := os.WriteFile(configFile, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(dir, "plugins", "armis-appsec-mcp")
	setupFakeVenv(t, pluginDir)

	if err := RegisterCodexMCP(pluginDir); err != nil {
		t.Fatalf("RegisterCodexMCP() error: %v", err)
	}

	content, err := os.ReadFile(configFile) //nolint:gosec // test file with controlled path
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	got := string(content)
	// Existing content preserved
	if !strings.Contains(got, `model = "gpt-5-codex"`) {
		t.Errorf("existing model setting lost:\n%s", got)
	}
	if !strings.Contains(got, "[mcp_servers.context7]") {
		t.Errorf("existing MCP server lost:\n%s", got)
	}
	// New section added
	if !strings.Contains(got, "[mcp_servers.armis_scanner]") {
		t.Errorf("missing armis_scanner section:\n%s", got)
	}
}

func TestRegisterCodexMCP_Idempotent(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	pluginDir := filepath.Join(dir, "plugins", "armis-appsec-mcp")
	setupFakeVenv(t, pluginDir)

	// Register twice
	if err := RegisterCodexMCP(pluginDir); err != nil {
		t.Fatalf("first RegisterCodexMCP() error: %v", err)
	}
	if err := RegisterCodexMCP(pluginDir); err != nil {
		t.Fatalf("second RegisterCodexMCP() error: %v", err)
	}

	content, err := os.ReadFile(configFile) //nolint:gosec // test file with controlled path
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	got := string(content)
	count := strings.Count(got, "[mcp_servers.armis_scanner]")
	if count != 1 {
		t.Errorf("expected 1 section header, got %d:\n%s", count, got)
	}
}

func TestRegisterCodexMCP_UpdatesExistingSection(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	// Pre-existing section with old path
	existing := `model = "gpt-5-codex"

[mcp_servers.armis_scanner]
command = "/old/path/python"
args = ["/old/path/server.py"]

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
`
	if err := os.WriteFile(configFile, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(dir, "plugins", "armis-appsec-mcp")
	setupFakeVenv(t, pluginDir)

	if err := RegisterCodexMCP(pluginDir); err != nil {
		t.Fatalf("RegisterCodexMCP() error: %v", err)
	}

	content, err := os.ReadFile(configFile) //nolint:gosec // test file with controlled path
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	got := string(content)
	// Old path gone
	if strings.Contains(got, "/old/path/") {
		t.Errorf("old path still present:\n%s", got)
	}
	// New path present
	if !strings.Contains(got, venvPython(pluginDir)) {
		t.Errorf("new python path missing:\n%s", got)
	}
	// Other sections preserved
	if !strings.Contains(got, "[mcp_servers.context7]") {
		t.Errorf("context7 section lost:\n%s", got)
	}
	if !strings.Contains(got, `model = "gpt-5-codex"`) {
		t.Errorf("model setting lost:\n%s", got)
	}
}

func TestDeregisterCodexMCP(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	existing := `model = "gpt-5-codex"

[mcp_servers.armis_scanner]
command = "/some/path/python"
args = ["/some/path/server.py"]

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
`
	if err := os.WriteFile(configFile, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := DeregisterCodexMCP(); err != nil {
		t.Fatalf("DeregisterCodexMCP() error: %v", err)
	}

	content, err := os.ReadFile(configFile) //nolint:gosec // test file with controlled path
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	got := string(content)
	if strings.Contains(got, "armis_scanner") {
		t.Errorf("armis_scanner section not removed:\n%s", got)
	}
	if !strings.Contains(got, "[mcp_servers.context7]") {
		t.Errorf("context7 section lost:\n%s", got)
	}
	if !strings.Contains(got, `model = "gpt-5-codex"`) {
		t.Errorf("model setting lost:\n%s", got)
	}
}

func TestDeregisterCodexMCP_NoSection(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	existing := `model = "gpt-5-codex"

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
`
	if err := os.WriteFile(configFile, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := DeregisterCodexMCP(); err != nil {
		t.Fatalf("DeregisterCodexMCP() error: %v", err)
	}

	content, err := os.ReadFile(configFile) //nolint:gosec // test file with controlled path
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	// File unchanged
	if string(content) != existing {
		t.Errorf("file was modified when it shouldn't have been:\n%s", string(content))
	}
}

func TestDeregisterCodexMCP_FileMissing(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	// No error when file doesn't exist
	if err := DeregisterCodexMCP(); err != nil {
		t.Fatalf("DeregisterCodexMCP() error: %v", err)
	}
}

func TestIsCodexDetected(t *testing.T) {
	dir := t.TempDir()
	codexDir := filepath.Join(dir, ".codex")
	configFile := filepath.Join(codexDir, "config.toml")
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	// Not detected when dir doesn't exist
	if IsCodexDetected() {
		t.Error("IsCodexDetected() = true, want false (dir missing)")
	}

	// Detected when dir exists
	if err := os.MkdirAll(codexDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if !IsCodexDetected() {
		t.Error("IsCodexDetected() = false, want true (dir exists)")
	}
}

func TestRegisterCodexMCP_RelativePath(t *testing.T) {
	if err := RegisterCodexMCP("relative/path"); err == nil {
		t.Error("expected error for relative path")
	}
}

// setupFakeVenv creates a minimal directory structure so venvPython resolves.
func setupFakeVenv(t *testing.T, pluginDir string) {
	t.Helper()
	venvBin := filepath.Join(pluginDir, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0o750); err != nil {
		t.Fatal(err)
	}
}
