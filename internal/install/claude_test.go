package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const testVersion = "1.0.0"

func TestNewClaudeInstaller(t *testing.T) {
	ci := NewClaudeInstaller()
	if ci.claudeDir == "" {
		t.Fatal("claudeDir should not be empty")
	}
	if ci.plugin == nil {
		t.Fatal("plugin should not be nil")
	}
}

func TestPluginCacheDir(t *testing.T) {
	base := filepath.Join("home", "test", ".claude")
	ci := &ClaudeInstaller{claudeDir: base, plugin: newPluginInstaller()}
	got := ci.pluginCacheDir()
	want := filepath.Join(base, "plugins", "cache", "armis-appsec-mcp", "armis-appsec", "latest")
	if got != want {
		t.Errorf("pluginCacheDir() = %q, want %q", got, want)
	}
}

func TestHasExistingEnv(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir, plugin: newPluginInstaller()}

	if ci.HasExistingEnv() {
		t.Error("HasExistingEnv() should return false when .env doesn't exist")
	}

	pluginDir := ci.pluginCacheDir()
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("PLACEHOLDER=test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ci.HasExistingEnv() {
		t.Error("HasExistingEnv() should return true when .env exists")
	}
}

func TestInstalledVersion(t *testing.T) {
	ci := &ClaudeInstaller{plugin: newPluginInstaller()}
	if v := ci.InstalledVersion(); v != "" {
		t.Errorf("InstalledVersion() = %q, want empty", v)
	}
	ci.plugin.installedVersion = testVersion
	if v := ci.InstalledVersion(); v != testVersion {
		t.Errorf("InstalledVersion() = %q, want %q", v, testVersion)
	}
}

func TestRegisterMarketplace(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir, plugin: newPluginInstaller()}
	pluginsDir := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(dir, "plugins", "cache", "test")
	if err := ci.registerMarketplace(pluginDir); err != nil {
		t.Fatalf("registerMarketplace() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(pluginsDir, "known_marketplaces.json")))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if _, ok := result[marketplaceName]; !ok {
		t.Error("marketplace not registered")
	}
}

func TestRegisterPlugin(t *testing.T) {
	dir := t.TempDir()
	pi := newPluginInstaller()
	pi.installedVersion = testVersion
	ci := &ClaudeInstaller{claudeDir: dir, plugin: pi}
	pluginsDir := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(dir, "plugins", "cache", "test")
	if err := ci.registerPlugin(pluginDir); err != nil {
		t.Fatalf("registerPlugin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(pluginsDir, "installed_plugins.json")))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	plugins, ok := result["plugins"].(map[string]interface{})
	if !ok {
		t.Fatal("plugins key missing or wrong type")
	}
	key := pluginName + "@" + marketplaceName
	entries, ok := plugins[key].([]interface{})
	if !ok || len(entries) == 0 {
		t.Fatalf("plugin %q not registered", key)
	}
	entry := entries[0].(map[string]interface{})
	if entry["version"] != testVersion {
		t.Errorf("version = %q, want %q", entry["version"], testVersion)
	}
}

func TestGetInstalledVersion(t *testing.T) {
	dir := t.TempDir()
	pi := newPluginInstaller()
	ci := &ClaudeInstaller{claudeDir: dir, plugin: pi}

	if v := ci.GetInstalledVersion(); v != "" {
		t.Errorf("GetInstalledVersion() = %q, want empty for missing file", v)
	}

	pi.installedVersion = "2.1.0"
	pluginsDir := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(dir, "plugins", "cache", "test")
	if err := ci.registerPlugin(pluginDir); err != nil {
		t.Fatal(err)
	}

	if v := ci.GetInstalledVersion(); v != "2.1.0" {
		t.Errorf("GetInstalledVersion() = %q, want %q", v, "2.1.0")
	}
}

func TestEnablePlugin(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir, plugin: newPluginInstaller()}

	if err := ci.enablePlugin(); err != nil {
		t.Fatalf("enablePlugin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "settings.json")))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	enabled, ok := result["enabledPlugins"].(map[string]interface{})
	if !ok {
		t.Fatal("enabledPlugins key missing or wrong type")
	}
	key := pluginName + "@" + marketplaceName
	if enabled[key] != true {
		t.Errorf("plugin %q not enabled", key)
	}
}

func TestEnablePluginPreservesExistingSettings(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir, plugin: newPluginInstaller()}

	existing := map[string]interface{}{
		"permissions": map[string]interface{}{"allow": []string{"Bash"}},
		"enabledPlugins": map[string]interface{}{
			"other-plugin@other-mkt": true,
		},
	}
	b, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ci.enablePlugin(); err != nil {
		t.Fatalf("enablePlugin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "settings.json")))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	if result["permissions"] == nil {
		t.Error("existing permissions key was lost")
	}

	enabled := result["enabledPlugins"].(map[string]interface{})
	if enabled["other-plugin@other-mkt"] != true {
		t.Error("existing enabled plugin was lost")
	}
	key := pluginName + "@" + marketplaceName
	if enabled[key] != true {
		t.Error("new plugin not enabled")
	}
}

func TestInstallMissingClaudeDir(t *testing.T) {
	ci := &ClaudeInstaller{
		claudeDir: "/nonexistent/path/.claude",
		plugin:    newPluginInstaller(),
	}
	err := ci.Install()
	if err == nil {
		t.Fatal("expected error for missing Claude directory")
	}
	if got := err.Error(); !contains(got, "Claude Code directory not found") {
		t.Errorf("unexpected error: %s", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
