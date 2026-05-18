package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeregisterMCPServersFormat(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "mcp.json")

	data := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"armis-appsec": map[string]interface{}{"command": "/bin/python", "args": []string{"server.py"}},
			"other-server": map[string]interface{}{"command": "/bin/other"},
		},
	}
	mustWriteJSON(t, configFile, data)

	if err := deregisterMCPServersFormat(configFile); err != nil {
		t.Fatalf("deregisterMCPServersFormat() error: %v", err)
	}

	result := mustReadJSON(t, configFile)
	servers := result["mcpServers"].(map[string]interface{})
	if _, exists := servers["armis-appsec"]; exists {
		t.Error("armis-appsec should be removed")
	}
	if _, exists := servers["other-server"]; !exists {
		t.Error("other-server should be preserved")
	}
}

func TestDeregisterVSCodeFormat(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "mcp.json")

	data := map[string]interface{}{
		"servers": map[string]interface{}{
			"armis-appsec": map[string]interface{}{"type": "stdio", "command": "/bin/python"},
			"copilot":      map[string]interface{}{"type": "stdio", "command": "/bin/copilot"},
		},
	}
	mustWriteJSON(t, configFile, data)

	if err := deregisterVSCodeFormat(configFile); err != nil {
		t.Fatalf("deregisterVSCodeFormat() error: %v", err)
	}

	result := mustReadJSON(t, configFile)
	servers := result["servers"].(map[string]interface{})
	if _, exists := servers["armis-appsec"]; exists {
		t.Error("armis-appsec should be removed")
	}
	if _, exists := servers["copilot"]; !exists {
		t.Error("copilot should be preserved")
	}
}

func TestDeregisterZedFormat(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "settings.json")

	data := map[string]interface{}{
		"context_servers": map[string]interface{}{
			"armis-appsec": map[string]interface{}{"command": map[string]interface{}{"path": "/bin/python"}},
		},
		"theme": "dark",
	}
	mustWriteJSON(t, configFile, data)

	if err := deregisterZedFormat(configFile); err != nil {
		t.Fatalf("deregisterZedFormat() error: %v", err)
	}

	result := mustReadJSON(t, configFile)
	servers := result["context_servers"].(map[string]interface{})
	if _, exists := servers["armis-appsec"]; exists {
		t.Error("armis-appsec should be removed")
	}
	if _, exists := result["theme"]; !exists {
		t.Error("other settings should be preserved")
	}
}

func TestDeregisterNoopWhenNotPresent(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "mcp.json")

	data := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"other-server": map[string]interface{}{"command": "/bin/other"},
		},
	}
	mustWriteJSON(t, configFile, data)

	if err := deregisterMCPServersFormat(configFile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := mustReadJSON(t, configFile)
	servers := result["mcpServers"].(map[string]interface{})
	if _, exists := servers["other-server"]; !exists {
		t.Error("existing servers should be untouched")
	}
}

func TestDeregisterMissingFile(t *testing.T) {
	err := deregisterMCPServersFormat("/nonexistent/path/mcp.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRemoveContinueFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "armis-appsec.json")
	mustWriteJSON(t, configFile, map[string]interface{}{"mcpServers": map[string]interface{}{}})

	if err := removeContinueFile(configFile); err != nil {
		t.Fatalf("removeContinueFile() error: %v", err)
	}
	if _, err := os.Stat(configFile); !os.IsNotExist(err) {
		t.Error("file should be deleted")
	}
}

func TestRemovePluginFiles(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "armis-appsec-mcp")
	_ = os.MkdirAll(pluginDir, 0o750)
	_ = os.WriteFile(filepath.Join(pluginDir, "server.py"), []byte("# server"), 0o600)
	_ = os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("CLIENT_ID=test"), 0o600)

	u := &Uninstaller{pluginDir: pluginDir}
	if err := u.RemovePluginFiles(false); err != nil {
		t.Fatalf("RemovePluginFiles() error: %v", err)
	}
	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		t.Error("plugin dir should be removed")
	}
}

func TestRemovePluginFilesKeepCredentials(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "armis-appsec-mcp")
	_ = os.MkdirAll(pluginDir, 0o750)
	_ = os.WriteFile(filepath.Join(pluginDir, "server.py"), []byte("# server"), 0o600)
	_ = os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("CLIENT_ID=test"), 0o600)

	u := &Uninstaller{pluginDir: pluginDir}
	if err := u.RemovePluginFiles(true); err != nil {
		t.Fatalf("RemovePluginFiles(keepCreds) error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(pluginDir, ".env")); err != nil {
		t.Error(".env should be preserved")
	}
	if _, err := os.Stat(filepath.Join(pluginDir, "server.py")); !os.IsNotExist(err) {
		t.Error("server.py should be removed")
	}

	content, _ := os.ReadFile(filepath.Clean(filepath.Join(pluginDir, ".env"))) //nolint:gosec // test file with known path
	if string(content) != "CLIENT_ID=test" {
		t.Errorf(".env content = %q, want original", string(content))
	}
}

func TestDeregisterClaude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	claudeDir := filepath.Join(home, ".claude")
	pluginsDir := filepath.Join(claudeDir, "plugins")
	_ = os.MkdirAll(pluginsDir, 0o750)
	cacheDir := filepath.Join(pluginsDir, "cache", marketplaceName)
	_ = os.MkdirAll(cacheDir, 0o750)

	mustWriteJSON(t, filepath.Join(pluginsDir, "known_marketplaces.json"), map[string]interface{}{
		marketplaceName: map[string]interface{}{"installLocation": "/tmp"},
	})
	mustWriteJSON(t, filepath.Join(pluginsDir, "installed_plugins.json"), map[string]interface{}{
		"version": 2,
		"plugins": map[string]interface{}{
			pluginName + "@" + marketplaceName: []interface{}{},
		},
	})
	mustWriteJSON(t, filepath.Join(claudeDir, "settings.json"), map[string]interface{}{
		"enabledPlugins": map[string]interface{}{
			pluginName + "@" + marketplaceName: true,
			"other-plugin@other":               true,
		},
	})

	u := &Uninstaller{}
	if err := u.DeregisterClaude(); err != nil {
		t.Fatalf("DeregisterClaude() error: %v", err)
	}

	mkts := mustReadJSON(t, filepath.Join(pluginsDir, "known_marketplaces.json"))
	if _, exists := mkts[marketplaceName]; exists {
		t.Error("marketplace entry should be removed")
	}

	inst := mustReadJSON(t, filepath.Join(pluginsDir, "installed_plugins.json"))
	plugins := inst["plugins"].(map[string]interface{})
	if _, exists := plugins[pluginName+"@"+marketplaceName]; exists {
		t.Error("installed plugin entry should be removed")
	}

	settings := mustReadJSON(t, filepath.Join(claudeDir, "settings.json"))
	enabled := settings["enabledPlugins"].(map[string]interface{})
	if _, exists := enabled[pluginName+"@"+marketplaceName]; exists {
		t.Error("enabledPlugins entry should be removed")
	}
	if _, exists := enabled["other-plugin@other"]; !exists {
		t.Error("other plugins should be preserved")
	}

	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Error("cache directory should be removed")
	}
}

func TestHasArmisEntry(t *testing.T) {
	dir := t.TempDir()

	t.Run("mcpServers present", func(t *testing.T) {
		f := filepath.Join(dir, "cursor.json")
		mustWriteJSON(t, f, map[string]interface{}{
			"mcpServers": map[string]interface{}{"armis-appsec": map[string]interface{}{}},
		})
		if !hasArmisEntry(EditorCursor, f) {
			t.Error("should detect armis-appsec in mcpServers")
		}
	})

	t.Run("mcpServers absent", func(t *testing.T) {
		f := filepath.Join(dir, "empty.json")
		mustWriteJSON(t, f, map[string]interface{}{
			"mcpServers": map[string]interface{}{"other": map[string]interface{}{}},
		})
		if hasArmisEntry(EditorCursor, f) {
			t.Error("should not detect armis-appsec")
		}
	})

	t.Run("vscode format", func(t *testing.T) {
		f := filepath.Join(dir, "vscode.json")
		mustWriteJSON(t, f, map[string]interface{}{
			"servers": map[string]interface{}{"armis-appsec": map[string]interface{}{}},
		})
		if !hasArmisEntry(EditorVSCode, f) {
			t.Error("should detect in servers format")
		}
	})
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := NewManifest(dir, "1.2.3")
	m.AddEditor(EditorCursor, "/tmp/cursor.json", "mcpServers")
	m.AddEditor(EditorVSCode, "/tmp/vscode.json", "vscode-servers")
	m.SetClaude("/tmp/claude-cache")

	if err := WriteManifest(m); err != nil {
		t.Fatalf("WriteManifest() error: %v", err)
	}

	loaded := ReadManifest(dir)
	if loaded == nil {
		t.Fatal("ReadManifest() returned nil")
	}
	if loaded.PluginVersion != "1.2.3" {
		t.Errorf("PluginVersion = %q, want %q", loaded.PluginVersion, "1.2.3")
	}
	if len(loaded.Editors) != 2 {
		t.Errorf("len(Editors) = %d, want 2", len(loaded.Editors))
	}
	if loaded.Claude == nil || loaded.Claude.CacheDir != "/tmp/claude-cache" {
		t.Error("Claude section not preserved")
	}
}

func TestManifestRemoveEditor(t *testing.T) {
	m := NewManifest("/tmp", "1.0.0")
	m.AddEditor(EditorCursor, "/tmp/cursor.json", "mcpServers")
	m.AddEditor(EditorVSCode, "/tmp/vscode.json", "vscode-servers")

	m.RemoveEditor(EditorCursor)

	if _, exists := m.Editors[EditorCursor]; exists {
		t.Error("cursor should be removed")
	}
	if _, exists := m.Editors[EditorVSCode]; !exists {
		t.Error("vscode should be preserved")
	}
}

func TestReadManifestMissing(t *testing.T) {
	m := ReadManifest("/nonexistent/dir")
	if m != nil {
		t.Error("ReadManifest should return nil for missing file")
	}
}

func TestConfigFormat(t *testing.T) {
	tests := []struct {
		id   EditorID
		want string
	}{
		{EditorVSCode, "vscode-servers"},
		{EditorZed, "zed-context_servers"},
		{EditorCursor, "mcpServers"},
		{EditorGemini, "mcpServers"},
	}
	for _, tt := range tests {
		if got := ConfigFormat(tt.id); got != tt.want {
			t.Errorf("ConfigFormat(%s) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

// --- Test helpers ---

func mustWriteJSON(t *testing.T, path string, data interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustReadJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	return data
}
