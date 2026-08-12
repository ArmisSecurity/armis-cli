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

// TestRemoveContinueEntryPreservesOtherSettings pins the reason Continue is
// edited rather than deleted: config.yaml holds the user's entire Continue
// configuration, so removing our server must leave everything else intact.
func TestRemoveContinueEntryPreservesOtherSettings(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := writeYAML(configFile, map[string]interface{}{
		"name":   "Main Config",
		"schema": "v1",
		"models": []interface{}{map[string]interface{}{"name": "gpt"}},
		"mcpServers": []interface{}{
			map[string]interface{}{"name": "other-server", "command": "/bin/other"},
			map[string]interface{}{"name": mcpServerName, "command": "/bin/python"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := removeContinueEntry(configFile, []string{mcpServerName}); err != nil {
		t.Fatalf("removeContinueEntry() error: %v", err)
	}

	if _, err := os.Stat(configFile); err != nil {
		t.Fatal("config.yaml must be edited, never deleted — it holds all Continue settings")
	}

	got := readYAMLFileAsMap(configFile)
	if got["models"] == nil {
		t.Error("unrelated Continue settings (models) were lost")
	}
	servers, ok := got["mcpServers"].([]interface{})
	if !ok || len(servers) != 1 {
		t.Fatalf("expected exactly one surviving server, got: %v", got["mcpServers"])
	}
	m, _ := servers[0].(map[string]interface{})
	if n, _ := m["name"].(string); n != "other-server" {
		t.Errorf("surviving server = %q, want other-server", n)
	}
}

func TestRemoveContinueEntryNoArmisEntry(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := writeYAML(configFile, map[string]interface{}{
		"mcpServers": []interface{}{
			map[string]interface{}{"name": "other-server", "command": "/bin/other"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := removeContinueEntry(configFile, []string{mcpServerName}); err != nil {
		t.Fatalf("removeContinueEntry() error: %v", err)
	}

	got := readYAMLFileAsMap(configFile)
	servers, ok := got["mcpServers"].([]interface{})
	if !ok || len(servers) != 1 {
		t.Errorf("a config without an Armis entry must be left alone, got: %v", got["mcpServers"])
	}
}

// TestDeregisterAllEditorsRemovesContinueYAML covers the gate in front of
// removal, not just removal itself: DeregisterAllEditors only calls the
// deregister dispatcher when hasArmisEntry says an entry exists. hasArmisEntry
// used to parse every config as JSON, so Continue's YAML raised a parse error,
// the editor was skipped, and the entry survived an uninstall while the user was
// shown a confusing "cannot read config" warning.
//
// Both discovery paths are exercised: the manifest path and the AllEditors scan
// that catches installs predating manifest tracking.
func TestDeregisterAllEditorsRemovesContinueYAML(t *testing.T) {
	for _, withManifest := range []bool{false, true} {
		name := "scan path"
		if withManifest {
			name = "manifest path"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			configFile := filepath.Join(home, ".continue", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(configFile), 0o750); err != nil {
				t.Fatal(err)
			}
			configPathOverrides = map[EditorID]string{EditorContinue: configFile}
			t.Cleanup(func() { configPathOverrides = nil })

			pluginDir := filepath.Join(t.TempDir(), "armis-appsec-mcp")
			e, _ := EditorByID(EditorContinue)
			if err := e.Register(pluginDir); err != nil {
				t.Fatalf("Register() error: %v", err)
			}

			u := &Uninstaller{pluginDir: pluginDir}
			if withManifest {
				m := NewManifest(pluginDir, "1.0.0")
				m.AddEditor(EditorContinue, configFile, ConfigFormat(EditorContinue))
				u.manifest = m
			}

			deregistered, warnings := u.DeregisterAllEditors()
			if len(warnings) != 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if len(deregistered) != 1 || deregistered[0] != e.Name {
				t.Errorf("deregistered = %v, want [%s]", deregistered, e.Name)
			}

			servers, _ := readYAMLFileAsMap(configFile)["mcpServers"].([]interface{})
			if len(servers) != 0 {
				t.Errorf("Armis entry survived uninstall: %v", servers)
			}
		})
	}
}

// TestRegisterContinueFormatIsIdempotent guards against duplicate list entries:
// Continue's servers are a list, so a naive append would register Armis twice on
// a second install.
func TestRegisterContinueFormatIsIdempotent(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.yaml")
	pluginDir := t.TempDir()

	for i := 0; i < 2; i++ {
		if err := registerContinueFormat(configFile, scannerEntry(pluginDir)); err != nil {
			t.Fatalf("registerContinueFormat() run %d error: %v", i+1, err)
		}
	}

	got := readYAMLFileAsMap(configFile)
	servers, ok := got["mcpServers"].([]interface{})
	if !ok {
		t.Fatalf("mcpServers missing: %v", got)
	}
	if len(servers) != 1 {
		t.Errorf("registering twice produced %d entries, want 1", len(servers))
	}
	// Continue requires these top-level keys; a config we create must be valid.
	for _, k := range []string{"name", "version", "schema"} {
		if got[k] == nil {
			t.Errorf("required Continue key %q missing from generated config", k)
		}
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
		has, err := hasArmisEntry(EditorCursor, f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !has {
			t.Error("should detect armis-appsec in mcpServers")
		}
	})

	t.Run("mcpServers absent", func(t *testing.T) {
		f := filepath.Join(dir, "empty.json")
		mustWriteJSON(t, f, map[string]interface{}{
			"mcpServers": map[string]interface{}{"other": map[string]interface{}{}},
		})
		has, err := hasArmisEntry(EditorCursor, f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if has {
			t.Error("should not detect armis-appsec")
		}
	})

	t.Run("vscode format", func(t *testing.T) {
		f := filepath.Join(dir, "vscode.json")
		mustWriteJSON(t, f, map[string]interface{}{
			"servers": map[string]interface{}{"armis-appsec": map[string]interface{}{}},
		})
		has, err := hasArmisEntry(EditorVSCode, f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !has {
			t.Error("should detect in servers format")
		}
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		f := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(f, []byte("{invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := hasArmisEntry(EditorCursor, f)
		if err == nil {
			t.Error("expected error for malformed JSON")
		}
	})

	t.Run("missing file returns false without error", func(t *testing.T) {
		has, err := hasArmisEntry(EditorCursor, filepath.Join(dir, "nonexistent.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if has {
			t.Error("missing file should return false")
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
	}
	for _, tt := range tests {
		if got := ConfigFormat(tt.id); got != tt.want {
			t.Errorf("ConfigFormat(%s) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestManifestPath(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name      string
		input     string
		wantEmpty bool
	}{
		{"empty string", "", true},
		{"relative path", "relative/dir", true},
		{"valid absolute path", dir, false},
		{"root path", "/", true}, // Join("/", ".manifest.json") == "/.manifest.json" which doesn't start with "/"+"/"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ManifestPath(tt.input)
			if tt.wantEmpty && got != "" {
				t.Errorf("ManifestPath(%q) = %q, want empty", tt.input, got)
			}
			if !tt.wantEmpty && got == "" {
				t.Errorf("ManifestPath(%q) = empty, want non-empty path", tt.input)
			}
		})
	}

	t.Run("valid path ends with .manifest.json", func(t *testing.T) {
		got := ManifestPath(dir)
		if got == "" {
			t.Fatal("expected non-empty path")
		}
		if filepath.Base(got) != ".manifest.json" {
			t.Errorf("ManifestPath() base = %q, want .manifest.json", filepath.Base(got))
		}
	})
}

func TestDeregisterAllEditors(t *testing.T) {
	t.Run("manifest-based deregistration", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
		if err := os.MkdirAll(pluginDir, 0o750); err != nil {
			t.Fatal(err)
		}

		// Create a cursor config with armis entry
		cursorConfig := filepath.Join(home, "cursor-mcp.json")
		mustWriteJSON(t, cursorConfig, map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"armis-appsec": map[string]interface{}{"command": "/bin/python"},
				"other":        map[string]interface{}{"command": "/bin/other"},
			},
		})

		// Create manifest pointing to the cursor config
		m := NewManifest(pluginDir, "1.0.0")
		m.AddEditor(EditorCursor, cursorConfig, "mcpServers")
		if err := WriteManifest(m); err != nil {
			t.Fatal(err)
		}

		// Override all editor paths to nonexistent so scan doesn't find extra editors
		configPathOverrides = make(map[EditorID]string)
		for _, e := range AllEditors {
			configPathOverrides[e.ID] = filepath.Join(home, "nonexistent", string(e.ID)+".json")
		}
		defer func() { configPathOverrides = nil }()

		u := NewUninstaller()
		deregistered, warnings := u.DeregisterAllEditors()

		if len(warnings) > 0 {
			t.Errorf("unexpected warnings: %v", warnings)
		}
		if len(deregistered) != 1 || deregistered[0] != "Cursor" {
			t.Errorf("deregistered = %v, want [Cursor]", deregistered)
		}

		// Verify armis-appsec was removed from cursor config
		result := mustReadJSON(t, cursorConfig)
		servers := result["mcpServers"].(map[string]interface{})
		if _, exists := servers["armis-appsec"]; exists {
			t.Error("armis-appsec should be removed from cursor config")
		}
		if _, exists := servers["other"]; !exists {
			t.Error("other server should be preserved")
		}
	})

	t.Run("no manifest scans known paths", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
		if err := os.MkdirAll(pluginDir, 0o750); err != nil {
			t.Fatal(err)
		}

		// Create a cursor config with armis entry in the overridden path
		cursorConfig := filepath.Join(home, "cursor-mcp.json")
		mustWriteJSON(t, cursorConfig, map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"armis-appsec": map[string]interface{}{"command": "/bin/python"},
			},
		})

		configPathOverrides = make(map[EditorID]string)
		for _, e := range AllEditors {
			configPathOverrides[e.ID] = filepath.Join(home, "nonexistent", string(e.ID)+".json")
		}
		configPathOverrides[EditorCursor] = cursorConfig
		defer func() { configPathOverrides = nil }()

		u := &Uninstaller{pluginDir: pluginDir, manifest: nil}
		deregistered, warnings := u.DeregisterAllEditors()

		if len(warnings) > 0 {
			t.Errorf("unexpected warnings: %v", warnings)
		}
		if len(deregistered) != 1 || deregistered[0] != "Cursor" {
			t.Errorf("deregistered = %v, want [Cursor]", deregistered)
		}
	})

	t.Run("missing config file is silently skipped", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
		if err := os.MkdirAll(pluginDir, 0o750); err != nil {
			t.Fatal(err)
		}

		configPathOverrides = make(map[EditorID]string)
		for _, e := range AllEditors {
			configPathOverrides[e.ID] = filepath.Join(home, "nonexistent", string(e.ID)+".json")
		}
		defer func() { configPathOverrides = nil }()

		u := &Uninstaller{pluginDir: pluginDir, manifest: nil}
		deregistered, warnings := u.DeregisterAllEditors()

		if len(deregistered) != 0 {
			t.Errorf("deregistered = %v, want empty", deregistered)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})
}

func TestWriteJSONAtomic(t *testing.T) {
	t.Run("writes valid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.json")
		data := map[string]interface{}{
			"key": "value",
			"num": 42,
		}

		if err := writeJSONAtomic(path, data); err != nil {
			t.Fatalf("writeJSONAtomic() error: %v", err)
		}

		result := mustReadJSON(t, path)
		if result["key"] != "value" {
			t.Errorf("key = %v, want 'value'", result["key"])
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.json")
		mustWriteJSON(t, path, map[string]interface{}{"old": true})

		if err := writeJSONAtomic(path, map[string]interface{}{"new": true}); err != nil {
			t.Fatalf("writeJSONAtomic() error: %v", err)
		}

		result := mustReadJSON(t, path)
		if _, exists := result["old"]; exists {
			t.Error("old content should be overwritten")
		}
		if _, exists := result["new"]; !exists {
			t.Error("new content should be present")
		}
	})
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

func TestRemoveKnowledgeLeavesScannerEntry(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "mcp.json")
	scannerDir := t.TempDir()
	knowledgeDir := filepath.Join(t.TempDir(), "knowledge")
	if err := os.MkdirAll(knowledgeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Both products registered in one config file.
	if err := registerEditorEntry(EditorCursor, configFile, scannerEntry(scannerDir)); err != nil {
		t.Fatal(err)
	}
	knowledge := mcpEntry{
		name:    "armis-knowledge",
		command: venvPython(knowledgeDir),
		args:    []string{filepath.Join(knowledgeDir, "bridge.py")},
	}
	if err := registerEditorEntry(EditorCursor, configFile, knowledge); err != nil {
		t.Fatal(err)
	}

	m := NewManifest(scannerDir, "1.0.0")
	k := m.EnsureKnowledge(knowledgeDir, "abc1234")
	k.AddEditor(EditorCursor, configFile, "mcpServers")

	u := &Uninstaller{pluginDir: scannerDir, manifest: m}
	if !u.HasKnowledge() {
		t.Fatal("HasKnowledge() = false, want true when the manifest records knowledge")
	}

	removed, warnings := u.RemoveKnowledge(false)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(removed) == 0 {
		t.Error("expected at least one removal to be reported")
	}

	b, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatalf("mcpServers missing after knowledge removal: %s", b)
	}
	if servers["armis-knowledge"] != nil {
		t.Error("knowledge entry should be removed")
	}
	if servers["armis-appsec"] == nil {
		t.Error("scanner entry must survive knowledge removal")
	}

	if _, err := os.Stat(knowledgeDir); !os.IsNotExist(err) {
		t.Error("knowledge plugin directory should be deleted")
	}
}

func TestRemoveKnowledgeNoopWithoutManifestEntry(t *testing.T) {
	dir := t.TempDir()
	u := &Uninstaller{pluginDir: dir, manifest: NewManifest(dir, "1.0.0")}

	if u.HasKnowledge() {
		t.Error("HasKnowledge() = true, want false when the manifest has no knowledge section")
	}

	removed, warnings := u.RemoveKnowledge(false)
	if len(removed) != 0 || len(warnings) != 0 {
		t.Errorf("expected a no-op, got removed=%v warnings=%v", removed, warnings)
	}
}
