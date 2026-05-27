package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallNativeHook(t *testing.T) {
	t.Run("cursor hook creates correct format", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "hooks.json")
		pluginDir := setupFakePluginDir(t, "cursor_pre_tool.py")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, ok := HookClientByID(HookClientCursor)
		if !ok {
			t.Fatal("cursor client not found")
		}

		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("InstallNativeHook() error = %v", err)
		}

		data := readTestJSON(t, configPath)
		if _, ok := data["version"]; !ok {
			t.Error("expected version key for cursor config")
		}
		hooks, ok := data["hooks"].(map[string]interface{})
		if !ok {
			t.Fatal("expected hooks key")
		}
		if _, ok := hooks["beforeShellExecution"]; !ok {
			t.Error("expected beforeShellExecution key")
		}
		if _, ok := hooks["preToolUse"]; !ok {
			t.Error("expected preToolUse key")
		}
	})

	t.Run("gemini hook creates correct format", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "settings.json")
		pluginDir := setupFakePluginDir(t, "gemini_pre_tool.py")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientGemini: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientGemini)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("InstallNativeHook() error = %v", err)
		}

		data := readTestJSON(t, configPath)
		hooks, ok := data["hooks"].(map[string]interface{})
		if !ok {
			t.Fatal("expected hooks key")
		}
		if _, ok := hooks["BeforeTool"]; !ok {
			t.Error("expected BeforeTool key")
		}
	})

	t.Run("codex hook creates correct format", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "hooks.json")
		pluginDir := setupFakePluginDir(t, "codex_pre_tool.py")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCodex: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCodex)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("InstallNativeHook() error = %v", err)
		}

		data := readTestJSON(t, configPath)
		hooks := data["hooks"].(map[string]interface{})
		preToolUse, ok := hooks["PreToolUse"].([]interface{})
		if !ok {
			t.Fatal("expected PreToolUse array")
		}
		if len(preToolUse) != 2 {
			t.Errorf("expected 2 PreToolUse entries (shell + write), got %d", len(preToolUse))
		}
	})

	t.Run("copilot hook merges into settings and uses bash key", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "settings.json")
		pluginDir := setupFakePluginDir(t, "copilot_pre_tool.py")

		// Pre-populate with existing settings to verify merge behavior.
		existing := map[string]interface{}{"memory": true, "model": "claude-opus-4.7"}
		writeTestJSON(t, configPath, existing)

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCopilot: configPath,
		}
		// Redirect HOME so cleanupLegacyCopilotHook targets the temp dir.
		t.Setenv("HOME", dir)
		t.Setenv("USERPROFILE", dir)
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCopilot)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("InstallNativeHook() error = %v", err)
		}

		data := readTestJSON(t, configPath)

		// Existing settings preserved.
		if data["memory"] != true {
			t.Error("existing 'memory' setting was lost")
		}
		if data["model"] != "claude-opus-4.7" {
			t.Error("existing 'model' setting was lost")
		}

		// No "version" key (settings.json doesn't use it).
		if _, ok := data["version"]; ok {
			t.Error("settings.json should not have 'version' key")
		}

		// Hook uses "bash" key.
		hooks := data["hooks"].(map[string]interface{})
		preToolUse := hooks["preToolUse"].([]interface{})
		entry := preToolUse[0].(map[string]interface{})
		if _, ok := entry["bash"]; !ok {
			t.Error("expected 'bash' key in copilot hook (not 'command')")
		}
	})

	t.Run("copilot legacy cleanup removes armis-only file", func(t *testing.T) {
		dir := t.TempDir()
		// Place legacy file where cleanupLegacyCopilotHook will look.
		legacyDir := filepath.Join(dir, ".config", "github-copilot")
		if err := os.MkdirAll(legacyDir, 0o750); err != nil {
			t.Fatal(err)
		}
		legacyPath := filepath.Join(legacyDir, "hooks.json")

		legacy := map[string]interface{}{
			"version": float64(1),
			"hooks": map[string]interface{}{
				"preToolUse": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"bash":    "'/path/to/python' '/path/to/copilot_pre_tool.py'",
						"matcher": "bash|powershell|create|edit",
					},
				},
			},
		}
		writeTestJSON(t, legacyPath, legacy)

		t.Setenv("HOME", dir)
		t.Setenv("USERPROFILE", dir)
		cleanupLegacyCopilotHook()

		if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
			t.Error("expected legacy file to be removed")
		}
	})

	t.Run("copilot legacy cleanup preserves non-armis file", func(t *testing.T) {
		dir := t.TempDir()
		legacyDir := filepath.Join(dir, ".config", "github-copilot")
		if err := os.MkdirAll(legacyDir, 0o750); err != nil {
			t.Fatal(err)
		}
		legacyPath := filepath.Join(legacyDir, "hooks.json")

		legacy := map[string]interface{}{
			"version": float64(1),
			"hooks": map[string]interface{}{
				"preToolUse": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"bash":    "some-other-tool",
						"matcher": "bash",
					},
				},
			},
		}
		writeTestJSON(t, legacyPath, legacy)

		t.Setenv("HOME", dir)
		t.Setenv("USERPROFILE", dir)
		cleanupLegacyCopilotHook()

		if _, err := os.Stat(legacyPath); err != nil {
			t.Error("expected legacy file to be preserved when it has non-Armis entries")
		}
	})

	t.Run("cline hook creates correct format", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "hooks.json")
		pluginDir := setupFakePluginDir(t, "cline_pre_tool.py")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCline: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCline)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("InstallNativeHook() error = %v", err)
		}

		data := readTestJSON(t, configPath)
		hooks := data["hooks"].(map[string]interface{})
		if _, ok := hooks["PreToolUse"]; !ok {
			t.Error("expected PreToolUse key for cline")
		}
	})

	t.Run("idempotent - does not duplicate", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "hooks.json")
		pluginDir := setupFakePluginDir(t, "cursor_pre_tool.py")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCursor)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("first install: %v", err)
		}
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("second install: %v", err)
		}

		data := readTestJSON(t, configPath)
		hooks := data["hooks"].(map[string]interface{})
		beforeShell := hooks["beforeShellExecution"].([]interface{})
		if len(beforeShell) != 1 {
			t.Errorf("expected 1 beforeShellExecution entry after double install, got %d", len(beforeShell))
		}
	})

	t.Run("merges with existing config", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "settings.json")
		pluginDir := setupFakePluginDir(t, "gemini_pre_tool.py")

		existing := map[string]interface{}{
			"model": "gemini-pro",
			"hooks": map[string]interface{}{
				"BeforeTool": []interface{}{
					map[string]interface{}{
						"matcher": "some_tool",
						"hooks": []interface{}{
							map[string]interface{}{
								"type":    "command",
								"command": "echo hello",
							},
						},
					},
				},
			},
		}
		writeTestJSON(t, configPath, existing)

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientGemini: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientGemini)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("InstallNativeHook() error = %v", err)
		}

		data := readTestJSON(t, configPath)
		if data["model"] != "gemini-pro" {
			t.Error("existing settings were lost")
		}
		hooks := data["hooks"].(map[string]interface{})
		beforeTool := hooks["BeforeTool"].([]interface{})
		if len(beforeTool) != 2 {
			t.Errorf("expected 2 BeforeTool entries (existing + armis), got %d", len(beforeTool))
		}
	})

	t.Run("error when adapter not found", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "hooks.json")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCursor)
		err := InstallNativeHook(client, "/nonexistent/plugin/dir")
		if err == nil {
			t.Fatal("expected error when adapter not found")
		}
	})
}

func TestRemoveNativeHook(t *testing.T) {
	t.Run("removes armis entries", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "hooks.json")
		pluginDir := setupFakePluginDir(t, "cursor_pre_tool.py")

		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor: configPath,
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCursor)
		if err := InstallNativeHook(client, pluginDir); err != nil {
			t.Fatalf("install: %v", err)
		}

		if err := RemoveNativeHook(client); err != nil {
			t.Fatalf("remove: %v", err)
		}

		data := readTestJSON(t, configPath)
		hooks, _ := data["hooks"].(map[string]interface{})
		for key, entries := range hooks {
			arr, _ := entries.([]interface{})
			if len(arr) > 0 {
				t.Errorf("expected empty %s after removal, got %d entries", key, len(arr))
			}
		}
	})

	t.Run("noop when config does not exist", func(t *testing.T) {
		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor: "/nonexistent/hooks.json",
		}
		defer func() { hookConfigPathOverrides = nil }()

		client, _ := HookClientByID(HookClientCursor)
		if err := RemoveNativeHook(client); err != nil {
			t.Fatalf("RemoveNativeHook() error = %v, expected nil for missing file", err)
		}
	})
}

func TestDetectHookClients(t *testing.T) {
	t.Run("returns empty when no clients installed", func(t *testing.T) {
		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor:  "/nonexistent/cursor",
			HookClientGemini:  "/nonexistent/gemini",
			HookClientCodex:   "/nonexistent/codex",
			HookClientCopilot: "/nonexistent/copilot",
			HookClientCline:   "/nonexistent/cline",
		}
		defer func() { hookConfigPathOverrides = nil }()

		detected := DetectHookClients()
		if len(detected) != 0 {
			t.Errorf("expected 0 detected clients, got %d", len(detected))
		}
	})

	t.Run("detects client when parent dir exists", func(t *testing.T) {
		dir := t.TempDir()
		hookConfigPathOverrides = map[HookClientID]string{
			HookClientCursor:  filepath.Join(dir, "hooks.json"),
			HookClientGemini:  "/nonexistent/gemini/settings.json",
			HookClientCodex:   "/nonexistent/codex/hooks.json",
			HookClientCopilot: "/nonexistent/copilot/hooks.json",
			HookClientCline:   "/nonexistent/cline/hooks.json",
		}
		defer func() { hookConfigPathOverrides = nil }()

		detected := DetectHookClients()
		if len(detected) != 1 {
			t.Fatalf("expected 1 detected client, got %d", len(detected))
		}
		if detected[0].ID != HookClientCursor {
			t.Errorf("expected cursor, got %s", detected[0].ID)
		}
	})
}

func TestIsArmisHookJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want bool
	}{
		{"armis command", `{"command": "python3 /path/armis-appsec/hooks/cursor_pre_tool.py"}`, true},
		{"armis-cli ref", `{"command": "armis-cli scan repo ."}`, true},
		{"pre_tool.py ref", `{"command": "python3 /path/hooks/gemini_pre_tool.py"}`, true},
		{"unrelated command", `{"command": "echo hello"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry interface{}
			if err := json.Unmarshal([]byte(tt.json), &entry); err != nil {
				t.Fatal(err)
			}
			if got := isArmisHookJSON(entry); got != tt.want {
				t.Errorf("isArmisHookJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func setupFakePluginDir(t *testing.T, adapterName string) string {
	t.Helper()
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	adapterPath := filepath.Join(hooksDir, adapterName)
	if err := os.WriteFile(adapterPath, []byte("# fake adapter\n"), 0o644); err != nil { //nolint:gosec // test helper with temp dir path
		t.Fatal(err)
	}
	// Also create a fake venv python for venvPython() resolution
	venvBin := filepath.Join(dir, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvBin, "python"), []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // executable needed for test
		t.Fatal(err)
	}
	return dir
}
