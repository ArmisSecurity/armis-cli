package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallHooksToFile(t *testing.T) {
	t.Run("creates parent directory if missing", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "nonexistent", "subdir", "settings.json")

		if err := installHooksToFile(settingsPath); err != nil {
			t.Fatalf("installHooksToFile() error = %v", err)
		}

		if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
			t.Fatal("settings file was not created")
		}

		var settings map[string]interface{}
		data, _ := os.ReadFile(settingsPath) //nolint:gosec // test
		if err := json.Unmarshal(data, &settings); err != nil {
			t.Fatalf("parsing settings: %v", err)
		}
		hooks, ok := settings["hooks"].(map[string]interface{})
		if !ok {
			t.Fatal("expected hooks key")
		}
		if _, ok := hooks["PreToolUse"]; !ok {
			t.Fatal("expected PreToolUse key")
		}
	})

	t.Run("creates settings file if missing", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		if err := installHooksToFile(settingsPath); err != nil {
			t.Fatalf("installHooksToFile() error = %v", err)
		}

		data, err := os.ReadFile(settingsPath) //nolint:gosec // G304: test reading from t.TempDir()
		if err != nil {
			t.Fatalf("reading settings: %v", err)
		}

		var settings map[string]interface{}
		if err := json.Unmarshal(data, &settings); err != nil {
			t.Fatalf("parsing settings: %v", err)
		}

		hooks, ok := settings["hooks"].(map[string]interface{})
		if !ok {
			t.Fatal("expected hooks key in settings")
		}
		preToolUse, ok := hooks["PreToolUse"].([]interface{})
		if !ok {
			t.Fatal("expected PreToolUse array")
		}
		if len(preToolUse) != 1 {
			t.Fatalf("expected 1 PreToolUse entry, got %d", len(preToolUse))
		}

		entry := preToolUse[0].(map[string]interface{})
		if matcher, _ := entry["matcher"].(string); matcher != armisHookMatcher {
			t.Errorf("matcher = %q, want %q", matcher, armisHookMatcher)
		}
	})

	t.Run("merges into existing settings", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		existing := map[string]interface{}{
			"permissions": map[string]interface{}{
				"allow": []string{"Read", "Write"},
			},
			"hooks": map[string]interface{}{
				"PreToolUse": []interface{}{
					map[string]interface{}{
						"matcher": "Bash",
						"hooks": []interface{}{
							map[string]interface{}{
								"type":    "command",
								"command": "echo pre-bash",
							},
						},
					},
				},
			},
		}
		writeTestJSON(t, settingsPath, existing)

		if err := installHooksToFile(settingsPath); err != nil {
			t.Fatalf("installHooksToFile() error = %v", err)
		}

		settings := readTestJSON(t, settingsPath)

		// Verify existing settings preserved
		if _, ok := settings["permissions"]; !ok {
			t.Error("existing permissions key was lost")
		}

		hooks := settings["hooks"].(map[string]interface{})
		preToolUse := hooks["PreToolUse"].([]interface{})
		if len(preToolUse) != 2 {
			t.Fatalf("expected 2 PreToolUse entries, got %d", len(preToolUse))
		}

		// First entry should be the existing one
		first := preToolUse[0].(map[string]interface{})
		if matcher, _ := first["matcher"].(string); matcher != "Bash" {
			t.Errorf("first entry matcher = %q, want %q", matcher, "Bash")
		}
	})

	t.Run("idempotent - does not duplicate", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		if err := installHooksToFile(settingsPath); err != nil {
			t.Fatalf("first install: %v", err)
		}
		if err := installHooksToFile(settingsPath); err != nil {
			t.Fatalf("second install: %v", err)
		}

		settings := readTestJSON(t, settingsPath)
		hooks := settings["hooks"].(map[string]interface{})
		preToolUse := hooks["PreToolUse"].([]interface{})
		if len(preToolUse) != 1 {
			t.Errorf("expected 1 entry after double install, got %d", len(preToolUse))
		}
	})

	t.Run("returns error on unparseable JSON", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		// Write JSONC (comments make it invalid JSON)
		if err := os.WriteFile(settingsPath, []byte(`{
			// This is a comment
			"hooks": {}
		}`), 0o600); err != nil {
			t.Fatal(err)
		}

		err := installHooksToFile(settingsPath)
		if err == nil {
			t.Fatal("expected error for unparseable JSON")
		}
	})
}

func TestRemoveHooksFromFile(t *testing.T) {
	t.Run("removes armis hook entries", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		settings := map[string]interface{}{
			"hooks": map[string]interface{}{
				"PreToolUse": []interface{}{
					map[string]interface{}{
						"matcher": "Bash",
						"hooks": []interface{}{
							map[string]interface{}{
								"type":    "command",
								"command": "echo hello",
							},
						},
					},
					map[string]interface{}{
						"matcher": armisHookMatcher,
						"hooks": []interface{}{
							map[string]interface{}{
								"type":    "command",
								"command": "armis-cli scan repo --format json .",
							},
						},
					},
				},
			},
		}
		writeTestJSON(t, settingsPath, settings)

		if err := removeHooksFromFile(settingsPath); err != nil {
			t.Fatalf("removeHooksFromFile() error = %v", err)
		}

		result := readTestJSON(t, settingsPath)
		hooks := result["hooks"].(map[string]interface{})
		preToolUse := hooks["PreToolUse"].([]interface{})
		if len(preToolUse) != 1 {
			t.Fatalf("expected 1 remaining entry, got %d", len(preToolUse))
		}
		remaining := preToolUse[0].(map[string]interface{})
		if matcher, _ := remaining["matcher"].(string); matcher != "Bash" {
			t.Errorf("remaining matcher = %q, want %q", matcher, "Bash")
		}
	})

	t.Run("removes hooks key when empty", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		settings := map[string]interface{}{
			"hooks": map[string]interface{}{
				"PreToolUse": []interface{}{
					map[string]interface{}{
						"matcher": armisHookMatcher,
						"hooks": []interface{}{
							map[string]interface{}{
								"type":    "command",
								"command": "armis-cli scan repo .",
							},
						},
					},
				},
			},
		}
		writeTestJSON(t, settingsPath, settings)

		if err := removeHooksFromFile(settingsPath); err != nil {
			t.Fatalf("removeHooksFromFile() error = %v", err)
		}

		result := readTestJSON(t, settingsPath)
		if _, ok := result["hooks"]; ok {
			t.Error("expected hooks key to be removed when empty")
		}
	})

	t.Run("noop when file does not exist", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "nonexistent.json")

		if err := removeHooksFromFile(settingsPath); err != nil {
			t.Fatalf("removeHooksFromFile() error = %v, want nil for missing file", err)
		}
	})

	t.Run("noop when no armis hooks present", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "settings.json")

		settings := map[string]interface{}{
			"hooks": map[string]interface{}{
				"PreToolUse": []interface{}{
					map[string]interface{}{
						"matcher": "Bash",
						"hooks": []interface{}{
							map[string]interface{}{
								"type":    "command",
								"command": "echo test",
							},
						},
					},
				},
			},
		}
		writeTestJSON(t, settingsPath, settings)

		if err := removeHooksFromFile(settingsPath); err != nil {
			t.Fatalf("removeHooksFromFile() error = %v", err)
		}

		result := readTestJSON(t, settingsPath)
		hooks := result["hooks"].(map[string]interface{})
		preToolUse := hooks["PreToolUse"].([]interface{})
		if len(preToolUse) != 1 {
			t.Errorf("expected 1 entry unchanged, got %d", len(preToolUse))
		}
	})
}

func TestIsArmisHookCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		{"armis-cli command", "armis-cli scan repo .", true},
		{"armis-appsec command", "armis-appsec scan .", true},
		{"unrelated command", "echo hello", false},
		{"empty string", "", false},
		{"partial match", "armis-cli-wrapper foo", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isArmisHookCommand(tt.cmd); got != tt.want {
				t.Errorf("isArmisHookCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func writeTestJSON(t *testing.T, path string, data interface{}) {
	t.Helper()
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("marshaling test JSON: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // test helper with temp dir path
		t.Fatalf("writing test JSON: %v", err)
	}
}

func readTestJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test helper reading from t.TempDir()
	if err != nil {
		t.Fatalf("reading test JSON: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parsing test JSON: %v", err)
	}
	return result
}
