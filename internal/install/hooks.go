package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	armisHookMatcher = "Edit|Write|MultiEdit"
	maxSettingsSize  = 10 << 20 // 10 MB — sanity limit for settings files
)

// InstallHooks adds Armis security scanning hooks to the user's Claude Code settings.
// If the settings file cannot be parsed (e.g., JSONC with comments), returns an error
// with a user-friendly message.
func InstallHooks() error {
	// armis:ignore cwe:22 reason:os.UserHomeDir is a trusted OS source, not external input
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	return installHooksToFile(settingsPath)
}

func installHooksToFile(settingsPath string) error {
	settings := make(map[string]interface{})

	if info, err := os.Stat(settingsPath); err == nil && info.Size() > maxSettingsSize {
		return fmt.Errorf("settings file too large (%d bytes): %s", info.Size(), settingsPath)
	}
	// armis:ignore cwe:59 cwe:770 reason:settingsPath from filepath.Join(UserHomeDir, hardcoded ".claude/settings.json"); size bounded by maxSettingsSize guard above
	data, err := os.ReadFile(settingsPath) //nolint:gosec // G304: path constructed from UserHomeDir + hardcoded segments
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading settings: %w", err)
	}
	if len(data) > 0 {
		// armis:ignore cwe:502 reason:JSON config from user's own ~/.claude/settings.json (trusted local file, size-limited above)
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("could not parse %s — skipping hook setup.\n"+
				"  You can configure hooks manually.\n"+
				"  Parse error: %w", settingsPath, err)
		}
	}

	hooks, _ := settings[jsonKeyHooks].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
	}

	preToolUse, _ := hooks["PreToolUse"].([]interface{})

	// Check if Armis hook already exists
	for _, entry := range preToolUse {
		if m, ok := entry.(map[string]interface{}); ok {
			if matcher, _ := m[jsonKeyMatcher].(string); matcher == armisHookMatcher {
				if innerHooks, _ := m[jsonKeyHooks].([]interface{}); len(innerHooks) > 0 {
					for _, h := range innerHooks {
						if hm, ok := h.(map[string]interface{}); ok {
							if cmd, _ := hm[jsonKeyCommand].(string); cmd != "" && isArmisHookCommand(cmd) {
								return nil // already installed
							}
						}
					}
				}
			}
		}
	}

	armisHook := map[string]interface{}{
		jsonKeyMatcher: armisHookMatcher,
		jsonKeyHooks: []map[string]interface{}{
			{
				jsonKeyType:    jsonTypeCommand,
				jsonKeyCommand: "armis-cli scan repo --format json --no-progress --fail-on CRITICAL . >/dev/null 2>&1",
			},
		},
	}

	preToolUse = append(preToolUse, armisHook)
	hooks["PreToolUse"] = preToolUse
	settings[jsonKeyHooks] = hooks

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o750); err != nil {
		return fmt.Errorf("creating settings directory: %w", err)
	}
	return writeJSONAtomic(settingsPath, settings)
}

// RemoveHooks removes Armis-related hooks from Claude Code settings.
func RemoveHooks() error {
	// armis:ignore cwe:22 reason:os.UserHomeDir is a trusted OS source, not external input
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	return removeHooksFromFile(settingsPath)
}

func removeHooksFromFile(settingsPath string) error {
	if info, err := os.Stat(settingsPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading settings: %w", err)
	} else if info.Size() > maxSettingsSize {
		return fmt.Errorf("settings file too large (%d bytes): %s", info.Size(), settingsPath)
	}
	// armis:ignore cwe:59 cwe:770 reason:settingsPath from filepath.Join(UserHomeDir, hardcoded ".claude/settings.json"); size bounded by maxSettingsSize guard above
	data, err := os.ReadFile(settingsPath) //nolint:gosec // G304: path constructed from UserHomeDir + hardcoded segments
	if err != nil {
		return fmt.Errorf("reading settings: %w", err)
	}

	settings := make(map[string]interface{})
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parsing settings: %w", err)
	}

	hooks, _ := settings[jsonKeyHooks].(map[string]interface{})
	if hooks == nil {
		return nil
	}

	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	if preToolUse == nil {
		return nil
	}

	var filtered []interface{}
	for _, entry := range preToolUse {
		m, ok := entry.(map[string]interface{})
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		if !isArmisHookEntry(m) {
			filtered = append(filtered, entry)
		}
	}

	if len(filtered) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filtered
	}

	if len(hooks) == 0 {
		delete(settings, jsonKeyHooks)
	} else {
		settings[jsonKeyHooks] = hooks
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o750); err != nil {
		return fmt.Errorf("creating settings directory: %w", err)
	}
	return writeJSONAtomic(settingsPath, settings)
}

func isArmisHookEntry(m map[string]interface{}) bool {
	innerHooks, _ := m[jsonKeyHooks].([]interface{})
	for _, h := range innerHooks {
		if hm, ok := h.(map[string]interface{}); ok {
			if cmd, _ := hm[jsonKeyCommand].(string); isArmisHookCommand(cmd) {
				return true
			}
		}
	}
	return false
}

func isArmisHookCommand(cmd string) bool {
	return strings.Contains(cmd, "armis-cli scan repo") || strings.Contains(cmd, "armis-appsec")
}
