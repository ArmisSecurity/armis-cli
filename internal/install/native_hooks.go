package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// HookClientID identifies a client that supports native pre-tool-use hooks.
type HookClientID string

const (
	HookClientCursor  HookClientID = "cursor"
	HookClientGemini  HookClientID = "gemini"
	HookClientCodex   HookClientID = "codex"
	HookClientCopilot HookClientID = "copilot"
	HookClientCline   HookClientID = "cline"
)

// HookClient represents an AI coding client with native hook support.
type HookClient struct {
	ID         HookClientID
	Name       string
	AdapterPy  string // filename in hooks/ dir (e.g. "cursor_pre_tool.py")
	configPath func() string
	buildHooks func(pluginDir string) interface{}
}

// AllHookClients lists every client with native hook support (excluding Claude Code,
// which is handled automatically by the plugin system).
var AllHookClients = []HookClient{
	{
		ID:         HookClientCursor,
		Name:       "Cursor",
		AdapterPy:  "cursor_pre_tool.py",
		configPath: cursorHooksPath,
		buildHooks: buildCursorHooks,
	},
	{
		ID:         HookClientGemini,
		Name:       "Gemini CLI",
		AdapterPy:  "gemini_pre_tool.py",
		configPath: geminiHooksPath,
		buildHooks: buildGeminiHooks,
	},
	{
		ID:         HookClientCodex,
		Name:       "Codex CLI",
		AdapterPy:  "codex_pre_tool.py",
		configPath: codexHooksPath,
		buildHooks: buildCodexHooks,
	},
	{
		ID:         HookClientCopilot,
		Name:       "Copilot CLI",
		AdapterPy:  "copilot_pre_tool.py",
		configPath: copilotHooksPath,
		buildHooks: buildCopilotHooks,
	},
	{
		ID:         HookClientCline,
		Name:       "Cline",
		AdapterPy:  "cline_pre_tool.py",
		configPath: clineHooksPath,
		buildHooks: buildClineHooks,
	},
}

// HookClientByID returns the hook client with the given ID.
func HookClientByID(id HookClientID) (HookClient, bool) {
	for _, c := range AllHookClients {
		if c.ID == id {
			return c, true
		}
	}
	return HookClient{}, false
}

// ConfigPath returns the hook config file path for this client.
func (c HookClient) ConfigPath() string {
	return c.configPath()
}

// IsDetected checks whether the client appears to be installed.
func (c HookClient) IsDetected() bool {
	p := c.ConfigPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(filepath.Dir(p))
	return err == nil
}

// DetectHookClients returns hook clients that appear to be installed on this system.
func DetectHookClients() []HookClient {
	var detected []HookClient
	for _, c := range AllHookClients {
		if c.IsDetected() {
			detected = append(detected, c)
		}
	}
	return detected
}

// hookConfigPathOverrides allows tests to inject custom paths.
var hookConfigPathOverrides map[HookClientID]string

func hookConfigPath(id HookClientID, defaultFn func() string) string {
	if hookConfigPathOverrides != nil {
		if p, ok := hookConfigPathOverrides[id]; ok {
			return p
		}
	}
	return defaultFn()
}

// InstallNativeHook writes the hook config for a client, pointing to the
// Python adapter in the plugin directory.
func InstallNativeHook(client HookClient, pluginDir string) error {
	// armis:ignore cwe:78 reason:pluginDir is resolved from known install location, not user input
	if !filepath.IsAbs(pluginDir) {
		return fmt.Errorf("plugin directory must be an absolute path: %s", pluginDir)
	}
	adapterPath := filepath.Join(pluginDir, "hooks", client.AdapterPy)
	if _, err := os.Stat(adapterPath); os.IsNotExist(err) {
		return fmt.Errorf("hook adapter not found: %s (is the MCP server installed?)", adapterPath)
	}

	configPath := client.ConfigPath()
	if configPath == "" {
		return fmt.Errorf("%s hook config path not available on this platform", client.Name)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	return installClientHook(client, pluginDir, configPath)
}

// RemoveNativeHook removes hook entries for a client.
func RemoveNativeHook(client HookClient) error {
	configPath := client.ConfigPath()
	if configPath == "" {
		return nil
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil
	}
	return removeClientHook(client, configPath)
}

// installClientHook writes the appropriate hook config for the given client.
func installClientHook(client HookClient, pluginDir, configPath string) error {
	switch client.ID {
	case HookClientCursor:
		return installCursorHook(pluginDir, configPath)
	case HookClientGemini:
		return installMergedHook(pluginDir, configPath, client)
	case HookClientCodex:
		return installMergedHook(pluginDir, configPath, client)
	case HookClientCopilot:
		return installCopilotHook(pluginDir, configPath)
	case HookClientCline:
		return installMergedHook(pluginDir, configPath, client)
	}
	return fmt.Errorf("unknown hook client: %s", client.ID)
}

// removeClientHook removes Armis hook entries from a client's config.
func removeClientHook(client HookClient, configPath string) error {
	switch client.ID {
	case HookClientCursor:
		return removeCursorHook(configPath)
	case HookClientCopilot:
		return removeCopilotHook(configPath)
	default:
		return removeMergedHook(configPath, client)
	}
}

// --- Config paths ---

func cursorHooksPath() string {
	return hookConfigPath(HookClientCursor, func() string {
		return homeDir(".cursor", "hooks.json")
	})
}

func geminiHooksPath() string {
	return hookConfigPath(HookClientGemini, func() string {
		return homeDir(".gemini", "settings.json")
	})
}

func codexHooksPath() string {
	return hookConfigPath(HookClientCodex, func() string {
		return homeDir(".codex", "hooks.json")
	})
}

func copilotHooksPath() string {
	return hookConfigPath(HookClientCopilot, func() string {
		switch runtime.GOOS {
		case osDarwin, osLinux:
			return homeDir(".config", "github-copilot", "hooks.json")
		case osWindows:
			// armis:ignore cwe:73 reason:APPDATA is the OS-standard config dir; validated as absolute path below
			appdata := os.Getenv("APPDATA")
			if appdata == "" {
				return ""
			}
			appdata = filepath.Clean(appdata)
			if !filepath.IsAbs(appdata) {
				return ""
			}
			return filepath.Join(appdata, "github-copilot", "hooks.json")
		}
		return ""
	})
}

func clineHooksPath() string {
	return hookConfigPath(HookClientCline, func() string {
		switch runtime.GOOS {
		case osDarwin:
			return appSupportPath("Code", "User", "globalStorage",
				"saoudrizwan.claude-dev", "hooks.json")
		case osLinux:
			return appSupportPath("Code", "User", "globalStorage",
				"saoudrizwan.claude-dev", "hooks.json")
		case osWindows:
			return appSupportPath("Code", "User", "globalStorage",
				"saoudrizwan.claude-dev", "hooks.json")
		}
		return ""
	})
}

// --- Per-client hook installers ---

const armisHookMarker = "armis-appsec"

// readJSONFileAsMapSafe reads a JSON file into a map, returning an error
// if the file exists but cannot be parsed. This prevents silent data loss
// when overwriting a corrupt or JSONC config file.
func readJSONFileAsMapSafe(path string) (map[string]interface{}, error) {
	data := make(map[string]interface{})
	b, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // path from known config locations
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if len(b) == 0 {
		return data, nil
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("could not parse %s — skipping hook setup.\n  Fix the JSON syntax or remove the file.\n  Parse error: %w", path, err)
	}
	return data, nil
}

// installMergedHook handles clients that use a merged JSON settings file
// with a hooks section (Gemini, Codex, Cline).
func installMergedHook(pluginDir, configPath string, client HookClient) error {
	data, err := readJSONFileAsMapSafe(configPath)
	if err != nil {
		return err
	}

	hooks := client.buildHooks(pluginDir)

	hooksSection, _ := data["hooks"].(map[string]interface{})
	if hooksSection == nil {
		hooksSection = make(map[string]interface{})
	}

	newHooks, ok := hooks.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected hook format for %s", client.Name)
	}

	for key, entries := range newHooks {
		existing, _ := hooksSection[key].([]interface{})
		if !hasArmisHookEntries(existing) {
			newEntries, _ := entries.([]interface{})
			existing = append(existing, newEntries...)
			hooksSection[key] = existing
		}
	}

	data["hooks"] = hooksSection
	return writeJSONAtomic(configPath, data)
}

// removeMergedHook removes Armis hook entries from a merged config file.
func removeMergedHook(configPath string, _ HookClient) error {
	data, err := readJSONFileAsMapSafe(configPath)
	if err != nil {
		return err
	}

	hooksSection, _ := data["hooks"].(map[string]interface{})
	if hooksSection == nil {
		return nil
	}

	for key, entries := range hooksSection {
		arr, ok := entries.([]interface{})
		if !ok {
			continue
		}
		filtered := filterNonArmisEntries(arr)
		if len(filtered) == 0 {
			delete(hooksSection, key)
		} else {
			hooksSection[key] = filtered
		}
	}

	if len(hooksSection) == 0 {
		delete(data, "hooks")
	} else {
		data["hooks"] = hooksSection
	}

	return writeJSONAtomic(configPath, data)
}

// installCursorHook handles Cursor's hook format.
func installCursorHook(pluginDir, configPath string) error {
	data, err := readJSONFileAsMapSafe(configPath)
	if err != nil {
		return err
	}

	if _, ok := data["version"]; !ok {
		data["version"] = 1
	}

	hooks := buildCursorHooks(pluginDir).(map[string]interface{})

	hooksSection, _ := data["hooks"].(map[string]interface{})
	if hooksSection == nil {
		hooksSection = make(map[string]interface{})
	}

	for key, entries := range hooks {
		existing, _ := hooksSection[key].([]interface{})
		if !hasArmisHookEntries(existing) {
			newEntries, _ := entries.([]interface{})
			existing = append(existing, newEntries...)
			hooksSection[key] = existing
		}
	}

	data["hooks"] = hooksSection
	return writeJSONAtomic(configPath, data)
}

// removeCursorHook removes Armis entries from Cursor hook config.
func removeCursorHook(configPath string) error {
	data, err := readJSONFileAsMapSafe(configPath)
	if err != nil {
		return err
	}

	hooksSection, _ := data["hooks"].(map[string]interface{})
	if hooksSection == nil {
		return nil
	}

	for key, entries := range hooksSection {
		arr, ok := entries.([]interface{})
		if !ok {
			continue
		}
		filtered := filterNonArmisEntries(arr)
		if len(filtered) == 0 {
			delete(hooksSection, key)
		} else {
			hooksSection[key] = filtered
		}
	}

	if len(hooksSection) == 0 {
		delete(data, "hooks")
	} else {
		data["hooks"] = hooksSection
	}

	return writeJSONAtomic(configPath, data)
}

// installCopilotHook handles Copilot CLI's hook format (uses "bash" key instead of "command").
func installCopilotHook(pluginDir, configPath string) error {
	data, err := readJSONFileAsMapSafe(configPath)
	if err != nil {
		return err
	}

	if _, ok := data["version"]; !ok {
		data["version"] = 1
	}

	hooks := buildCopilotHooks(pluginDir).(map[string]interface{})

	hooksSection, _ := data["hooks"].(map[string]interface{})
	if hooksSection == nil {
		hooksSection = make(map[string]interface{})
	}

	for key, entries := range hooks {
		existing, _ := hooksSection[key].([]interface{})
		if !hasArmisHookEntries(existing) {
			newEntries, _ := entries.([]interface{})
			existing = append(existing, newEntries...)
			hooksSection[key] = existing
		}
	}

	data["hooks"] = hooksSection
	return writeJSONAtomic(configPath, data)
}

// removeCopilotHook removes Armis entries from Copilot hook config.
func removeCopilotHook(configPath string) error {
	return removeCursorHook(configPath) // same structure
}

// --- Hook config builders ---

func buildCursorHooks(pluginDir string) interface{} {
	py := venvPython(pluginDir)
	adapter := filepath.Join(pluginDir, "hooks", "cursor_pre_tool.py")
	cmd := quotedCommand(py, adapter)
	return map[string]interface{}{
		"beforeShellExecution": []interface{}{
			map[string]interface{}{
				"command": cmd,
				"matcher": `git\s+(commit|push)|gh\s+pr\s+create`,
				"timeout": 10,
			},
		},
		"preToolUse": []interface{}{
			map[string]interface{}{
				"command": cmd,
				"matcher": "Write|Edit",
				"timeout": 5,
			},
		},
	}
}

func buildGeminiHooks(pluginDir string) interface{} {
	py := venvPython(pluginDir)
	adapter := filepath.Join(pluginDir, "hooks", "gemini_pre_tool.py")
	cmd := quotedCommand(py, adapter)
	return map[string]interface{}{
		"BeforeTool": []interface{}{
			map[string]interface{}{
				"matcher": "shell|bash|run_shell_command|write_file|edit_file|patch_file",
				"hooks": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"command": cmd,
						"timeout": 10,
					},
				},
			},
		},
	}
}

func buildCodexHooks(pluginDir string) interface{} {
	py := venvPython(pluginDir)
	adapter := filepath.Join(pluginDir, "hooks", "codex_pre_tool.py")
	cmd := quotedCommand(py, adapter)
	return map[string]interface{}{
		"PreToolUse": []interface{}{
			map[string]interface{}{
				"matcher": "shell",
				"hooks": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"command": cmd,
						"timeout": 10,
					},
				},
			},
			map[string]interface{}{
				"matcher": "write_file|apply_patch|edit_file",
				"hooks": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"command": cmd,
						"timeout": 5,
					},
				},
			},
		},
	}
}

func buildCopilotHooks(pluginDir string) interface{} {
	py := venvPython(pluginDir)
	adapter := filepath.Join(pluginDir, "hooks", "copilot_pre_tool.py")
	cmd := quotedCommand(py, adapter)
	return map[string]interface{}{
		"preToolUse": []interface{}{
			map[string]interface{}{
				"type":       "command",
				"bash":       cmd,
				"matcher":    "bash|powershell|create|edit",
				"timeoutSec": 10,
			},
		},
	}
}

func buildClineHooks(pluginDir string) interface{} {
	py := venvPython(pluginDir)
	adapter := filepath.Join(pluginDir, "hooks", "cline_pre_tool.py")
	cmd := quotedCommand(py, adapter)
	return map[string]interface{}{
		"PreToolUse": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": cmd,
				"matcher": "execute_command|write_to_file|replace_in_file",
				"timeout": 10,
			},
		},
	}
}

// --- Helpers ---

func hasArmisHookEntries(entries []interface{}) bool {
	for _, entry := range entries {
		if isArmisHookJSON(entry) {
			return true
		}
	}
	return false
}

func filterNonArmisEntries(entries []interface{}) []interface{} {
	var filtered []interface{}
	for _, entry := range entries {
		if !isArmisHookJSON(entry) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func isArmisHookJSON(entry interface{}) bool {
	b, err := json.Marshal(entry)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, armisHookMarker) ||
		strings.Contains(s, "armis-appsec") ||
		strings.Contains(s, "armis-cli scan repo") ||
		strings.Contains(s, "cursor_pre_tool.py") ||
		strings.Contains(s, "gemini_pre_tool.py") ||
		strings.Contains(s, "codex_pre_tool.py") ||
		strings.Contains(s, "copilot_pre_tool.py") ||
		strings.Contains(s, "cline_pre_tool.py")
}

// posixQuote wraps a string in POSIX-safe single quotes, escaping embedded single quotes.
func posixQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quotedCommand(pythonPath, adapterPath string) string {
	return posixQuote(pythonPath) + " " + posixQuote(adapterPath)
}

// HookConfigFormat returns the hook config format name for manifest tracking.
func HookConfigFormat(id HookClientID) string {
	switch id {
	case HookClientCursor:
		return "cursor-hooks"
	case HookClientGemini:
		return "gemini-hooks"
	case HookClientCodex:
		return "codex-hooks"
	case HookClientCopilot:
		return "copilot-hooks"
	case HookClientCline:
		return "cline-hooks"
	}
	return "unknown"
}
