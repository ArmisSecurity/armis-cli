package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Uninstaller removes the Armis AppSec MCP plugin from editors and the filesystem.
type Uninstaller struct {
	pluginDir string
	manifest  *Manifest
}

// NewUninstaller creates an uninstaller. It loads the manifest if one exists,
// otherwise it will fall back to scanning known paths.
func NewUninstaller() *Uninstaller {
	ei := NewEditorInstaller()
	return &Uninstaller{
		pluginDir: ei.PluginDir(),
		manifest:  ReadManifest(ei.PluginDir()),
	}
}

// HasManifest returns true if an install manifest was found.
func (u *Uninstaller) HasManifest() bool {
	return u.manifest != nil
}

// PluginDir returns the shared plugin directory.
func (u *Uninstaller) PluginDir() string {
	return u.pluginDir
}

// DeregisterEditor removes the armis-appsec entry from a single editor's config.
func (u *Uninstaller) DeregisterEditor(id EditorID) error {
	e, ok := EditorByID(id)
	if !ok {
		return fmt.Errorf("unknown editor: %s", id)
	}

	configFile := u.editorConfigPath(id, e)
	if configFile == "" {
		return nil
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}

	return deregisterEditor(id, configFile)
}

// DeregisterAllEditors removes armis-appsec from all editors. Uses manifest
// entries first, then scans remaining known editor paths to catch registrations
// that predate manifest tracking.
func (u *Uninstaller) DeregisterAllEditors() (deregistered []string, warnings []string) {
	handled := make(map[EditorID]bool)

	if u.manifest != nil {
		for id, entry := range u.manifest.Editors {
			handled[id] = true
			e, ok := EditorByID(id)
			name := string(id)
			if ok {
				name = e.Name
			}
			if err := deregisterFromFile(id, entry.ConfigFile); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", name, err))
			} else {
				deregistered = append(deregistered, name)
			}
		}
	}

	for _, e := range AllEditors {
		if handled[e.ID] {
			continue
		}
		configFile := e.ConfigPath()
		if configFile == "" {
			continue
		}
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			continue
		}
		if hasArmisEntry(e.ID, configFile) {
			if err := deregisterEditor(e.ID, configFile); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", e.Name, err))
			} else {
				deregistered = append(deregistered, e.Name)
			}
		}
	}
	return
}

// DeregisterClaude removes the plugin from Claude Code's registry files.
func (u *Uninstaller) DeregisterClaude() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	claudeDir := filepath.Join(home, ".claude")

	if _, err := os.Stat(claudeDir); os.IsNotExist(err) {
		return nil
	}

	if err := removeFromMarketplace(claudeDir); err != nil {
		return fmt.Errorf("marketplace cleanup: %w", err)
	}
	if err := removeFromInstalledPlugins(claudeDir); err != nil {
		return fmt.Errorf("installed plugins cleanup: %w", err)
	}
	if err := removeFromSettings(claudeDir); err != nil {
		return fmt.Errorf("settings cleanup: %w", err)
	}

	// armis:ignore cwe:22 reason:cacheDir is filepath.Join of ~/.claude + compile-time constant marketplaceName; no user input
	cacheDir := filepath.Join(claudeDir, "plugins", "cache", marketplaceName)
	if _, err := os.Stat(cacheDir); err == nil {
		if err := os.RemoveAll(cacheDir); err != nil {
			return fmt.Errorf("cache dir removal: %w", err)
		}
	}

	return nil
}

// RemovePluginFiles deletes the shared plugin directory.
// If keepCredentials is true, the .env file is preserved (moved out and back).
func (u *Uninstaller) RemovePluginFiles(keepCredentials bool) error {
	if _, err := os.Stat(u.pluginDir); os.IsNotExist(err) {
		return nil
	}

	if keepCredentials {
		envPath := filepath.Join(u.pluginDir, ".env")
		envContent, err := os.ReadFile(filepath.Clean(envPath))
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("reading credentials: %w", err)
		}

		if err := os.RemoveAll(u.pluginDir); err != nil {
			return err
		}

		if envContent != nil {
			if err := os.MkdirAll(u.pluginDir, 0o750); err != nil {
				return err
			}
			return os.WriteFile(filepath.Clean(envPath), envContent, 0o600) //nolint:gosec // envPath is pluginDir + ".env" constant
		}
		return nil
	}

	return os.RemoveAll(u.pluginDir)
}

// --- Internal helpers ---

func (u *Uninstaller) editorConfigPath(id EditorID, e Editor) string {
	if u.manifest != nil {
		if entry, ok := u.manifest.Editors[id]; ok {
			return entry.ConfigFile // armis:ignore cwe:73 reason:manifest written by our install with paths from ConfigPath(); not external input
		}
		// Editor not in manifest — still check its default path so we catch
		// registrations that predate manifest tracking.
	}
	return e.ConfigPath()
}

func deregisterEditor(id EditorID, configFile string) error {
	switch id {
	case EditorVSCode:
		return deregisterVSCodeFormat(configFile)
	case EditorZed:
		return deregisterZedFormat(configFile)
	case EditorContinue:
		return removeContinueFile(configFile)
	default:
		return deregisterMCPServersFormat(configFile)
	}
}

func deregisterFromFile(id EditorID, configFile string) error {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}
	return deregisterEditor(id, configFile)
}

func deregisterMCPServersFormat(configFile string) error {
	data, err := readAndParseJSON(configFile)
	if err != nil {
		return err
	}

	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok || servers[mcpServerName] == nil {
		return nil
	}
	delete(servers, mcpServerName)
	data["mcpServers"] = servers

	return writeJSONAtomic(configFile, data)
}

func deregisterVSCodeFormat(configFile string) error {
	data, err := readAndParseJSON(configFile)
	if err != nil {
		return err
	}

	servers, ok := data["servers"].(map[string]interface{})
	if !ok || servers[mcpServerName] == nil {
		return nil
	}
	delete(servers, mcpServerName)
	data["servers"] = servers

	return writeJSONAtomic(configFile, data)
}

func deregisterZedFormat(configFile string) error {
	data, err := readAndParseJSON(configFile)
	if err != nil {
		return err
	}

	servers, ok := data["context_servers"].(map[string]interface{})
	if !ok || servers[mcpServerName] == nil {
		return nil
	}
	delete(servers, mcpServerName)
	data["context_servers"] = servers

	return writeJSONAtomic(configFile, data)
}

func removeContinueFile(configFile string) error {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}
	if !hasArmisEntry(EditorContinue, configFile) {
		return nil
	}
	return os.Remove(configFile)
}

func removeFromMarketplace(claudeDir string) error {
	path := filepath.Join(claudeDir, "plugins", "known_marketplaces.json")
	return removeJSONKey(path, marketplaceName)
}

func removeFromInstalledPlugins(claudeDir string) error {
	path := filepath.Join(claudeDir, "plugins", "installed_plugins.json")
	return removeNestedJSONKey(path, "plugins", pluginName+"@"+marketplaceName)
}

func removeFromSettings(claudeDir string) error {
	path := filepath.Join(claudeDir, "settings.json")
	return removeNestedJSONKey(path, "enabledPlugins", pluginName+"@"+marketplaceName)
}

func removeJSONKey(path, key string) error {
	data, err := readAndParseJSON(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cannot read %s: %w", filepath.Base(path), err)
	}
	if _, exists := data[key]; !exists {
		return nil
	}
	delete(data, key)
	return writeJSONAtomic(path, data)
}

func removeNestedJSONKey(path, parentKey, childKey string) error {
	data, err := readAndParseJSON(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cannot read %s: %w", filepath.Base(path), err)
	}
	parent, ok := data[parentKey].(map[string]interface{})
	if !ok {
		return nil
	}
	if _, exists := parent[childKey]; !exists {
		return nil
	}
	delete(parent, childKey)
	data[parentKey] = parent
	return writeJSONAtomic(path, data)
}

func hasArmisEntry(id EditorID, configFile string) bool {
	data, err := readAndParseJSON(configFile)
	if err != nil {
		return false
	}
	switch id {
	case EditorVSCode:
		servers, ok := data["servers"].(map[string]interface{})
		return ok && servers[mcpServerName] != nil
	case EditorZed:
		servers, ok := data["context_servers"].(map[string]interface{})
		return ok && servers[mcpServerName] != nil
	default:
		servers, ok := data["mcpServers"].(map[string]interface{})
		return ok && servers[mcpServerName] != nil
	}
}

// armis:ignore cwe:770 reason:reads bounded local config files from known editor paths (e.g. ~/.cursor/mcp.json); not unbounded input
func readAndParseJSON(path string) (map[string]interface{}, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", path, err)
	}
	return data, nil
}

func writeJSONAtomic(path string, data interface{}) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()

	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp) //nolint:gosec // tmp comes from os.CreateTemp in a validated dir
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp) //nolint:gosec // tmp comes from os.CreateTemp in a validated dir
		return err
	}
	if err := os.Rename(tmp, path); err != nil { //nolint:gosec // tmp from CreateTemp, path from caller-validated editor configs
		_ = os.Remove(tmp) //nolint:gosec // tmp comes from os.CreateTemp in a validated dir
		return err
	}
	return nil
}
