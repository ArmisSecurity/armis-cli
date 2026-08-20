package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
			has, _ := hasArmisEntry(id, entry.ConfigFile)
			if !has {
				continue
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
		has, err := hasArmisEntry(e.ID, configFile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: cannot read config: %v", e.Name, err))
			continue
		}
		if has {
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
	if u.pluginDir == "" || !filepath.IsAbs(u.pluginDir) {
		return fmt.Errorf("invalid plugin directory: must be an absolute path")
	}
	if _, err := os.Stat(u.pluginDir); os.IsNotExist(err) {
		return nil
	}

	if keepCredentials {
		envPath := filepath.Join(u.pluginDir, ".env")
		// armis:ignore cwe:73 reason:envPath constructed from pluginDir (known cache dir) + hardcoded ".env" filename
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
			return entry.ConfigFile // armis:ignore cwe:73 cwe:22 reason:manifest written by our install with paths from ConfigPath(); not external input
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
		return removeContinueEntry(configFile, []string{mcpServerName})
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

// removeContinueEntry drops Armis servers from Continue's config.yaml list.
//
// The file must be edited rather than deleted: config.yaml is Continue's whole
// configuration (models, rules, context providers), not an Armis-only drop-in
// like the per-server JSON file Continue used to accept.
func removeContinueEntry(configFile string, names []string) error {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}

	data := readYAMLFileAsMap(configFile)
	existing, ok := data["mcpServers"].([]interface{})
	if !ok || len(existing) == 0 {
		return nil
	}

	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}

	kept := make([]interface{}, 0, len(existing))
	for _, s := range existing {
		if m, ok := s.(map[string]interface{}); ok {
			if n, _ := m["name"].(string); drop[n] {
				continue
			}
		}
		kept = append(kept, s)
	}
	if len(kept) == len(existing) {
		return nil
	}

	if len(kept) == 0 {
		delete(data, "mcpServers")
	} else {
		data["mcpServers"] = kept
	}

	return writeYAML(configFile, data)
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

func hasArmisEntry(id EditorID, configFile string) (bool, error) {
	// Continue stores MCP servers as a YAML list of objects that each carry
	// their own name, so it cannot go through the JSON reader below.
	if id == EditorContinue {
		return continueHasEntry(configFile, mcpServerName), nil
	}

	data, err := readAndParseJSON(configFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	switch id {
	case EditorVSCode:
		servers, ok := data["servers"].(map[string]interface{})
		return ok && servers[mcpServerName] != nil, nil
	case EditorZed:
		servers, ok := data["context_servers"].(map[string]interface{})
		return ok && servers[mcpServerName] != nil, nil
	default:
		servers, ok := data["mcpServers"].(map[string]interface{})
		return ok && servers[mcpServerName] != nil, nil
	}
}

// continueHasEntry reports whether Continue's config.yaml lists a server with
// the given name. Returns false for a missing or unparseable file, matching the
// JSON path's "nothing to remove" behavior.
func continueHasEntry(configFile, name string) bool {
	servers, ok := readYAMLFileAsMap(configFile)["mcpServers"].([]interface{})
	if !ok {
		return false
	}
	for _, s := range servers {
		if m, ok := s.(map[string]interface{}); ok {
			if n, _ := m["name"].(string); n == name {
				return true
			}
		}
	}
	return false
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

// HasKnowledge reports whether the manifest records a knowledge install.
func (u *Uninstaller) HasKnowledge() bool {
	return u.manifest != nil && u.manifest.Knowledge != nil
}

// RemoveKnowledge deregisters the knowledge MCP server from every config the
// manifest recorded, unregisters it from Claude Code, and deletes its plugin
// directory. Leaving a config entry pointing at a removed plugin dir would break
// the user's agents, so this runs as part of a full uninstall rather than behind
// a flag.
//
// Other MCP servers in those files — notably the scanner — are left untouched.
func (u *Uninstaller) RemoveKnowledge(keepCredentials bool) (removed []string, warnings []string) {
	if !u.HasKnowledge() {
		return nil, nil
	}
	k := u.manifest.Knowledge

	for id, entry := range k.Editors {
		if entry.ConfigFile == "" {
			continue
		}
		if _, err := os.Stat(entry.ConfigFile); os.IsNotExist(err) {
			continue
		}
		if err := deregisterServerFromFile(entry.ConfigFile, entry.Format, knowledgeServerNames()); err != nil {
			warnings = append(warnings, fmt.Sprintf("knowledge %s: %v", id, err))
			continue
		}
		removed = append(removed, string(id))
	}

	if k.Codex != nil && k.Codex.ConfigFile != "" {
		codexOK := true
		codexChanged := false
		for _, name := range knowledgeServerNames() {
			codexName := strings.ReplaceAll(name, "-", "_")
			gone, err := removeCodexSection(k.Codex.ConfigFile, codexName)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("knowledge Codex CLI: %v", err))
				codexOK = false
				break
			}
			codexChanged = codexChanged || gone
		}
		if codexOK && codexChanged {
			removed = append(removed, "codex")
		}
	}

	if k.Claude != nil {
		if err := u.deregisterKnowledgeClaude(); err != nil {
			warnings = append(warnings, fmt.Sprintf("knowledge Claude Code: %v", err))
		} else {
			removed = append(removed, "claude")
		}
	}

	if k.PluginDir != "" {
		if err := removeKnowledgeFiles(k.PluginDir, keepCredentials); err != nil {
			warnings = append(warnings, fmt.Sprintf("knowledge files: %v", err))
		}
	}

	return removed, warnings
}

// knowledgeServerNames lists every environment's knowledge server key, so a
// single uninstall clears prod, stage, and dev registrations.
func knowledgeServerNames() []string {
	return []string{"armis-knowledge", "armis-knowledge-stage", "armis-knowledge-dev"}
}

// deregisterServerFromFile removes the named servers from a JSON MCP config,
// dispatching on the format string recorded in the manifest.
func deregisterServerFromFile(configFile, format string, names []string) error {
	key := "mcpServers"
	switch format {
	case "vscode-servers":
		key = "servers"
	case "zed-context_servers":
		key = "context_servers"
	case "continue-yaml":
		// Continue's servers are a YAML list, not a JSON map.
		return removeContinueEntry(configFile, names)
	}

	data, err := readAndParseJSON(configFile)
	if err != nil {
		return err
	}

	servers, ok := data[key].(map[string]interface{})
	if !ok {
		return nil
	}
	changed := false
	for _, n := range names {
		if servers[n] != nil {
			delete(servers, n)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	data[key] = servers

	return writeJSONAtomic(configFile, data)
}

// deregisterKnowledgeClaude removes the knowledge plugin from Claude Code's
// marketplace registry, installed plugins, and enabled plugins.
func (u *Uninstaller) deregisterKnowledgeClaude() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	claudeDir := filepath.Join(home, ".claude")

	if err := removeJSONKey(filepath.Join(claudeDir, "plugins", "known_marketplaces.json"), knowledgeClaudeMarketplace); err != nil {
		return err
	}
	for _, name := range knowledgeServerNames() {
		key := name + "@" + knowledgeClaudeMarketplace
		if err := removeNestedJSONKey(filepath.Join(claudeDir, "plugins", "installed_plugins.json"), "plugins", key); err != nil {
			return err
		}
		if err := removeNestedJSONKey(filepath.Join(claudeDir, "settings.json"), "enabledPlugins", key); err != nil {
			return err
		}
	}
	return nil
}

// removeKnowledgeFiles deletes the knowledge plugin directory, optionally
// preserving its .env credentials for an easy reinstall.
func removeKnowledgeFiles(pluginDir string, keepCredentials bool) error {
	if pluginDir == "" || !filepath.IsAbs(pluginDir) {
		return fmt.Errorf("refusing to remove non-absolute plugin directory %q", pluginDir)
	}

	var saved []byte
	envPath := filepath.Join(pluginDir, ".env")
	if keepCredentials {
		// armis:ignore cwe:522 cwe:770 reason:reads the user's own bounded .env from a known plugin dir to restore it after removal
		if b, err := os.ReadFile(filepath.Clean(envPath)); err == nil {
			saved = b
		}
	}

	if err := os.RemoveAll(filepath.Clean(pluginDir)); err != nil {
		return fmt.Errorf("removing %s: %w", pluginDir, err)
	}

	if len(saved) > 0 {
		if err := os.MkdirAll(pluginDir, 0o750); err != nil {
			return fmt.Errorf("restoring credentials directory: %w", err)
		}
		// armis:ignore cwe:522 cwe:22 reason:envPath is filepath.Join(pluginDir, ".env") where pluginDir was validated absolute above; restores the user's own credentials to a 0600 file
		if err := os.WriteFile(filepath.Clean(envPath), saved, 0o600); err != nil { // #nosec G703 -- envPath derives from the absolute-validated pluginDir + hardcoded ".env"
			return fmt.Errorf("restoring credentials: %w", err)
		}
	}

	return nil
}
