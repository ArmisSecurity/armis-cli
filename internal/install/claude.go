package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	marketplaceName = "armis-appsec-mcp"
	pluginName      = "armis-appsec"
)

// ClaudeInstaller installs the Armis AppSec MCP plugin for Claude Code.
type ClaudeInstaller struct {
	claudeDir string
	plugin    *PluginInstaller
}

// NewClaudeInstaller creates an installer with the default Claude directory.
func NewClaudeInstaller() *ClaudeInstaller {
	// armis:ignore cwe:253 reason:UserHomeDir error yields empty string; filepath.Join("", ".claude") is a safe fallback
	home, _ := os.UserHomeDir()
	return &ClaudeInstaller{
		claudeDir: filepath.Join(home, ".claude"),
		plugin:    newPluginInstaller(),
	}
}

// InstalledVersion returns the version that was installed (available after Install).
func (ci *ClaudeInstaller) InstalledVersion() string {
	return ci.plugin.InstalledVersion()
}

// Install downloads and installs the MCP plugin for Claude Code.
func (ci *ClaudeInstaller) Install() error {
	if _, err := os.Stat(ci.claudeDir); os.IsNotExist(err) {
		return fmt.Errorf("Claude Code directory not found at %s — is Claude Code installed?", ci.claudeDir) //nolint:staticcheck // proper noun
	}

	pluginDir := ci.pluginCacheDir()

	if err := ci.plugin.FetchAndInstall(pluginDir); err != nil {
		return err
	}

	if err := ci.registerMarketplace(pluginDir); err != nil {
		return fmt.Errorf("failed to register marketplace: %w", err)
	}

	if err := ci.registerPlugin(pluginDir); err != nil {
		return fmt.Errorf("failed to register plugin: %w", err)
	}

	if err := ci.enablePlugin(); err != nil {
		return fmt.Errorf("failed to enable plugin: %w", err)
	}

	if err := writeEnvFromEnvironment(ci.EnvFilePath()); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	return nil
}

func (ci *ClaudeInstaller) pluginCacheDir() string {
	return filepath.Join(ci.claudeDir, "plugins", "cache", marketplaceName, pluginName, "latest")
}

// EnvFilePath returns the path to the plugin's .env file.
func (ci *ClaudeInstaller) EnvFilePath() string {
	return filepath.Join(ci.pluginCacheDir(), ".env")
}

// GetInstalledVersion reads the installed plugin version from the registry.
func (ci *ClaudeInstaller) GetInstalledVersion() string {
	instFile := filepath.Join(ci.claudeDir, "plugins", "installed_plugins.json")
	b, err := os.ReadFile(filepath.Clean(instFile))
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return ""
	}
	plugins, ok := data["plugins"].(map[string]interface{})
	if !ok {
		return ""
	}
	key := pluginName + "@" + marketplaceName
	entries, ok := plugins[key].([]interface{})
	if !ok || len(entries) == 0 {
		return ""
	}
	entry, ok := entries[0].(map[string]interface{})
	if !ok {
		return ""
	}
	v, _ := entry["version"].(string)
	if v == "latest" {
		return ""
	}
	return v
}

// HasExistingEnv checks whether credentials are already configured.
func (ci *ClaudeInstaller) HasExistingEnv() bool {
	_, err := os.Stat(ci.EnvFilePath())
	return err == nil
}

func (ci *ClaudeInstaller) registerMarketplace(pluginDir string) error {
	mktsFile := filepath.Join(ci.claudeDir, "plugins", "known_marketplaces.json")
	data := make(map[string]interface{})
	if b, err := os.ReadFile(filepath.Clean(mktsFile)); err == nil {
		_ = json.Unmarshal(b, &data)
	}

	data[marketplaceName] = map[string]interface{}{
		"source":          map[string]interface{}{"source": "directory", "path": pluginDir},
		"installLocation": pluginDir,
		"lastUpdated":     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	return writeJSON(mktsFile, data)
}

func (ci *ClaudeInstaller) registerPlugin(pluginDir string) error {
	instFile := filepath.Join(ci.claudeDir, "plugins", "installed_plugins.json")
	data := map[string]interface{}{"version": 2, "plugins": map[string]interface{}{}}
	if b, err := os.ReadFile(filepath.Clean(instFile)); err == nil {
		_ = json.Unmarshal(b, &data)
	}

	plugins, ok := data["plugins"].(map[string]interface{})
	if !ok {
		plugins = make(map[string]interface{})
		data["plugins"] = plugins
	}

	key := pluginName + "@" + marketplaceName
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	plugins[key] = []interface{}{
		map[string]interface{}{
			"scope":       "user",
			"installPath": pluginDir,
			"version":     ci.plugin.InstalledVersion(),
			"installedAt": now,
			"lastUpdated": now,
		},
	}

	return writeJSON(instFile, data)
}

func (ci *ClaudeInstaller) enablePlugin() error {
	settingsFile := filepath.Join(ci.claudeDir, "settings.json")
	data := make(map[string]interface{})
	if b, err := os.ReadFile(filepath.Clean(settingsFile)); err == nil {
		_ = json.Unmarshal(b, &data)
	}

	enabled, ok := data["enabledPlugins"].(map[string]interface{})
	if !ok {
		enabled = make(map[string]interface{})
		data["enabledPlugins"] = enabled
	}

	key := pluginName + "@" + marketplaceName
	enabled[key] = true

	return writeJSON(settingsFile, data)
}
