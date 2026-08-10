package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
func NewClaudeInstaller() (*ClaudeInstaller, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	return &ClaudeInstaller{
		claudeDir: filepath.Join(home, ".claude"),
		plugin:    newPluginInstaller(),
	}, nil
}

// InstalledVersion returns the version that was installed (available after Install).
func (ci *ClaudeInstaller) InstalledVersion() string {
	return ci.plugin.InstalledVersion()
}

// Install downloads and installs the MCP plugin for Claude Code.
func (ci *ClaudeInstaller) Install() error {
	// armis:ignore cwe:253 reason:intentionally checks only IsNotExist; other stat errors are irrelevant to user-facing message
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

	// armis:ignore cwe:522 reason:env file written with 0600 permissions; credentials sourced from caller's environment variables
	if err := writeEnvFromEnvironment(ci.EnvFilePath()); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	return nil
}

func (ci *ClaudeInstaller) pluginCacheDir() string {
	return filepath.Join(ci.claudeDir, "plugins", "cache", marketplaceName, pluginName, "latest")
}

// PluginCacheDir returns the Claude Code plugin cache directory (for manifest recording).
func (ci *ClaudeInstaller) PluginCacheDir() string {
	return ci.pluginCacheDir()
}

// EnvFilePath returns the path to the plugin's .env file.
func (ci *ClaudeInstaller) EnvFilePath() string {
	return filepath.Join(ci.pluginCacheDir(), ".env")
}

// GetInstalledVersion reads the installed plugin version from the registry.
func (ci *ClaudeInstaller) GetInstalledVersion() string {
	instFile := filepath.Join(ci.claudeDir, "plugins", "installed_plugins.json")
	// armis:ignore cwe:770 reason:reads bounded JSON config file from user's ~/.claude dir; not unbounded input
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
	return registerDirectoryMarketplace(ci.claudeDir, marketplaceName, pluginDir)
}

func (ci *ClaudeInstaller) registerPlugin(pluginDir string) error {
	key := pluginName + "@" + marketplaceName
	return registerInstalledPlugin(ci.claudeDir, key, pluginDir, ci.plugin.InstalledVersion())
}

func (ci *ClaudeInstaller) enablePlugin() error {
	key := pluginName + "@" + marketplaceName
	return enableInstalledPlugin(ci.claudeDir, key)
}
