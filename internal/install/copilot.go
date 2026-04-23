package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const copilotPluginDir = "armis-appsec-mcp"

// CopilotInstaller installs the Armis AppSec MCP plugin for GitHub Copilot in VS Code.
type CopilotInstaller struct {
	installDir string
	plugin     *PluginInstaller
}

// NewCopilotInstaller creates an installer that places the plugin in ~/.armis/plugins.
func NewCopilotInstaller() *CopilotInstaller {
	home, _ := os.UserHomeDir()
	return &CopilotInstaller{
		installDir: filepath.Join(home, ".armis", "plugins", copilotPluginDir),
		plugin:     newPluginInstaller(),
	}
}

// InstalledVersion returns the version that was installed (available after Install).
func (ci *CopilotInstaller) InstalledVersion() string {
	return ci.plugin.InstalledVersion()
}

// Install downloads the plugin and registers it in VS Code's user-level MCP config.
func (ci *CopilotInstaller) Install() error {
	if err := ci.plugin.FetchAndInstall(ci.installDir); err != nil {
		return err
	}

	if err := ci.registerMCPServer(); err != nil {
		return fmt.Errorf("failed to register MCP server in VS Code: %w", err)
	}

	return nil
}

// HasExistingEnv checks whether credentials are already configured.
func (ci *CopilotInstaller) HasExistingEnv() bool {
	envPath := filepath.Join(ci.installDir, ".env")
	_, err := os.Stat(envPath)
	return err == nil
}

// EnvFilePath returns the path to the plugin's .env file.
func (ci *CopilotInstaller) EnvFilePath() string {
	return filepath.Join(ci.installDir, ".env")
}

// GetInstalledVersion checks if the plugin is registered in VS Code's MCP config.
func (ci *CopilotInstaller) GetInstalledVersion() string {
	mcpFile := getMCPConfigPath()
	if mcpFile == "" {
		return ""
	}

	b, err := os.ReadFile(filepath.Clean(mcpFile))
	if err != nil {
		return ""
	}

	var config mcpConfig
	if err := json.Unmarshal(b, &config); err != nil {
		return ""
	}

	if _, ok := config.Servers["armis-appsec"]; ok {
		versionFile := filepath.Join(ci.installDir, ".installed-version")
		v, err := os.ReadFile(filepath.Clean(versionFile))
		if err != nil {
			return "unknown"
		}
		return string(v)
	}

	return ""
}

type mcpConfig struct {
	Servers map[string]mcpServer `json:"servers"`
}

type mcpServer struct {
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// userMCPConfigPathOverride allows tests to inject a custom config path.
var userMCPConfigPathOverride func() string

func getMCPConfigPath() string {
	if userMCPConfigPathOverride != nil {
		return userMCPConfigPathOverride()
	}
	return userMCPConfigPath()
}

func (ci *CopilotInstaller) registerMCPServer() error {
	mcpFile := getMCPConfigPath()
	if mcpFile == "" {
		return fmt.Errorf("could not determine VS Code user configuration path")
	}

	var config mcpConfig
	if b, err := os.ReadFile(filepath.Clean(mcpFile)); err == nil {
		_ = json.Unmarshal(b, &config)
	}
	if config.Servers == nil {
		config.Servers = make(map[string]mcpServer)
	}

	pythonPath := venvPython(ci.installDir)
	serverScript := filepath.Join(ci.installDir, "server.py")

	config.Servers["armis-appsec"] = mcpServer{
		Type:    "stdio",
		Command: pythonPath,
		Args:    []string{serverScript},
		Env: map[string]string{ //nolint:gosec // VS Code input variable syntax, not hardcoded credentials
			"ARMIS_CLIENT_ID":     "${input:armisClientId}",
			"ARMIS_CLIENT_SECRET": "${input:armisClientSecret}",
		},
	}

	if err := writeJSON(mcpFile, config); err != nil {
		return fmt.Errorf("writing MCP config: %w", err)
	}

	versionFile := filepath.Join(ci.installDir, ".installed-version")
	if err := os.WriteFile(filepath.Clean(versionFile), []byte(ci.plugin.InstalledVersion()), 0o600); err != nil {
		return fmt.Errorf("writing version file: %w", err)
	}

	return nil
}

func userMCPConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json")
	case "linux":
		configDir := os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			configDir = filepath.Join(home, ".config")
		}
		return filepath.Join(configDir, "Code", "User", "mcp.json")
	case osWindows:
		appData := os.Getenv("APPDATA")
		if appData == "" {
			return ""
		}
		return filepath.Join(appData, "Code", "User", "mcp.json")
	default:
		return ""
	}
}
