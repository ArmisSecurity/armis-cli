package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const mcpServerName = "armis-appsec"

// EditorID identifies a supported editor.
type EditorID string

const (
	EditorVSCode        EditorID = "vscode"
	EditorCursor        EditorID = "cursor"
	EditorWindsurf      EditorID = "windsurf"
	EditorZed           EditorID = "zed"
	EditorCline         EditorID = "cline"
	EditorAmazonQ       EditorID = "amazonq"
	EditorContinue      EditorID = "continue"
	EditorAntigravity   EditorID = "antigravity"
	EditorGemini        EditorID = "gemini"
	EditorRooCode       EditorID = "roocode"
	EditorJunie         EditorID = "junie"
	EditorClaudeDesktop EditorID = "claude-desktop"
)

// Editor represents a code editor with MCP server support.
type Editor struct {
	ID   EditorID
	Name string
}

// AllEditors lists every editor that can be auto-configured.
var AllEditors = []Editor{
	{EditorVSCode, "VS Code"},
	{EditorCursor, "Cursor"},
	{EditorWindsurf, "Windsurf"},
	{EditorZed, "Zed"},
	{EditorCline, "Cline"},
	{EditorAmazonQ, "Amazon Q"},
	{EditorContinue, "Continue"},
	{EditorAntigravity, "Antigravity"},
	{EditorGemini, "Gemini CLI"},
	{EditorRooCode, "Roo Code"},
	{EditorJunie, "Junie"},
	{EditorClaudeDesktop, "Claude Desktop"},
}

// EditorByID returns the editor with the given ID.
func EditorByID(id EditorID) (Editor, bool) {
	for _, e := range AllEditors {
		if e.ID == id {
			return e, true
		}
	}
	return Editor{}, false
}

// configPathOverrides lets tests inject custom config paths.
var configPathOverrides map[EditorID]string

// ConfigPath returns the MCP config file path for this editor on the current OS.
func (e Editor) ConfigPath() string {
	if configPathOverrides != nil {
		if p, ok := configPathOverrides[e.ID]; ok {
			return p
		}
	}
	return defaultConfigPath(e.ID)
}

// IsDetected checks whether the editor appears to be installed by looking
// for the parent directory of its config file.
func (e Editor) IsDetected() bool {
	p := e.ConfigPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(filepath.Dir(p))
	return err == nil
}

// Register adds the Armis MCP server to this editor's configuration.
func (e Editor) Register(pluginDir string) error {
	configFile := e.ConfigPath()
	if configFile == "" {
		return fmt.Errorf("%s is not supported on this platform", e.Name)
	}
	return registerEditor(e.ID, pluginDir, configFile)
}

// DetectedEditors returns editors that appear to be installed on this system.
func DetectedEditors() []Editor {
	var detected []Editor
	for _, e := range AllEditors {
		if e.IsDetected() {
			detected = append(detected, e)
		}
	}
	return detected
}

// EditorInstaller downloads the plugin once and registers it across editors.
type EditorInstaller struct {
	pluginDir string
	plugin    *PluginInstaller
}

// NewEditorInstaller creates an installer using the shared plugin directory (~/.armis/plugins/armis-appsec-mcp).
func NewEditorInstaller() *EditorInstaller {
	home, _ := os.UserHomeDir()
	return &EditorInstaller{
		pluginDir: filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp"),
		plugin:    newPluginInstaller(),
	}
}

// InstalledVersion returns the version that was installed (available after FetchPlugin).
func (ei *EditorInstaller) InstalledVersion() string { return ei.plugin.InstalledVersion() }

// PluginDir returns the shared plugin installation directory.
func (ei *EditorInstaller) PluginDir() string { return ei.pluginDir }

// EnvFilePath returns the path to the shared .env credentials file.
func (ei *EditorInstaller) EnvFilePath() string { return filepath.Join(ei.pluginDir, ".env") }

// HasExistingEnv checks whether credentials are already configured.
func (ei *EditorInstaller) HasExistingEnv() bool {
	_, err := os.Stat(ei.EnvFilePath())
	return err == nil
}

// FetchPlugin downloads and sets up the plugin (venv + deps), writes credentials
// from the environment, and records the installed version.
func (ei *EditorInstaller) FetchPlugin() error {
	if err := ei.plugin.FetchAndInstall(ei.pluginDir); err != nil {
		return err
	}
	// armis:ignore cwe:522 reason:delegates to writeEnvFromEnvironment which writes with 0600 permissions
	if err := writeEnvFromEnvironment(ei.EnvFilePath()); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}
	versionFile := filepath.Join(ei.pluginDir, ".installed-version")
	_ = os.WriteFile(filepath.Clean(versionFile), []byte(ei.plugin.InstalledVersion()), 0o600)
	return nil
}

// GetInstalledVersion reads the version from the shared plugin directory.
func (ei *EditorInstaller) GetInstalledVersion() string {
	versionFile := filepath.Join(ei.pluginDir, ".installed-version")
	v, err := os.ReadFile(filepath.Clean(versionFile))
	if err != nil {
		return ""
	}
	return string(v)
}

// RegisterJetBrains writes a .jb-mcp.json file at the given path.
func RegisterJetBrains(pluginDir, configFile string) error {
	return registerMCPServersFormat(pluginDir, configFile)
}

// --- Config path resolution ---

func defaultConfigPath(id EditorID) string {
	switch id {
	case EditorVSCode:
		return appSupportPath("Code", "User", "mcp.json")
	case EditorCursor:
		return homeDir(".cursor", "mcp.json")
	case EditorWindsurf:
		return homeDir(".codeium", "windsurf", "mcp_config.json")
	case EditorContinue:
		return homeDir(".continue", "mcpServers", "armis-appsec.json")
	case EditorZed:
		if runtime.GOOS == osWindows {
			return ""
		}
		return appSupportPath("Zed", "settings.json")
	case EditorCline:
		return appSupportPath("Code", "User", "globalStorage",
			"saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
	case EditorAmazonQ:
		return homeDir(".aws", "amazonq", "mcp.json")
	case EditorAntigravity:
		return homeDir(".gemini", "antigravity", "mcp_config.json")
	case EditorGemini:
		return homeDir(".gemini", "settings.json")
	case EditorRooCode:
		return homeDir(".roo-cline", "mcp_settings.json")
	case EditorJunie:
		return homeDir(".junie", "mcp", "mcp.json")
	case EditorClaudeDesktop:
		if runtime.GOOS != osDarwin && runtime.GOOS != osWindows {
			return ""
		}
		return appSupportPath("Claude", "claude_desktop_config.json")
	}
	return ""
}

func homeDir(parts ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home}, parts...)...)
}

func appSupportPath(parts ...string) string {
	var base string
	switch runtime.GOOS {
	case osDarwin:
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, "Library", "Application Support")
	case osLinux:
		base = os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			base = filepath.Join(home, ".config")
		}
	case osWindows:
		base = os.Getenv("APPDATA")
		if base == "" {
			return ""
		}
	default:
		return ""
	}
	return filepath.Join(append([]string{base}, parts...)...)
}

// --- Registration ---

func registerEditor(id EditorID, pluginDir, configFile string) error {
	switch id {
	case EditorVSCode:
		return registerVSCodeFormat(pluginDir, configFile)
	case EditorZed:
		return registerZedFormat(pluginDir, configFile)
	default:
		// Shared by the standard mcpServers editors.
		return registerMCPServersFormat(pluginDir, configFile)
	}
}

// registerMCPServersFormat handles {"mcpServers": {"name": {command, args}}}.
// Shared by the standard mcpServers editors (and JetBrains via RegisterJetBrains).
func registerMCPServersFormat(pluginDir, configFile string) error {
	data := readJSONFileAsMap(configFile)

	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	servers[mcpServerName] = stdServerEntry(pluginDir)
	data["mcpServers"] = servers

	return writeJSON(configFile, data)
}

// registerVSCodeFormat handles {"servers": {"name": {type, command, args, envFile}}}.
func registerVSCodeFormat(pluginDir, configFile string) error {
	data := readJSONFileAsMap(configFile)

	servers, ok := data["servers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	servers[mcpServerName] = map[string]interface{}{
		"type":    "stdio",
		"command": venvPython(pluginDir),
		"args":    []string{filepath.Join(pluginDir, "server.py")},
		"envFile": filepath.Join(pluginDir, ".env"),
	}
	data["servers"] = servers

	return writeJSON(configFile, data)
}

// registerZedFormat handles {"context_servers": {"name": {command: {path, args}}}}.
func registerZedFormat(pluginDir, configFile string) error {
	data := readJSONFileAsMap(configFile)

	servers, ok := data["context_servers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	servers[mcpServerName] = map[string]interface{}{
		"command": map[string]interface{}{
			"path": venvPython(pluginDir),
			"args": []string{filepath.Join(pluginDir, "server.py")},
		},
		"settings": map[string]interface{}{},
	}
	data["context_servers"] = servers

	return writeJSON(configFile, data)
}

func stdServerEntry(pluginDir string) map[string]interface{} {
	return map[string]interface{}{
		"command": venvPython(pluginDir),
		"args":    []string{filepath.Join(pluginDir, "server.py")},
	}
}

func readJSONFileAsMap(path string) map[string]interface{} {
	data := make(map[string]interface{})
	// armis:ignore cwe:22 reason:path is constructed from filepath.Join with known base dirs; filepath.Clean applied
	if b, err := os.ReadFile(filepath.Clean(path)); err == nil {
		_ = json.Unmarshal(b, &data)
	}
	return data
}
