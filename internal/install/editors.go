package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

const (
	mcpServerName       = "armis-appsec"
	maxEditorConfigSize = 10 << 20 // 10 MB — matches the settings file limit in hooks.go
)

// JSON key constants shared across MCP/hook config builders.
const (
	jsonKeyType        = "type"
	jsonKeyCommand     = "command"
	jsonKeyArgs        = "args"
	jsonKeyMatcher     = "matcher"
	jsonKeyHooks       = "hooks"
	jsonKeyTimeout     = "timeout"
	jsonKeyVersion     = "version"
	jsonKeyPath        = "path"
	jsonKeyLastUpdated = "lastUpdated"
	jsonKeySource      = "source"

	jsonTypeCommand = "command"
)

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
	EditorRooCode       EditorID = "roocode"
	EditorJunie         EditorID = "junie"
	EditorClaudeDesktop EditorID = "claude-desktop"
	EditorCopilotCLI    EditorID = "copilot"
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
	{EditorRooCode, "Roo Code"},
	{EditorJunie, "Junie"},
	{EditorClaudeDesktop, "Claude Desktop"},
	{EditorCopilotCLI, "Copilot CLI"},
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

// RegisterEntry adds the given MCP server to this editor's configuration.
func (e Editor) RegisterEntry(entry mcpEntry) error {
	configFile := e.ConfigPath()
	if configFile == "" {
		return fmt.Errorf("%s is not supported on this platform", e.Name)
	}
	return registerEditorEntry(e.ID, configFile, entry)
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
	// armis:ignore cwe:253 reason:UserHomeDir error results in empty string which fails gracefully downstream
	home, _ := os.UserHomeDir() //nolint:errcheck // armis:ignore cwe:253
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

// ErrAlreadyCurrent is returned when the installed version matches the latest release.
var ErrAlreadyCurrent = errors.New("already up to date")

// FetchPlugin downloads and sets up the plugin (venv + deps), writes credentials
// from the environment, and records the installed version.
// If force is false and the installed version matches the latest, returns ErrAlreadyCurrent.
func (ei *EditorInstaller) FetchPlugin(force bool) error {
	if !force {
		current := ei.GetInstalledVersion()
		if current != "" {
			latest, err := ei.plugin.LatestVersion()
			if err == nil && current == latest {
				ei.plugin.installedVersion = current
				return ErrAlreadyCurrent
			}
		}
	}

	if err := ei.plugin.FetchAndInstall(ei.pluginDir); err != nil {
		return err
	}
	// armis:ignore cwe:522 reason:delegates to writeEnvFromEnvironment which writes with 0600 permissions
	if err := writeEnvFromEnvironment(ei.EnvFilePath()); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}
	versionFile := filepath.Join(ei.pluginDir, ".installed-version")
	// armis:ignore cwe:253 reason:best-effort version tracking; write failure is non-critical
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
	return registerMCPServersFormat(configFile, scannerEntry(pluginDir))
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
		// Continue keeps MCP servers inline in its YAML config, not as separate
		// JSON files under a mcpServers/ directory (which it never creates).
		return homeDir(".continue", "config.yaml")
	case EditorZed:
		if runtime.GOOS == osWindows {
			return ""
		}
		return appSupportPath("Zed", "settings.json")
	case EditorCline:
		// Cline moved its settings out of VS Code's globalStorage into a
		// standalone ~/.cline data directory, so it is no longer VS-Code-scoped.
		// The old globalStorage file still exists on upgraded installs but Cline
		// does not read it — writing there registered nothing.
		return homeDir(".cline", "data", "settings", "cline_mcp_settings.json")
	case EditorAmazonQ:
		return homeDir(".aws", "amazonq", "mcp.json")
	case EditorAntigravity:
		// Antigravity 2.0, the CLI (agy), and the IDE all share this one global
		// MCP config, so a single registration covers whichever is installed.
		// Antigravity migrated here from ~/.gemini/antigravity/, leaving a
		// .migrated marker behind; the old path is never created on current
		// installs, so registering there silently reached no agent.
		return homeDir(".gemini", "config", "mcp_config.json")
	case EditorRooCode:
		// Roo Code stores MCP settings in VS Code's globalStorage, the same way
		// Cline does — not in a ~/.roo-cline home directory, which it never
		// creates. Detection keys on this directory, so the old path meant Roo
		// Code was never detected even when installed.
		return appSupportPath("Code", "User", "globalStorage",
			"rooveterinaryinc.roo-cline", "settings", "mcp_settings.json")
	case EditorJunie:
		return homeDir(".junie", "mcp", "mcp.json")
	case EditorClaudeDesktop:
		if runtime.GOOS != osDarwin && runtime.GOOS != osWindows {
			return ""
		}
		return appSupportPath("Claude", "claude_desktop_config.json")
	case EditorCopilotCLI:
		return homeDir(".copilot", "mcp-config.json")
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
		// armis:ignore cwe:22 reason:XDG_CONFIG_HOME is a user-local config env var; affects only the current user context
		base = os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			base = filepath.Join(home, ".config")
		}
	case osWindows:
		// armis:ignore cwe:22 reason:APPDATA is a standard OS env var for user config; not user-controlled input
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

// mcpEntry describes one MCP server registration. Both products (scanner and
// knowledge) register through the same four config-format writers below; only
// these fields differ between them.
type mcpEntry struct {
	name    string
	command string
	args    []string
	envFile string
}

// scannerEntry builds the registration for the Armis AppSec MCP server.
func scannerEntry(pluginDir string) mcpEntry {
	return mcpEntry{
		name:    mcpServerName,
		command: venvPython(pluginDir),
		args:    []string{filepath.Join(pluginDir, "server.py")},
		envFile: filepath.Join(pluginDir, ".env"),
	}
}

func registerEditor(id EditorID, pluginDir, configFile string) error {
	return registerEditorEntry(id, configFile, scannerEntry(pluginDir))
}

// registerEditorEntry writes entry into configFile using the format the given
// editor expects, preserving any other servers already present.
func registerEditorEntry(id EditorID, configFile string, entry mcpEntry) error {
	switch id {
	case EditorVSCode:
		return registerVSCodeFormat(configFile, entry)
	case EditorZed:
		return registerZedFormat(configFile, entry)
	case EditorContinue:
		return registerContinueFormat(configFile, entry)
	default:
		// Shared by the standard mcpServers editors.
		return registerMCPServersFormat(configFile, entry)
	}
}

// registerMCPServersFormat handles {"mcpServers": {"name": {command, args}}}.
// Shared by the standard mcpServers editors (and JetBrains via RegisterJetBrains).
func registerMCPServersFormat(configFile string, entry mcpEntry) error {
	data := readJSONFileAsMap(configFile)

	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	servers[entry.name] = map[string]interface{}{
		jsonKeyCommand: entry.command,
		jsonKeyArgs:    entry.args,
	}
	data["mcpServers"] = servers

	return writeJSON(configFile, data)
}

// registerVSCodeFormat handles {"servers": {"name": {type, command, args, envFile}}}.
func registerVSCodeFormat(configFile string, entry mcpEntry) error {
	data := readJSONFileAsMap(configFile)

	servers, ok := data["servers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	server := map[string]interface{}{
		jsonKeyType:    "stdio",
		jsonKeyCommand: entry.command,
		jsonKeyArgs:    entry.args,
	}
	if entry.envFile != "" {
		server["envFile"] = entry.envFile
	}
	servers[entry.name] = server
	data["servers"] = servers

	return writeJSON(configFile, data)
}

// registerZedFormat handles {"context_servers": {"name": {command: {path, args}}}}.
func registerZedFormat(configFile string, entry mcpEntry) error {
	data := readJSONFileAsMap(configFile)

	servers, ok := data["context_servers"].(map[string]interface{})
	if !ok {
		servers = make(map[string]interface{})
	}
	servers[entry.name] = map[string]interface{}{
		jsonKeyCommand: map[string]interface{}{
			jsonKeyPath: entry.command,
			jsonKeyArgs: entry.args,
		},
		"settings": map[string]interface{}{},
	}
	data["context_servers"] = servers

	return writeJSON(configFile, data)
}

// registerContinueFormat writes entry into Continue's config.yaml.
//
// Continue is the one supported editor whose MCP servers are a YAML *list* of
// objects each carrying its own `name`, rather than a map keyed by server name:
//
//	mcpServers:
//	  - name: armis-appsec
//	    command: /path/to/python
//	    args: [/path/to/server.py]
//
// The whole file is round-tripped so unrelated Continue settings (models, rules,
// context providers) survive, and an existing entry with the same name is
// replaced in place rather than duplicated.
func registerContinueFormat(configFile string, entry mcpEntry) error {
	data := readYAMLFileAsMap(configFile)

	// Continue rejects a config without these, so seed them when creating one.
	if data["name"] == nil {
		data["name"] = "Main Config"
	}
	if data["version"] == nil {
		data["version"] = "1.0.0"
	}
	if data["schema"] == nil {
		data["schema"] = "v1"
	}

	server := map[string]interface{}{
		"name":         entry.name,
		jsonKeyCommand: entry.command,
	}
	if len(entry.args) > 0 {
		server[jsonKeyArgs] = entry.args
	}

	existing, _ := data["mcpServers"].([]interface{})
	servers := make([]interface{}, 0, len(existing)+1)
	replaced := false
	for _, s := range existing {
		if m, ok := s.(map[string]interface{}); ok {
			if n, _ := m["name"].(string); n == entry.name {
				servers = append(servers, server)
				replaced = true
				continue
			}
		}
		servers = append(servers, s)
	}
	if !replaced {
		servers = append(servers, server)
	}
	data["mcpServers"] = servers

	return writeYAML(configFile, data)
}

// readYAMLFileAsMap parses a YAML config into a map, returning an empty map when
// the file is absent, oversized, or unparseable — mirroring readJSONFileAsMap so
// a corrupt config cannot abort an install.
func readYAMLFileAsMap(path string) map[string]interface{} {
	data := make(map[string]interface{})
	clean := filepath.Clean(path)
	// Reject non-regular files (devices, FIFOs) and oversized configs, matching
	// the JSON reader's bounds (CWE-770).
	// armis:ignore cwe:22 reason:path from homeDir with hardcoded segments; filepath.Clean applied
	if info, err := os.Stat(clean); err != nil || !info.Mode().IsRegular() || info.Size() > maxEditorConfigSize {
		return data
	}
	// armis:ignore cwe:22 cwe:253 cwe:770 reason:path from homeDir with hardcoded segments; size-bounded by the guard above; parse error handled below
	b, err := os.ReadFile(clean) //nolint:gosec // path from homeDir with hardcoded segments, size-checked above
	if err != nil {
		return data
	}
	// armis:ignore cwe:502 reason:yaml.Unmarshal into map[string]interface{} performs no type resolution; input is the user's own local editor config, size-bounded above
	if err := yaml.Unmarshal(b, &data); err != nil || data == nil {
		return make(map[string]interface{})
	}
	return data
}

func writeYAML(path string, data interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	// armis:ignore cwe:22 cwe:73 reason:path from homeDir with hardcoded segments; filepath.Clean applied
	return os.WriteFile(filepath.Clean(path), b, 0o600)
}

func readJSONFileAsMap(path string) map[string]interface{} {
	data := make(map[string]interface{})
	clean := filepath.Clean(path)
	// armis:ignore cwe:22 reason:path from filepath.Join with known base dirs; filepath.Clean applied
	// Reject non-regular files (devices, FIFOs): they can report Size()==0 yet
	// stream unbounded data into os.ReadFile, defeating the size cap (CWE-770).
	if info, err := os.Stat(clean); err != nil || !info.Mode().IsRegular() || info.Size() > maxEditorConfigSize {
		return data
	}
	// armis:ignore cwe:22 cwe:253 reason:path from filepath.Join with known base dirs; filepath.Clean applied; ReadFile error handled by err == nil guard
	if b, err := os.ReadFile(clean); err == nil { //nolint:gosec
		// armis:ignore cwe:502 cwe:770 reason:Go encoding/json into map[string]interface{} has no gadget/polymorphic deserialization; input is the user's own local editor config, size-bounded by the maxEditorConfigSize guard above
		_ = json.Unmarshal(b, &data)
	}
	return data
}
