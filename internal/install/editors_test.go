package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEditorByID(t *testing.T) {
	e, ok := EditorByID(EditorVSCode)
	if !ok {
		t.Fatal("EditorByID(EditorVSCode) not found")
	}
	if e.Name != "VS Code" {
		t.Errorf("Name = %q, want %q", e.Name, "VS Code")
	}

	_, ok = EditorByID("nonexistent")
	if ok {
		t.Error("EditorByID(nonexistent) should return false")
	}
}

func TestEditorConfigPath(t *testing.T) {
	for _, e := range AllEditors {
		p := e.ConfigPath()
		if p == "" {
			t.Logf("skipping %s (not supported on this OS)", e.Name)
			continue
		}
		if !filepath.IsAbs(p) {
			t.Errorf("%s config path %q is not absolute", e.Name, p)
		}
	}
}

func TestClaudeDesktopUnsupportedOS(t *testing.T) {
	e, ok := EditorByID(EditorClaudeDesktop)
	if !ok {
		t.Fatal("EditorByID(EditorClaudeDesktop) not found")
	}
	if runtime.GOOS == osDarwin || runtime.GOOS == osWindows {
		if e.ConfigPath() == "" {
			t.Errorf("ConfigPath() unexpectedly empty on %s", runtime.GOOS)
		}
		return
	}
	if got := e.ConfigPath(); got != "" {
		t.Errorf("ConfigPath() on %s = %q, want empty (Claude Desktop only ships on macOS/Windows)", runtime.GOOS, got)
	}
	if e.IsDetected() {
		t.Errorf("IsDetected() on %s = true, want false", runtime.GOOS)
	}
}

func TestEditorConfigPathOverride(t *testing.T) {
	configPathOverrides = map[EditorID]string{
		EditorCursor: "/tmp/test-cursor-mcp.json",
	}
	defer func() { configPathOverrides = nil }()

	e, _ := EditorByID(EditorCursor)
	if got := e.ConfigPath(); got != "/tmp/test-cursor-mcp.json" {
		t.Errorf("ConfigPath() = %q, want override path", got)
	}
}

func TestEditorIsDetected(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "mcp.json")

	configPathOverrides = map[EditorID]string{
		EditorCursor: configFile,
	}
	defer func() { configPathOverrides = nil }()

	e, _ := EditorByID(EditorCursor)
	if !e.IsDetected() {
		t.Error("IsDetected() should return true when parent dir exists")
	}

	configPathOverrides[EditorCursor] = "/nonexistent/dir/mcp.json"
	if e.IsDetected() {
		t.Error("IsDetected() should return false when parent dir missing")
	}
}

func TestDetectedEditors(t *testing.T) {
	dir := t.TempDir()
	configPathOverrides = make(map[EditorID]string)
	for _, e := range AllEditors {
		configPathOverrides[e.ID] = "/nonexistent/" + string(e.ID) + "/mcp.json"
	}
	cursorFile := filepath.Join(dir, "cursor-mcp.json")
	configPathOverrides[EditorCursor] = cursorFile
	defer func() { configPathOverrides = nil }()

	detected := DetectedEditors()
	if len(detected) != 1 {
		t.Fatalf("DetectedEditors() = %d editors, want 1", len(detected))
	}
	if detected[0].ID != EditorCursor {
		t.Errorf("detected[0].ID = %q, want %q", detected[0].ID, EditorCursor)
	}
}

func TestRegisterMCPServersFormat(t *testing.T) {
	editors := []EditorID{EditorCursor, EditorWindsurf, EditorCline, EditorAmazonQ, EditorAntigravity, EditorContinue, EditorGemini, EditorClaudeDesktop}
	for _, id := range editors {
		t.Run(string(id), func(t *testing.T) {
			dir := t.TempDir()
			configFile := filepath.Join(dir, "mcp.json")
			pluginDir := filepath.Join(dir, "plugin")

			configPathOverrides = map[EditorID]string{id: configFile}
			defer func() { configPathOverrides = nil }()

			e, _ := EditorByID(id)
			if err := e.Register(pluginDir); err != nil {
				t.Fatalf("Register() error: %v", err)
			}

			var data map[string]interface{}
			b, _ := os.ReadFile(filepath.Clean(configFile))
			if err := json.Unmarshal(b, &data); err != nil {
				t.Fatal(err)
			}

			servers, ok := data["mcpServers"].(map[string]interface{})
			if !ok {
				t.Fatal("mcpServers key missing")
			}
			server, ok := servers[mcpServerName].(map[string]interface{})
			if !ok {
				t.Fatal("armis-appsec server not registered")
			}
			if server["command"] != venvPython(pluginDir) {
				t.Errorf("command = %q, want %q", server["command"], venvPython(pluginDir))
			}
		})
	}
}

func TestRegisterVSCodeFormat(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "mcp.json")
	pluginDir := filepath.Join(dir, "plugin")

	configPathOverrides = map[EditorID]string{EditorVSCode: configFile}
	defer func() { configPathOverrides = nil }()

	e, _ := EditorByID(EditorVSCode)
	if err := e.Register(pluginDir); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	var data map[string]interface{}
	b, _ := os.ReadFile(filepath.Clean(configFile))
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}

	servers, ok := data["servers"].(map[string]interface{})
	if !ok {
		t.Fatal("servers key missing")
	}
	server, ok := servers[mcpServerName].(map[string]interface{})
	if !ok {
		t.Fatal("armis-appsec server not registered")
	}
	if server["type"] != "stdio" {
		t.Errorf("type = %q, want %q", server["type"], "stdio")
	}
	if server["envFile"] == nil {
		t.Error("envFile should be set for VS Code")
	}
}

func TestRegisterZedFormat(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "settings.json")
	pluginDir := filepath.Join(dir, "plugin")

	configPathOverrides = map[EditorID]string{EditorZed: configFile}
	defer func() { configPathOverrides = nil }()

	e, _ := EditorByID(EditorZed)
	if err := e.Register(pluginDir); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	var data map[string]interface{}
	b, _ := os.ReadFile(filepath.Clean(configFile))
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}

	ctxServers, ok := data["context_servers"].(map[string]interface{})
	if !ok {
		t.Fatal("context_servers key missing")
	}
	server, ok := ctxServers[mcpServerName].(map[string]interface{})
	if !ok {
		t.Fatal("armis-appsec server not registered")
	}
	cmd, ok := server["command"].(map[string]interface{})
	if !ok {
		t.Fatal("command object missing")
	}
	if cmd["path"] != venvPython(pluginDir) {
		t.Errorf("command.path = %q, want %q", cmd["path"], venvPython(pluginDir))
	}
}

func TestRegisterContinueCreatesDirectoryFile(t *testing.T) {
	dir := t.TempDir()
	mcpServersDir := filepath.Join(dir, "mcpServers")
	if err := os.MkdirAll(mcpServersDir, 0o750); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(mcpServersDir, "armis-appsec.json")
	pluginDir := filepath.Join(dir, "plugin")

	configPathOverrides = map[EditorID]string{EditorContinue: configFile}
	defer func() { configPathOverrides = nil }()

	e, _ := EditorByID(EditorContinue)
	if err := e.Register(pluginDir); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	var data map[string]interface{}
	b, _ := os.ReadFile(filepath.Clean(configFile))
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}

	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers key missing")
	}
	server, ok := servers[mcpServerName].(map[string]interface{})
	if !ok {
		t.Fatal("armis-appsec server not registered")
	}
	if server["command"] != venvPython(pluginDir) {
		t.Errorf("command = %q, want %q", server["command"], venvPython(pluginDir))
	}
}

func TestRegisterPreservesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "mcp.json")
	pluginDir := filepath.Join(dir, "plugin")

	existing := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"other-server": map[string]interface{}{
				"command": "node",
				"args":    []string{"server.js"},
			},
		},
	}
	b, _ := json.MarshalIndent(existing, "", "  ")
	_ = os.WriteFile(configFile, b, 0o600)

	configPathOverrides = map[EditorID]string{EditorCursor: configFile}
	defer func() { configPathOverrides = nil }()

	e, _ := EditorByID(EditorCursor)
	if err := e.Register(pluginDir); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	var data map[string]interface{}
	b, _ = os.ReadFile(filepath.Clean(configFile))
	_ = json.Unmarshal(b, &data)

	servers := data["mcpServers"].(map[string]interface{})
	if _, ok := servers["other-server"]; !ok {
		t.Error("existing server was lost")
	}
	if _, ok := servers[mcpServerName]; !ok {
		t.Error("armis-appsec not registered")
	}
}

func TestRegisterJetBrains(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, ".jb-mcp.json")
	pluginDir := filepath.Join(dir, "plugin")

	if err := RegisterJetBrains(pluginDir, configFile); err != nil {
		t.Fatalf("RegisterJetBrains() error: %v", err)
	}

	var data map[string]interface{}
	b, _ := os.ReadFile(filepath.Clean(configFile))
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}

	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers key missing")
	}
	if _, ok := servers[mcpServerName]; !ok {
		t.Fatal("armis-appsec server not registered")
	}
}

func TestEditorInstallerFields(t *testing.T) {
	dir := t.TempDir()
	ei := &EditorInstaller{pluginDir: dir, plugin: newPluginInstaller()}
	if ei.PluginDir() == "" {
		t.Error("PluginDir() should not be empty")
	}
	if ei.EnvFilePath() == "" {
		t.Error("EnvFilePath() should not be empty")
	}
	if ei.InstalledVersion() != "" {
		t.Error("InstalledVersion() should be empty before install")
	}
	if v := ei.GetInstalledVersion(); v != "" {
		t.Errorf("GetInstalledVersion() = %q, want empty", v)
	}
}

func TestNewEditorInstaller(t *testing.T) {
	ei := NewEditorInstaller()
	if ei.PluginDir() == "" {
		t.Error("PluginDir() should not be empty")
	}
}

func TestEditorInstallerHasExistingEnv(t *testing.T) {
	dir := t.TempDir()
	ei := &EditorInstaller{pluginDir: dir, plugin: newPluginInstaller()}

	if ei.HasExistingEnv() {
		t.Error("HasExistingEnv() should return false when .env doesn't exist")
	}

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ei.HasExistingEnv() {
		t.Error("HasExistingEnv() should return true when .env exists")
	}
}
