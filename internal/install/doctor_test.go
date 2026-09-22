package install

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain intercepts re-exec calls used by the mcpHandshake tests: when
// ARMIS_TEST_MCP_HELPER is set, this process acts as a fake MCP stdio server
// instead of running the test suite.
func TestMain(m *testing.M) {
	if mode := os.Getenv("ARMIS_TEST_MCP_HELPER"); mode != "" {
		runMCPHelperProcess(mode)
		return
	}
	os.Exit(m.Run())
}

func runMCPHelperProcess(mode string) {
	switch mode {
	case "hang":
		select {}
	case "garbage":
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
		fmt.Fprintln(os.Stdout, "not json")
	case "error":
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
		fmt.Fprintln(os.Stdout, `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"boom"}}`)
	default: // "ok"
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
		fmt.Fprintln(os.Stdout, `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"fake-mcp","version":"9.9.9"}}}`)
	}
}

func TestMCPHandshakeSuccess(t *testing.T) {
	res, tail, err := mcpHandshake(os.Args[0], nil, map[string]string{"ARMIS_TEST_MCP_HELPER": "ok"}, 5*time.Second)
	if err != nil {
		t.Fatalf("mcpHandshake() error = %v (stderr: %s)", err, tail)
	}
	if res.ServerName != "fake-mcp" || res.ServerVersion != "9.9.9" {
		t.Errorf("mcpHandshake() result = %+v, want fake-mcp v9.9.9", res)
	}
}

func TestMCPHandshakeServerError(t *testing.T) {
	_, _, err := mcpHandshake(os.Args[0], nil, map[string]string{"ARMIS_TEST_MCP_HELPER": "error"}, 5*time.Second)
	if err == nil {
		t.Fatal("mcpHandshake() error = nil, want error from server's JSON-RPC error response")
	}
}

func TestMCPHandshakeInvalidResponse(t *testing.T) {
	_, _, err := mcpHandshake(os.Args[0], nil, map[string]string{"ARMIS_TEST_MCP_HELPER": "garbage"}, 5*time.Second)
	if err == nil {
		t.Fatal("mcpHandshake() error = nil, want error from invalid JSON response")
	}
}

func TestMCPHandshakeTimeout(t *testing.T) {
	_, _, err := mcpHandshake(os.Args[0], nil, map[string]string{"ARMIS_TEST_MCP_HELPER": "hang"}, 300*time.Millisecond)
	if err == nil {
		t.Fatal("mcpHandshake() error = nil, want timeout error")
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "ARMIS_CLIENT_ID=abc123\nARMIS_CLIENT_SECRET=s3cr3t\n# comment\n\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	env, err := parseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile() error = %v", err)
	}
	if env["ARMIS_CLIENT_ID"] != "abc123" || env["ARMIS_CLIENT_SECRET"] != "s3cr3t" {
		t.Errorf("parseEnvFile() = %+v, want ARMIS_CLIENT_ID/ARMIS_CLIENT_SECRET set", env)
	}
}

func TestParseEnvFileMissing(t *testing.T) {
	if _, err := parseEnvFile(filepath.Join(t.TempDir(), "missing.env")); err == nil {
		t.Fatal("parseEnvFile() error = nil, want error for missing file")
	}
}

func TestLookupEntryCommand(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		format      string
		content     string
		fileName    string
		identifier  string
		wantFound   bool
		wantCommand string
	}{
		{
			name:        "mcpServers format match",
			format:      "mcpServers",
			content:     `{"mcpServers":{"armis-appsec":{"command":"/bin/python"}}}`,
			fileName:    "mcp.json",
			identifier:  "armis-appsec",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:       "mcpServers format no match",
			format:     "mcpServers",
			content:    `{"mcpServers":{"other":{"command":"/bin/python"}}}`,
			fileName:   "mcp2.json",
			identifier: "armis-appsec",
			wantFound:  false,
		},
		{
			name:        "vscode-servers format match",
			format:      "vscode-servers",
			content:     `{"servers":{"armis-appsec":{"type":"stdio","command":"/bin/python"}}}`,
			fileName:    "vscode.json",
			identifier:  "armis-appsec",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:        "zed-context_servers format match",
			format:      "zed-context_servers",
			content:     `{"context_servers":{"armis-appsec":{"command":{"path":"/bin/python","args":[]}}}}`,
			fileName:    "zed.json",
			identifier:  "armis-appsec",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:        "continue-yaml format match",
			format:      "continue-yaml",
			content:     "mcpServers:\n  - name: armis-knowledge\n    command: /bin/python\n",
			fileName:    "continue.yaml",
			identifier:  "armis-knowledge",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:       "continue-yaml format no match",
			format:     "continue-yaml",
			content:    "mcpServers:\n  - name: other\n    command: /bin/python\n",
			fileName:   "continue2.yaml",
			identifier: "armis-knowledge",
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.fileName)
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			gotCommand, gotFound := lookupEntryCommand(path, tt.format, tt.identifier)
			if gotFound != tt.wantFound {
				t.Errorf("lookupEntryCommand() found = %v, want %v", gotFound, tt.wantFound)
			}
			if gotCommand != tt.wantCommand {
				t.Errorf("lookupEntryCommand() command = %q, want %q", gotCommand, tt.wantCommand)
			}
		})
	}
}

func TestCheckManifestEditors(t *testing.T) {
	dir := t.TempDir()

	realCommand := filepath.Join(dir, "python")
	_ = os.WriteFile(realCommand, []byte("x"), 0o700)

	presentFile := filepath.Join(dir, "present.json")
	mustWriteJSON(t, presentFile, map[string]interface{}{
		"mcpServers": map[string]interface{}{"armis-appsec": map[string]interface{}{"command": realCommand}},
	})

	staleFile := filepath.Join(dir, "stale.json")
	_ = os.WriteFile(staleFile, []byte(`{"mcpServers":{}}`), 0o600)

	missingFile := filepath.Join(dir, "does-not-exist.json")

	// Simulates the exact bug found by exercising the tool: the entry is
	// still present by name (e.g. VS Code's mcp.json survived), but the
	// command path it points to no longer exists — the kind of drift a
	// Windows profile rename or a reinstall into a new plugin dir causes.
	deadCommandFile := filepath.Join(dir, "dead-command.json")
	mustWriteJSON(t, deadCommandFile, map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"armis-appsec": map[string]interface{}{
				"command": filepath.Join(dir, "no-longer-exists", "python"),
			},
		},
	})

	editors := map[EditorID]ManifestEntry{
		EditorCursor:   {ConfigFile: presentFile, Format: "mcpServers"},
		EditorWindsurf: {ConfigFile: staleFile, Format: "mcpServers"},
		EditorZed:      {ConfigFile: missingFile, Format: "mcpServers"},
		EditorVSCode:   {ConfigFile: deadCommandFile, Format: "mcpServers"},
	}

	report := &DoctorReport{}
	checkManifestEditors(report, "scanner", "armis-appsec", editors)

	statuses := make(map[string]CheckStatus)
	for _, c := range report.Checks {
		statuses[c.Name] = c.Status
	}

	if statuses["Cursor"] != StatusOK {
		t.Errorf("Cursor status = %v, want ok", statuses["Cursor"])
	}
	if statuses["Windsurf"] != StatusWarn {
		t.Errorf("Windsurf status = %v, want warn (entry removed)", statuses["Windsurf"])
	}
	if statuses["Zed"] != StatusFail {
		t.Errorf("Zed status = %v, want fail (config missing)", statuses["Zed"])
	}
	if statuses["VS Code"] != StatusFail {
		t.Errorf("VS Code status = %v, want fail (command path dead)", statuses["VS Code"])
	}
}

func TestClaudeRegistryStatus(t *testing.T) {
	dir := t.TempDir()
	pluginsDir := filepath.Join(dir, "plugins")
	_ = os.MkdirAll(pluginsDir, 0o750)

	mustWriteJSON(t, filepath.Join(pluginsDir, "installed_plugins.json"), map[string]interface{}{
		"plugins": map[string]interface{}{
			"armis-appsec@armis-appsec-mcp": []interface{}{},
		},
	})
	mustWriteJSON(t, filepath.Join(dir, "settings.json"), map[string]interface{}{
		"enabledPlugins": map[string]interface{}{
			"armis-appsec@armis-appsec-mcp": true,
		},
	})

	installed, enabled := claudeRegistryStatus(dir, "armis-appsec")
	if !installed || !enabled {
		t.Errorf("claudeRegistryStatus() = (%v, %v), want (true, true)", installed, enabled)
	}

	installed, enabled = claudeRegistryStatus(dir, "armis-knowledge")
	if installed || enabled {
		t.Errorf("claudeRegistryStatus() for unrelated prefix = (%v, %v), want (false, false)", installed, enabled)
	}
}

func TestCheckCodexSection(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(configFile, []byte("[mcp_servers.armis_scanner]\ncommand = \"/bin/python\"\n"), 0o600)

	report := &DoctorReport{}
	checkCodexSection(report, "scanner", &ManifestCodex{ConfigFile: configFile}, "armis_scanner")
	if len(report.Checks) != 1 || report.Checks[0].Status != StatusOK {
		t.Errorf("checkCodexSection() = %+v, want single ok check", report.Checks)
	}

	report2 := &DoctorReport{}
	checkCodexSection(report2, "scanner", &ManifestCodex{ConfigFile: configFile}, "armis_knowledge")
	if len(report2.Checks) != 1 || report2.Checks[0].Status != StatusWarn {
		t.Errorf("checkCodexSection() with missing identifier = %+v, want single warn check", report2.Checks)
	}
}

func TestIsExecutableFile(t *testing.T) {
	dir := t.TempDir()
	if isExecutableFile(filepath.Join(dir, "missing")) {
		t.Error("isExecutableFile() = true for a missing file")
	}

	regular := filepath.Join(dir, "not-executable")
	_ = os.WriteFile(regular, []byte("x"), 0o600)
	if runtime.GOOS != osWindows && isExecutableFile(regular) {
		t.Error("isExecutableFile() = true for a non-executable file")
	}

	executable := filepath.Join(dir, "executable")
	_ = os.WriteFile(executable, []byte("x"), 0o700)
	if !isExecutableFile(executable) {
		t.Error("isExecutableFile() = false for an executable file")
	}
}

func TestRunDoctorNoManifest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	report := RunDoctor(DoctorOptions{Handshake: false})
	if !report.HasFailures() {
		t.Fatal("RunDoctor() with no manifest should report a failure")
	}
	if len(report.Checks) != 1 || report.Checks[0].Component != "install" {
		t.Errorf("RunDoctor() checks = %+v, want a single install/manifest failure", report.Checks)
	}
}

func TestRunDoctorStructuralChecks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	writeFakeVenv(t, pluginDir)
	_ = os.WriteFile(filepath.Join(pluginDir, "server.py"), []byte("# server"), 0o600)
	_ = os.WriteFile(filepath.Join(pluginDir, ".env"),
		[]byte("ARMIS_CLIENT_ID=id\nARMIS_CLIENT_SECRET=secret\n"), 0o600)

	editorConfig := filepath.Join(home, "editor-mcp.json")
	_ = os.WriteFile(editorConfig, []byte(`{"mcpServers":{"armis-appsec":{}}}`), 0o600)

	manifest := NewManifest(pluginDir, "1.2.3")
	manifest.AddEditor(EditorCursor, editorConfig, "mcpServers")
	if err := WriteManifest(manifest); err != nil {
		t.Fatalf("WriteManifest() error = %v", err)
	}

	report := RunDoctor(DoctorOptions{Handshake: false})
	if report.HasFailures() {
		t.Fatalf("RunDoctor() unexpected failures: %+v", report.Checks)
	}

	found := false
	for _, c := range report.Checks {
		if c.Component == "scanner" && c.Name == "Cursor" && c.Status == StatusOK {
			found = true
		}
	}
	if !found {
		t.Errorf("RunDoctor() checks = %+v, want ok check for scanner/Cursor", report.Checks)
	}
}

// TestCheckKnowledgePluginSkipsUninstalledSiblingEnv pins the fix for a false
// failure: Fetch extracts the whole knowledge repo, so every env's bridge.py
// (prod/stage/dev) lands on disk even though only the chosen env gets a venv.
// A sibling env with bridge.py but no .venv/ was never installed and must not
// be reported as a failure.
func TestCheckKnowledgePluginSkipsUninstalledSiblingEnv(t *testing.T) {
	dir := t.TempDir()

	// "prod" is the env the user actually installed: bridge.py + a real venv.
	writeFakeVenv(t, filepath.Join(dir, "prod"))
	_ = os.WriteFile(filepath.Join(dir, "prod", "bridge.py"), []byte("# bridge"), 0o600)

	// "dev" is a sibling extracted alongside it, with no venv ever created.
	_ = os.MkdirAll(filepath.Join(dir, "dev"), 0o750)
	_ = os.WriteFile(filepath.Join(dir, "dev", "bridge.py"), []byte("# bridge"), 0o600)

	report := &DoctorReport{}
	checkKnowledgePlugin(report, &ManifestKnowledge{PluginDir: dir}, DoctorOptions{Handshake: false})

	if report.HasFailures() {
		t.Errorf("checkKnowledgePlugin() unexpected failures for uninstalled sibling env: %+v", report.Checks)
	}

	var sawProdOK bool
	for _, c := range report.Checks {
		if c.Component == "knowledge prod" && c.Name == "python venv" && c.Status == StatusOK {
			sawProdOK = true
		}
		if c.Component == "knowledge dev" || strings.HasPrefix(c.Name, "dev ") {
			t.Errorf("checkKnowledgePlugin() reported a check for uninstalled sibling env dev: %+v", c)
		}
	}
	if !sawProdOK {
		t.Errorf("checkKnowledgePlugin() checks = %+v, want ok check for knowledge prod / python venv", report.Checks)
	}
}

// writeFakeVenv creates a fake venv python executable so structural checks
// (which only stat for existence + executable bit) pass without a real
// Python install.
func writeFakeVenv(t *testing.T, pluginDir string) {
	t.Helper()
	python := venvPython(pluginDir)
	if err := os.MkdirAll(filepath.Dir(python), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(python, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}
