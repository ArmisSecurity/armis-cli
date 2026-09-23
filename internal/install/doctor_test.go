package install

import (
	"bufio"
	"encoding/json"
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

// runMCPHelperProcess acts as a fake MCP stdio server. It answers each
// request line by method so the doctor's full session (initialize,
// tools/list, tools/call) can be exercised.
func runMCPHelperProcess(mode string) {
	if mode == "hang" {
		select {}
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var req struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal(line, &req) != nil || req.ID == nil {
			continue // notification
		}
		reply := func(body string) {
			_, _ = fmt.Fprintf(os.Stdout, `{"jsonrpc":"2.0","id":%d,%s}`+"\n", *req.ID, body)
		}
		switch {
		case mode == "garbage":
			_, _ = fmt.Fprintln(os.Stdout, "not json")
			return
		case mode == "error":
			reply(`"error":{"code":-1,"message":"boom"}`)
			return
		case req.Method == "initialize":
			// A log notification before the response must be skipped.
			_, _ = fmt.Fprintln(os.Stdout, `{"jsonrpc":"2.0","method":"notifications/message","params":{}}`)
			reply(`"result":{"serverInfo":{"name":"fake-mcp","version":"9.9.9"}}`)
		case req.Method == "tools/list" && mode == "garbage-after-init":
			_, _ = fmt.Fprintln(os.Stdout, "not json")
			return
		case req.Method == "tools/list" && mode == "notools":
			reply(`"result":{"tools":[]}`)
		case req.Method == "tools/list":
			reply(`"result":{"tools":[{"name":"scan_code"},{"name":"debug_config"}]}`)
		case req.Method == "tools/call" && mode == "toolerror":
			reply(`"result":{"content":[{"type":"text","text":"config broken"}],"isError":true}`)
		case req.Method == "tools/call":
			reply(`"result":{"content":[{"type":"text","text":"Auth: configured\nAuth method: JWT\nAPI URL: https://moose.armis.com/api/v1\nEnv: prod"}]}`)
		default:
			reply(`"error":{"code":-32601,"message":"method not found"}`)
		}
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
	if res.ToolsErr != nil || strings.Join(res.Tools, ",") != "scan_code,debug_config" {
		t.Errorf("mcpHandshake() tools = %v (err %v), want scan_code,debug_config", res.Tools, res.ToolsErr)
	}
	if res.DebugErr != nil || !strings.Contains(res.DebugConfig, "Auth method: JWT") {
		t.Errorf("mcpHandshake() debug_config = %q (err %v), want Auth method line", res.DebugConfig, res.DebugErr)
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

// TestMCPHandshakeInvalidResponseAfterInit pins that non-JSON stdout is
// caught even once the session is past initialize, not just before it: a
// server that starts clean but later corrupts its own stdout stream should
// surface as a tools error rather than being silently skipped forever.
func TestMCPHandshakeInvalidResponseAfterInit(t *testing.T) {
	res, _, err := mcpHandshake(os.Args[0], nil, map[string]string{"ARMIS_TEST_MCP_HELPER": "garbage-after-init"}, 5*time.Second)
	if err != nil {
		t.Fatalf("mcpHandshake() error = %v, want initialize to still succeed", err)
	}
	if res.ToolsErr == nil {
		t.Fatal("mcpHandshake() ToolsErr = nil, want error from invalid JSON on stdout during tools/list")
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
			format:      configFormatVSCode,
			content:     `{"servers":{"armis-appsec":{"type":"stdio","command":"/bin/python"}}}`,
			fileName:    "vscode.json",
			identifier:  "armis-appsec",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:        "zed-context_servers format match",
			format:      configFormatZed,
			content:     `{"context_servers":{"armis-appsec":{"command":{"path":"/bin/python","args":[]}}}}`,
			fileName:    "zed.json",
			identifier:  "armis-appsec",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:        "continue-yaml format match",
			format:      configFormatContinue,
			content:     "mcpServers:\n  - name: armis-knowledge\n    command: /bin/python\n",
			fileName:    "continue.yaml",
			identifier:  "armis-knowledge",
			wantFound:   true,
			wantCommand: "/bin/python",
		},
		{
			name:       "continue-yaml format no match",
			format:     configFormatContinue,
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
	_ = os.WriteFile(realCommand, []byte("x"), 0o700) // #nosec G306 -- needs exec bit for isExecutableFile checks

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

	// Malformed JSON: not auto-fixable, since re-registering reads this file
	// as an empty map and would drop every other server it configures.
	invalidFile := filepath.Join(dir, "invalid.json")
	_ = os.WriteFile(invalidFile, []byte(`{"mcpServers": {`), 0o600)

	editors := map[EditorID]ManifestEntry{
		EditorCursor:   {ConfigFile: presentFile, Format: "mcpServers"},
		EditorWindsurf: {ConfigFile: staleFile, Format: "mcpServers"},
		EditorZed:      {ConfigFile: missingFile, Format: "mcpServers"},
		EditorVSCode:   {ConfigFile: deadCommandFile, Format: "mcpServers"},
		EditorCline:    {ConfigFile: invalidFile, Format: "mcpServers"},
	}

	d := newDoctorRun(DoctorOptions{})
	checkManifestEditors(d, "scanner", "armis-appsec", editors)
	report := d.report

	statuses := make(map[string]CheckStatus)
	fixes := make(map[string]FixAction)
	for _, c := range report.Checks {
		statuses[c.Name] = c.Status
		fixes[c.Name] = c.Fix
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
	if statuses["Cline"] != StatusFail || fixes["Cline"] != FixBlocked {
		t.Errorf("Cline status/fix = %v/%v, want fail/blocked (invalid JSON)", statuses["Cline"], fixes["Cline"])
	}

	// Zed and VS Code alone would call for FixReregister, but the invalid
	// Cline config must veto it for the whole report: reregistering goes
	// through every manifest editor, including Cline's.
	for _, f := range report.Fixes() {
		if f == FixReregister || f == FixReinstall {
			t.Errorf("Fixes() = %v, want FixReregister/FixReinstall withheld while a config is unparsable", report.Fixes())
		}
	}
}

func TestCheckVSCodeWorkspaceInvalidConfig(t *testing.T) {
	workspace := t.TempDir()
	vscodeDir := filepath.Join(workspace, ".vscode")
	_ = os.MkdirAll(vscodeDir, 0o750)
	// Malformed JSONC: VS Code ignores the whole file, so a real armis-appsec
	// entry in here would silently stop loading.
	_ = os.WriteFile(filepath.Join(vscodeDir, "mcp.json"), []byte(`{"servers": {`), 0o600)

	d := newDoctorRun(DoctorOptions{})
	checkVSCodeWorkspace(d, workspace)

	if len(d.report.Checks) != 1 {
		t.Fatalf("checks = %+v, want exactly one failing check for the unparsable workspace config", d.report.Checks)
	}
	c := d.report.Checks[0]
	if c.Status != StatusFail || c.Component != componentVSCode {
		t.Errorf("check = %+v, want a StatusFail check in the vscode component", c)
	}
	if c.Remediation == "" {
		t.Errorf("check has no remediation hint for the unparsable config")
	}
}

// TestReadJSONCObjectBOMOnly pins that a file containing only a UTF-8 BOM (or
// BOM plus comments/whitespace) is treated as empty rather than a parse
// error: TrimSpace alone doesn't strip the BOM rune, so the emptiness check
// must run after stripJSONC removes it.
func TestReadJSONCObjectBOMOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")

	_ = os.WriteFile(path, []byte("\xEF\xBB\xBF"), 0o600)
	if obj, exists, err := readJSONCObject(path); err != nil || !exists || len(obj) != 0 {
		t.Errorf("readJSONCObject(BOM only) = (%v, %v, %v), want (empty map, true, nil)", obj, exists, err)
	}

	_ = os.WriteFile(path, []byte("\xEF\xBB\xBF// just a comment\n"), 0o600)
	if obj, exists, err := readJSONCObject(path); err != nil || !exists || len(obj) != 0 {
		t.Errorf("readJSONCObject(BOM + comment) = (%v, %v, %v), want (empty map, true, nil)", obj, exists, err)
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
	_ = os.WriteFile(executable, []byte("x"), 0o700) // #nosec G306 -- needs exec bit for isExecutableFile checks
	if !isExecutableFile(executable) {
		t.Error("isExecutableFile() = false for an executable file")
	}
}

func TestRunDoctorNoManifest(t *testing.T) {
	stubVSCode(t, nil)
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
	stubVSCode(t, nil)
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

	d := newDoctorRun(DoctorOptions{Handshake: false})
	checkKnowledgePlugin(d, &ManifestKnowledge{PluginDir: dir})
	report := d.report

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
	if err := os.WriteFile(python, []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- needs exec bit to run as fake venv python
		t.Fatal(err)
	}
}
