package install

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func knowledgeTarball(t *testing.T) []byte {
	t.Helper()

	tmpFile := filepath.Join(t.TempDir(), "k.tar.gz")
	f, err := os.Create(filepath.Clean(tmpFile))
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	writeEntry := func(name string, data []byte) {
		t.Helper()
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	const root = "ArmisSecurity-armis-knowledge-mcp-abc1234/"
	// The root marketplace manifest is what Claude Code reads to resolve a
	// "directory" marketplace; its per-environment plugin sources are why the
	// whole repo is extracted rather than a single subtree.
	writeEntry(root+".claude-plugin/marketplace.json", []byte(
		`{"name":"armis-knowledge","metadata":{"pluginRoot":".."},`+
			`"plugins":[{"name":"armis-knowledge","source":"./prod/"},`+
			`{"name":"armis-knowledge-dev","source":"./dev/"}]}`))
	writeEntry(root+"prod/bridge.py", []byte("print('bridge')\n"))
	writeEntry(root+"prod/auth.py", []byte("print('auth')\n"))
	writeEntry(root+"prod/requirements.txt", []byte("mcp>=1.8,<2\n"))
	writeEntry(root+"prod/.claude-plugin/plugin.json", []byte(`{"name":"armis-knowledge"}`))
	writeEntry(root+"dev/bridge.py", []byte("print('dev')\n"))

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Clean(tmpFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKnowledgeServerNamePerEnv(t *testing.T) {
	tests := []struct {
		env       KnowledgeEnv
		wantJSON  string
		wantCodex string
	}{
		{KnowledgeEnvProd, "armis-knowledge", "armis_knowledge"},
		{KnowledgeEnvStage, "armis-knowledge-stage", "armis_knowledge_stage"},
		{KnowledgeEnvDev, "armis-knowledge-dev", "armis_knowledge_dev"},
	}

	for _, tt := range tests {
		t.Run(string(tt.env), func(t *testing.T) {
			ki := NewKnowledgeMCPInstaller(tt.env)
			if got := ki.ServerName(); got != tt.wantJSON {
				t.Errorf("ServerName() = %q, want %q", got, tt.wantJSON)
			}
			if got := ki.CodexServerName(); got != tt.wantCodex {
				t.Errorf("CodexServerName() = %q, want %q", got, tt.wantCodex)
			}
		})
	}
}

func TestKnowledgeFetchExtractsWholeRepoWithMarketplaceManifest(t *testing.T) {
	tarball := knowledgeTarball(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sha" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sha":"abc1234567890"}`))
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	dir := filepath.Join(t.TempDir(), "knowledge")
	ki := &KnowledgeMCPInstaller{
		env:               KnowledgeEnvProd,
		pluginDir:         dir,
		httpClient:        server.Client(),
		commitURL:         server.URL + "/sha",
		tarballURL:        server.URL + "/tarball",
		skipURLValidation: true,
		skipVenv:          true,
	}

	if err := ki.Fetch(false); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	// The environment's files land in its own subdirectory, which is where
	// run.sh resolves .venv and where bridge.py loads .env from.
	for _, want := range []string{"bridge.py", "auth.py", "requirements.txt"} {
		if _, err := os.Stat(filepath.Join(ki.EnvDir(), want)); err != nil {
			t.Errorf("expected %q in the prod env dir", want)
		}
	}
	// The ROOT marketplace manifest is the file Claude Code reads to resolve a
	// "directory" marketplace. Extracting only a subtree yields
	// .claude-plugin/plugin.json instead, which Claude Code cannot resolve — the
	// plugin then silently never loads, so this assertion guards the regression.
	if _, err := os.Stat(filepath.Join(dir, ".claude-plugin", "marketplace.json")); err != nil {
		t.Error("expected .claude-plugin/marketplace.json at the plugin dir root")
	}
	// Sibling environments come along, since the marketplace manifest declares
	// all of them and Claude Code resolves their sources relative to the root.
	if _, err := os.Stat(filepath.Join(dir, "dev", "bridge.py")); err != nil {
		t.Error("expected sibling dev/ environment to be extracted alongside prod/")
	}

	if got := ki.InstalledSHA(); got != "abc1234567890" {
		t.Errorf("InstalledSHA() = %q, want abc1234567890", got)
	}
}

func TestKnowledgeFetchSkipsWhenSHAUnchanged(t *testing.T) {
	tarball := knowledgeTarball(t)
	var tarballHits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sha" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sha":"abc1234567890"}`))
			return
		}
		tarballHits++
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	dir := filepath.Join(t.TempDir(), "knowledge")
	newInstaller := func() *KnowledgeMCPInstaller {
		return &KnowledgeMCPInstaller{
			env:               KnowledgeEnvProd,
			pluginDir:         dir,
			httpClient:        server.Client(),
			commitURL:         server.URL + "/sha",
			tarballURL:        server.URL + "/tarball",
			skipURLValidation: true,
			skipVenv:          true,
		}
	}

	if err := newInstaller().Fetch(false); err != nil {
		t.Fatalf("first Fetch() error: %v", err)
	}
	if tarballHits != 1 {
		t.Fatalf("tarball downloads after first fetch = %d, want 1", tarballHits)
	}

	err := newInstaller().Fetch(false)
	if !errors.Is(err, ErrAlreadyCurrent) {
		t.Errorf("second Fetch() = %v, want ErrAlreadyCurrent", err)
	}
	if tarballHits != 1 {
		t.Errorf("tarball re-downloaded when SHA unchanged (hits = %d)", tarballHits)
	}

	if err := newInstaller().Fetch(true); err != nil {
		t.Fatalf("forced Fetch() error: %v", err)
	}
	if tarballHits != 2 {
		t.Errorf("--force did not re-download (hits = %d, want 2)", tarballHits)
	}
}

func TestKnowledgeEntryPointsAtBridge(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "knowledge")
	ki := &KnowledgeMCPInstaller{env: KnowledgeEnvProd, pluginDir: dir}

	e := ki.entry()
	if e.name != "armis-knowledge" {
		t.Errorf("entry name = %q, want armis-knowledge", e.name)
	}
	if e.command != venvPython(ki.EnvDir()) {
		t.Errorf("entry command = %q, want %q", e.command, venvPython(ki.EnvDir()))
	}
	wantArg := filepath.Join(ki.EnvDir(), "bridge.py")
	if len(e.args) != 1 || e.args[0] != wantArg {
		t.Errorf("entry args = %v, want [%q]", e.args, wantArg)
	}
	if e.envFile != filepath.Join(ki.EnvDir(), ".env") {
		t.Errorf("entry envFile = %q, want %q", e.envFile, filepath.Join(ki.EnvDir(), ".env"))
	}
}

// TestKnowledgeCodexEntryUsesUnderscoreName pins codexEntry() to the
// underscore-separated Codex server name while leaving the rest of the entry
// (command/args/envFile) identical to entry() — Codex TOML config uses
// "armis_knowledge", not the JSON editors' hyphenated "armis-knowledge".
func TestKnowledgeCodexEntryUsesUnderscoreName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "knowledge")
	ki := &KnowledgeMCPInstaller{env: KnowledgeEnvStage, pluginDir: dir}

	e := ki.codexEntry()
	if e.name != "armis_knowledge_stage" {
		t.Errorf("codexEntry name = %q, want armis_knowledge_stage", e.name)
	}
	if e.command != venvPython(ki.EnvDir()) {
		t.Errorf("codexEntry command = %q, want %q", e.command, venvPython(ki.EnvDir()))
	}
	wantArg := filepath.Join(ki.EnvDir(), "bridge.py")
	if len(e.args) != 1 || e.args[0] != wantArg {
		t.Errorf("codexEntry args = %v, want [%q]", e.args, wantArg)
	}
}

func TestKnowledgeRegisterEditorWritesBridgeEntry(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "mcp.json")
	configPathOverrides = map[EditorID]string{EditorCursor: configFile}
	t.Cleanup(func() { configPathOverrides = nil })

	dir := filepath.Join(t.TempDir(), "knowledge")
	ki := &KnowledgeMCPInstaller{env: KnowledgeEnvProd, pluginDir: dir}

	e, ok := EditorByID(EditorCursor)
	if !ok {
		t.Fatal("cursor editor not found")
	}
	if err := ki.RegisterEditor(e); err != nil {
		t.Fatalf("RegisterEditor() error: %v", err)
	}

	b, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	servers, ok := data["mcpServers"].(map[string]interface{})
	if !ok || servers["armis-knowledge"] == nil {
		t.Fatalf("armis-knowledge entry missing, got: %s", b)
	}
}

func TestKnowledgeRegisterClaudeWritesDirectoryMarketplace(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "knowledge")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	ki := &KnowledgeMCPInstaller{
		env:       KnowledgeEnvProd,
		pluginDir: dir,
		claudeDir: claudeDir,
	}

	if err := ki.RegisterClaude(); err != nil {
		t.Fatalf("RegisterClaude() error: %v", err)
	}

	readJSON := func(name string) map[string]interface{} {
		t.Helper()
		b, err := os.ReadFile(filepath.Clean(filepath.Join(claudeDir, "plugins", name)))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s is not valid JSON: %v", name, err)
		}
		return m
	}

	mkts := readJSON("known_marketplaces.json")
	entry, ok := mkts["armis-knowledge"].(map[string]interface{})
	if !ok {
		t.Fatalf("knowledge marketplace not registered, got: %v", mkts)
	}
	src, ok := entry["source"].(map[string]interface{})
	if !ok || src["source"] != "directory" {
		t.Errorf("expected a directory source, got: %v", entry["source"])
	}
	// The path must point at the extracted plugin so Claude Code reads its
	// .claude-plugin/plugin.json and loads the bundled skills.
	if src["path"] != dir {
		t.Errorf("marketplace path = %v, want %q", src["path"], dir)
	}

	installed := readJSON("installed_plugins.json")
	plugins, ok := installed["plugins"].(map[string]interface{})
	if !ok || plugins["armis-knowledge@armis-knowledge"] == nil {
		t.Errorf("plugin not recorded in installed_plugins.json, got: %v", installed)
	}

	sb, err := os.ReadFile(filepath.Clean(filepath.Join(claudeDir, "settings.json")))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(sb, &settings); err != nil {
		t.Fatal(err)
	}
	enabled, ok := settings["enabledPlugins"].(map[string]interface{})
	if !ok || enabled["armis-knowledge@armis-knowledge"] != true {
		t.Errorf("plugin not enabled, got: %v", settings["enabledPlugins"])
	}
}

// TestKnowledgeRegisterClaudePreservesScannerEntries guards the read-modify-write
// contract that registerDirectoryMarketplace/registerInstalledPlugin/
// enableInstalledPlugin (shared by ClaudeInstaller and KnowledgeMCPInstaller)
// must uphold: registering the knowledge plugin must never unregister the
// scanner plugin that got there first, and vice versa. Both installers write
// into the same three files, so this is the coexistence contract that keeps
// `armis-cli install` and `armis-cli install knowledge` from stepping on each
// other. If a future edit replaces the read-then-merge with an unconditional
// map assignment, this test is what catches it.
func TestKnowledgeRegisterClaudePreservesScannerEntries(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	pluginsDir := filepath.Join(claudeDir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o750); err != nil {
		t.Fatal(err)
	}

	scannerPluginDir := filepath.Join(home, "scanner-plugin")
	scannerKey := pluginName + "@" + marketplaceName

	// Pre-populate all three registry files with a scanner entry, as if
	// `armis-cli install` (ClaudeInstaller) had already run.
	marketplaces := map[string]interface{}{
		marketplaceName: map[string]interface{}{
			"source":          map[string]interface{}{"source": "directory", "path": scannerPluginDir},
			"installLocation": scannerPluginDir,
			"lastUpdated":     "2025-01-01T00:00:00.000Z",
		},
	}
	if err := writeJSON(filepath.Join(pluginsDir, "known_marketplaces.json"), marketplaces); err != nil {
		t.Fatal(err)
	}

	installed := map[string]interface{}{
		jsonKeyVersion: 2,
		"plugins": map[string]interface{}{
			scannerKey: []interface{}{
				map[string]interface{}{
					"scope":       "user",
					"installPath": scannerPluginDir,
					"version":     "1.2.3",
					"installedAt": "2025-01-01T00:00:00.000Z",
					"lastUpdated": "2025-01-01T00:00:00.000Z",
				},
			},
		},
	}
	if err := writeJSON(filepath.Join(pluginsDir, "installed_plugins.json"), installed); err != nil {
		t.Fatal(err)
	}

	settings := map[string]interface{}{
		"enabledPlugins": map[string]interface{}{
			scannerKey: true,
		},
	}
	if err := writeJSON(filepath.Join(claudeDir, "settings.json"), settings); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "knowledge")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	ki := &KnowledgeMCPInstaller{
		env:       KnowledgeEnvProd,
		pluginDir: dir,
		claudeDir: claudeDir,
	}

	if err := ki.RegisterClaude(); err != nil {
		t.Fatalf("RegisterClaude() error: %v", err)
	}

	readJSON := func(name string) map[string]interface{} {
		t.Helper()
		b, err := os.ReadFile(filepath.Clean(filepath.Join(claudeDir, "plugins", name)))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		var m map[string]interface{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s is not valid JSON: %v", name, err)
		}
		return m
	}

	mkts := readJSON("known_marketplaces.json")
	if _, ok := mkts[marketplaceName]; !ok {
		t.Errorf("scanner marketplace %q was lost, got: %v", marketplaceName, mkts)
	}
	if _, ok := mkts["armis-knowledge"]; !ok {
		t.Errorf("knowledge marketplace not registered, got: %v", mkts)
	}

	installedAfter := readJSON("installed_plugins.json")
	plugins, ok := installedAfter["plugins"].(map[string]interface{})
	if !ok {
		t.Fatalf("plugins key missing or wrong type, got: %v", installedAfter)
	}
	if plugins[scannerKey] == nil {
		t.Errorf("scanner plugin entry %q was lost, got: %v", scannerKey, plugins)
	}
	if plugins["armis-knowledge@armis-knowledge"] == nil {
		t.Errorf("knowledge plugin not recorded, got: %v", plugins)
	}

	sb, err := os.ReadFile(filepath.Clean(filepath.Join(claudeDir, "settings.json")))
	if err != nil {
		t.Fatal(err)
	}
	var settingsAfter map[string]interface{}
	if err := json.Unmarshal(sb, &settingsAfter); err != nil {
		t.Fatal(err)
	}
	enabled, ok := settingsAfter["enabledPlugins"].(map[string]interface{})
	if !ok {
		t.Fatalf("enabledPlugins missing or wrong type, got: %v", settingsAfter)
	}
	if enabled[scannerKey] != true {
		t.Errorf("scanner plugin was disabled, got: %v", enabled)
	}
	if enabled["armis-knowledge@armis-knowledge"] != true {
		t.Errorf("knowledge plugin not enabled, got: %v", enabled)
	}
}

func TestKnowledgeRegisterCodexAddsSection(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	codexConfigPathOverride = configPath
	t.Cleanup(func() { codexConfigPathOverride = "" })

	dir := filepath.Join(t.TempDir(), "knowledge")
	ki := &KnowledgeMCPInstaller{env: KnowledgeEnvProd, pluginDir: dir}

	if err := ki.RegisterCodex(); err != nil {
		t.Fatalf("RegisterCodex() error: %v", err)
	}

	b, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if !testutil.ContainsSubstring(string(b), "[mcp_servers.armis_knowledge]") {
		t.Errorf("expected armis_knowledge section, got:\n%s", b)
	}
}
