package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustReadYAML(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := readYAMLFileAsMap(path)
	if err != nil {
		t.Fatalf("readYAMLFileAsMap(%s) error: %v", path, err)
	}
	return data
}

// isolateHome points HOME at a throwaway directory so nothing a test registers
// can reach the developer's real editor configs.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

func overrideConfigPaths(t *testing.T, paths map[EditorID]string) {
	t.Helper()
	configPathOverrides = paths
	t.Cleanup(func() { configPathOverrides = nil })
}

// configKind describes one config format and the content used to seed it.
type configKind struct {
	id       EditorID
	file     string
	yaml     bool
	valid    string // parseable, contains an "other" server that must survive
	jsonc    string // same server, written with comments and trailing commas
	invalid  string
	otherKey string // top-level key that holds the "other" server
}

var configKinds = []configKind{
	{
		id: EditorCursor, file: "mcp.json", otherKey: "mcpServers",
		valid:   `{"mcpServers": {"other": {"command": "node"}}, "theme": "dark"}`,
		jsonc:   "\xEF\xBB\xBF{\n  // my servers\n  \"mcpServers\": {\n    /* keep */ \"other\": {\"command\": \"node\",},\n  },\n}\n",
		invalid: `{"mcpServers": {"other": {"command": "node"},, }`,
	},
	{
		id: EditorVSCode, file: "mcp.json", otherKey: "servers",
		valid:   `{"servers": {"other": {"command": "node"}}}`,
		jsonc:   "{\n  // my servers\n  \"servers\": {\n    \"other\": {\"command\": \"node\",},\n  },\n}\n",
		invalid: `{"servers": {"other": `,
	},
	{
		id: EditorZed, file: "settings.json", otherKey: "context_servers",
		valid:   `{"context_servers": {"other": {"command": {"path": "node"}}}}`,
		jsonc:   "{\n  // zed\n  \"context_servers\": {\n    \"other\": {\"command\": {\"path\": \"node\"},},\n  },\n}\n",
		invalid: `{"context_servers": nope}`,
	},
	{
		id: EditorContinue, file: "config.yaml", yaml: true, otherKey: "mcpServers",
		valid:   "name: mine\nmcpServers:\n  - name: other\n    command: node\n",
		invalid: "mcpServers: [unclosed\n  - : :\n",
	},
}

// hasOtherServer reports whether the "other" server is still in the config.
func hasOtherServer(t *testing.T, k configKind, path string) bool {
	t.Helper()
	if k.yaml {
		list, _ := mustReadYAML(t, path)[k.otherKey].([]interface{})
		for _, s := range list {
			if m, ok := s.(map[string]interface{}); ok && m["name"] == "other" {
				return true
			}
		}
		return false
	}
	servers, _ := mustReadJSON(t, path)[k.otherKey].(map[string]interface{})
	_, ok := servers["other"]
	return ok
}

func hasArmisServer(t *testing.T, k configKind, path string) bool {
	t.Helper()
	has, err := hasArmisEntry(k.id, path)
	if err != nil {
		t.Fatalf("hasArmisEntry(%s) error: %v", path, err)
	}
	return has
}

// unusableConfigs are files that exist but that registration must never
// replace. setup returns the bytes to compare afterwards, or nil when the
// path is not a regular file.
var unusableConfigs = []struct {
	name  string
	setup func(t *testing.T, k configKind, path string) []byte
}{
	{"invalid syntax", func(t *testing.T, k configKind, path string) []byte {
		mustWrite(t, path, k.invalid)
		return []byte(k.invalid)
	}},
	{"top-level array", func(t *testing.T, k configKind, path string) []byte {
		content := "[1, 2, 3]"
		mustWrite(t, path, content)
		return []byte(content)
	}},
	{"oversized", func(t *testing.T, k configKind, path string) []byte {
		var content string
		if k.yaml {
			content = "pad: " + strings.Repeat("a", maxEditorConfigSize+1) + "\n"
		} else {
			content = `{"pad": "` + strings.Repeat("a", maxEditorConfigSize+1) + `"}`
		}
		mustWrite(t, path, content)
		return []byte(content)
	}},
	{"directory", func(t *testing.T, k configKind, path string) []byte {
		if err := os.MkdirAll(filepath.Join(path, "child"), 0o750); err != nil {
			t.Fatal(err)
		}
		return nil
	}},
}

func snapshotDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func assertRefusal(t *testing.T, err error, path string) {
	t.Helper()
	if err == nil {
		t.Fatal("registration succeeded, want a refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, path) {
		t.Errorf("error %q does not name the file %s", msg, path)
	}
	if !strings.Contains(msg, "fix or remove it") {
		t.Errorf("error %q does not tell the user to fix or remove the file", msg)
	}
}

func assertUntouched(t *testing.T, path string, want []byte, dirBefore []string) {
	t.Helper()
	if want != nil {
		got, err := os.ReadFile(path) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s was modified (%d bytes, want %d)", path, len(got), len(want))
		}
	} else if info, err := os.Stat(path); err != nil || info.Mode().IsRegular() {
		t.Errorf("%s was replaced by a regular file (stat err %v)", path, err)
	}
	if after := snapshotDir(t, filepath.Dir(path)); strings.Join(after, ",") != strings.Join(dirBefore, ",") {
		t.Errorf("directory contents changed: before %v, after %v", dirBefore, after)
	}
}

func TestRegisterRefusesUnusableConfig(t *testing.T) {
	for _, k := range configKinds {
		for _, tc := range unusableConfigs {
			t.Run(string(k.id)+"/"+tc.name, func(t *testing.T) {
				isolateHome(t)
				path := filepath.Join(t.TempDir(), k.file)
				want := tc.setup(t, k, path)
				before := snapshotDir(t, filepath.Dir(path))
				overrideConfigPaths(t, map[EditorID]string{k.id: path})

				e, _ := EditorByID(k.id)
				err := e.Register(filepath.Join(t.TempDir(), "plugin"))

				assertRefusal(t, err, path)
				assertUntouched(t, path, want, before)
			})
		}
	}
}

func TestRegisterAcceptsUsableConfig(t *testing.T) {
	cases := []struct {
		name      string
		seed      func(k configKind) *string // nil means the file does not exist
		wantOther bool
	}{
		{"missing file is created", func(configKind) *string { return nil }, false},
		{"empty file", func(configKind) *string { s := ""; return &s }, false},
		{"valid config keeps other servers", func(k configKind) *string { return &k.valid }, true},
		{"jsonc comments and trailing commas", func(k configKind) *string {
			if k.yaml {
				return &k.valid
			}
			return &k.jsonc
		}, true},
	}
	for _, k := range configKinds {
		for _, tc := range cases {
			t.Run(string(k.id)+"/"+tc.name, func(t *testing.T) {
				isolateHome(t)
				path := filepath.Join(t.TempDir(), "nested", k.file)
				if seed := tc.seed(k); seed != nil {
					mustWrite(t, path, *seed)
				}
				overrideConfigPaths(t, map[EditorID]string{k.id: path})

				e, _ := EditorByID(k.id)
				if err := e.Register(filepath.Join(t.TempDir(), "plugin")); err != nil {
					t.Fatalf("Register() error: %v", err)
				}

				if !hasArmisServer(t, k, path) {
					t.Error("armis-appsec was not registered")
				}
				if got := hasOtherServer(t, k, path); got != tc.wantOther {
					t.Errorf("other server present = %v, want %v", got, tc.wantOther)
				}
				for _, name := range snapshotDir(t, filepath.Dir(path)) {
					if name != k.file {
						t.Errorf("stray file %q left next to the config", name)
					}
				}
			})
		}
	}
}

func TestRegisterKeepsUnrelatedSettings(t *testing.T) {
	isolateHome(t)
	path := filepath.Join(t.TempDir(), "mcp.json")
	mustWrite(t, path, `{"mcpServers": {"other": {"command": "node"}}, "theme": "dark"}`)
	overrideConfigPaths(t, map[EditorID]string{EditorCursor: path})

	e, _ := EditorByID(EditorCursor)
	if err := e.Register(t.TempDir()); err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if got := mustReadJSON(t, path)["theme"]; got != "dark" {
		t.Errorf("theme = %v, want dark", got)
	}
}

// TestInstallContinuesPastBadConfig mirrors the install loop: each editor is
// registered independently and a refusal affects only its own client.
func TestInstallContinuesPastBadConfig(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	paths := map[EditorID]string{
		EditorCursor:   filepath.Join(root, "cursor", "mcp.json"),
		EditorWindsurf: filepath.Join(root, "windsurf", "mcp_config.json"),
		EditorVSCode:   filepath.Join(root, "vscode", "mcp.json"),
		EditorContinue: filepath.Join(root, "continue", "config.yaml"),
		EditorZed:      filepath.Join(root, "zed", "settings.json"),
	}
	badCursor := `{"mcpServers": {"keep-me": {"command": "node"},}` // truncated
	mustWrite(t, paths[EditorCursor], badCursor)
	mustWrite(t, paths[EditorVSCode], "{\n // comment\n \"servers\": {\"other\": {\"command\": \"node\"},},\n}")
	mustWrite(t, paths[EditorContinue], "mcpServers: [unclosed\n")
	overrideConfigPaths(t, paths)

	pluginDir := filepath.Join(root, "plugin")
	failed := map[EditorID]error{}
	registered := map[EditorID]bool{}
	for _, id := range []EditorID{EditorCursor, EditorWindsurf, EditorVSCode, EditorContinue, EditorZed} {
		e, _ := EditorByID(id)
		if err := e.Register(pluginDir); err != nil {
			failed[id] = err
		} else {
			registered[id] = true
		}
	}

	if len(failed) != 2 || failed[EditorCursor] == nil || failed[EditorContinue] == nil {
		t.Fatalf("failed = %v, want exactly cursor and continue", failed)
	}
	assertRefusal(t, failed[EditorCursor], paths[EditorCursor])
	assertRefusal(t, failed[EditorContinue], paths[EditorContinue])
	for _, id := range []EditorID{EditorWindsurf, EditorVSCode, EditorZed} {
		if !registered[id] {
			t.Errorf("%s was not registered", id)
		}
	}
	got, _ := os.ReadFile(paths[EditorCursor]) //nolint:gosec // test temp dir
	if string(got) != badCursor {
		t.Errorf("cursor config was modified: %q", got)
	}
	if !hasOtherServer(t, configKinds[1], paths[EditorVSCode]) {
		t.Error("VS Code lost its existing server")
	}
}

func TestDeregisterRefusesUnparseableConfig(t *testing.T) {
	for _, k := range configKinds {
		t.Run(string(k.id), func(t *testing.T) {
			isolateHome(t)
			path := filepath.Join(t.TempDir(), k.file)
			mustWrite(t, path, k.invalid)
			before := snapshotDir(t, filepath.Dir(path))
			overrideConfigPaths(t, map[EditorID]string{k.id: path})

			u := &Uninstaller{pluginDir: t.TempDir()}
			err := u.DeregisterEditor(k.id)
			if err == nil {
				t.Fatal("DeregisterEditor() succeeded on an unparseable file")
			}
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "cannot read") {
				t.Errorf("error %q should say the file could not be read and name %s", err, path)
			}
			assertUntouched(t, path, []byte(k.invalid), before)
		})
	}
}

func TestDeregisterAllEditorsReportsUnparseableConfig(t *testing.T) {
	for _, withManifest := range []bool{false, true} {
		name := "scan path"
		if withManifest {
			name = "manifest path"
		}
		t.Run(name, func(t *testing.T) {
			isolateHome(t)
			root := t.TempDir()
			paths := map[EditorID]string{
				EditorCursor:   filepath.Join(root, "cursor", "mcp.json"),
				EditorContinue: filepath.Join(root, "continue", "config.yaml"),
				EditorWindsurf: filepath.Join(root, "windsurf", "mcp_config.json"),
			}
			badJSON := `{"mcpServers": {"armis-appsec": {"command": "x"},,}`
			badYAML := "mcpServers: [unclosed\n"
			mustWrite(t, paths[EditorCursor], badJSON)
			mustWrite(t, paths[EditorContinue], badYAML)
			overrideConfigPaths(t, paths)

			windsurf, _ := EditorByID(EditorWindsurf)
			if err := windsurf.Register(filepath.Join(root, "plugin")); err != nil {
				t.Fatal(err)
			}

			u := &Uninstaller{pluginDir: filepath.Join(root, "plugin")}
			if withManifest {
				m := NewManifest(u.pluginDir, "1.0.0")
				for id, p := range paths {
					m.AddEditor(id, p, ConfigFormat(id))
				}
				u.manifest = m
			}

			deregistered, warnings := u.DeregisterAllEditors()

			if len(deregistered) != 1 || deregistered[0] != windsurf.Name {
				t.Errorf("deregistered = %v, want only %s", deregistered, windsurf.Name)
			}
			for _, id := range []EditorID{EditorCursor, EditorContinue} {
				found := false
				for _, w := range warnings {
					if strings.Contains(w, paths[id]) && strings.Contains(w, "cannot read") {
						found = true
					}
				}
				if !found {
					t.Errorf("no warning naming %s in %v", paths[id], warnings)
				}
			}
			for id, want := range map[EditorID]string{EditorCursor: badJSON, EditorContinue: badYAML} {
				got, _ := os.ReadFile(paths[id]) //nolint:gosec // test temp dir
				if string(got) != want {
					t.Errorf("%s was modified: %q", id, got)
				}
			}
		})
	}
}

func TestDeregisterHandlesJSONCConfig(t *testing.T) {
	isolateHome(t)
	path := filepath.Join(t.TempDir(), "mcp.json")
	mustWrite(t, path, "{\n // mine\n \"mcpServers\": {\"armis-appsec\": {\"command\": \"x\"}, \"other\": {\"command\": \"node\",},},\n}")
	overrideConfigPaths(t, map[EditorID]string{EditorCursor: path})

	u := &Uninstaller{pluginDir: t.TempDir()}
	if err := u.DeregisterEditor(EditorCursor); err != nil {
		t.Fatalf("DeregisterEditor() error: %v", err)
	}
	servers, _ := mustReadJSON(t, path)["mcpServers"].(map[string]interface{})
	if _, ok := servers["armis-appsec"]; ok {
		t.Error("armis-appsec survived uninstall")
	}
	if _, ok := servers["other"]; !ok {
		t.Error("uninstall dropped the other server")
	}
}

func TestReadersTreatMissingAndEmptyAsEmpty(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	mustWrite(t, empty, "  \n")
	null := filepath.Join(dir, "null")
	mustWrite(t, null, "null")

	for _, path := range []string{filepath.Join(dir, "missing"), empty, null} {
		if got, err := readJSONFileAsMap(path); err != nil || got == nil || len(got) != 0 {
			t.Errorf("readJSONFileAsMap(%s) = %v, %v; want empty map, nil", path, got, err)
		}
		if got, err := readYAMLFileAsMap(path); err != nil || got == nil || len(got) != 0 {
			t.Errorf("readYAMLFileAsMap(%s) = %v, %v; want empty map, nil", path, got, err)
		}
	}
}

func TestClaudeRegistryHelpersRefuseInvalidJSON(t *testing.T) {
	helpers := []struct {
		name string
		file string
		call func(claudeDir string) error
	}{
		{"marketplace", filepath.Join("plugins", "known_marketplaces.json"), func(d string) error {
			return registerDirectoryMarketplace(d, "m", "/plugin")
		}},
		{"installed plugins", filepath.Join("plugins", "installed_plugins.json"), func(d string) error {
			return registerInstalledPlugin(d, "p@m", "/plugin", "1.0.0")
		}},
		{"settings", "settings.json", func(d string) error {
			return enableInstalledPlugin(d, "p@m")
		}},
	}
	for _, h := range helpers {
		t.Run(h.name, func(t *testing.T) {
			claudeDir := t.TempDir()
			path := filepath.Join(claudeDir, h.file)
			bad := `{"enabledPlugins": {"mine@x": true},`
			mustWrite(t, path, bad)

			err := h.call(claudeDir)

			assertRefusal(t, err, path)
			assertUntouched(t, path, []byte(bad), snapshotDir(t, filepath.Dir(path)))
		})
	}
}

func TestClaudeSettingsJSONCIsPreserved(t *testing.T) {
	claudeDir := t.TempDir()
	path := filepath.Join(claudeDir, "settings.json")
	mustWrite(t, path, "{\n // mine\n \"model\": \"opus\",\n}")

	if err := enableInstalledPlugin(claudeDir, "p@m"); err != nil {
		t.Fatalf("enableInstalledPlugin() error: %v", err)
	}
	data := mustReadJSON(t, path)
	if data["model"] != "opus" {
		t.Errorf("model = %v, want opus", data["model"])
	}
	enabled, _ := data["enabledPlugins"].(map[string]interface{})
	if enabled["p@m"] != true {
		t.Errorf("enabledPlugins = %v, want p@m enabled", enabled)
	}
}

func TestCodexRegisterRefusesUnusableConfig(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	if err := os.MkdirAll(filepath.Join(configFile, "child"), 0o750); err != nil {
		t.Fatal(err)
	}
	codexConfigPathOverride = configFile
	t.Cleanup(func() { codexConfigPathOverride = "" })

	err := RegisterCodexEntry(mcpEntry{name: codexMCPServerName, command: filepath.Join(dir, "python")})

	assertRefusal(t, err, configFile)
	if info, statErr := os.Stat(configFile); statErr != nil || !info.IsDir() {
		t.Errorf("config path was replaced (stat err %v)", statErr)
	}
}

func TestAtomicWritesFollowSymlinkAndLeaveNoTempFiles(t *testing.T) {
	writers := []struct {
		name  string
		write func(path string) error
		check func(t *testing.T, path string)
	}{
		{"yaml", func(p string) error { return writeYAML(p, map[string]interface{}{"a": 1}) }, func(t *testing.T, p string) {
			if mustReadYAML(t, p)["a"] != 1 {
				t.Error("yaml content not written to the symlink target")
			}
		}},
		{"json", func(p string) error { return writeJSON(p, map[string]interface{}{"a": 1}) }, func(t *testing.T, p string) {
			var got map[string]interface{}
			b, _ := os.ReadFile(p) //nolint:gosec // test temp dir
			if err := json.Unmarshal(b, &got); err != nil || got["a"] != float64(1) {
				t.Errorf("json content = %q (%v)", b, err)
			}
		}},
	}
	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "real", "config")
			mustWrite(t, target, "old")
			link := filepath.Join(dir, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}

			if err := w.write(link); err != nil {
				t.Fatalf("write error: %v", err)
			}

			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Errorf("symlink was replaced by a regular file (err %v)", err)
			}
			w.check(t, target)
			if names := snapshotDir(t, filepath.Dir(target)); len(names) != 1 {
				t.Errorf("temp files left behind: %v", names)
			}
		})
	}
}

func TestDoctorOffersFixForConfigsRegistrationAccepts(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	mustWrite(t, empty, "")
	null := filepath.Join(dir, "null.json")
	mustWrite(t, null, "null")
	emptyYAML := filepath.Join(dir, "config.yaml")
	mustWrite(t, emptyYAML, "")

	editors := map[EditorID]ManifestEntry{
		EditorCursor:   {ConfigFile: empty, Format: "mcpServers"},
		EditorWindsurf: {ConfigFile: null, Format: "mcpServers"},
		EditorContinue: {ConfigFile: emptyYAML, Format: configFormatContinue},
	}
	d := newDoctorRun(DoctorOptions{})
	checkManifestEditors(d, "scanner", "armis-appsec", editors)

	for _, c := range d.report.Checks {
		if c.Fix != FixReregister {
			t.Errorf("%s: fix = %q (%s), want %q since registration accepts this file", c.Name, c.Fix, c.Detail, FixReregister)
		}
	}
	if d.report.HasBlockedRegistration() {
		t.Error("HasBlockedRegistration() = true for configs registration can rewrite")
	}
}

func TestDoctorBlocksFixForUnreadableCodexConfig(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.toml")
	if err := os.MkdirAll(configFile, 0o750); err != nil {
		t.Fatal(err)
	}
	report := &DoctorReport{}
	checkCodexSection(report, "scanner", &ManifestCodex{ConfigFile: configFile}, codexMCPServerName)

	if len(report.Checks) != 1 || report.Checks[0].Fix != FixBlocked {
		t.Fatalf("checks = %+v, want one FixBlocked check", report.Checks)
	}
}

func TestClaudeInstallRefusesBeforeWritingAnyRegistryFile(t *testing.T) {
	claudeDir := t.TempDir()
	settings := filepath.Join(claudeDir, "settings.json")
	bad := `{"model": "opus",`
	mustWrite(t, settings, bad)

	before := snapshotDir(t, claudeDir)

	ci := &ClaudeInstaller{claudeDir: claudeDir, plugin: newPluginInstaller()}
	err := ci.Install()

	assertRefusal(t, err, settings)
	assertUntouched(t, settings, []byte(bad), before)
	if _, statErr := os.Stat(filepath.Join(claudeDir, "plugins")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("plugins dir was created before the refusal (stat err %v)", statErr)
	}
}
