package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

// pinnedInstallHome returns a temp HOME whose shared plugin is already at the
// pinned version, with a stub Python on PATH, so installTargets registers
// editors without touching the network.
func pinnedInstallHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell-script python stub")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(install.EnvMCPVersion, "")

	bin := t.TempDir()
	stub := filepath.Join(bin, "python3.12")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho True\n"), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".installed-version"), []byte("1.4.2"), 0o600); err != nil {
		t.Fatal(err)
	}
	hooksDir := filepath.Join(pluginDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, c := range install.AllHookClients {
		if err := os.WriteFile(filepath.Join(hooksDir, c.AdapterPy), []byte("# stub\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := install.SetVersionPin("1.4.2"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = install.SetVersionPin("") })
	return home
}

func TestInstallTargetsReportsFailedTargets(t *testing.T) {
	home := pinnedInstallHome(t)

	// A directory where cursor's mcp.json should be makes only that write fail.
	if err := os.MkdirAll(filepath.Join(home, ".cursor", "mcp.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o750); err != nil {
		t.Fatal(err)
	}

	err := installTargets([]string{"cursor", "copilot"}, installOptions{})
	if err == nil {
		t.Fatal("expected an error when a target fails")
	}
	if !strings.Contains(err.Error(), "Cursor") {
		t.Errorf("error should name the failed target, got: %v", err)
	}
	if strings.Contains(err.Error(), "Copilot CLI") {
		t.Errorf("error should not name the target that succeeded, got: %v", err)
	}

	b, readErr := os.ReadFile(filepath.Join(home, ".copilot", "mcp-config.json")) //nolint:gosec // test path
	if readErr != nil {
		t.Fatalf("the healthy target should still be registered: %v", readErr)
	}
	if !strings.Contains(string(b), "armis-appsec") {
		t.Errorf("copilot config missing the armis-appsec server: %s", b)
	}
}

func TestInstallTargetsSucceedsWhenAllTargetsWork(t *testing.T) {
	home := pinnedInstallHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := installTargets([]string{"copilot"}, installOptions{}); err != nil {
		t.Fatalf("installTargets() = %v, want nil", err)
	}
}

func TestInstallJetBrainsProjectMergesConfig(t *testing.T) {
	home := pinnedInstallHome(t)
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(project, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(project, ".jb-mcp.json")
	if err := os.WriteFile(cfg, []byte(`{"mcpServers":{"other":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := installTargets([]string{"jetbrains"}, installOptions{jetbrainsProject: project}); err != nil {
		t.Fatalf("installTargets() = %v", err)
	}

	b, err := os.ReadFile(cfg) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("config is not valid JSON: %v\n%s", err, b)
	}
	if _, ok := got.MCPServers["other"]; !ok {
		t.Error("existing server was dropped")
	}
	if _, ok := got.MCPServers["armis-appsec"]; !ok {
		t.Error("armis-appsec server not written")
	}
}

func TestInstallJetBrainsProjectMustBeDirectory(t *testing.T) {
	home := pinnedInstallHome(t)
	err := installTargets([]string{"jetbrains"}, installOptions{jetbrainsProject: filepath.Join(home, "missing")})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("got %v, want a not-a-directory error", err)
	}
}

func TestInstallHasPluginVersionAndProjectFlags(t *testing.T) {
	for _, name := range []string{"plugin-version", "project"} {
		if installCmd.Flags().Lookup(name) == nil {
			t.Errorf("install command is missing --%s", name)
		}
	}
}

func TestMCPUpdateKeepsStoredPin(t *testing.T) {
	home := pinnedInstallHome(t)
	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")

	// Persist the pin, then run as a later invocation that requests nothing.
	if err := install.WriteManifest(install.NewManifest(pluginDir, "1.4.2")); err != nil {
		t.Fatal(err)
	}
	if err := install.SetVersionPin(""); err != nil {
		t.Fatal(err)
	}

	if err := performMCPUpdate(false, false); err != nil {
		t.Fatalf("performMCPUpdate() = %v", err)
	}
	m := install.ReadManifest(pluginDir)
	if m == nil || m.PinnedVersion != "1.4.2" || m.PluginVersion != "1.4.2" {
		t.Errorf("manifest after update = %+v, want pin and version 1.4.2", m)
	}
}

func TestJetBrainsConfigPathRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".jb-mcp.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := jetbrainsConfigPath(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("got %v, want a refusal for a symlinked .jb-mcp.json", err)
	}
	if got, err := jetbrainsConfigPath(t.TempDir()); err != nil || !strings.HasSuffix(got, ".jb-mcp.json") {
		t.Errorf("plain directory: got %q, %v", got, err)
	}
}

func TestInstallTargetsJSONReportsPinnedVersionAndFailures(t *testing.T) {
	home := pinnedInstallHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".cursor", "mcp.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o750); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	var err error
	captureStderr(t, func() {
		err = installTargets([]string{"cursor", "copilot"}, installOptions{format: formatJSON, stdout: &out})
	})
	if err == nil || !strings.Contains(err.Error(), "Cursor") || strings.Contains(err.Error(), "Copilot CLI") {
		t.Fatalf("err = %v, want it to name only Cursor", err)
	}

	doc := decodeReport(t, []byte(out.String()))
	plugin, _ := doc["plugin"].(map[string]interface{})
	if plugin["version"] != "1.4.2" || plugin["pinned"] != true || plugin["already_current"] != true {
		t.Errorf("plugin = %v, want pinned version 1.4.2 already current", plugin)
	}
	if got := clientByID(t, doc, "cursor")["status"]; got != "fail" {
		t.Errorf("cursor status = %v, want fail", got)
	}
	if got := clientByID(t, doc, "copilot")["status"]; got != "ok" {
		t.Errorf("copilot status = %v, want ok", got)
	}
	if msg, _ := doc["error"].(string); !strings.Contains(msg, "install failed for: Cursor") {
		t.Errorf("error field = %q", msg)
	}
}

func TestInstallJetBrainsProjectJSON(t *testing.T) {
	home := pinnedInstallHome(t)
	project := filepath.Join(home, "repo")
	if err := os.MkdirAll(project, 0o750); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	var err error
	captureStderr(t, func() {
		err = installTargets([]string{"jetbrains"}, installOptions{jetbrainsProject: project, format: formatJSON, stdout: &out})
	})
	if err != nil {
		t.Fatalf("installTargets() = %v", err)
	}
	doc := decodeReport(t, []byte(out.String()))
	jb := clientByID(t, doc, "jetbrains")
	files, _ := jb["files"].([]interface{})
	if jb["status"] != "ok" || len(files) != 1 || !strings.HasSuffix(files[0].(string), ".jb-mcp.json") {
		t.Errorf("jetbrains = %v", jb)
	}
}
