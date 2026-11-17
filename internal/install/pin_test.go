package install

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolatePin(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(EnvMCPVersion, "")
	if err := SetVersionPin(""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetVersionPin("") })
	return filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
}

func TestNormalizePin(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"latest", "latest", false},
		{"1.4.2", "1.4.2", false},
		{"v1.4.2", "1.4.2", false},
		{" v1.4.2-rc.1 ", "1.4.2-rc.1", false},
		{"1.4", "", true},
		{"1.4.2/../x", "", true},
		{"v1.4.2 && id", "", true},
		{"main", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizePin(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizePin(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("NormalizePin(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEffectivePinPrecedence(t *testing.T) {
	pluginDir := isolatePin(t)
	m := NewManifest(pluginDir, "1.0.0")
	m.PinnedVersion = "1.1.0"
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}

	if got := EffectivePin(); got != "1.1.0" {
		t.Errorf("manifest pin: got %q, want 1.1.0", got)
	}

	t.Setenv(EnvMCPVersion, "v1.2.0")
	if got := EffectivePin(); got != "1.2.0" {
		t.Errorf("env over manifest: got %q, want 1.2.0", got)
	}

	if err := SetVersionPin("1.3.0"); err != nil {
		t.Fatal(err)
	}
	if got := EffectivePin(); got != "1.3.0" {
		t.Errorf("flag over env: got %q, want 1.3.0", got)
	}

	if err := SetVersionPin("latest"); err != nil {
		t.Fatal(err)
	}
	if got := EffectivePin(); got != "" {
		t.Errorf("latest clears the pin: got %q, want empty", got)
	}
}

func TestSetVersionPinRejectsInvalid(t *testing.T) {
	isolatePin(t)
	if err := SetVersionPin("not-a-version"); err == nil {
		t.Fatal("expected error for an invalid version")
	}
}

func TestWriteManifestPersistsAndClearsPin(t *testing.T) {
	pluginDir := isolatePin(t)

	if err := SetVersionPin("1.4.2"); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(NewManifest(pluginDir, "1.4.2")); err != nil {
		t.Fatal(err)
	}
	if got := ReadManifest(pluginDir).PinnedVersion; got != "1.4.2" {
		t.Fatalf("persisted pin = %q, want 1.4.2", got)
	}

	// A later invocation that asks for nothing keeps the stored pin.
	if err := SetVersionPin(""); err != nil {
		t.Fatal(err)
	}
	m := ReadManifest(pluginDir)
	if err := WriteManifest(m); err != nil {
		t.Fatal(err)
	}
	if got := ReadManifest(pluginDir).PinnedVersion; got != "1.4.2" {
		t.Errorf("pin after plain rewrite = %q, want 1.4.2", got)
	}

	if err := SetVersionPin("latest"); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(ReadManifest(pluginDir)); err != nil {
		t.Fatal(err)
	}
	if got := ReadManifest(pluginDir).PinnedVersion; got != "" {
		t.Errorf("pin after latest = %q, want cleared", got)
	}
}

func TestPluginInstallerReleaseURL(t *testing.T) {
	isolatePin(t)

	if got := newPluginInstaller().releaseURL(); got != releasesURL {
		t.Errorf("unpinned URL = %q, want %q", got, releasesURL)
	}

	if err := SetVersionPin("v1.4.2"); err != nil {
		t.Fatal(err)
	}
	want := "https://api.github.com/repos/ArmisSecurity/armis-appsec-mcp/releases/tags/v1.4.2"
	if got := newPluginInstaller().releaseURL(); got != want {
		t.Errorf("pinned URL = %q, want %q", got, want)
	}
	if err := validateGitHubURL(want); err != nil {
		t.Errorf("tag URL fails validation: %v", err)
	}
}

func TestFetchPinnedReleaseNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	pi := &PluginInstaller{httpClient: server.Client(), releasesURL: server.URL, pin: "9.9.9", skipURLValidation: true}
	_, err := pi.fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for unknown pinned release")
	}
	if !strings.Contains(err.Error(), "v9.9.9") || !strings.Contains(err.Error(), "--plugin-version latest") {
		t.Errorf("error should name the version and the way out, got: %v", err)
	}
}

func TestPinnedLatestVersionNeedsNoNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("pinned LatestVersion must not call GitHub")
	}))
	defer server.Close()

	pi := &PluginInstaller{httpClient: server.Client(), releasesURL: server.URL, pin: "1.4.2", skipURLValidation: true}
	got, err := pi.LatestVersion()
	if err != nil || got != "1.4.2" {
		t.Errorf("LatestVersion() = %q, %v; want 1.4.2, nil", got, err)
	}
}

func TestFetchPluginAtPinSkipsNetworkAndRebuild(t *testing.T) {
	pluginDir := isolatePin(t)
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".installed-version"), []byte("1.4.2"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("an install already at the pin must not call GitHub")
	}))
	defer server.Close()

	ei := &EditorInstaller{
		pluginDir: pluginDir,
		plugin:    &PluginInstaller{httpClient: server.Client(), releasesURL: server.URL, pin: "1.4.2", skipURLValidation: true},
	}
	err := ei.FetchPlugin(false)
	if !errors.Is(err, ErrAlreadyCurrent) {
		t.Fatalf("FetchPlugin() = %v, want ErrAlreadyCurrent", err)
	}
	if got := ei.InstalledVersion(); got != "1.4.2" {
		t.Errorf("InstalledVersion() = %q, want 1.4.2", got)
	}
}

func TestClaudeInstallAtPinIsNoOp(t *testing.T) {
	isolatePin(t)
	claudeDir := filepath.Join(t.TempDir(), ".claude")
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a Claude install already at the pin must not call GitHub")
	}))
	defer server.Close()

	ci := &ClaudeInstaller{
		claudeDir: claudeDir,
		plugin:    &PluginInstaller{httpClient: server.Client(), releasesURL: server.URL, pin: "1.4.2", skipURLValidation: true},
	}
	if err := registerInstalledPlugin(claudeDir, pluginName+"@"+marketplaceName, ci.pluginCacheDir(), "1.4.2"); err != nil {
		t.Fatal(err)
	}
	py := venvPython(ci.pluginCacheDir())
	if err := os.MkdirAll(filepath.Dir(py), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(py, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	instFile := filepath.Join(claudeDir, "plugins", "installed_plugins.json")
	before, err := os.ReadFile(instFile) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}

	if !ci.alreadyAtPin() {
		t.Skip("venv interpreter is not recognised as executable on this platform")
	}
	if err := ci.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	after, err := os.ReadFile(instFile) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("installed_plugins.json changed on a no-op install:\nbefore: %s\nafter:  %s", before, after)
	}
	if got := ci.InstalledVersion(); got != "1.4.2" {
		t.Errorf("InstalledVersion() = %q, want 1.4.2", got)
	}

	ci.SetForce(true)
	if ci.alreadyAtPin() {
		t.Error("--force must bypass the no-op")
	}
}

func TestCheckPluginVersionPinned(t *testing.T) {
	isolatePin(t)
	stubGOOS(t, "linux")
	if err := SetVersionPin("1.4.2"); err != nil {
		t.Fatal(err)
	}

	t.Run("at pin is ok", func(t *testing.T) {
		d := &doctorRun{report: &DoctorReport{}}
		checkPluginVersion(d, "scanner", "1.4.2", "1.4.2")
		c := d.report.Checks[0]
		if c.Status != StatusOK || !strings.Contains(c.Detail, "pinned") {
			t.Errorf("got %s %q, want ok mentioning pinned", c.Status, c.Detail)
		}
	})

	t.Run("outside pin warns with reinstall", func(t *testing.T) {
		d := &doctorRun{report: &DoctorReport{}}
		checkPluginVersion(d, "scanner", "1.3.0", "1.4.2")
		c := d.report.Checks[0]
		if c.Status != StatusWarn || c.Fix != FixReinstall || !strings.Contains(c.Detail, "pinned to v1.4.2") {
			t.Errorf("got %s %q fix=%q", c.Status, c.Detail, c.Fix)
		}
	})
}
