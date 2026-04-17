package install

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewClaudeInstaller(t *testing.T) {
	ci := NewClaudeInstaller()
	if ci.claudeDir == "" {
		t.Fatal("claudeDir should not be empty")
	}
	if ci.httpClient == nil {
		t.Fatal("httpClient should not be nil")
	}
}

func TestPluginCacheDir(t *testing.T) {
	ci := &ClaudeInstaller{claudeDir: "/home/test/.claude"}
	got := ci.pluginCacheDir()
	want := "/home/test/.claude/plugins/cache/armis-appsec-mcp/armis-appsec/latest"
	if got != want {
		t.Errorf("pluginCacheDir() = %q, want %q", got, want)
	}
}

func TestHasExistingEnv(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir}

	if ci.HasExistingEnv() {
		t.Error("HasExistingEnv() should return false when .env doesn't exist")
	}

	pluginDir := ci.pluginCacheDir()
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".env"), []byte("TOKEN=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ci.HasExistingEnv() {
		t.Error("HasExistingEnv() should return true when .env exists")
	}
}

func TestFetchLatestRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v1.2.3","tarball_url":"https://api.github.com/repos/test/tarball/v1.2.3"}`)
	}))
	defer server.Close()

	ci := &ClaudeInstaller{
		httpClient:  server.Client(),
		releasesURL: server.URL,
	}

	release, err := ci.fetchLatestRelease()
	if err != nil {
		t.Fatalf("fetchLatestRelease() error: %v", err)
	}
	if release.TagName != "v1.2.3" {
		t.Errorf("TagName = %q, want %q", release.TagName, "v1.2.3")
	}
	if release.TarballURL == "" {
		t.Error("TarballURL should not be empty")
	}
}

func TestFetchLatestRelease_NoRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ci := &ClaudeInstaller{
		httpClient:  server.Client(),
		releasesURL: server.URL,
	}

	_, err := ci.fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestDownloadAndExtract(t *testing.T) {
	tarball := createTestTarball(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(tarball)
	}))
	defer server.Close()

	ci := &ClaudeInstaller{
		claudeDir:  t.TempDir(),
		httpClient: server.Client(),
	}

	destDir := filepath.Join(ci.claudeDir, "extract")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := ci.downloadAndExtract(server.URL, destDir); err != nil {
		t.Fatalf("downloadAndExtract() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "server.py")); err != nil {
		t.Error("server.py not extracted")
	}
	if _, err := os.Stat(filepath.Join(destDir, "requirements.txt")); err != nil {
		t.Error("requirements.txt not extracted")
	}
}

func TestInstalledVersion(t *testing.T) {
	ci := &ClaudeInstaller{}
	if v := ci.InstalledVersion(); v != "" {
		t.Errorf("InstalledVersion() = %q, want empty", v)
	}
	ci.installedVersion = "1.0.0"
	if v := ci.InstalledVersion(); v != "1.0.0" {
		t.Errorf("InstalledVersion() = %q, want %q", v, "1.0.0")
	}
}

func TestRegisterMarketplace(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir}
	pluginsDir := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(dir, "plugins", "cache", "test")
	if err := ci.registerMarketplace(pluginDir); err != nil {
		t.Fatalf("registerMarketplace() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(pluginsDir, "known_marketplaces.json"))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if _, ok := result[marketplaceName]; !ok {
		t.Error("marketplace not registered")
	}
}

func TestRegisterPlugin(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir, installedVersion: "1.0.0"}
	pluginsDir := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(dir, "plugins", "cache", "test")
	if err := ci.registerPlugin(pluginDir); err != nil {
		t.Fatalf("registerPlugin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(pluginsDir, "installed_plugins.json"))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	plugins, ok := result["plugins"].(map[string]interface{})
	if !ok {
		t.Fatal("plugins key missing or wrong type")
	}
	key := pluginName + "@" + marketplaceName
	entries, ok := plugins[key].([]interface{})
	if !ok || len(entries) == 0 {
		t.Fatalf("plugin %q not registered", key)
	}
	entry := entries[0].(map[string]interface{})
	if entry["version"] != "1.0.0" {
		t.Errorf("version = %q, want %q", entry["version"], "1.0.0")
	}
}

func TestGetInstalledVersion(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir}

	if v := ci.GetInstalledVersion(); v != "" {
		t.Errorf("GetInstalledVersion() = %q, want empty for missing file", v)
	}

	ci.installedVersion = "2.1.0"
	pluginsDir := filepath.Join(dir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(dir, "plugins", "cache", "test")
	if err := ci.registerPlugin(pluginDir); err != nil {
		t.Fatal(err)
	}

	if v := ci.GetInstalledVersion(); v != "2.1.0" {
		t.Errorf("GetInstalledVersion() = %q, want %q", v, "2.1.0")
	}
}

func TestEnablePlugin(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir}

	if err := ci.enablePlugin(); err != nil {
		t.Fatalf("enablePlugin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	enabled, ok := result["enabledPlugins"].(map[string]interface{})
	if !ok {
		t.Fatal("enabledPlugins key missing or wrong type")
	}
	key := pluginName + "@" + marketplaceName
	if enabled[key] != true {
		t.Errorf("plugin %q not enabled", key)
	}
}

func TestEnablePluginPreservesExistingSettings(t *testing.T) {
	dir := t.TempDir()
	ci := &ClaudeInstaller{claudeDir: dir}

	existing := map[string]interface{}{
		"permissions": map[string]interface{}{"allow": []string{"Bash"}},
		"enabledPlugins": map[string]interface{}{
			"other-plugin@other-mkt": true,
		},
	}
	b, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ci.enablePlugin(); err != nil {
		t.Fatalf("enablePlugin() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	// Verify existing settings preserved
	if result["permissions"] == nil {
		t.Error("existing permissions key was lost")
	}

	enabled := result["enabledPlugins"].(map[string]interface{})
	if enabled["other-plugin@other-mkt"] != true {
		t.Error("existing enabled plugin was lost")
	}
	key := pluginName + "@" + marketplaceName
	if enabled[key] != true {
		t.Error("new plugin not enabled")
	}
}

func TestFindPython(t *testing.T) {
	// This test just verifies findPython doesn't panic.
	// On CI without Python 3.11+, it may return "".
	_ = findPython()
}

func TestInstallMissingClaudeDir(t *testing.T) {
	ci := &ClaudeInstaller{
		claudeDir:  "/nonexistent/path/.claude",
		httpClient: http.DefaultClient,
	}
	err := ci.Install()
	if err == nil {
		t.Fatal("expected error for missing Claude directory")
	}
	if got := err.Error(); !contains(got, "Claude Code directory not found") {
		t.Errorf("unexpected error: %s", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDownloadAndExtractFlattensPrefix(t *testing.T) {
	tarball := createTestTarball(t, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(tarball)
	}))
	defer server.Close()

	ci := &ClaudeInstaller{
		claudeDir:  t.TempDir(),
		httpClient: server.Client(),
	}

	destDir := filepath.Join(ci.claudeDir, "extract")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := ci.downloadAndExtract(server.URL, destDir); err != nil {
		t.Fatalf("downloadAndExtract() error: %v", err)
	}

	wantFiles := []string{"server.py", "requirements.txt"}
	for _, f := range wantFiles {
		if _, err := os.Stat(filepath.Join(destDir, f)); err != nil {
			t.Errorf("expected file %q not found in extracted directory", f)
		}
	}
}

// createTestTarball creates a gzipped tarball matching GitHub's format:
// top-level directory prefix like "org-repo-sha/" with files inside.
// If withPaxHeader is true, includes a pax_global_header like real GitHub tarballs.
func createTestTarball(t *testing.T, withPaxHeader ...bool) []byte {
	t.Helper()
	var buf []byte

	tmpFile := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	if len(withPaxHeader) > 0 && withPaxHeader[0] {
		tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeXGlobalHeader,
			Name:     "pax_global_header",
			Size:     0,
		})
	}

	// Add directory entry
	tw.WriteHeader(&tar.Header{
		Name:     "ArmisSecurity-armis-appsec-mcp-abc1234/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})

	// Add a Python file
	content := []byte("print('hello')\n")
	tw.WriteHeader(&tar.Header{
		Name:     "ArmisSecurity-armis-appsec-mcp-abc1234/server.py",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	})
	tw.Write(content)

	// Add requirements.txt
	reqs := []byte("mcp[cli]==1.25.0\nhttpx==0.28.1\n")
	tw.WriteHeader(&tar.Header{
		Name:     "ArmisSecurity-armis-appsec-mcp-abc1234/requirements.txt",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(reqs)),
	})
	tw.Write(reqs)

	tw.Close()
	gw.Close()
	f.Close()

	buf, err = os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}
