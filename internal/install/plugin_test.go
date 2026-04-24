package install

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchLatestRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3","tarball_url":"https://api.github.com/repos/test/tarball/v1.2.3"}`))
	}))
	defer server.Close()

	pi := &PluginInstaller{
		httpClient:        server.Client(),
		releasesURL:       server.URL,
		skipURLValidation: true,
	}

	release, err := pi.fetchLatestRelease()
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	pi := &PluginInstaller{
		httpClient:        server.Client(),
		releasesURL:       server.URL,
		skipURLValidation: true,
	}

	_, err := pi.fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestDownloadAndExtract(t *testing.T) {
	tarball := createTestTarball(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	pi := &PluginInstaller{
		httpClient:        server.Client(),
		skipURLValidation: true,
	}

	destDir := filepath.Join(t.TempDir(), "extract")
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := pi.downloadAndExtract(server.URL, destDir); err != nil {
		t.Fatalf("downloadAndExtract() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "server.py")); err != nil {
		t.Error("server.py not extracted")
	}
	if _, err := os.Stat(filepath.Join(destDir, "requirements.txt")); err != nil {
		t.Error("requirements.txt not extracted")
	}
}

func TestDownloadAndExtractFlattensPrefix(t *testing.T) {
	tarball := createTestTarball(t, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer server.Close()

	pi := &PluginInstaller{
		httpClient:        server.Client(),
		skipURLValidation: true,
	}

	destDir := filepath.Join(t.TempDir(), "extract")
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := pi.downloadAndExtract(server.URL, destDir); err != nil {
		t.Fatalf("downloadAndExtract() error: %v", err)
	}

	for _, f := range []string{"server.py", "requirements.txt"} {
		if _, err := os.Stat(filepath.Join(destDir, f)); err != nil {
			t.Errorf("expected file %q not found in extracted directory", f)
		}
	}
}

func TestPluginInstalledVersion(t *testing.T) {
	pi := newPluginInstaller()
	if v := pi.InstalledVersion(); v != "" {
		t.Errorf("InstalledVersion() = %q, want empty", v)
	}
	pi.installedVersion = testVersion
	if v := pi.InstalledVersion(); v != testVersion {
		t.Errorf("InstalledVersion() = %q, want %q", v, testVersion)
	}
}

func TestFindPython(t *testing.T) {
	_ = findPython()
}

func TestValidateGitHubURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid", "https://api.github.com/repos/test/releases/latest", false},
		{"http scheme", "http://api.github.com/repos/test", true},
		{"wrong host", "https://evil.com/repos/test", true},
		{"malformed", "://bad", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGitHubURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestWriteEnvFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	t.Run("writes env when both vars set", func(t *testing.T) {
		t.Setenv("ARMIS_CLIENT_ID", "test-id")
		t.Setenv("ARMIS_CLIENT_SECRET", "test-secret")

		if !writeEnvFromEnvironment(envPath) {
			t.Fatal("writeEnvFromEnvironment() returned false, want true")
		}

		b, err := os.ReadFile(filepath.Clean(envPath))
		if err != nil {
			t.Fatal(err)
		}
		content := string(b)
		if !searchString(content, "ARMIS_CLIENT_ID=test-id") {
			t.Error("missing ARMIS_CLIENT_ID")
		}
		if !searchString(content, "ARMIS_CLIENT_SECRET=test-secret") {
			t.Error("missing ARMIS_CLIENT_SECRET")
		}

		info, _ := os.Stat(envPath)
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file permissions = %o, want 600", perm)
		}
	})

	t.Run("skips when file exists", func(t *testing.T) {
		t.Setenv("ARMIS_CLIENT_ID", "new-id")
		t.Setenv("ARMIS_CLIENT_SECRET", "new-secret")

		if writeEnvFromEnvironment(envPath) {
			t.Error("writeEnvFromEnvironment() returned true for existing file")
		}

		b, _ := os.ReadFile(filepath.Clean(envPath))
		if searchString(string(b), "new-id") {
			t.Error("existing file was overwritten")
		}
	})

	t.Run("skips when vars missing", func(t *testing.T) {
		freshPath := filepath.Join(t.TempDir(), ".env")
		t.Setenv("ARMIS_CLIENT_ID", "")
		t.Setenv("ARMIS_CLIENT_SECRET", "")

		if writeEnvFromEnvironment(freshPath) {
			t.Error("writeEnvFromEnvironment() returned true with empty vars")
		}
		if _, err := os.Stat(freshPath); err == nil {
			t.Error("file should not exist when vars are empty")
		}
	})

	t.Run("skips when only one var set", func(t *testing.T) {
		freshPath := filepath.Join(t.TempDir(), ".env")
		t.Setenv("ARMIS_CLIENT_ID", "test-id")
		t.Setenv("ARMIS_CLIENT_SECRET", "")

		if writeEnvFromEnvironment(freshPath) {
			t.Error("writeEnvFromEnvironment() returned true with only client ID")
		}
	})
}

// createTestTarball creates a gzipped tarball matching GitHub's format.
func createTestTarball(t *testing.T, withPaxHeader ...bool) []byte {
	t.Helper()

	tmpFile := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(filepath.Clean(tmpFile))
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	if len(withPaxHeader) > 0 && withPaxHeader[0] {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeXGlobalHeader,
			Name:     "pax_global_header",
			Size:     0,
		}); err != nil {
			t.Fatal(err)
		}
	}

	writeEntry := func(hdr *tar.Header, data []byte) {
		t.Helper()
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}

	writeEntry(&tar.Header{
		Name:     "ArmisSecurity-armis-appsec-mcp-abc1234/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}, nil)

	content := []byte("print('hello')\n")
	writeEntry(&tar.Header{
		Name:     "ArmisSecurity-armis-appsec-mcp-abc1234/server.py",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}, content)

	reqs := []byte("mcp[cli]==1.25.0\nhttpx==0.28.1\n")
	writeEntry(&tar.Header{
		Name:     "ArmisSecurity-armis-appsec-mcp-abc1234/requirements.txt",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(reqs)),
	}, reqs)

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	buf, err := os.ReadFile(filepath.Clean(tmpFile))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}
