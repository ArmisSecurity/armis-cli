package sbomcpe

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/api"
)

// ---------------------------------------------------------------------------
// Path/extension helpers
// ---------------------------------------------------------------------------

func TestIsPrebuiltTarball(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"foo.tar", true},
		{"foo.tar.gz", true},
		{"foo.tgz", true},
		{"foo.TAR.GZ", true},
		{"foo.TGZ", true},
		{"foo.json", false},
		{"foo.xml", false},
		{"foo", false},
	}
	for _, c := range cases {
		if got := isPrebuiltTarball(c.path); got != c.want {
			t.Errorf("isPrebuiltTarball(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestTrimTarSuffix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"foo.tar.gz", "foo"},
		{"bar.tgz", "bar"},
		{"baz.tar", "baz"},
		{"other.json", "other.json"},
		{"nested.name.tar.gz", "nested.name"},
	}
	for _, c := range cases {
		if got := trimTarSuffix(c.in); got != c.want {
			t.Errorf("trimTarSuffix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTrimSbomExtension(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"torizon.json", "torizon"},
		{"asset.xml", "asset"},
		{"asset.JSON", "asset"},
		{"noext", "noext"},
		{"has.dots.json", "has.dots"},
	}
	for _, c := range cases {
		if got := trimSbomExtension(c.in); got != c.want {
			t.Errorf("trimSbomExtension(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidateSbomExtension(t *testing.T) {
	// Happy paths
	for _, p := range []string{"foo.json", "bar.xml", "PATH.JSON"} {
		if err := validateSbomExtension(p); err != nil {
			t.Errorf("validateSbomExtension(%q) unexpected error: %v", p, err)
		}
	}
	// Rejections
	for _, p := range []string{"foo.txt", "bar.zip", "baz", "qux.tar.gz"} {
		if err := validateSbomExtension(p); err == nil {
			t.Errorf("validateSbomExtension(%q): expected error, got nil", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Tar packing
// ---------------------------------------------------------------------------

// readTarGz returns the list of tar-entry names inside a gzipped tar buffer.
func readTarGz(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	gr, err := gzip.NewReader(buf)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		names = append(names, hdr.Name)
	}
	sort.Strings(names)
	return names
}

func TestPackSingleFile(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "openssl.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"components":[]}`), 0600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := packSingleFile(sbomPath, &buf); err != nil {
		t.Fatalf("packSingleFile: %v", err)
	}
	names := readTarGz(t, &buf)
	if len(names) != 1 {
		t.Fatalf("expected 1 tar entry, got %v", names)
	}
	if names[0] != "openssl.cdx.json" {
		t.Errorf("expected entry name 'openssl.cdx.json', got %q", names[0])
	}
}

func TestPackDir_PicksUpJsonAndXml(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.xml"), []byte(`<x/>`), 0600); err != nil {
		t.Fatal(err)
	}
	// Non-SBOM extension → skipped
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(`ignore`), 0600); err != nil {
		t.Fatal(err)
	}
	// Nested dir with SBOM → picked up with relative path
	nested := filepath.Join(dir, "sub")
	if err := os.MkdirAll(nested, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "c.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := packDir(dir, &buf); err != nil {
		t.Fatalf("packDir: %v", err)
	}
	names := readTarGz(t, &buf)
	// Order is deterministic after our sort in readTarGz.
	want := []string{"a.json", "b.xml", "sub/c.json"}
	if len(names) != len(want) {
		t.Fatalf("expected %d entries, got %v", len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("entry[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestPackDir_ErrorsWhenNoSbomFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := packDir(dir, &buf)
	if err == nil {
		t.Fatal("expected error when no SBOM files present")
	}
	if !strings.Contains(err.Error(), "no SBOM files") {
		t.Errorf("expected 'no SBOM files' in error, got: %v", err)
	}
}

func TestPackDir_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}

	var buf bytes.Buffer
	if err := packDir(dir, &buf); err != nil {
		t.Fatalf("packDir: %v", err)
	}
	names := readTarGz(t, &buf)
	// Symlink is excluded — only 'real.json' should appear.
	if len(names) != 1 || names[0] != "real.json" {
		t.Errorf("expected only real.json, got %v", names)
	}
}

// ---------------------------------------------------------------------------
// Retry classifier
// ---------------------------------------------------------------------------

func TestIsRetryableError(t *testing.T) {
	if isRetryableError(nil) {
		t.Error("nil error should not be retryable")
	}
	// 5xx from the API is transient; 4xx is not.
	for _, code := range []int{500, 502, 503, 504} {
		if !isRetryableError(&api.APIError{StatusCode: code, Body: "server hiccup"}) {
			t.Errorf("expected retryable for status %d", code)
		}
	}
	for _, code := range []int{400, 401, 403, 404, 409, 422} {
		if isRetryableError(&api.APIError{StatusCode: code, Body: "nope"}) {
			t.Errorf("did not expect retryable for status %d", code)
		}
	}
	if !isRetryableError(context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded should be retryable")
	}
	if isRetryableError(errors.New("scan not found")) {
		t.Error("plain non-API error should not be retryable")
	}
}

// ---------------------------------------------------------------------------
// Scanner constructor + options
// ---------------------------------------------------------------------------

func TestNewScanner_DefaultDownloadRawIsTrue(t *testing.T) {
	s := NewScanner(nil, false, "tenant", 10, 0, false)
	if !s.downloadRaw {
		t.Error("NewScanner should default downloadRaw=true")
	}
}

func TestWithRawOutput_SetsField(t *testing.T) {
	s := NewScanner(nil, false, "tenant", 10, 0, false).WithRawOutput("/tmp/out.json")
	if s.rawOutput != "/tmp/out.json" {
		t.Errorf("rawOutput = %q, want /tmp/out.json", s.rawOutput)
	}
}

func TestWithoutRawDownload_DisablesFlag(t *testing.T) {
	s := NewScanner(nil, false, "tenant", 10, 0, false).WithoutRawDownload()
	if s.downloadRaw {
		t.Error("WithoutRawDownload should set downloadRaw=false")
	}
}

// ---------------------------------------------------------------------------
// ResultKeySBOMCPE constant is contract with the backend
// ---------------------------------------------------------------------------

func TestResultKeySBOMCPE_MatchesBackendContract(t *testing.T) {
	// The backend (services/artifact-scanner/.../persist_results_task.py)
	// writes results_refs["sbom_cpe_results"] = key when a CpeSbomScanner
	// run completes. This test locks the client-side constant to that
	// string so a rename on either side gets caught here.
	if ResultKeySBOMCPE != "sbom_cpe_results" {
		t.Errorf("ResultKeySBOMCPE = %q; backend contract expects %q",
			ResultKeySBOMCPE, "sbom_cpe_results")
	}
}
