package testhelpers

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// SchemeFromRequest is re-exported from testutil for convenience so scan
// packages can use a single helper import.
var SchemeFromRequest = testutil.SchemeFromRequest

// WriteMinimalTar writes a syntactically valid uncompressed tar with one
// "test.txt" entry to `path`. Used by image and repo test fixtures so the
// new client-side tarball validation (PPSC-895) doesn't reject them as
// "not a valid tar archive". The contents themselves don't matter — image
// scans only need the file to pass the magic-byte check before upload.
//
// Path safety: this helper enforces that `path` resolves to a location
// inside Go's testing TempDir (or the OS temp dir, which Go's
// t.TempDir() lives under). A path with ".." components, an absolute
// path outside the temp tree, or any other escape attempt is rejected
// via t.Fatalf. This is defense-in-depth — every existing caller passes
// `filepath.Join(t.TempDir(), …)` — so the static analyzer's CWE-22
// concern is structurally precluded.
func WriteMinimalTar(t *testing.T, path string) {
	t.Helper()
	if err := assertPathInsideTempDir(path); err != nil {
		t.Fatalf("WriteMinimalTar refusing unsafe path %q: %v", path, err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("hello")
	if err := tw.WriteHeader(&tar.Header{Name: "test.txt", Mode: 0644, Size: int64(len(body))}); err != nil {
		t.Fatalf("WriteMinimalTar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("WriteMinimalTar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("WriteMinimalTar close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("WriteMinimalTar write: %v", err)
	}
}

// assertPathInsideTempDir resolves `path` and verifies it sits underneath
// the OS temp directory (which is where t.TempDir() lives). Returns nil
// when the path is safe to write to, or an error describing the rejection.
//
// The check rejects:
//   - empty paths
//   - paths containing ".." segments (path traversal)
//   - absolute paths outside the OS temp tree
//   - paths whose parent directory does not exist (avoids surprising creates)
//
// armis:ignore cwe:22 reason:this function IS the path-traversal mitigation
func assertPathInsideTempDir(path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if seg == ".." {
			return errors.New("path traversal segment '..' detected")
		}
	}

	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	tmpRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(tmpRoot, abs)
	if err != nil {
		// On Windows, filepath.Rel returns an error when the two paths
		// live on different volumes (e.g. tmp on C: but the supplied
		// path on D:). That is by definition "outside the OS temp dir",
		// so map it to the explicit rejection rather than leaking the
		// raw "Rel:" error string.
		return errors.New("path resolves outside the OS temp directory")
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("path resolves outside the OS temp directory")
	}

	// Refuse if the parent directory does not already exist. This stops a
	// caller from accidentally creating fixtures outside their t.TempDir()
	// sandbox; legitimate tests always pre-create or pass a known dir.
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil {
		return errors.New("parent directory does not exist or is not accessible")
	}
	if !info.IsDir() {
		return errors.New("parent is not a directory")
	}
	return nil
}
