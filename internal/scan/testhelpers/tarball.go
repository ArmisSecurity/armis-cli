package testhelpers

import (
	"archive/tar"
	"bytes"
	"os"
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
func WriteMinimalTar(t *testing.T, path string) {
	t.Helper()
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
