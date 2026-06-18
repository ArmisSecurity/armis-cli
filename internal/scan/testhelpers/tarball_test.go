package testhelpers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAssertPathInsideTempDir verifies the path-safety guard in
// WriteMinimalTar. The guard exists to satisfy the static analyzer's
// CWE-22 concern: even though every caller passes
// filepath.Join(t.TempDir(), ...), the helper enforces the invariant
// structurally so a future caller cannot accidentally traverse out of
// the per-test sandbox.
func TestAssertPathInsideTempDir(t *testing.T) {
	tmp := t.TempDir()

	cases := []struct {
		name      string
		path      string
		wantOK    bool
		errSubstr string
	}{
		{
			name:   "valid path inside t.TempDir()",
			path:   filepath.Join(tmp, "fixture.tar"),
			wantOK: true,
		},
		{
			name:      "empty path rejected",
			path:      "",
			errSubstr: "empty path",
		},
		{
			name: "double-dot segment rejected",
			// Bypass filepath.Join — it collapses ".." eagerly. Use a raw
			// string-concat to keep the literal traversal segment intact,
			// mirroring what an attacker-supplied input would look like.
			path:      tmp + string(filepath.Separator) + ".." + string(filepath.Separator) + "escaped.tar",
			errSubstr: "path traversal",
		},
		{
			name:      "absolute path outside tmp rejected",
			path:      "/etc/passwd",
			errSubstr: "outside the OS temp directory",
		},
		{
			name:      "path under non-existent parent rejected",
			path:      filepath.Join(tmp, "no-such-dir", "fixture.tar"),
			errSubstr: "parent directory does not exist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assertPathInsideTempDir(tc.path)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected ok, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

// TestWriteMinimalTar_HappyPath confirms a valid path under t.TempDir()
// produces a real tar file on disk.
func TestWriteMinimalTar_HappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.tar")
	WriteMinimalTar(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected tar at %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Errorf("tar size = 0; expected non-empty body")
	}
}
