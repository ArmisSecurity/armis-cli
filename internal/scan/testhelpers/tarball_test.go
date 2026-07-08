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
			name: "absolute path outside tmp rejected",
			// One level above the cleaned os.TempDir() is, by
			// construction, outside the temp tree on every OS. We
			// Clean first because some OSes (notably macOS) report
			// os.TempDir() with a trailing slash, which would make
			// filepath.Dir a no-op. A literal "/etc/passwd" would
			// normalise to "<curdrive>:\etc\passwd" on Windows and
			// trigger filepath.Rel's cross-drive error branch — which
			// the production code maps to the same rejection message.
			path:      filepath.Dir(filepath.Clean(os.TempDir())),
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

// TestAssertPathInsideTempDir_RejectsSymlinkOutsideTemp guards the
// symlink-traversal variant of CWE-22: a malicious symlink in the parent
// directory could redirect a write outside the temp tree even though the
// supplied path string looks safe. assertPathInsideTempDir uses
// filepath.EvalSymlinks on the parent to catch that.
func TestAssertPathInsideTempDir_RejectsSymlinkOutsideTemp(t *testing.T) {
	if runtimeIsWindows() {
		t.Skip("symlink creation requires elevated privileges on Windows CI runners")
	}
	tmp := t.TempDir()

	// Plant a symlink inside tmp that points to a directory outside tmp
	// (one level above the cleaned temp root, by construction outside).
	outside := filepath.Dir(filepath.Clean(os.TempDir()))
	link := filepath.Join(tmp, "evil-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// A write through evil-link/foo.tar would escape t.TempDir() on disk,
	// even though the string never contains "..". The guard must reject.
	err := assertPathInsideTempDir(filepath.Join(link, "foo.tar"))
	if err == nil {
		t.Fatal("expected rejection of symlink-traversal path")
	}
	if !strings.Contains(err.Error(), "outside the OS temp directory") {
		t.Errorf("expected 'outside' rejection, got: %v", err)
	}
}

// runtimeIsWindows is a tiny indirection to avoid pulling runtime.GOOS
// into the rest of the file. Used to skip the symlink test where
// non-elevated CI runners can't create symlinks.
func runtimeIsWindows() bool {
	return os.PathSeparator == '\\'
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
