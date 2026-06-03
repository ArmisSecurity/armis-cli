package supplychain

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDetectEcosystems(t *testing.T) {
	t.Run("detects npm from package-lock.json", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644) //nolint:errcheck,gosec

		ecosystems, err := DetectEcosystems(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ecosystems) != 1 {
			t.Fatalf("expected 1 ecosystem, got %d", len(ecosystems))
		}
		if ecosystems[0].Ecosystem != EcosystemNPM {
			t.Errorf("expected npm, got %s", ecosystems[0].Ecosystem)
		}
	})

	t.Run("detects multiple ecosystems", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644)                  //nolint:errcheck,gosec
		os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'"), 0o644) //nolint:errcheck,gosec

		ecosystems, err := DetectEcosystems(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ecosystems) != 2 {
			t.Fatalf("expected 2 ecosystems, got %d", len(ecosystems))
		}
	})

	t.Run("returns error when no lockfile found", func(t *testing.T) {
		dir := t.TempDir()

		_, err := DetectEcosystems(dir)
		if err == nil {
			t.Fatal("expected error for empty directory")
		}
	})

	t.Run("detects pnpm", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'"), 0o644) //nolint:errcheck,gosec

		ecosystems, err := DetectEcosystems(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ecosystems[0].Ecosystem != EcosystemPNPM {
			t.Errorf("expected pnpm, got %s", ecosystems[0].Ecosystem)
		}
	})

	t.Run("detects bun", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "bun.lock"), []byte("{}"), 0o644) //nolint:errcheck,gosec

		ecosystems, err := DetectEcosystems(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ecosystems[0].Ecosystem != EcosystemBun {
			t.Errorf("expected bun, got %s", ecosystems[0].Ecosystem)
		}
	})

	t.Run("surfaces non-not-exist stat errors", func(t *testing.T) {
		// Use a regular file as the "directory": filepath.Join(file, "package-lock.json")
		// becomes "<file>/package-lock.json", and stat'ing a path whose parent is a
		// file fails with ENOTDIR — a non-IsNotExist error. DetectEcosystems must
		// surface it instead of silently reporting "no lockfile found", so a real
		// permission/I/O problem isn't mistaken for an absent lockfile.
		//
		// This ENOTDIR behavior is Unix-only: on Windows, stat'ing a path under a
		// non-directory returns ERROR_PATH_NOT_FOUND, which os.IsNotExist reports as
		// true, so the error is (correctly) treated as "lockfile absent" there.
		if runtime.GOOS == goosWindows {
			t.Skip("ENOTDIR-style stat errors are not reproducible on Windows (maps to IsNotExist)")
		}
		base := t.TempDir()
		notADir := filepath.Join(base, "not-a-dir")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}

		_, err := DetectEcosystems(notADir)
		if err == nil {
			t.Fatal("expected error when a lockfile path cannot be stat'd")
		}
		// The error must describe an access failure, not the generic "no supported
		// lockfile found" message that callers map to an empty-but-valid state.
		if strings.Contains(err.Error(), "no supported lockfile found") {
			t.Errorf("stat failure should not be reported as a missing lockfile, got: %v", err)
		}
	})

	t.Run("lockfile path is absolute", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644) //nolint:errcheck,gosec

		ecosystems, err := DetectEcosystems(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !filepath.IsAbs(ecosystems[0].LockfilePath) {
			t.Errorf("expected absolute path, got %s", ecosystems[0].LockfilePath)
		}
	})
}

func TestFindEcosystemLockfile(t *testing.T) {
	t.Run("finds lockfile in the start directory", func(t *testing.T) {
		dir := t.TempDir()
		want := filepath.Join(dir, "poetry.lock")
		os.WriteFile(want, []byte(""), 0o644) //nolint:errcheck,gosec

		got := FindEcosystemLockfile(dir, EcosystemPoetry)
		if got != want {
			t.Errorf("FindEcosystemLockfile = %q, want %q", got, want)
		}
	})

	t.Run("walks up to a parent directory", func(t *testing.T) {
		// poetry/pdm/pipenv are routinely run from a project subdirectory while the
		// lockfile lives at the project root; the walk must find it rather than
		// silently skipping enforcement.
		root := t.TempDir()
		want := filepath.Join(root, "pdm.lock")
		os.WriteFile(want, []byte(""), 0o644) //nolint:errcheck,gosec
		sub := filepath.Join(root, "service", "nested")
		if err := os.MkdirAll(sub, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		got := FindEcosystemLockfile(sub, EcosystemPDM)
		if got != want {
			t.Errorf("FindEcosystemLockfile from subdir = %q, want %q", got, want)
		}
	})

	t.Run("returns empty when no lockfile exists", func(t *testing.T) {
		if got := FindEcosystemLockfile(t.TempDir(), EcosystemPoetry); got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("returns empty for an ecosystem without a fixed lockfile name", func(t *testing.T) {
		// pip requirements files have no canonical name, so there is nothing to
		// walk up for; the function must not match an unrelated file.
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(""), 0o644) //nolint:errcheck,gosec
		if got := FindEcosystemLockfile(dir, EcosystemPip); got != "" {
			t.Errorf("expected empty string for pip, got %q", got)
		}
	})
}
