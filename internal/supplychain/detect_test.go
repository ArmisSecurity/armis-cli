package supplychain

import (
	"os"
	"path/filepath"
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
