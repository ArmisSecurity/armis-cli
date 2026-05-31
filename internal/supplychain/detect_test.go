package supplychain

import (
	"os"
	"path/filepath"
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
		os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644)   //nolint:errcheck,gosec
		os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask"), 0o644) //nolint:errcheck,gosec

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
