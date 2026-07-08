package check

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseYarnClassicLockfile(t *testing.T) {
	t.Run("valid yarn v1 lockfile", func(t *testing.T) {
		entries, err := ParseYarnLockfile(filepath.Join("testdata", "yarn.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "@types/node", Version: "18.19.3"},
			{Name: "express", Version: "4.18.2"},
			{Name: "lodash", Version: "4.17.21"},
			{Name: "typescript", Version: "5.3.3"},
		}

		if len(entries) != len(expected) {
			t.Fatalf("expected %d entries, got %d: %+v", len(expected), len(entries), entries)
		}

		for i, e := range entries {
			if e.Name != expected[i].Name || e.Version != expected[i].Version {
				t.Errorf("entry %d: expected %s@%s, got %s@%s", i, expected[i].Name, expected[i].Version, e.Name, e.Version)
			}
		}
	})

	t.Run("skips file and git protocols", func(t *testing.T) {
		entries, err := ParseYarnLockfile(filepath.Join("testdata", "yarn.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "my-local-pkg" || e.Name == "git-package" { //nolint:goconst // test value
				t.Errorf("should have skipped %s", e.Name)
			}
		}
	})

	t.Run("deduplicates multi-range entries", func(t *testing.T) {
		entries, err := ParseYarnLockfile(filepath.Join("testdata", "yarn.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		count := 0
		for _, e := range entries {
			if e.Name == "typescript" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected 1 typescript entry, got %d", count)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParseYarnLockfile("testdata/nonexistent.lock")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("parses lines longer than the default scanner token", func(t *testing.T) {
		// A resolved URL or integrity hash can exceed bufio.Scanner's default
		// 64KB token limit. Build a line well past that to assert the raised
		// buffer keeps such a lockfile parseable instead of failing "token too long".
		var sb strings.Builder
		sb.WriteString(`  resolved "https://registry.yarnpkg.com/big/-/big-1.0.0.tgz?`)
		for i := 0; i < 2000; i++ {
			sb.WriteString("0000000000000000000000000000000000000000000000000000000000000000")
		}
		sb.WriteString(`"`)
		if sb.Len() <= bufio.MaxScanTokenSize {
			t.Fatalf("test line is %d bytes, expected > %d to exercise the raised buffer", sb.Len(), bufio.MaxScanTokenSize)
		}

		lockfile := "big@^1.0.0:\n  version \"1.0.0\"\n" + sb.String() + "\n"

		dir := t.TempDir()
		path := filepath.Join(dir, "yarn.lock")
		if err := os.WriteFile(path, []byte(lockfile), 0o600); err != nil {
			t.Fatalf("writing fixture: %v", err)
		}

		entries, err := ParseYarnLockfile(path)
		if err != nil {
			t.Fatalf("unexpected error on long line: %v", err)
		}
		if len(entries) != 1 || entries[0].Name != "big" || entries[0].Version != "1.0.0" {
			t.Errorf("expected [big@1.0.0], got %v", entries)
		}
	})
}

func TestParseYarnBerryLockfile(t *testing.T) {
	t.Run("valid yarn berry lockfile", func(t *testing.T) {
		entries, err := ParseYarnLockfile(filepath.Join("testdata", "yarn-berry.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "@types/node", Version: "18.19.3"},
			{Name: "express", Version: "4.18.2"},
			{Name: "lodash", Version: "4.17.21"},
			{Name: "typescript", Version: "5.3.3"},
		}

		if len(entries) != len(expected) {
			t.Fatalf("expected %d entries, got %d: %+v", len(expected), len(entries), entries)
		}

		for i, e := range entries {
			if e.Name != expected[i].Name || e.Version != expected[i].Version {
				t.Errorf("entry %d: expected %s@%s, got %s@%s", i, expected[i].Name, expected[i].Version, e.Name, e.Version)
			}
		}
	})

	t.Run("skips workspace and link protocols", func(t *testing.T) {
		entries, err := ParseYarnLockfile(filepath.Join("testdata", "yarn-berry.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "my-workspace" || e.Name == "linked-pkg" {
				t.Errorf("should have skipped %s", e.Name)
			}
		}
	})
}
