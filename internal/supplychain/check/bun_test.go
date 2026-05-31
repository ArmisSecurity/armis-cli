package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParseBunLockfile(t *testing.T) {
	t.Run("valid bun lockfile", func(t *testing.T) {
		entries, err := ParseBunLockfile(filepath.Join("testdata", "bun.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "@types/node", Version: "20.10.0"},
			{Name: "express", Version: "4.18.2"},
			{Name: "lodash", Version: "4.17.21"},
		}

		if len(entries) != len(expected) {
			t.Fatalf("expected %d entries, got %d: %v", len(expected), len(entries), entries)
		}

		for i, e := range entries {
			if e.Name != expected[i].Name || e.Version != expected[i].Version {
				t.Errorf("entry %d: expected %s@%s, got %s@%s", i, expected[i].Name, expected[i].Version, e.Name, e.Version)
			}
		}
	})

	t.Run("skips git and local packages", func(t *testing.T) {
		entries, err := ParseBunLockfile(filepath.Join("testdata", "bun.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "my-git-pkg" {
				t.Error("should have skipped git package")
			}
			if e.Name == "my-local-pkg" {
				t.Error("should have skipped local package")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParseBunLockfile("nonexistent.lock")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}
