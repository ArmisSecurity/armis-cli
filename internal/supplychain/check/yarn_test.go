package check

import (
	"path/filepath"
	"sort"
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
