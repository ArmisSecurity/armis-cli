package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParsePoetryLockfile(t *testing.T) {
	t.Run("valid poetry.lock", func(t *testing.T) {
		entries, err := ParsePoetryLockfile(filepath.Join("testdata", "poetry.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "flask", Version: "3.0.0"},
			{Name: "numpy", Version: "1.26.2"},
			{Name: "requests", Version: "2.31.0"},
			{Name: "sqlalchemy", Version: "2.0.23"},
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

	t.Run("skips git and directory sources", func(t *testing.T) {
		entries, err := ParsePoetryLockfile(filepath.Join("testdata", "poetry.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "my-git-dep" || e.Name == "local-dep" {
				t.Errorf("should have skipped %s", e.Name)
			}
		}
	})

	t.Run("normalizes names", func(t *testing.T) {
		entries, err := ParsePoetryLockfile(filepath.Join("testdata", "poetry.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "SQLAlchemy" {
				t.Error("name not normalized")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePoetryLockfile("testdata/nonexistent.lock")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
