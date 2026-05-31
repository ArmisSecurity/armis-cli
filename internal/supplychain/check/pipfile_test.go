package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParsePipfileLock(t *testing.T) {
	t.Run("valid Pipfile.lock", func(t *testing.T) {
		entries, err := ParsePipfileLock(filepath.Join("testdata", "Pipfile.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		// click (>=8.0) should be skipped — not pinned
		expected := []PackageEntry{
			{Name: "black", Version: "23.12.0"},
			{Name: "flask", Version: "3.0.0"},
			{Name: "my-package", Version: "1.0.0"},
			{Name: "pytest", Version: "7.4.3"},
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

	t.Run("normalizes names", func(t *testing.T) {
		entries, err := ParsePipfileLock(filepath.Join("testdata", "Pipfile.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "SQLAlchemy" || e.Name == "my_package" {
				t.Errorf("name not normalized: %s", e.Name)
			}
		}
	})

	t.Run("skips non-pinned versions", func(t *testing.T) {
		entries, err := ParsePipfileLock(filepath.Join("testdata", "Pipfile.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "click" {
				t.Error("should have skipped non-pinned version (>=8.0)")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePipfileLock("testdata/nonexistent.lock")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
