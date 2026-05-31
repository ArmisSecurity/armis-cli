package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParseUVLockfile(t *testing.T) {
	t.Run("valid uv.lock", func(t *testing.T) {
		entries, err := ParseUVLockfile(filepath.Join("testdata", "uv.lock"))
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

	t.Run("skips path sources", func(t *testing.T) {
		entries, err := ParseUVLockfile(filepath.Join("testdata", "uv.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "my-local" {
				t.Error("should have skipped path source")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParseUVLockfile("testdata/nonexistent.lock")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
