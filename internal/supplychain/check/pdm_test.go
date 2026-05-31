package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParsePDMLockfile(t *testing.T) {
	t.Run("valid pdm.lock", func(t *testing.T) {
		entries, err := ParsePDMLockfile(filepath.Join("testdata", "pdm.lock"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "click", Version: "8.1.7"},
			{Name: "flask", Version: "3.0.0"},
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

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePDMLockfile("testdata/nonexistent.lock")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
