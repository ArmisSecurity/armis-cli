package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParseGradleLockfile(t *testing.T) {
	t.Run("valid gradle lockfile", func(t *testing.T) {
		entries, err := ParseGradleLockfile(filepath.Join("testdata", "gradle.lockfile"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "com.fasterxml.jackson.core:jackson-core", Version: "2.16.0"},
			{Name: "com.google.guava:guava", Version: "32.1.3-jre"},
			{Name: "org.slf4j:slf4j-api", Version: "2.0.9"},
			{Name: "org.springframework:spring-core", Version: "6.1.2"},
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
		_, err := ParseGradleLockfile("testdata/nonexistent.lockfile")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
