package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParseMavenDeps(t *testing.T) {
	t.Run("valid pom.xml", func(t *testing.T) {
		entries, err := ParseMavenDeps(filepath.Join("testdata", "pom.xml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		// Should include guava, jackson-core, and commons-io (version inherited
		// from <dependencyManagement>).
		// Should skip: junit (test scope), servlet-api (provided scope),
		// spring-core (${property}), and commons-lang3 (managed-only, never
		// declared under <dependencies>).
		expected := []PackageEntry{
			{Name: "com.fasterxml.jackson.core:jackson-core", Version: "2.16.0"},
			{Name: "com.google.guava:guava", Version: "32.1.3-jre"},
			{Name: "commons-io:commons-io", Version: "2.15.1"},
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

	t.Run("skips test scope", func(t *testing.T) {
		entries, err := ParseMavenDeps(filepath.Join("testdata", "pom.xml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "org.junit.jupiter:junit-jupiter" {
				t.Error("should have skipped test-scope dependency")
			}
		}
	})

	t.Run("skips property version refs", func(t *testing.T) {
		entries, err := ParseMavenDeps(filepath.Join("testdata", "pom.xml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "org.springframework:spring-core" {
				t.Error("should have skipped property-referenced version")
			}
		}
	})

	t.Run("inherits version from dependencyManagement", func(t *testing.T) {
		entries, err := ParseMavenDeps(filepath.Join("testdata", "pom.xml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var found bool
		for _, e := range entries {
			if e.Name == "commons-io:commons-io" {
				found = true
				if e.Version != "2.15.1" {
					t.Errorf("expected commons-io to inherit managed version 2.15.1, got %s", e.Version)
				}
			}
		}
		if !found {
			t.Error("expected commons-io (versionless dependency) to inherit a managed version")
		}
	})

	t.Run("ignores managed-only dependencies", func(t *testing.T) {
		entries, err := ParseMavenDeps(filepath.Join("testdata", "pom.xml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, e := range entries {
			if e.Name == "org.apache.commons:commons-lang3" {
				t.Error("should not include a dependencyManagement-only entry that is never declared under <dependencies>")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParseMavenDeps("testdata/nonexistent.xml")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}
