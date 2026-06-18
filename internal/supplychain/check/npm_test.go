package check

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestParseNPMLockfile(t *testing.T) {
	t.Run("valid v3 lockfile", func(t *testing.T) {
		entries, err := ParseNPMLockfile(filepath.Join("testdata", "valid-v3.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})

		expected := []PackageEntry{
			{Name: "@types/node", Version: "20.10.0"},
			{Name: "debug", Version: "2.6.9"},
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

	t.Run("skips git resolved", func(t *testing.T) {
		entries, err := ParseNPMLockfile(filepath.Join("testdata", "valid-v3.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "my-git-pkg" { //nolint:goconst // test value
				t.Error("should have skipped git-resolved package")
			}
			if e.Name == "my-local-pkg" { //nolint:goconst // test value
				t.Error("should have skipped file-resolved package")
			}
			if e.Name == "linked-pkg" {
				t.Error("should have skipped linked package")
			}
		}
	})

	t.Run("handles scoped packages", func(t *testing.T) {
		entries, err := ParseNPMLockfile(filepath.Join("testdata", "valid-v3.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, e := range entries {
			if e.Name == "@types/node" {
				found = true
				break
			}
		}
		if !found {
			t.Error("scoped package @types/node not found")
		}
	})

	t.Run("npm alias uses real registry name", func(t *testing.T) {
		// An npm alias ("alias": "npm:real-pkg@1.2.3") records the local alias as
		// the node_modules/ key but the real registry package in the "name" field.
		// The entry must be audited under "path-to-regexp" (which exists at 6.3.0),
		// not "path-to-regexp-updated" (the alias, which does not), or the package
		// silently escapes the age check with a "version not found" warning.
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "alias.json")
		content := `{"lockfileVersion":3,"packages":{` +
			`"node_modules/path-to-regexp-updated":{"name":"path-to-regexp","version":"6.3.0","resolved":"https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-6.3.0.tgz"},` +
			`"node_modules/express":{"version":"4.18.2","resolved":"https://registry.npmjs.org/express/-/express-4.18.2.tgz"}}}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		entries, err := ParseNPMLockfile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var aliasVer string
		var sawAlias, sawUpdated bool
		for _, e := range entries {
			switch e.Name {
			case "path-to-regexp":
				sawAlias = true
				aliasVer = e.Version
			case "path-to-regexp-updated":
				sawUpdated = true
			}
		}
		if !sawAlias {
			t.Error(`alias must be audited under the real name "path-to-regexp"`)
		}
		if sawUpdated {
			t.Error(`alias must not be audited under the local alias "path-to-regexp-updated"`)
		}
		if aliasVer != "6.3.0" {
			t.Errorf("alias version = %q, want 6.3.0", aliasVer)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParseNPMLockfile("nonexistent.json")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bad.json")
		if err := os.WriteFile(path, []byte("{invalid json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ParseNPMLockfile(path)
		if err == nil {
			t.Error("expected error for malformed JSON")
		}
	})

	t.Run("empty packages field", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "empty.json")
		content := `{"lockfileVersion": 3, "packages": {}}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		entries, err := ParseNPMLockfile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("expected 0 entries, got %d", len(entries))
		}
	})
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"node_modules/express", "express"},
		{"node_modules/@types/node", "@types/node"},
		{"node_modules/a/node_modules/b", "b"},
		{"node_modules/@scope/pkg/node_modules/dep", "dep"},
		{"", ""},
		{"something-else", ""},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := extractPackageName(tt.key)
			if got != tt.expected {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}
