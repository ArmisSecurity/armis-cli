package check

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestParsePNPMLockfile(t *testing.T) {
	t.Run("valid pnpm v9 lockfile", func(t *testing.T) {
		entries, err := ParsePNPMLockfile(filepath.Join("testdata", "pnpm-lock.yaml"))
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

	t.Run("skips git and local packages", func(t *testing.T) {
		entries, err := ParsePNPMLockfile(filepath.Join("testdata", "pnpm-lock.yaml"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, e := range entries {
			if e.Name == "my-git-pkg" { //nolint:goconst // test value
				t.Error("should have skipped git package")
			}
			if e.Name == "local-pkg" || e.Name == "../local-pkg" {
				t.Error("should have skipped local package")
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePNPMLockfile("nonexistent.yaml")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}

func TestParsePnpmPackageKey(t *testing.T) {
	tests := []struct {
		key      string
		wantName string
		wantVer  string
	}{
		{"/express@4.18.2", "express", "4.18.2"},
		{"/@types/node@20.10.0", "@types/node", "20.10.0"},
		{"/debug@2.6.9(@types/node@20.10.0)", "debug", "2.6.9"},
		{"/lodash@4.17.21_peer@1.0.0", "lodash", "4.17.21"},
		{"/is_glob@4.0.3", "is_glob", "4.0.3"},
		{"/call_bind@1.0.7_tslib@2.6.0", "call_bind", "1.0.7"},
		{"/express/4.18.2", "express", "4.18.2"},
		{"/@scope/pkg/1.0.0", "@scope/pkg", "1.0.0"},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			name, version := parsePnpmPackageKey(tt.key, pnpmPackageInfo{})
			if name != tt.wantName || version != tt.wantVer {
				t.Errorf("parsePnpmPackageKey(%q) = (%q, %q), want (%q, %q)", tt.key, name, version, tt.wantName, tt.wantVer)
			}
		})
	}
}

func TestStripPeerSuffix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"4.18.2", "4.18.2"},
		{"2.6.9(@types/node@20.10.0)", "2.6.9"},
		{"4.17.21_peer@1.0.0", "4.17.21"},
		{"1.0.0", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPeerSuffix(tt.input)
			if got != tt.want {
				t.Errorf("stripPeerSuffix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
