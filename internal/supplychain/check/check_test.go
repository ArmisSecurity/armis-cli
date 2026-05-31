package check

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

func TestDiffEntries(t *testing.T) {
	t.Run("returns only new packages", func(t *testing.T) {
		current := []PackageEntry{
			{Name: "express", Version: "4.18.2"},
			{Name: "lodash", Version: "4.17.21"},
			{Name: "new-pkg", Version: "1.0.0"},
		}
		base := []PackageEntry{
			{Name: "express", Version: "4.18.2"},
			{Name: "lodash", Version: "4.17.21"},
		}

		result := diffEntries(current, base)

		if len(result) != 1 {
			t.Fatalf("expected 1 new entry, got %d", len(result))
		}
		if result[0].Name != "new-pkg" || result[0].Version != "1.0.0" {
			t.Errorf("unexpected entry: %+v", result[0])
		}
	})

	t.Run("version upgrade counts as new", func(t *testing.T) {
		current := []PackageEntry{
			{Name: "express", Version: "4.19.0"},
		}
		base := []PackageEntry{
			{Name: "express", Version: "4.18.2"},
		}

		result := diffEntries(current, base)

		if len(result) != 1 {
			t.Fatalf("expected 1 new entry (version change), got %d", len(result))
		}
	})

	t.Run("empty base returns all current", func(t *testing.T) {
		current := []PackageEntry{
			{Name: "a", Version: "1.0.0"},
			{Name: "b", Version: "2.0.0"},
		}

		result := diffEntries(current, nil)

		if len(result) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(result))
		}
	})

	t.Run("identical sets returns empty", func(t *testing.T) {
		entries := []PackageEntry{
			{Name: "express", Version: "4.18.2"},
		}

		result := diffEntries(entries, entries)

		if len(result) != 0 {
			t.Errorf("expected 0 entries, got %d", len(result))
		}
	})
}

func TestDetectEcosystemFromPath(t *testing.T) {
	tests := []struct {
		path string
		want supplychain.Ecosystem
	}{
		{"./package-lock.json", supplychain.EcosystemNPM},
		{"/foo/bar/pnpm-lock.yaml", supplychain.EcosystemPNPM},
		{"bun.lock", supplychain.EcosystemBun},
		{"yarn.lock", supplychain.EcosystemYarn},
		{"/project/yarn.lock", supplychain.EcosystemYarn},
		{"unknown.lock", supplychain.EcosystemNPM},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectEcosystemFromPath(tt.path)
			if got != tt.want {
				t.Errorf("detectEcosystemFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
