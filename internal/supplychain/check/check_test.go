package check

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

// testPkgSQLAlchemy is the mixed-case package name used across the Python
// lockfile fixtures to assert that parsers apply PEP 503 name normalization
// (lowercasing). Shared so the assertion reads the same in every parser test.
const testPkgSQLAlchemy = "SQLAlchemy"

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
		// Python ecosystems.
		{"poetry.lock", supplychain.EcosystemPoetry},
		{"/srv/app/poetry.lock", supplychain.EcosystemPoetry},
		{"Pipfile.lock", supplychain.EcosystemPipfile},
		{"/home/u/Pipfile.lock", supplychain.EcosystemPipfile},
		{"pdm.lock", supplychain.EcosystemPDM},
		{"uv.lock", supplychain.EcosystemUV},
		{"requirements.txt", supplychain.EcosystemPip},
		{"/project/requirements-dev.txt", supplychain.EcosystemPip},
		{"/project/requirements/base.txt", supplychain.EcosystemPip},
		// A "requirements" substring that is not a path segment (e.g.
		// "myrequirements.txt") must NOT be classified as pip — it would parse
		// empty and report a false "all clear". Only a "requirements*" basename
		// or a file under a "requirements/" directory qualifies.
		{"myrequirements.txt", supplychain.EcosystemNPM},
		{"/project/build-requirements-notes.txt", supplychain.EcosystemNPM},
		// requirements.in (pip-tools input, unpinned) must NOT be treated as a
		// pinned requirements lockfile — doing so would silently skip every
		// unpinned line and report a false "all clear". It falls through to the
		// npm default, which simply fails to parse rather than passing silently.
		{"requirements.in", supplychain.EcosystemNPM},
		{"/project/requirements.in", supplychain.EcosystemNPM},
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
