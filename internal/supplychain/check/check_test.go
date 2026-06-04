package check

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/registry"
)

// testPkgSQLAlchemy is the mixed-case package name used across the Python
// lockfile fixtures to assert that parsers apply PEP 503 name normalization
// (lowercasing). Shared so the assertion reads the same in every parser test.
const testPkgSQLAlchemy = "SQLAlchemy"

// pkgExpress is the npm package name used across the diff and RunCheck tests;
// hoisted to a constant so the repeated literal does not trip goconst.
const pkgExpress = "express"

func TestDiffEntries(t *testing.T) {
	t.Run("returns only new packages", func(t *testing.T) {
		current := []PackageEntry{
			{Name: pkgExpress, Version: "4.18.2"},
			{Name: "lodash", Version: "4.17.21"},
			{Name: "new-pkg", Version: "1.0.0"},
		}
		base := []PackageEntry{
			{Name: pkgExpress, Version: "4.18.2"},
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
			{Name: pkgExpress, Version: "4.19.0"},
		}
		base := []PackageEntry{
			{Name: pkgExpress, Version: "4.18.2"},
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
			{Name: pkgExpress, Version: "4.18.2"},
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

// staticAgeResolver returns a registryFn that reports every requested package as
// published `age` ago, so a single age value drives the violation outcome.
func staticAgeResolver(age time.Duration) registryFn {
	return func(_ context.Context, _ supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
		now := time.Now()
		out := make([]registry.QueryResult, len(packages))
		for i, p := range packages {
			out[i] = registry.QueryResult{Name: p.Name, Version: p.Version, PublishTime: now.Add(-age)}
		}
		return out
	}
}

// ageByNameResolver returns a registryFn that reports each package as published
// the age in `ages` (keyed by name) ago, falling back to `fallback` for names
// not listed. It lets a test make one package young while the rest stay old.
func ageByNameResolver(ages map[string]time.Duration, fallback time.Duration) registryFn {
	return func(_ context.Context, _ supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
		now := time.Now()
		out := make([]registry.QueryResult, len(packages))
		for i, p := range packages {
			age := fallback
			if a, ok := ages[p.Name]; ok {
				age = a
			}
			out[i] = registry.QueryResult{Name: p.Name, Version: p.Version, PublishTime: now.Add(-age)}
		}
		return out
	}
}

func TestRunCheck(t *testing.T) {
	npmLock := filepath.Join("testdata", "valid-v3.json")
	poetryLock := filepath.Join("testdata", "poetry.lock")
	pomXML := filepath.Join("testdata", "pom.xml")
	// valid-v3.json yields four checkable packages after the parser drops the
	// file:/git+/link: entries: express, @types/node, lodash, debug.
	const npmPkgCount = 4
	defaultPolicy := supplychain.Policy{MinReleaseAge: 72 * time.Hour}
	old := 100 * 24 * time.Hour // comfortably older than the 72h threshold

	t.Run("npm clean pass - all packages old", func(t *testing.T) {
		res, err := runCheck(context.Background(), defaultPolicy, npmLock, "", staticAgeResolver(old))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Checked != npmPkgCount {
			t.Errorf("Checked = %d, want %d", res.Checked, npmPkgCount)
		}
		if len(res.Violations) != 0 {
			t.Errorf("expected no violations, got %+v", res.Violations)
		}
	})

	t.Run("npm violation - one recent package is High severity", func(t *testing.T) {
		res, err := runCheck(context.Background(), defaultPolicy, npmLock, "",
			ageByNameResolver(map[string]time.Duration{pkgExpress: 12 * time.Hour}, old))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Violations) != 1 {
			t.Fatalf("expected 1 violation, got %d: %+v", len(res.Violations), res.Violations)
		}
		v := res.Violations[0]
		if v.Name != pkgExpress {
			t.Errorf("violation name = %q, want express", v.Name)
		}
		// 12h < 24h, so ClassifySeverity returns High.
		if v.Severity != model.SeverityHigh {
			t.Errorf("severity = %q, want %q", v.Severity, model.SeverityHigh)
		}
	})

	t.Run("routes poetry.lock to the PyPI ecosystem", func(t *testing.T) {
		var gotEcosystem supplychain.Ecosystem
		_, err := runCheck(context.Background(), defaultPolicy, poetryLock, "",
			func(_ context.Context, eco supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
				gotEcosystem = eco
				return staticAgeResolver(old)(context.Background(), eco, packages)
			})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotEcosystem != supplychain.EcosystemPoetry {
			t.Errorf("ecosystem passed to resolver = %q, want %q", gotEcosystem, supplychain.EcosystemPoetry)
		}
	})

	t.Run("routes pom.xml to the Maven ecosystem", func(t *testing.T) {
		var gotEcosystem supplychain.Ecosystem
		_, err := runCheck(context.Background(), defaultPolicy, pomXML, "",
			func(_ context.Context, eco supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
				gotEcosystem = eco
				return staticAgeResolver(old)(context.Background(), eco, packages)
			})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotEcosystem != supplychain.EcosystemMaven {
			t.Errorf("ecosystem passed to resolver = %q, want %q", gotEcosystem, supplychain.EcosystemMaven)
		}
	})

	t.Run("base lockfile diff excludes unchanged packages", func(t *testing.T) {
		// Same file as current and base: every entry is unchanged, so nothing
		// reaches the registry and the resolver must never be called.
		res, err := runCheck(context.Background(), defaultPolicy, npmLock, npmLock,
			func(_ context.Context, _ supplychain.Ecosystem, _ []registry.PackageRequest) []registry.QueryResult {
				t.Error("resolver should not be called when all packages are diffed out")
				return nil
			})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Checked != 0 {
			t.Errorf("Checked = %d, want 0", res.Checked)
		}
	})

	t.Run("policy exclusion skips a package", func(t *testing.T) {
		policy := supplychain.Policy{MinReleaseAge: 72 * time.Hour, Exclusions: []string{pkgExpress}}
		res, err := runCheck(context.Background(), policy, npmLock, "", staticAgeResolver(old))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Skipped != 1 {
			t.Errorf("Skipped = %d, want 1", res.Skipped)
		}
		if res.Checked != npmPkgCount-1 {
			t.Errorf("Checked = %d, want %d", res.Checked, npmPkgCount-1)
		}
	})

	t.Run("registry error becomes a warning not a violation", func(t *testing.T) {
		res, err := runCheck(context.Background(), defaultPolicy, npmLock, "",
			func(_ context.Context, _ supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
				now := time.Now()
				out := make([]registry.QueryResult, len(packages))
				for i, p := range packages {
					if p.Name == pkgExpress {
						out[i] = registry.QueryResult{Name: p.Name, Version: p.Version, Err: fmt.Errorf("registry unreachable")}
						continue
					}
					out[i] = registry.QueryResult{Name: p.Name, Version: p.Version, PublishTime: now.Add(-old)}
				}
				return out
			})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Warnings) != 1 {
			t.Errorf("expected 1 warning, got %d: %v", len(res.Warnings), res.Warnings)
		}
		if len(res.Violations) != 0 {
			t.Errorf("expected no violations, got %+v", res.Violations)
		}
	})

	t.Run("all packages excluded returns early without querying", func(t *testing.T) {
		policy := supplychain.Policy{
			MinReleaseAge: 72 * time.Hour,
			Exclusions:    []string{pkgExpress, "lodash", "debug", "@types/node"},
		}
		res, err := runCheck(context.Background(), policy, npmLock, "",
			func(_ context.Context, _ supplychain.Ecosystem, _ []registry.PackageRequest) []registry.QueryResult {
				t.Error("resolver should not be called when every package is excluded")
				return nil
			})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Checked != 0 {
			t.Errorf("Checked = %d, want 0", res.Checked)
		}
		if res.Skipped != npmPkgCount {
			t.Errorf("Skipped = %d, want %d", res.Skipped, npmPkgCount)
		}
	})

	t.Run("parse error propagates", func(t *testing.T) {
		// A missing lockfile cannot be parsed; the error must surface rather than
		// being swallowed into a false "all clear".
		missing := filepath.Join(t.TempDir(), "package-lock.json")
		_, err := runCheck(context.Background(), defaultPolicy, missing, "", staticAgeResolver(old))
		if err == nil {
			t.Fatal("expected error for missing lockfile, got nil")
		}
	})
}

// TestRunCheckEndToEndNPM exercises the full pipeline against a mock npm
// registry: lockfile parse -> real registry client over httptest -> publish-date
// classification. This is the one case that validates the on-the-wire npm "time"
// metadata format the production queryRegistry depends on.
func TestRunCheckEndToEndNPM(t *testing.T) {
	// One package is freshly published (now) and must be flagged; the rest are
	// old. The handler answers npm metadata for any requested package name.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/json")
		switch name {
		case pkgExpress:
			// Published "now" (RFC3339) -> younger than the 72h threshold.
			_, _ = fmt.Fprintf(w, `{"time":{"4.18.2":%q}}`, time.Now().UTC().Format(time.RFC3339))
		default:
			// Old enough to pass for every other package version in the fixture.
			_, _ = fmt.Fprint(w, `{"time":{`+
				`"20.10.0":"2020-01-01T00:00:00Z",`+
				`"4.17.21":"2020-01-01T00:00:00Z",`+
				`"2.6.9":"2020-01-01T00:00:00Z"}}`)
		}
	}))
	defer server.Close()

	resolver := func(ctx context.Context, _ supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
		return registry.NewClientWithHTTP(server.Client(), server.URL).GetPublishDates(ctx, packages)
	}

	policy := supplychain.Policy{MinReleaseAge: 72 * time.Hour}
	res, err := runCheck(context.Background(), policy, filepath.Join("testdata", "valid-v3.json"), "", resolver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected 1 violation (express), got %d: %+v", len(res.Violations), res.Violations)
	}
	if res.Violations[0].Name != pkgExpress {
		t.Errorf("violation name = %q, want express", res.Violations[0].Name)
	}
}
