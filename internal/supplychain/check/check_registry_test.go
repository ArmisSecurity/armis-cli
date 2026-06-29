package check

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/registry"
)

// TestDetectRegistryDivergence is test-plan case #12: flag npm-family packages
// resolved from a non-approved registry.
func TestDetectRegistryDivergence(t *testing.T) {
	const approved = "https://nexus.corp/repository/npm-group/"

	t.Run("flags off-registry package", func(t *testing.T) {
		entries := []PackageEntry{
			{Name: "express", Version: "4.18.2", Resolved: "https://nexus.corp/repository/npm-group/express/-/express-4.18.2.tgz"},
			{Name: "evil", Version: "1.0.0", Resolved: "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"},
		}
		vios, checked := detectRegistryDivergence(supplychain.EcosystemNPM, entries, approved)
		if checked != 2 {
			t.Errorf("checked = %d, want 2", checked)
		}
		if len(vios) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(vios))
		}
		if vios[0].Name != "evil" || vios[0].ResolvedHost != "registry.npmjs.org" {
			t.Errorf("unexpected violation: %+v", vios[0])
		}
	})

	t.Run("all approved → no violations", func(t *testing.T) {
		entries := []PackageEntry{
			{Name: "express", Version: "4.18.2", Resolved: "https://nexus.corp/repository/npm-group/express/-/express-4.18.2.tgz"},
		}
		vios, checked := detectRegistryDivergence(supplychain.EcosystemNPM, entries, approved)
		if len(vios) != 0 || checked != 1 {
			t.Errorf("expected 0 violations / 1 checked, got %d / %d", len(vios), checked)
		}
	})

	t.Run("packages with no resolved URL are not counted", func(t *testing.T) {
		entries := []PackageEntry{
			{Name: "noresolve", Version: "1.0.0", Resolved: ""},
		}
		vios, checked := detectRegistryDivergence(supplychain.EcosystemNPM, entries, approved)
		if len(vios) != 0 || checked != 0 {
			t.Errorf("a package with no resolved URL must not be counted, got %d / %d", len(vios), checked)
		}
	})

	t.Run("non-npm ecosystem is never checked", func(t *testing.T) {
		entries := []PackageEntry{{Name: "requests", Version: "2.0", Resolved: "https://files.pythonhosted.org/x"}}
		vios, checked := detectRegistryDivergence(supplychain.EcosystemPip, entries, approved)
		if vios != nil || checked != 0 {
			t.Errorf("PyPI must not be registry-checked in v1, got %d / %d", len(vios), checked)
		}
	})

	t.Run("empty registryURL is a no-op", func(t *testing.T) {
		entries := []PackageEntry{{Name: "express", Version: "4.18.2", Resolved: "https://registry.npmjs.org/x"}}
		vios, checked := detectRegistryDivergence(supplychain.EcosystemNPM, entries, "")
		if vios != nil || checked != 0 {
			t.Errorf("no registryURL → no divergence check, got %d / %d", len(vios), checked)
		}
	})
}

// TestRunCheckWithRegistryFlagsDivergence wires the divergence check through
// RunCheckWithRegistry against a real npm lockfile fixture.
func TestRunCheckWithRegistryFlagsDivergence(t *testing.T) {
	// Build a v3 package-lock with one approved and one public-registry package.
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/approved": {"version": "1.0.0", "resolved": "https://nexus.corp/repository/npm-group/approved/-/approved-1.0.0.tgz"},
    "node_modules/leaked":   {"version": "2.0.0", "resolved": "https://registry.npmjs.org/leaked/-/leaked-2.0.0.tgz"}
  }
}`
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}

	// A registry server that dates both packages old (so age is not the variable
	// under test — divergence is).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"time":{"1.0.0":"2020-01-01T00:00:00Z","2.0.0":"2020-01-01T00:00:00Z"}}`) //nolint:errcheck
	}))
	defer server.Close()

	policy := supplychain.Policy{MinReleaseAge: 72 * time.Hour}
	// Use the internal runCheck with an injected resolver + the approved URL so
	// the test does not depend on the real npmjs.org.
	resolver := queryRegistryWithURL(server.URL)
	res, err := runCheck(context.Background(), policy, lockPath, "", resolver, "https://nexus.corp/repository/npm-group/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.RegistryViolations) != 1 {
		t.Fatalf("expected 1 registry violation, got %d: %+v", len(res.RegistryViolations), res.RegistryViolations)
	}
	if res.RegistryViolations[0].Name != "leaked" {
		t.Errorf("expected 'leaked' flagged, got %q", res.RegistryViolations[0].Name)
	}
	if res.RegistryChecked != 2 {
		t.Errorf("RegistryChecked = %d, want 2", res.RegistryChecked)
	}
}

// TestQueryRegistryWithURLHitsConfiguredHost is test-plan case #11: the
// configured RegistryURL is the host actually queried, not npmjs.org.
func TestQueryRegistryWithURLHitsConfiguredHost(t *testing.T) {
	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"time":{"1.0.0":"2020-01-01T00:00:00Z"}}`) //nolint:errcheck
	}))
	defer server.Close()

	fn := queryRegistryWithURL(server.URL)
	results := fn(context.Background(), supplychain.EcosystemNPM, []registry.PackageRequest{{Name: "leftpad", Version: "1.0.0"}})
	if !hit {
		t.Fatal("the configured registry host was not queried")
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
}
