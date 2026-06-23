package supplychain

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestDirectDependencies_PackageJSONUnionsAllGroups(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{
		"dependencies": {"express": "^4.0.0"},
		"devDependencies": {"jest": "^29.0.0"},
		"peerDependencies": {"react": "^18.0.0"},
		"optionalDependencies": {"fsevents": "^2.0.0"}
	}`)

	names, ok := DirectDependencies(dir, EcosystemNPM)
	if !ok {
		t.Fatal("expected direct set to be determinable")
	}
	got := make(map[string]bool)
	for _, n := range names {
		got[n] = true
	}
	for _, want := range []string{"express", "jest", "react", "fsevents"} {
		if !got[want] {
			t.Errorf("missing %q from direct set %v", want, names)
		}
	}
}

func TestDirectDependencies_NoManifestUndeterminable(t *testing.T) {
	dir := t.TempDir()
	// No package.json anywhere up the tree we control — but the walk reaches the
	// real filesystem root. Use a deeply nested temp dir and accept that the only
	// guarantee is the bool reflects presence; assert the false path via a dir
	// with no manifest by checking a non-npm ecosystem instead (deterministic).
	if _, ok := DirectDependencies(dir, EcosystemMaven); ok {
		t.Error("maven (unsupported for direct-set) must be undeterminable → fail safe")
	}
}

func TestDirectDependencies_MalformedManifestUndeterminable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{ this is not json `)
	if _, ok := DirectDependencies(dir, EcosystemNPM); ok {
		t.Error("a malformed package.json must be undeterminable → fail safe (treat all as direct)")
	}
}

func TestDirectDependencies_EmptyManifestDeterminableButEmpty(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name": "app", "version": "1.0.0"}`)
	names, ok := DirectDependencies(dir, EcosystemNPM)
	if !ok {
		t.Fatal("a present, parseable manifest with no deps must be determinable")
	}
	if len(names) != 0 {
		t.Errorf("expected empty direct set; got %v", names)
	}
}

func TestParseTransitivePolicy_FailsSafe(t *testing.T) {
	tests := []struct {
		in   string
		want TransitivePolicy
	}{
		{"warn", TransitivePolicyWarn},
		{"WARN", TransitivePolicyWarn},
		{" warn ", TransitivePolicyWarn},
		{"block", TransitivePolicyBlock},
		{"", TransitivePolicyBlock},
		{"wrn", TransitivePolicyBlock},     // typo → block
		{"allow", TransitivePolicyBlock},   // unknown → block
		{"warning", TransitivePolicyBlock}, // not an exact match → block
	}
	for _, tt := range tests {
		if got := ParseTransitivePolicy(tt.in); got != tt.want {
			t.Errorf("ParseTransitivePolicy(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
