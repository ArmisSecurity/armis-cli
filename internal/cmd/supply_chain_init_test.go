package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

func TestExtractScope(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple scope", "@myorg/pkg", "@myorg"},
		{"uppercase legacy scope", "@MyOrg/pkg", "@MyOrg"},
		{"digits and dashes", "@org-1.2_x/pkg", "@org-1.2_x"},
		{"no slash", "@noslash", ""},
		{"empty scope", "@/pkg", ""},
		{"not a scope", "express", ""},
		{"invalid char", "@bad org/pkg", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractScope(tt.in); got != tt.want {
				t.Errorf("extractScope(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDetectOrgScopes_BoundsResults(t *testing.T) {
	tmpDir := t.TempDir()
	lockfile := filepath.Join(tmpDir, "package-lock.json")

	// Write far more distinct scopes than the cap so the bounding is exercised.
	var b strings.Builder
	total := maxDetectedScopes * 3
	for i := 0; i < total; i++ {
		fmt.Fprintf(&b, "\"@scope%04d/pkg\": {}\n", i)
	}
	if err := os.WriteFile(lockfile, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	ecosystems := []supplychain.DetectedEcosystem{
		{Ecosystem: supplychain.EcosystemNPM, LockfilePath: lockfile},
	}

	scopes := detectOrgScopes(ecosystems)
	if len(scopes) != maxDetectedScopes {
		t.Errorf("expected scope collection to be bounded at %d, got %d", maxDetectedScopes, len(scopes))
	}
}

func TestDetectOrgScopes_Deduplicates(t *testing.T) {
	tmpDir := t.TempDir()
	lockfile := filepath.Join(tmpDir, "package-lock.json")

	content := strings.Repeat("\"@myorg/a\": {}\n\"@myorg/b\": {}\n\"@other/c\": {}\n", 5)
	if err := os.WriteFile(lockfile, []byte(content), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	ecosystems := []supplychain.DetectedEcosystem{
		{Ecosystem: supplychain.EcosystemNPM, LockfilePath: lockfile},
	}

	scopes := detectOrgScopes(ecosystems)
	if len(scopes) != 2 {
		t.Fatalf("expected 2 distinct scopes, got %d: %v", len(scopes), scopes)
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		seen[s] = true
	}
	if !seen["@myorg"] || !seen["@other"] {
		t.Errorf("expected @myorg and @other, got %v", scopes)
	}
}

func TestDetectOrgScopes_SkipsYarn(t *testing.T) {
	tmpDir := t.TempDir()
	lockfile := filepath.Join(tmpDir, "yarn.lock")
	if err := os.WriteFile(lockfile, []byte("\"@myorg/pkg\": {}\n"), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	// detectOrgScopes only inspects npm/pnpm/bun lockfiles (yarn's format makes
	// the naive @-scan unreliable), so a yarn ecosystem should yield no scopes.
	ecosystems := []supplychain.DetectedEcosystem{
		{Ecosystem: supplychain.EcosystemYarn, LockfilePath: lockfile},
	}
	if scopes := detectOrgScopes(ecosystems); len(scopes) != 0 {
		t.Errorf("expected no scopes for yarn ecosystem, got %v", scopes)
	}
}
