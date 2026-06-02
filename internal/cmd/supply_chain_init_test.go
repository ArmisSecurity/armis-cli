package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

func TestReadYesNo(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		defaultYes bool
		want       bool
	}{
		{"explicit yes", "y\n", true, true},
		{"explicit yes word", "yes\n", false, true},
		{"uppercase yes", "Y\n", true, true},
		{"explicit no", "n\n", true, false},
		{"explicit no word", "no\n", true, false},
		{"empty accepts default true", "\n", true, true},
		{"empty accepts default false", "\n", false, false},
		{"whitespace accepts default", "   \n", true, true},
		{"yes without trailing newline (Ctrl-D)", "y", true, true},
		{"unrecognized answer is not consent", "maybe\n", true, false},
		// Closed/empty stream must fail closed regardless of the default so a
		// non-interactive context can never auto-confirm a destructive action.
		{"closed stream fails closed (default yes)", "", true, false},
		{"closed stream fails closed (default no)", "", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readYesNo(strings.NewReader(tt.input), tt.defaultYes)
			if got != tt.want {
				t.Errorf("readYesNo(%q, default=%v) = %v, want %v", tt.input, tt.defaultYes, got, tt.want)
			}
		})
	}
}

func TestDetectWrappablePMs_DefaultsToNpm(t *testing.T) {
	// In a directory with no lockfiles, DetectEcosystems errors; detectWrappablePMs
	// must fall back to npm rather than silently wrapping nothing.
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(cwd) //nolint:errcheck
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	pms := detectWrappablePMs()
	if len(pms) != 1 || pms[0] != "npm" {
		t.Errorf("detectWrappablePMs() = %v, want [npm]", pms)
	}
}

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
