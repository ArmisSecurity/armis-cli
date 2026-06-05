package cmd

import (
	"fmt"
	"io"
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

// TestReadYesNoBoundsInput ensures a pathologically large stdin (e.g. a file
// piped into the program) cannot force an unbounded read: readYesNo reads at
// most maxPromptInput bytes via io.LimitReader. We feed it far more than the
// cap with no newline; the read returns the truncated prefix rather than
// consuming the whole stream, and the answer is not parsed as consent.
func TestReadYesNoBoundsInput(t *testing.T) {
	// 1MB of 'y' with no newline — without the cap this would all be buffered.
	huge := strings.Repeat("y", 1<<20)

	// A reader that records how many bytes were actually pulled so we can assert
	// the read stopped at the cap instead of draining the entire stream.
	counting := &countingReader{r: strings.NewReader(huge)}

	got := readYesNo(counting, true)

	if counting.n > maxPromptInput {
		t.Errorf("read %d bytes, want at most %d (input must be bounded)", counting.n, maxPromptInput)
	}
	// The truncated 4KB block of 'y' is a single unrecognized token (no newline,
	// no "y"/"yes" match), so it must not be treated as affirmative consent.
	if got {
		t.Errorf("oversized run-on input must not be parsed as consent, got %v", got)
	}
}

// countingReader wraps a reader and tallies bytes read, letting a test assert
// that a consumer stops at a byte bound rather than draining the source.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
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

	pms, detected := detectWrappablePMs()
	if len(pms) != 1 || pms[0] != "npm" {
		t.Errorf("detectWrappablePMs() = %v, want [npm]", pms)
	}
	// No lockfiles means DetectEcosystems errored, so the detected list is empty —
	// this is how the caller distinguishes "no lockfiles" (npm fallback) from
	// "scoped out" (nothing in scope).
	if len(detected) != 0 {
		t.Errorf("detectWrappablePMs() detected = %v, want empty (no lockfiles)", detected)
	}
}

func TestDetectWrappablePMs_HonorsEcosystemScope(t *testing.T) {
	// Two lockfiles are present (npm + pnpm) but the config scopes enforcement to
	// pnpm only, so init must wrap only pnpm.
	dir := chdirTemp(t)
	for _, f := range []string{"package-lock.json", "pnpm-lock.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName),
		[]byte("version: 1\necosystems:\n  - pnpm\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pms, detected := detectWrappablePMs()
	if len(pms) != 1 || pms[0] != "pnpm" {
		t.Errorf("detectWrappablePMs() = %v, want [pnpm] (npm excluded by config scope)", pms)
	}
	// Both lockfiles are still reported as detected; scoping only narrows the PM
	// list, not what was found on disk.
	if len(detected) != 2 {
		t.Errorf("detectWrappablePMs() detected = %v, want 2 ecosystems (npm + pnpm)", detected)
	}
}

// TestDetectWrappablePMs_AllScopedOut covers the case the npm fallback used to
// mask: lockfiles exist but the config scopes enforcement away from every one.
// The PM list must come back empty (so the caller can report "nothing in
// scope") while the detected list still names what was found.
func TestDetectWrappablePMs_AllScopedOut(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Scope enforcement to pip only; the sole detected ecosystem (npm) is excluded.
	if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName),
		[]byte("version: 1\necosystems:\n  - pip\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pms, detected := detectWrappablePMs()
	if len(pms) != 0 {
		t.Errorf("detectWrappablePMs() = %v, want empty (npm scoped out, no npm fallback)", pms)
	}
	if len(detected) != 1 || detected[0].Ecosystem != supplychain.EcosystemNPM {
		t.Errorf("detectWrappablePMs() detected = %v, want [npm]", detected)
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

// chdirTemp switches into a fresh temp dir for the duration of the test and
// restores the original cwd on cleanup. runInitNpmrc operates on ".npmrc" in
// the working directory, so each case needs an isolated dir.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	return dir
}

func TestRunInitNpmrc_PrependsNewline(t *testing.T) {
	const marker = "armis-cli supply-chain"

	tests := []struct {
		name    string
		initial string // existing .npmrc content; "" means no file
		// wantOriginalIntact asserts the original content is preserved verbatim
		// at the front (so npm never reads a corrupted "foo=bar# armis..." entry).
		wantOriginalIntact bool
	}{
		{name: "no existing file", initial: "", wantOriginalIntact: false},
		{name: "trailing newline present", initial: "foo=bar\n", wantOriginalIntact: true},
		{name: "no trailing newline", initial: "foo=bar", wantOriginalIntact: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chdirTemp(t)
			scInitDryRun = false
			t.Cleanup(func() { scInitDryRun = false })

			if tt.initial != "" {
				if err := os.WriteFile(".npmrc", []byte(tt.initial), 0o600); err != nil {
					t.Fatalf("seed .npmrc: %v", err)
				}
			}

			if err := runInitNpmrc(); err != nil {
				t.Fatalf("runInitNpmrc: %v", err)
			}

			got, err := os.ReadFile(".npmrc")
			if err != nil {
				t.Fatalf("read .npmrc: %v", err)
			}
			content := string(got)

			if !strings.Contains(content, marker) {
				t.Fatalf("expected marker comment in .npmrc, got %q", content)
			}

			// The original content must survive untouched at the front.
			if tt.wantOriginalIntact && !strings.HasPrefix(content, tt.initial) {
				t.Errorf("original content not preserved: got %q, want prefix %q", content, tt.initial)
			}

			// The crux of the fix: the appended comment must start a new line, so
			// the last original entry is never corrupted by concatenation.
			markerIdx := strings.Index(content, "#")
			if markerIdx > 0 && content[markerIdx-1] != '\n' {
				t.Errorf("comment must begin on its own line; byte before '#' was %q in %q", content[markerIdx-1], content)
			}
		})
	}
}

func TestRunInitNpmrc_Idempotent(t *testing.T) {
	chdirTemp(t)
	scInitDryRun = false
	t.Cleanup(func() { scInitDryRun = false })

	if err := runInitNpmrc(); err != nil {
		t.Fatalf("first runInitNpmrc: %v", err)
	}
	first, err := os.ReadFile(".npmrc")
	if err != nil {
		t.Fatalf("read after first run: %v", err)
	}

	// A second invocation must detect the existing marker and leave the file
	// unchanged rather than appending a duplicate comment.
	if err := runInitNpmrc(); err != nil {
		t.Fatalf("second runInitNpmrc: %v", err)
	}
	second, err := os.ReadFile(".npmrc")
	if err != nil {
		t.Fatalf("read after second run: %v", err)
	}

	if string(first) != string(second) {
		t.Errorf("runInitNpmrc not idempotent:\nfirst:  %q\nsecond: %q", first, second)
	}
	if strings.Count(string(second), "armis-cli supply-chain") != 1 {
		t.Errorf("expected exactly one marker comment, got %q", second)
	}
}
