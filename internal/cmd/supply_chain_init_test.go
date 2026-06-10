package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/output"
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

// seedPMsOnPath creates a fresh dir, writes an executable stub for each given
// package-manager command name, and points $PATH at only that dir for the test.
// detectWrappablePMs scans $PATH (not lockfiles), so this is how a test controls
// which package managers it "finds installed". Restricting PATH to the seeded
// dir keeps detection deterministic — a real npm/pip on the developer's machine
// can't leak into the result.
//
// On Windows, exec.LookPath only resolves files matching PATHEXT (.exe, .cmd,
// etc.), so stubs are written with a ".exe" suffix. scanPathExecutables strips
// known PATHEXT extensions before applying the match, so pip3.12.exe is still
// recognized as "pip3.12" rather than losing the ".12" suffix.
func seedPMsOnPath(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		fname := name
		if runtime.GOOS == "windows" {
			fname = name + ".exe"
		}
		// 0o755 so the Unix execute-bit filter in scanPathExecutables accepts it;
		// the bit is ignored on Windows, where the file's mere presence suffices.
		if err := os.WriteFile(filepath.Join(dir, fname), []byte{}, 0o755); err != nil { //nolint:gosec // test stub on an isolated PATH
			t.Fatalf("seed %s: %v", fname, err)
		}
	}
	t.Setenv("PATH", dir)
}

func TestDetectWrappablePMs_DefaultsToNpm(t *testing.T) {
	// With no supported package manager on PATH, detectWrappablePMs must fall back
	// to npm (and its runner npx) rather than silently wrapping nothing — a one-off
	// `npx <pkg>` is exactly the case worth guarding even on a bare machine.
	seedPMsOnPath(t) // empty PATH dir: nothing installed
	chdirTemp(t)     // isolated cwd so no stray config scopes the result

	pms, installed := detectWrappablePMs()
	if len(pms) != 2 || pms[0] != "npm" || pms[1] != "npx" {
		t.Errorf("detectWrappablePMs() = %v, want [npm npx]", pms)
	}
	// Nothing on PATH means installed is empty — this is how the caller
	// distinguishes "nothing found" (npm fallback) from "scoped out" (nothing in
	// scope).
	if len(installed) != 0 {
		t.Errorf("detectWrappablePMs() installed = %v, want empty (nothing on PATH)", installed)
	}
}

// containsPM reports whether name is in the PM slice. Used by the npx pairing
// tests, which care about presence/absence rather than slice position.
func containsPM(pms []string, name string) bool {
	for _, p := range pms {
		if p == name {
			return true
		}
	}
	return false
}

func TestDetectWrappablePMs_PairsNpxWithNpm(t *testing.T) {
	// npm and npx both on PATH: npx must be wrapped alongside npm so ad-hoc
	// `npx <pkg>` runs are filtered through the same proxy.
	seedPMsOnPath(t, pmNPM, pmNPX)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	if !containsPM(pms, pmNPM) || !containsPM(pms, pmNPX) {
		t.Errorf("detectWrappablePMs() = %v, want both npm and npx", pms)
	}
}

func TestDetectWrappablePMs_NpxNotPairedWithoutNpm(t *testing.T) {
	// A machine with poetry but no npm never wraps npm, so npx must not appear:
	// the runner is paired only where npm itself is in scope.
	seedPMsOnPath(t, pmPoetry)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	if containsPM(pms, pmNPX) {
		t.Errorf("detectWrappablePMs() = %v, must not contain npx without npm", pms)
	}
}

func TestDetectWrappablePMs_NpxNotWrappedWhenAbsentFromPath(t *testing.T) {
	// npm on PATH but npx not installed: the pairing guard must prevent wrapping a
	// missing npx binary. Unconditionally wrapping it would shadow "command not found"
	// with an Armis wrapper error.
	seedPMsOnPath(t, pmNPM)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	if containsPM(pms, pmNPX) {
		t.Errorf("detectWrappablePMs() = %v, must not wrap npx when it is not on PATH", pms)
	}
}

func TestDetectWrappablePMs_NpxAbsentWhenNpmScopedOut(t *testing.T) {
	// npx is paired AFTER ecosystem scoping, so it must inherit npm's exclusion:
	// with npm and pnpm both on PATH but the config scoping enforcement to pnpm
	// only, npm is out of scope — and npx must follow it out, never wrapped on its
	// own. This pins the invariant explicitly; TestDetectWrappablePMs_HonorsEcosystemScope
	// only covers it implicitly via a length check that predates npx.
	seedPMsOnPath(t, pmNPM, pmPNPM)
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName),
		[]byte("version: 1\necosystems:\n  - pnpm\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pms, _ := detectWrappablePMs()
	if containsPM(pms, pmNPX) {
		t.Errorf("detectWrappablePMs() = %v, must not contain npx when npm is scoped out", pms)
	}
	if !containsPM(pms, pmPNPM) {
		t.Errorf("detectWrappablePMs() = %v, want pnpm (the in-scope PM)", pms)
	}
}

func TestDetectWrappablePMs_PairsUvxWithUv(t *testing.T) {
	// uv and uvx both on PATH: uvx must be wrapped alongside uv so ad-hoc
	// `uvx <tool>` runs are filtered through the same PyPI proxy.
	seedPMsOnPath(t, pmUV, pmUVX)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	if !containsPM(pms, pmUV) || !containsPM(pms, pmUVX) {
		t.Errorf("detectWrappablePMs() = %v, want both uv and uvx", pms)
	}
}

func TestDetectWrappablePMs_UvxNotPairedWithoutUv(t *testing.T) {
	// A machine with poetry but no uv never wraps uv, so uvx must not appear:
	// the runner is paired only where uv itself is in scope.
	seedPMsOnPath(t, pmPoetry)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	if containsPM(pms, pmUVX) {
		t.Errorf("detectWrappablePMs() = %v, must not contain uvx without uv", pms)
	}
}

func TestDetectWrappablePMs_UvxNotWrappedWhenAbsentFromPath(t *testing.T) {
	// uv on PATH but uvx not installed: the pairing guard must prevent wrapping a
	// missing uvx binary. Unconditionally wrapping it would shadow "command not found"
	// with an Armis wrapper error.
	seedPMsOnPath(t, pmUV)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	if containsPM(pms, pmUVX) {
		t.Errorf("detectWrappablePMs() = %v, must not wrap uvx when it is not on PATH", pms)
	}
}

func TestDetectWrappablePMs_UvxAbsentWhenUvScopedOut(t *testing.T) {
	// uvx is paired AFTER ecosystem scoping, so it must inherit uv's exclusion:
	// with uv and npm both on PATH but the config scoping enforcement to npm only,
	// uv is out of scope — and uvx must follow it out, never wrapped on its own.
	seedPMsOnPath(t, pmUV, pmNPM)
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName),
		[]byte("version: 1\necosystems:\n  - npm\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pms, _ := detectWrappablePMs()
	if containsPM(pms, pmUVX) {
		t.Errorf("detectWrappablePMs() = %v, must not contain uvx when uv is scoped out", pms)
	}
	if !containsPM(pms, pmNPM) {
		t.Errorf("detectWrappablePMs() = %v, want npm (the in-scope PM)", pms)
	}
}

func TestDetectWrappablePMs_HonorsEcosystemScope(t *testing.T) {
	// npm and pnpm are both on PATH but the config scopes enforcement to pnpm only,
	// so init must wrap only pnpm.
	seedPMsOnPath(t, pmNPM, pmPNPM)
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName),
		[]byte("version: 1\necosystems:\n  - pnpm\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pms, installed := detectWrappablePMs()
	if len(pms) != 1 || pms[0] != "pnpm" {
		t.Errorf("detectWrappablePMs() = %v, want [pnpm] (npm excluded by config scope)", pms)
	}
	// Both PMs are still reported as installed; scoping only narrows the wrapped
	// list, not what was found on PATH.
	if len(installed) != 2 {
		t.Errorf("detectWrappablePMs() installed = %v, want 2 PMs (npm + pnpm)", installed)
	}
}

// TestDetectWrappablePMs_AllScopedOut covers the case the npm fallback used to
// mask: package managers are installed but the config scopes enforcement away
// from every one. The PM list must come back empty (so the caller can report
// "nothing in scope") while the installed list still names what was found.
func TestDetectWrappablePMs_AllScopedOut(t *testing.T) {
	seedPMsOnPath(t, pmNPM)
	dir := chdirTemp(t)
	// Scope enforcement to pip only; the sole installed PM (npm) is excluded.
	if err := os.WriteFile(filepath.Join(dir, supplychain.ConfigFileName),
		[]byte("version: 1\necosystems:\n  - pip\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pms, installed := detectWrappablePMs()
	if len(pms) != 0 {
		t.Errorf("detectWrappablePMs() = %v, want empty (npm scoped out, no npm fallback)", pms)
	}
	if len(installed) != 1 || installed[0] != pmNPM {
		t.Errorf("detectWrappablePMs() installed = %v, want [npm]", installed)
	}
}

// TestDetectWrappablePMs_WrapsPipWhenInstalled is the regression for the bug that
// motivated PATH-based detection: pip on PATH must be wrapped even when the cwd
// has no Python lockfile (e.g. running init from a Go repo). Lockfile-based
// detection used to fall back to npm-only here, silently leaving every later
// `pip install` in any directory unguarded.
func TestDetectWrappablePMs_WrapsPipWhenInstalled(t *testing.T) {
	seedPMsOnPath(t, pmPip)
	chdirTemp(t) // no lockfile, no config — the exact "Go repo" scenario

	pms, _ := detectWrappablePMs()
	if !containsPM(pms, pmPip) {
		t.Errorf("detectWrappablePMs() = %v, want pip wrapped (it is on PATH)", pms)
	}
}

// TestDetectWrappablePMs_WrapsAllInstalled verifies init wraps every supported
// PM found on PATH, mixing Node and Python tools, regardless of the cwd's
// lockfiles. npx is paired in because npm is present.
func TestDetectWrappablePMs_WrapsAllInstalled(t *testing.T) {
	// npx is seeded alongside npm: it is paired with npm but only when present
	// on PATH, so the test must reflect that both are actually installed.
	seedPMsOnPath(t, pmNPM, pmNPX, pmYarn, pmPip, pmPoetry)
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	for _, want := range []string{pmNPM, pmNPX, pmYarn, pmPip, pmPoetry} {
		if !containsPM(pms, want) {
			t.Errorf("detectWrappablePMs() = %v, want %q wrapped", pms, want)
		}
	}
}

// TestDetectWrappablePMs_WrapsPipVariants verifies that versioned pip binaries
// (pip3, pip3.12) are each wrapped: a shell function only shadows the exact name
// the user types, so every interpreter's pip must get its own wrapper.
func TestDetectWrappablePMs_WrapsPipVariants(t *testing.T) {
	seedPMsOnPath(t, "pip3", "pip3.12")
	chdirTemp(t)

	pms, _ := detectWrappablePMs()
	for _, want := range []string{"pip3", "pip3.12"} {
		if !containsPM(pms, want) {
			t.Errorf("detectWrappablePMs() = %v, want pip variant %q wrapped", pms, want)
		}
	}
}

// TestSummarizeDetectedPMs covers the init preview summary line. forceNoColor
// (from supply_chain_wrap_summary_test.go, same package) pins the plain style
// set so the rendered string can be matched without ANSI escapes.
func TestSummarizeDetectedPMs(t *testing.T) {
	forceNoColor(t)
	s := output.GetStyles()

	tests := []struct {
		name string
		pms  []string
		want string
	}{
		{
			// The exact shape that prompted the change: many pip variants must
			// collapse to one "pip (N variants)" entry, and npx must be marked as
			// paired rather than listed as a bare detection.
			name: "pip variants collapse and npx is annotated",
			pms:  []string{"bun", "npm", "pnpm", "poetry", "uv", "pip", "pip3", "pip3.10", "pip3.11", "pip3.12", "npx"},
			want: "bun, npm, pnpm, poetry, uv, pip (5 variants), npx (paired with npm)",
		},
		{
			// A single pip binary carries no variant count — "(1 variant)" would be
			// noise.
			name: "single pip has no variant count",
			pms:  []string{"npm", "pip", "npx"},
			want: "npm, pip, npx (paired with npm)",
		},
		{
			// No npm means no npx; non-pip names sort alphabetically.
			name: "no npx without npm",
			pms:  []string{"poetry", "bun"},
			want: "bun, poetry",
		},
		{
			name: "pip only",
			pms:  []string{"pip3", "pip3.12"},
			want: "pip (2 variants)",
		},
		{
			// uvx is annotated "(paired with uv)" and trails the line, mirroring npx.
			// When both runners are present, npx precedes uvx (npm before uv).
			name: "uvx is annotated as paired with uv",
			pms:  []string{"uv", "npm", "uvx", "npx"},
			want: "npm, uv, npx (paired with npm), uvx (paired with uv)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarizeDetectedPMs(s, tt.pms); got != tt.want {
				t.Errorf("summarizeDetectedPMs(%v) = %q, want %q", tt.pms, got, tt.want)
			}
		})
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
