package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

// seedShellInjection points $HOME at a fresh temp dir, writes a .bashrc carrying
// a real supply-chain injection block (via the public InjectFunctions API so the
// test exercises the genuine inject→uninit round-trip), and returns the RC path.
// $SHELL is cleared so DetectShells keys purely on which RC files exist, keeping
// the test independent of the shell CI runs under.
// Windows is skipped: DetectShells resolves RC paths from os.UserHomeDir(), which
// honors $HOME on Unix but not on Windows (same constraint as shell_test.go:456).
func seedShellInjection(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("DetectShells home-dir resolution is exercised via $HOME, which is Unix-only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "")

	rc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(rc, []byte("# user config\nexport FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("seed .bashrc: %v", err)
	}
	shells := supplychain.DetectShells()
	if len(shells) == 0 {
		t.Fatal("DetectShells found nothing after seeding .bashrc")
	}
	if _, err := supplychain.InjectFunctions(shells, []string{"npm"}); err != nil {
		t.Fatalf("InjectFunctions: %v", err)
	}
	if !supplychain.HasInjection(rc) {
		t.Fatal("expected injection in seeded .bashrc")
	}
	return rc
}

// TestRunSupplyChainUninit_DryRunWritesNothing verifies the #15 CI escape hatch:
// --dry-run previews the targets and exits 0 without modifying any file.
func TestRunSupplyChainUninit_DryRunWritesNothing(t *testing.T) {
	forceNoColor(t)
	rc := seedShellInjection(t)
	dir := chdirTemp(t)
	npmrc := filepath.Join(dir, supplychain.NpmrcFileName)
	if err := os.WriteFile(npmrc, []byte(supplychain.NpmrcMarkerComment+"\n"), 0o600); err != nil {
		t.Fatalf("seed .npmrc: %v", err)
	}

	rcBefore := readCmdFile(t, rc)
	npmrcBefore := readCmdFile(t, npmrc)

	origDryRun, origYes := scUninitDryRun, scUninitYes
	t.Cleanup(func() { scUninitDryRun, scUninitYes = origDryRun, origYes })
	scUninitDryRun, scUninitYes = true, false

	out := captureStderr(t, func() {
		if err := runSupplyChainUninit(scUninitCmd, nil); err != nil {
			t.Fatalf("runSupplyChainUninit: %v", err)
		}
	})

	if !strings.Contains(out, "dry-run") {
		t.Errorf("dry-run output missing the dry-run notice:\n%s", out)
	}
	// The preview block (file paths) is the informative half of --dry-run;
	// asserting only the "dry-run" notice would still pass if it were deleted.
	if !strings.Contains(out, rc) {
		t.Errorf("dry-run preview missing the RC file path %q:\n%s", rc, out)
	}
	if !strings.Contains(out, supplychain.NpmrcFileName) {
		t.Errorf("dry-run preview missing the .npmrc target:\n%s", out)
	}
	if got := readCmdFile(t, rc); got != rcBefore {
		t.Errorf(".bashrc modified during dry-run:\n%s", got)
	}
	if got := readCmdFile(t, npmrc); got != npmrcBefore {
		t.Errorf(".npmrc modified during dry-run:\n%s", got)
	}
}

// TestRunSupplyChainUninit_NpmrcOnly covers the path a user reaches after running
// `init --mode npmrc` with no shell wrappers: rcTargets is empty, only the .npmrc
// marker is present. The marker must be stripped (real config preserved) and the
// closing message must omit the "Restart your shell" hint, since no RC changed.
func TestRunSupplyChainUninit_NpmrcOnly(t *testing.T) {
	forceNoColor(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "")
	dir := chdirTemp(t)
	npmrc := filepath.Join(dir, supplychain.NpmrcFileName)
	if err := os.WriteFile(npmrc, []byte("registry=https://example.com/\n"+supplychain.NpmrcMarkerComment+"\n"), 0o600); err != nil {
		t.Fatalf("seed .npmrc: %v", err)
	}

	origDryRun, origYes := scUninitDryRun, scUninitYes
	t.Cleanup(func() { scUninitDryRun, scUninitYes = origDryRun, origYes })
	scUninitDryRun, scUninitYes = false, true

	out := captureStderr(t, func() {
		if err := runSupplyChainUninit(scUninitCmd, nil); err != nil {
			t.Fatalf("runSupplyChainUninit: %v", err)
		}
	})

	if supplychain.NpmrcFileHasMarker(npmrc) {
		t.Errorf(".npmrc still has the marker after npmrc-only uninit --yes")
	}
	if got := readCmdFile(t, npmrc); !strings.Contains(got, "registry=https://example.com/") {
		t.Errorf(".npmrc lost its real config: %q", got)
	}
	if !strings.Contains(out, "Done!") {
		t.Errorf("expected a Done! notice, got:\n%s", out)
	}
	// No RC file changed, so the shell-reload hint must not appear.
	if strings.Contains(out, "Restart your shell") {
		t.Errorf("npmrc-only uninit should not tell the user to restart their shell:\n%s", out)
	}
}

// TestRunSupplyChainUninit_YesRemovesBoth verifies that --yes performs the
// removal non-interactively, cleaning both the shell RC injection (#15) and the
// .npmrc marker (#14) in one pass.
func TestRunSupplyChainUninit_YesRemovesBoth(t *testing.T) {
	forceNoColor(t)
	rc := seedShellInjection(t)
	dir := chdirTemp(t)
	npmrc := filepath.Join(dir, supplychain.NpmrcFileName)
	if err := os.WriteFile(npmrc, []byte("registry=https://example.com/\n"+supplychain.NpmrcMarkerComment+"\n"), 0o600); err != nil {
		t.Fatalf("seed .npmrc: %v", err)
	}

	origDryRun, origYes := scUninitDryRun, scUninitYes
	t.Cleanup(func() { scUninitDryRun, scUninitYes = origDryRun, origYes })
	scUninitDryRun, scUninitYes = false, true

	if err := runSupplyChainUninit(scUninitCmd, nil); err != nil {
		t.Fatalf("runSupplyChainUninit: %v", err)
	}

	if supplychain.HasInjection(rc) {
		t.Errorf(".bashrc still has an injection block after uninit --yes")
	}
	if supplychain.NpmrcFileHasMarker(npmrc) {
		t.Errorf(".npmrc still has the marker after uninit --yes")
	}
	// Non-marker config must survive.
	if got := readCmdFile(t, npmrc); !strings.Contains(got, "registry=https://example.com/") {
		t.Errorf(".npmrc lost its real config: %q", got)
	}
}

// TestRunSupplyChainUninit_NothingToDo verifies the clean exit when there is no
// injection and no marker — no prompt, no error.
func TestRunSupplyChainUninit_NothingToDo(t *testing.T) {
	forceNoColor(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "")
	chdirTemp(t)

	origDryRun, origYes := scUninitDryRun, scUninitYes
	t.Cleanup(func() { scUninitDryRun, scUninitYes = origDryRun, origYes })
	scUninitDryRun, scUninitYes = false, false

	out := captureStderr(t, func() {
		if err := runSupplyChainUninit(scUninitCmd, nil); err != nil {
			t.Fatalf("runSupplyChainUninit: %v", err)
		}
	})
	if !strings.Contains(out, "No armis-cli supply-chain changes found") {
		t.Errorf("expected a nothing-to-do notice, got:\n%s", out)
	}
}

// TestSupplyChainUninitFlagsRegistered guards #15: the real scUninitCmd built by
// init() must expose --dry-run and --yes.
func TestSupplyChainUninitFlagsRegistered(t *testing.T) {
	for _, name := range []string{"dry-run", "yes"} {
		if scUninitCmd.Flags().Lookup(name) == nil {
			t.Errorf("supply-chain uninit must register the --%s flag", name)
		}
	}
}

// TestSupplyChainUninitShortScoped guards #32: the Short must describe shell
// wrappers, not the broader "package age enforcement" it does not control.
func TestSupplyChainUninitShortScoped(t *testing.T) {
	if strings.Contains(scUninitCmd.Short, "package age enforcement") {
		t.Errorf("uninit Short still overstates scope: %q", scUninitCmd.Short)
	}
	if !strings.Contains(scUninitCmd.Short, "shell wrapper") {
		t.Errorf("uninit Short should mention shell wrappers: %q", scUninitCmd.Short)
	}
}

func readCmdFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
