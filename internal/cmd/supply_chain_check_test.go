package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

// newResolvePolicyCmd builds a throwaway command with the same flags resolvePolicy
// inspects, bound to the package-level vars. The bool return reports whether
// --fail-open was marked as explicitly set.
func newResolvePolicyCmd(failOpenSet bool) *cobra.Command {
	cmd := &cobra.Command{Use: "check"}
	cmd.Flags().StringVar(&scMinAge, "min-age", "72h", "")
	cmd.Flags().StringSliceVar(&scExclude, "exclude", nil, "")
	cmd.Flags().BoolVar(&scFailOpen, "fail-open", false, "")
	if failOpenSet {
		_ = cmd.Flags().Set("fail-open", "true")
	}
	return cmd
}

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	path := filepath.Join(dir, supplychain.ConfigFileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestResolvePolicy_FailOpenFromConfig(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "version: 1\nfail-open: true\n")

	// Reset package var to its default so a prior test can't leak state in.
	scFailOpen = false
	cmd := newResolvePolicyCmd(false) // user did NOT pass --fail-open

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		t.Fatalf("resolvePolicy: %v", err)
	}
	if !policy.FailOpen {
		t.Error("config fail-open: true should propagate to policy.FailOpen")
	}
	// The package var must remain untouched — the old code mutated it as a side
	// effect, which leaked across invocations within the same process.
	if scFailOpen {
		t.Error("resolvePolicy must not mutate the package-level scFailOpen var")
	}
}

func TestResolvePolicy_FlagOverridesConfigFalse(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "version: 1\nfail-open: false\n")

	scFailOpen = true                // simulate --fail-open=true on the CLI
	cmd := newResolvePolicyCmd(true) // explicitly set

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		t.Fatalf("resolvePolicy: %v", err)
	}
	if !policy.FailOpen {
		t.Error("explicit --fail-open should override config fail-open: false")
	}
}

func TestResolvePolicy_DefaultNoFailOpen(t *testing.T) {
	dir := t.TempDir() // no config file present

	scFailOpen = false
	cmd := newResolvePolicyCmd(false)

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		t.Fatalf("resolvePolicy: %v", err)
	}
	if policy.FailOpen {
		t.Error("policy.FailOpen should default to false with no config and no flag")
	}
}

// initGitRepoWithOriginMain creates a bare "origin" repo and a working clone in
// which lockfileName has been committed and pushed to origin/main. It returns
// the clone's working directory so a test can call detectBaseLockfile against a
// path inside it. The helper skips the test if git is unavailable.
func initGitRepoWithOriginMain(t *testing.T, lockfileName, content string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}

	root := t.TempDir()
	clone := filepath.Join(root, "repo")

	mustGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) // #nosec G204 -- test helper, controlled args
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
		}
	}

	// Build a working repo, commit the lockfile on main, then point an "origin"
	// remote at the repo itself and fetch so that the origin/main remote-tracking
	// ref detectBaseLockfile reads resolves to the committed content. Using the
	// repo as its own origin avoids a separate bare repo and a network push.
	mustGit(root, "init", "-b", "main", clone)
	mustGit(clone, "config", "user.email", "test@example.com")
	mustGit(clone, "config", "user.name", "Test")

	if err := os.WriteFile(filepath.Join(clone, lockfileName), []byte(content), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	mustGit(clone, "add", lockfileName)
	mustGit(clone, "commit", "-m", "add lockfile")
	mustGit(clone, "remote", "add", "origin", clone)
	mustGit(clone, "fetch", "origin")

	// Resolve symlinks so the returned path matches what `git rev-parse
	// --show-toplevel` reports. On macOS t.TempDir() lives under /var which is a
	// symlink to /private/var; without this, detectBaseLockfile's filepath.Rel
	// would yield a "../"-prefixed path and the traversal guard would reject it.
	resolved, err := filepath.EvalSymlinks(clone)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	return resolved
}

func TestDetectBaseLockfile_NotAGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	dir := t.TempDir()
	if got := detectBaseLockfile(context.Background(), filepath.Join(dir, "package-lock.json")); got != "" {
		t.Errorf("detectBaseLockfile in non-repo = %q, want empty", got)
	}
}

func TestDetectBaseLockfile_NoOriginMain(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	dir := t.TempDir()
	if err := runTestGitCmd(dir, "init", "-b", "main"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	// A repo with no origin remote: neither origin/main nor origin/master
	// resolves, so detection yields no base file.
	if got := detectBaseLockfile(context.Background(), filepath.Join(dir, "package-lock.json")); got != "" {
		t.Errorf("detectBaseLockfile with no origin = %q, want empty", got)
	}
}

func TestDetectBaseLockfile_FromOriginMain(t *testing.T) {
	const content = `{"lockfileVersion":3,"packages":{}}`
	clone := initGitRepoWithOriginMain(t, "package-lock.json", content)

	base := detectBaseLockfile(context.Background(), filepath.Join(clone, "package-lock.json"))
	if base == "" {
		t.Fatal("expected a base lockfile temp path, got empty")
	}
	t.Cleanup(func() { _ = os.Remove(base) })

	got, err := os.ReadFile(base) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read base lockfile: %v", err)
	}
	if string(got) != content {
		t.Errorf("base lockfile content = %q, want %q", got, content)
	}
	// The temp file should carry the lockfile's extension so downstream
	// ecosystem detection (which is suffix-based) classifies it correctly.
	if filepath.Ext(base) != ".json" {
		t.Errorf("base temp file ext = %q, want .json", filepath.Ext(base))
	}
}

func TestDetectBaseLockfile_LockfileNotInOriginMain(t *testing.T) {
	// origin/main has a package-lock.json, but the caller asks about a different
	// lockfile that was never committed. `git show origin/main:<path>` fails for
	// it, so both ref candidates fall through and detection returns empty rather
	// than fabricating a base.
	clone := initGitRepoWithOriginMain(t, "package-lock.json", `{"packages":{}}`)

	uncommitted := filepath.Join(clone, "pnpm-lock.yaml")
	if err := os.WriteFile(uncommitted, []byte("lockfileVersion: '9.0'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectBaseLockfile(context.Background(), uncommitted); got != "" {
		_ = os.Remove(got)
		t.Errorf("detectBaseLockfile for lockfile absent from origin/main = %q, want empty", got)
	}
}

func TestDetectBaseLockfile_CanceledContext(t *testing.T) {
	// An already-canceled context must short-circuit the git subprocesses (each
	// runs under exec.CommandContext), so detection returns empty promptly rather
	// than running git to completion. This guards the timeout wiring.
	clone := initGitRepoWithOriginMain(t, "package-lock.json", `{"packages":{}}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	got := detectBaseLockfile(ctx, filepath.Join(clone, "package-lock.json"))
	if got != "" {
		_ = os.Remove(got)
		t.Errorf("detectBaseLockfile with canceled context = %q, want empty", got)
	}
	if elapsed := time.Since(start); elapsed > baseDetectGitTimeout {
		t.Errorf("detection took %v, expected to short-circuit well under the %v timeout", elapsed, baseDetectGitTimeout)
	}
}

func TestRunSupplyChainCheck_EcosystemScopeSkips(t *testing.T) {
	// Config scopes enforcement to pip only; a check against a package-lock.json
	// (npm) must skip the audit and return cleanly without querying any registry.
	// If the gate did not fire, RunCheck would attempt npm registry lookups.
	dir := chdirTemp(t)
	writeConfig(t, dir, "version: 1\necosystems:\n  - pip\n")
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Save/restore the package-level flag vars the check command reads.
	origLockfile, origAll, origMinAge, origFormat := scLockfile, scAll, scMinAge, format
	t.Cleanup(func() {
		scLockfile, scAll, scMinAge, format = origLockfile, origAll, origMinAge, origFormat
	})
	scLockfile = "package-lock.json"
	scAll = true // skip base-lockfile git detection
	scMinAge = "72h"
	format = "json"

	cmd := newWrapTestCmd() // a command with a live context
	cmd.Flags().StringVar(&scMinAge, "min-age", "72h", "")
	cmd.Flags().StringSliceVar(&scExclude, "exclude", nil, "")
	cmd.Flags().BoolVar(&scFailOpen, "fail-open", false, "")

	if err := runSupplyChainCheck(cmd, []string{"."}); err != nil {
		t.Fatalf("expected clean skip, got error: %v", err)
	}
}

// TestRunSupplyChainCheck_OutputFlagWritesFile verifies the --output flag is
// honored end-to-end: results are written to the named file (not stdout) and
// the format is auto-detected from the extension. An empty lockfile yields zero
// packages to check, so RunCheck short-circuits before any registry query while
// the full output pipeline (ResolveOutput → formatter → file) still runs. This
// is the path that was silently dead before --output was registered on the
// supply-chain check command.
func TestRunSupplyChainCheck_OutputFlagWritesFile(t *testing.T) {
	dir := chdirTemp(t)
	// An npm lockfile with no packages: nothing to check, no network access.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "report.sarif")

	// Save/restore every package-level var the check command reads so this test
	// can't leak state into others sharing the cmd package.
	origLockfile, origAll, origMinAge, origFormat, origOutput, origFailOn :=
		scLockfile, scAll, scMinAge, format, outputFile, failOn
	t.Cleanup(func() {
		scLockfile, scAll, scMinAge, format, outputFile, failOn =
			origLockfile, origAll, origMinAge, origFormat, origOutput, origFailOn
	})
	scLockfile = "package-lock.json"
	scAll = true // skip base-lockfile git detection
	scMinAge = "72h"
	format = "human" // left at default; extension should override to SARIF
	failOn = []string{"CRITICAL"}

	cmd := newWrapTestCmd() // command with a live context
	cmd.Flags().StringVar(&scMinAge, "min-age", "72h", "")
	cmd.Flags().StringSliceVar(&scExclude, "exclude", nil, "")
	cmd.Flags().BoolVar(&scFailOpen, "fail-open", false, "")
	// --format must exist (unchanged) so ResolveOutput can consult its .Changed
	// state to decide whether to auto-detect the format from the extension.
	cmd.Flags().StringVarP(&format, "format", "f", "human", "")
	// Register -o/--output bound to outputFile exactly as init() does, then drive
	// the value through the flag (not a direct outputFile = outPath assignment).
	// This exercises the flag→var binding the PR adds: if the flag were not bound
	// to outputFile, .Set would not reach the var ResolveOutput reads and the file
	// would never be written. (Registration on the real scCheckCmd is guarded
	// separately by TestSupplyChainCheckOutputFlagRegistered.)
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "")
	if err := cmd.Flags().Set("output", outPath); err != nil {
		t.Fatalf("set --output: %v", err)
	}

	if err := runSupplyChainCheck(cmd, []string{"."}); err != nil {
		t.Fatalf("runSupplyChainCheck: %v", err)
	}

	data, err := os.ReadFile(outPath) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("expected output written to %s: %v", outPath, err)
	}
	content := string(data)
	// Format auto-detected from the .sarif extension: a SARIF document carries a
	// $schema and runs array. If --output were ignored, the file would not exist;
	// if extension detection failed, this would be human-styled text instead.
	if !strings.Contains(content, "$schema") || !strings.Contains(content, "runs") {
		t.Errorf("output file does not look like SARIF (extension auto-detection failed):\n%s", content)
	}
}

// TestRunSupplyChainCheck_FailOnValidatedFirst verifies --fail-on is validated at
// the very top of runSupplyChainCheck, before lockfile detection and the scan
// (PPSC-1006 #11). With a bogus --fail-on AND no lockfile present, the error must
// be the fail-on validation error, not "no lockfile detected" — proving the
// validation runs first and no scan output is produced.
func TestRunSupplyChainCheck_FailOnValidatedFirst(t *testing.T) {
	chdirTemp(t) // empty dir: no lockfile, no network

	origAll, origFailOn := scAll, failOn
	t.Cleanup(func() { scAll, failOn = origAll, origFailOn })
	scAll = true
	failOn = []string{"bogus"}

	cmd := newWrapTestCmd()
	err := runSupplyChainCheck(cmd, []string{"."})
	if err == nil {
		t.Fatal("expected error for invalid --fail-on")
	}
	if !strings.Contains(err.Error(), "invalid severity level") {
		t.Errorf("expected fail-on validation error to fire before lockfile detection, got: %v", err)
	}
	if strings.Contains(err.Error(), "no lockfile detected") {
		t.Errorf("--fail-on must be validated before lockfile detection, got: %v", err)
	}
}

// TestSupplyChainCheckOutputFlagRegistered guards the exact regression this PR
// fixes: the real scCheckCmd (built by init()) must expose -o/--output bound to
// the outputFile var that runSupplyChainCheck reads. Unlike the functional test
// above — which constructs its own command — this asserts against the package's
// actual command, so it fails if init() ever stops registering the flag, binds
// it to the wrong variable, or drops the -o shorthand.
func TestSupplyChainCheckOutputFlagRegistered(t *testing.T) {
	f := scCheckCmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("supply-chain check must register the --output flag")
	}
	if f.Shorthand != "o" {
		t.Errorf("--output shorthand = %q, want %q", f.Shorthand, "o")
	}

	// Setting the flag must reach the outputFile var runSupplyChainCheck reads.
	orig := outputFile
	t.Cleanup(func() {
		outputFile = orig
		_ = f.Value.Set(orig)
	})
	if err := scCheckCmd.Flags().Set("output", "out.sarif"); err != nil {
		t.Fatalf("set --output: %v", err)
	}
	if outputFile != "out.sarif" {
		t.Errorf("--output not bound to outputFile: outputFile = %q, want %q", outputFile, "out.sarif")
	}
}
