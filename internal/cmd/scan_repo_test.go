package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const testChangedModeUncommitted = "uncommitted"

func TestScanRepoRunE_SuccessfulScan(t *testing.T) {
	// Create test findings
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("repo-finding-1", "HIGH", "sql_injection", []string{"CVE-2024-1111"}, []string{"CWE-89"}),
	}

	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: findings})

	// Create test repo
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n\nfunc main() {}"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalFormat := format
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalNoProgress := noProgress
	originalPollInterval := pollInterval

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		format = originalFormat
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		noProgress = originalNoProgress
		pollInterval = originalPollInterval
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	// Set up test environment
	_ = os.Setenv("ARMIS_API_URL", serverURL)
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	format = agentFormatJSON
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true
	noProgress = true
	// Override the production Scanner's default 5s poll interval so this test
	// doesn't pay for a real poll tick (RunE has no cobra-flag seam exercised
	// here, so we set the bound package var directly).
	pollInterval = 10 * time.Millisecond

	// Run the command
	// Note: The formatter writes directly to os.Stdout, so we verify success by checking for no error.
	// Full output verification is done in integration_test.go
	err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir})
	if err != nil {
		t.Fatalf("expected successful scan, got error: %v", err)
	}
}

// TestScanRepoRunE_DefaultsToCurrentDir verifies that `scan repo` with no path
// argument defaults to "." instead of erroring with "accepts 1 arg(s)"
// (PPSC-1006 #18). The command chdirs into a temp repo so "." resolves there.
func TestScanRepoRunE_DefaultsToCurrentDir(t *testing.T) {
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("repo-finding-1", "HIGH", "sql_injection", []string{"CVE-2024-1111"}, []string{"CWE-89"}),
	}
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: findings})

	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalFormat := format
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalNoProgress := noProgress
	originalPollInterval := pollInterval

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		format = originalFormat
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		noProgress = originalNoProgress
		pollInterval = originalPollInterval
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", serverURL)
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	format = agentFormatJSON
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true
	noProgress = true
	pollInterval = 10 * time.Millisecond

	// No path argument: RunE must default repoPath to "." (the temp dir).
	if err := scanRepoCmd.RunE(scanRepoCmd, []string{}); err != nil {
		t.Fatalf("expected scan of '.' to succeed with no path arg, got error: %v", err)
	}
}

func TestScanRepoRunE_IncludeFilesValidation(t *testing.T) {
	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalIncludeFiles := includeFiles

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		includeFiles = originalIncludeFiles
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	// Set up mock server URL (even though we won't reach it)
	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	// Create a temp directory for the "repo"
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Set include-files with path traversal attempt
	includeFiles = []string{"../../etc/passwd"}

	// Run the command - should fail on path validation
	err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir})
	if err == nil {
		t.Error("expected error for path traversal in include-files")
	}
	if err != nil && !strings.Contains(err.Error(), "traversal") && !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "outside") {
		// The error might be about invalid path or path outside base, which is acceptable
		t.Logf("Got error (acceptable): %v", err)
	}
}

func TestScanRepoRunE_InvalidPath(t *testing.T) {
	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	// Run with non-existent path
	err := scanRepoCmd.RunE(scanRepoCmd, []string{"/nonexistent/path/to/repo"})
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestScanRepoRunE_ChangedFlagNonGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalChangedRef := changedRef

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		// Reset flag state FIRST (this sets changedRef to "" via the bound variable)
		_ = scanRepoCmd.Flags().Set("changed", "")
		// Reset Changed field to prevent state leaking to subsequent tests.
		// Flags().Set leaves Changed=true, which would cause cmd.Flags().Changed("changed")
		// to return true even in tests that never set the flag.
		scanRepoCmd.Flags().Lookup("changed").Changed = false
		// Then restore the original value
		changedRef = originalChangedRef
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	// Create a temp directory (NOT a git repo)
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Set --changed flag to trigger git change detection
	changedRef = testChangedModeUncommitted
	if err := scanRepoCmd.Flags().Set("changed", testChangedModeUncommitted); err != nil {
		t.Fatalf("failed to set changed flag: %v", err)
	}

	// Run the command - should fail with user-friendly error about git repo
	err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir})
	if err == nil {
		t.Fatal("expected error for --changed on non-git directory")
	}
	if !strings.Contains(err.Error(), "--changed requires a git repository") {
		t.Errorf("expected git repository error, got: %v", err)
	}
}

func TestScanRepoRunE_ChangedFlagNoChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalChangedRef := changedRef

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		// Reset flag state FIRST (this sets changedRef to "" via the bound variable)
		_ = scanRepoCmd.Flags().Set("changed", "")
		// Reset Changed field to prevent state leaking to subsequent tests.
		// Flags().Set leaves Changed=true, which would cause cmd.Flags().Changed("changed")
		// to return true even in tests that never set the flag.
		scanRepoCmd.Flags().Lookup("changed").Changed = false
		// Then restore the original value
		changedRef = originalChangedRef
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	// Create a git repo with no uncommitted changes
	tmpDir := t.TempDir()
	if err := runTestGitCmd(tmpDir, "init"); err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}
	if err := runTestGitCmd(tmpDir, "config", "user.email", "test@example.com"); err != nil {
		t.Fatalf("failed to configure git: %v", err)
	}
	if err := runTestGitCmd(tmpDir, "config", "user.name", "Test User"); err != nil {
		t.Fatalf("failed to configure git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := runTestGitCmd(tmpDir, "add", "main.go"); err != nil {
		t.Fatalf("failed to stage file: %v", err)
	}
	if err := runTestGitCmd(tmpDir, "commit", "-m", "Initial commit"); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	// Set --changed flag
	changedRef = testChangedModeUncommitted
	if err := scanRepoCmd.Flags().Set("changed", testChangedModeUncommitted); err != nil {
		t.Fatalf("failed to set changed flag: %v", err)
	}

	// Run the command - should return nil (no error) when no changes found
	err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir})
	if err != nil {
		t.Errorf("expected nil error for no changes (early return), got: %v", err)
	}
}

// runTestGitCmd is a helper to run git commands in tests.
func runTestGitCmd(dir string, args ...string) error {
	// #nosec G204 -- test helper with controlled args
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	return cmd.Run()
}

// --- trailing file arguments ---------------------------------------------------
//
// `scan repo` accepts file paths after the repository path so that a caller which
// appends selected filenames to a fixed command line -- pre-commit with
// `pass_filenames: true` above all -- can drive it without knowing about
// --include-files. The tests below pin the four behaviours that makes possible.

func TestScanRepoArgs_AcceptsTrailingFiles(t *testing.T) {
	// Before this was ArbitraryArgs the command was MaximumNArgs(1), so
	// `scan repo . a.py b.py` failed argument validation before RunE ever ran.
	if err := scanRepoCmd.Args(scanRepoCmd, []string{".", "a.py", "b.py"}); err != nil {
		t.Errorf("expected trailing file arguments to be accepted, got %v", err)
	}
}

func TestScanRepoRunE_TrailingFilesRejectedWithChanged(t *testing.T) {
	t.Cleanup(func() {
		_ = scanRepoCmd.Flags().Set("changed", "")
		scanRepoCmd.Flags().Lookup("changed").Changed = false
		changedRef = ""
	})
	if err := scanRepoCmd.Flags().Set("changed", "staged"); err != nil {
		t.Fatalf("failed to set --changed: %v", err)
	}

	err := scanRepoCmd.RunE(scanRepoCmd, []string{t.TempDir(), "a.py"})
	if err == nil {
		t.Fatal("expected --changed with trailing file arguments to be rejected")
	}
	if !strings.Contains(err.Error(), "--changed") {
		t.Errorf("error should name the conflicting flag, got %v", err)
	}
}

func TestScanRepoRunE_TrailingFilesGetPathValidation(t *testing.T) {
	// The point of this test is that a trailing argument really does reach
	// ParseFileList: a traversal path has to be rejected exactly as it is when it
	// arrives through --include-files.
	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir, "../../etc/passwd"})
	if err == nil {
		t.Fatal("expected traversal in a trailing file argument to be rejected")
	}
	// The path came from a positional argument, so the error must not blame
	// --include-files -- a flag this invocation never passed.
	if !strings.Contains(err.Error(), "invalid file argument") {
		t.Errorf("expected the error to name the file argument, got %v", err)
	}
	if strings.Contains(err.Error(), "--include-files") {
		t.Errorf("error must not blame --include-files when it was not used, got %v", err)
	}
}

func TestScanRepoRunE_FileSelectionErrorNamesItsSource(t *testing.T) {
	// One rejected path, three provenances, three framings.
	originalIncludeFiles := includeFiles
	t.Cleanup(func() { includeFiles = originalIncludeFiles })

	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		includeFiles []string
		args         []string
		want         string
	}{
		{"flag only", []string{"../../etc/passwd"}, []string{tmpDir}, "invalid --include-files"},
		{"argument only", nil, []string{tmpDir, "../../etc/passwd"}, "invalid file argument"},
		{"both", []string{"ok.go"}, []string{tmpDir, "../../etc/passwd"}, "invalid file selection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			includeFiles = tt.includeFiles
			err := scanRepoCmd.RunE(scanRepoCmd, tt.args)
			if err == nil {
				t.Fatal("expected the traversal path to be rejected")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected %q in the error, got %v", tt.want, err)
			}
		})
	}
}

func TestScanRepoRunE_InvalidSelectionCostsNoNetworkCall(t *testing.T) {
	// ArbitraryArgs moved argument validation out of cobra's Args stage, where a
	// malformed invocation was rejected for free, and into RunE. It has to stay
	// ahead of getAuthProvider/GetTenantID: `scan repo <repo> ../../etc/passwd`
	// must not pay a live JWT token exchange to be told the path is invalid.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalIncludeFiles := includeFiles

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		clientID = originalClientID
		clientSecret = originalClientSecret
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		includeFiles = originalIncludeFiles
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	// Client credentials with no cached token: reaching auth means a round trip.
	_ = os.Setenv("ARMIS_API_URL", srv.URL)
	t.Setenv("ARMIS_CLIENT_ID", "test-client-id")
	t.Setenv("ARMIS_CLIENT_SECRET", "test-client-secret")
	token = ""
	tenantID = ""
	clientID = "test-client-id"
	clientSecret = "test-client-secret"
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true
	includeFiles = nil

	tmpDir := t.TempDir()

	if err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir, "../../etc/passwd"}); err == nil {
		t.Fatal("expected the traversal path to be rejected")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected 0 requests before argument validation, got %d", got)
	}
}

func TestScanRepoRunE_FileAsFirstArgumentExplainsItself(t *testing.T) {
	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "a.py")
	if err := os.WriteFile(file, []byte("x = 1\n"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Both arities: a script forwarding one changed filename makes the same
	// mistake as `scan repo a.py b.py`, and at n=1 it used to get the plain
	// message with no explanation at all.
	for _, args := range [][]string{{file}, {file, "b.py"}} {
		err := scanRepoCmd.RunE(scanRepoCmd, args)
		if err == nil {
			t.Fatalf("expected a file as the first argument to be rejected (args=%v)", args)
		}
		if !strings.Contains(err.Error(), "repository path") {
			t.Errorf("error should say the first argument is the repository path (args=%v), got %v", args, err)
		}
	}
}

func TestScanRepoRunE_TooManyFilesIsAnError(t *testing.T) {
	// An over-large selection is rejected, it does not fall back to a whole-repo
	// scan. A superset scan changes what the exit code covers, and the fallback
	// also turned the long-documented `--include-files` overflow error into a
	// passing full scan. `--changed` has always hard-errored on the same limit;
	// this is the same limit with the same behaviour, whichever path selects the
	// files.
	originalIncludeFiles := includeFiles
	t.Cleanup(func() { includeFiles = originalIncludeFiles })

	tmpDir := t.TempDir()

	tooMany := func(prefix string, n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("%s%d.py", prefix, i))
		}
		return out
	}

	tests := []struct {
		name         string
		includeFiles []string
		args         []string
		wantSource   string
	}{
		{
			name:         "trailing arguments",
			includeFiles: nil,
			args:         append([]string{tmpDir}, tooMany("f", repo.MaxFiles+1)...),
			wantSource:   "invalid file argument",
		},
		{
			name:         "include-files flag",
			includeFiles: tooMany("g", repo.MaxFiles+1),
			args:         []string{tmpDir},
			wantSource:   "invalid --include-files",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			includeFiles = tt.includeFiles
			err := scanRepoCmd.RunE(scanRepoCmd, tt.args)
			if err == nil {
				t.Fatal("expected an over-large file selection to be rejected")
			}
			if !strings.Contains(err.Error(), "too many files") {
				t.Errorf("expected the limit to be named, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantSource) {
				t.Errorf("expected %q in the error, got %v", tt.wantSource, err)
			}
			// The message has to say what to do instead, since the caller can no
			// longer rely on a silent fallback.
			if !strings.Contains(err.Error(), "--changed") {
				t.Errorf("expected the error to suggest an alternative, got %v", err)
			}
		})
	}
}

func TestScanRepoRunE_MergedSelectionDoesNotDoubleCount(t *testing.T) {
	// `args: [--include-files=a.py]` plus `pass_filenames: true` hands the same
	// file in through both paths. The two lists are concatenated before the limit
	// is applied, so without de-duplication in ParseFileList a selection of
	// MaxFiles distinct files would trip the limit at half that many files.
	originalIncludeFiles := includeFiles
	t.Cleanup(func() { includeFiles = originalIncludeFiles })

	tmpDir := t.TempDir()

	files := make([]string, 0, repo.MaxFiles)
	for i := 0; i < repo.MaxFiles; i++ {
		files = append(files, fmt.Sprintf("f%d.py", i))
	}
	includeFiles = files

	// Every file named a second time as a trailing argument: 2*MaxFiles arguments,
	// MaxFiles files. The scan must not be rejected for the file count.
	args := append([]string{tmpDir}, files...)

	// Validation now runs before auth, so reaching the credentials error is the
	// positive signal: 2*MaxFiles arguments naming MaxFiles files were accepted.
	err := scanRepoCmd.RunE(scanRepoCmd, args)
	if err == nil {
		t.Fatal("expected the unauthenticated run to stop at auth")
	}
	if strings.Contains(err.Error(), "too many files") {
		t.Fatalf("duplicates must not consume the file budget, got %v", err)
	}
	if !strings.Contains(err.Error(), "not authenticated") {
		t.Errorf("expected the selection to be accepted and the run to reach auth, got %v", err)
	}
}
