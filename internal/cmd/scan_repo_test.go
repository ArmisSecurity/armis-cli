package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

const testChangedModeUncommitted = "uncommitted"

func TestScanRepoRunE_SuccessfulScan(t *testing.T) {
	// Create test findings
	findings := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("repo-finding-1", "HIGH", "sql_injection", []string{"CVE-2024-1111"}, []string{"CWE-89"}),
	}

	// Setup mock server
	serverURL := testutil.GetMockServerURL(t, findings)

	// Create test repo
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main\n\nfunc main() {}"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalFormat := format
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalNoProgress := noProgress

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		format = originalFormat
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		noProgress = originalNoProgress
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	// Set up test environment
	_ = os.Setenv("ARMIS_API_URL", serverURL)
	token = testToken
	tenantID = testTenantID
	format = "json"
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true
	noProgress = true

	// Run the command
	// Note: The formatter writes directly to os.Stdout, so we verify success by checking for no error.
	// Full output verification is done in integration_test.go
	err := scanRepoCmd.RunE(scanRepoCmd, []string{tmpDir})
	if err != nil {
		t.Fatalf("expected successful scan, got error: %v", err)
	}
}

func TestScanRepoRunE_IncludeFilesValidation(t *testing.T) {
	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalIncludeFiles := includeFiles

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		includeFiles = originalIncludeFiles
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	// Set up mock server URL (even though we won't reach it)
	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	token = testToken
	tenantID = testTenantID
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
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	token = testToken
	tenantID = testTenantID
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
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalChangedRef := changedRef

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
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
	token = testToken
	tenantID = testTenantID
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
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalChangedRef := changedRef

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
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
	token = testToken
	tenantID = testTenantID
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
