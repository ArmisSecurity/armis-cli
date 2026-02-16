package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

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
