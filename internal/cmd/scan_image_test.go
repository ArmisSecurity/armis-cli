package cmd

import (
	"os"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func TestScanImageRunE_MissingTarget(t *testing.T) {
	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalTarballPath := tarballPath
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		tarballPath = originalTarballPath
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	token = testToken
	tenantID = testTenantID
	tarballPath = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	// Run with no image name and no tarball
	err := scanImageCmd.RunE(scanImageCmd, []string{})
	if err == nil {
		t.Error("expected error when neither image nor tarball provided")
	}
}

func TestScanImageRunE_InvalidTarballPath(t *testing.T) {
	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalTarballPath := tarballPath
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		tarballPath = originalTarballPath
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	_ = os.Setenv("ARMIS_API_URL", "http://localhost:8080")
	token = testToken
	tenantID = testTenantID
	tarballPath = "/nonexistent/image.tar"
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	// Run with non-existent tarball
	err := scanImageCmd.RunE(scanImageCmd, []string{})
	if err == nil {
		t.Error("expected error for non-existent tarball")
	}
}

func TestScanImageRunE_TarballScan(t *testing.T) {
	// Check if sample tarball exists
	sampleTarball := "../../test/sample-image.tar"
	if _, err := os.Stat(sampleTarball); os.IsNotExist(err) {
		t.Skip("sample-image.tar not found, skipping tarball test")
	}

	// Save and restore global state
	originalToken := token
	originalTenantID := tenantID
	originalTarballPath := tarballPath
	originalFormat := format
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalNoProgress := noProgress

	t.Cleanup(func() {
		token = originalToken
		tenantID = originalTenantID
		tarballPath = originalTarballPath
		format = originalFormat
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
		noProgress = originalNoProgress
		_ = os.Unsetenv("ARMIS_API_URL")
	})

	// Note: This test requires a running mock server and a valid tarball
	// For now, we just verify that the command validates inputs correctly
	t.Skip("Full tarball scan test requires mock server integration")
}

// TestScanImageRunE_PullPolicyValidation verifies --pull is validated at the top
// of RunE, before auth/network (PPSC-1006 #16). An invalid value must error with
// the pull message; valid values must pass that check (here surfacing the
// downstream "missing target" error, which proves the pull check let them
// through). No ARMIS_API_URL is set, so reaching auth would fail differently.
func TestScanImageRunE_PullPolicyValidation(t *testing.T) {
	originalPullPolicy := pullPolicy
	originalTarballPath := tarballPath
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck

	t.Cleanup(func() {
		pullPolicy = originalPullPolicy
		tarballPath = originalTarballPath
		colorFlag = originalColorFlag
		themeFlag = originalThemeFlag
		noUpdateCheck = originalNoUpdateCheck
	})

	tarballPath = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true

	t.Run("invalid pull errors before missing-target", func(t *testing.T) {
		pullPolicy = "badvalue"
		err := scanImageCmd.RunE(scanImageCmd, []string{})
		if err == nil {
			t.Fatal("expected error for invalid --pull value")
		}
		if !testutil.ContainsSubstring(err.Error(), "invalid --pull value") {
			t.Errorf("error should mention 'invalid --pull value', got: %v", err)
		}
	})

	t.Run("empty pull rejected", func(t *testing.T) {
		pullPolicy = ""
		err := scanImageCmd.RunE(scanImageCmd, []string{})
		if err == nil || !testutil.ContainsSubstring(err.Error(), "invalid --pull value") {
			t.Errorf("expected invalid --pull error for empty value, got: %v", err)
		}
	})

	for _, valid := range []string{"always", "missing", "never"} {
		t.Run("valid pull "+valid+" passes the check", func(t *testing.T) {
			pullPolicy = valid
			// No image and no tarball: the pull check passes, so RunE proceeds to
			// the missing-target guard. Seeing that error (not the pull error)
			// confirms the valid value was accepted.
			err := scanImageCmd.RunE(scanImageCmd, []string{})
			if err == nil {
				t.Fatalf("expected missing-target error for valid --pull %q", valid)
			}
			if testutil.ContainsSubstring(err.Error(), "invalid --pull value") {
				t.Errorf("valid --pull %q wrongly rejected: %v", valid, err)
			}
			if !testutil.ContainsSubstring(err.Error(), "missing target") {
				t.Errorf("expected missing-target error for valid --pull %q, got: %v", valid, err)
			}
		})
	}
}
