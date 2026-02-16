package cmd

import (
	"os"
	"testing"
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
