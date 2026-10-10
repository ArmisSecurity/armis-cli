package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// TestScanSBOMRunE_SuccessfulScan drives `scan sbom <file>` end to end against
// the mock API, verifying the command uploads the SBOM and writes the VEX
// document without erroring on the empty findings set.
func TestScanSBOMRunE_SuccessfulScan(t *testing.T) {
	const vex = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"GHSA-1"}}]}`
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		ScanID:     "sbom-scan-cmd",
		VEXContent: vex,
	})

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	vexOut := filepath.Join(tmpDir, "result-vex.json")

	originalToken := token
	originalTenantID := tenantID
	originalClientID := clientID
	originalClientSecret := clientSecret
	originalFormat := format
	originalColorFlag := colorFlag
	originalThemeFlag := themeFlag
	originalNoUpdateCheck := noUpdateCheck
	originalNoProgress := noProgress
	originalVEXOutput := vexOutput
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
		vexOutput = originalVEXOutput
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
	vexOutput = vexOut
	// Override the production Scanner's default 5s poll interval so this test
	// doesn't pay for a real poll tick (RunE has no cobra-flag seam exercised
	// here, so we set the bound package var directly, same as vexOutput above).
	pollInterval = 10 * time.Millisecond

	if err := scanSBOMCmd.RunE(scanSBOMCmd, []string{sbomPath}); err != nil {
		t.Fatalf("expected successful sbom scan, got error: %v", err)
	}

	if _, err := os.Stat(vexOut); err != nil {
		t.Errorf("expected VEX written to %s: %v", vexOut, err)
	}
}

func TestScanSBOMCmd_Registered(t *testing.T) {
	if scanSBOMCmd == nil {
		t.Fatal("scanSBOMCmd should not be nil")
	}
	found := false
	for _, c := range scanCmd.Commands() {
		if c.Name() == "sbom" {
			found = true
			break
		}
	}
	if !found {
		t.Error("scan sbom subcommand not registered under scan")
	}
}

func TestScanSBOMRunE_InvalidPath(t *testing.T) {
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

	if err := scanSBOMCmd.RunE(scanSBOMCmd, []string{"/nonexistent/sbom.json"}); err == nil {
		t.Error("expected error for non-existent path")
	}
}

// TestScanSBOMRunE_FailsOnExposedSecret covers the gate `--fail-on-secret`
// promises. The flag is registered on scanCmd as a persistent flag defaulting
// to true (scan.go), so `scan sbom --help` advertises it and it is on unless
// the user opts out -- but this command gated on severity alone, so a secret
// the backend graded below the --fail-on threshold exited 0. Unreachable with
// today's SBOM inputs (a CycloneDX document carries no code location, so the
// backend has nothing to find a secret in), which is precisely why only a test
// keeps it honest: the day the backend attaches a secret to an SBOM finding,
// the default-on gate has to fire here as it does for repo and image.
func TestScanSBOMRunE_FailsOnExposedSecret(t *testing.T) {
	secret := model.NormalizedFinding{}
	secret.NormalizedTask.FindingID = "finding-sbom-secret"
	secret.NormalizedRemediation.Description = "hard-coded credential"
	secret.NormalizedRemediation.FindingCategory = "SECRET_EXPOSURE"
	secret.NormalizedRemediation.ToolSeverity = "LOW"

	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		ScanID:   "sbom-scan-secret",
		Findings: []model.NormalizedFinding{secret},
	})

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
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
	originalFailOn := failOn
	originalFailOnSecret := failOnSecret

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
		failOn = originalFailOn
		failOnSecret = originalFailOnSecret
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
	// The secret is LOW; nothing here reaches the severity threshold, so a
	// non-zero exit can only come from the secret policy.
	failOn = []string{"CRITICAL"}
	failOnSecret = true

	err := scanSBOMCmd.RunE(scanSBOMCmd, []string{sbomPath})
	if err == nil {
		t.Fatal("scan sbom exited 0 with an exposed secret in the results; --fail-on-secret is advertised on this command and must gate it")
	}

	failOnSecret = false
	if err := scanSBOMCmd.RunE(scanSBOMCmd, []string{sbomPath}); err != nil {
		t.Fatalf("--fail-on-secret=false must leave the severity-only gate in charge, got: %v", err)
	}
}
