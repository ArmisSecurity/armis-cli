package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
	"github.com/spf13/pflag"
)

// resetParsedFlag undoes what parsing a command line did to a flag, so the
// next Execute in the same test binary starts from the default.
func resetParsedFlag(t *testing.T, fs *pflag.FlagSet, name string) {
	t.Helper()
	f := fs.Lookup(name)
	if f == nil {
		t.Fatalf("flag --%s not found", name)
	}
	if sv, ok := f.Value.(pflag.SliceValue); ok {
		if err := sv.Replace(nil); err != nil {
			t.Fatalf("reset --%s: %v", name, err)
		}
	} else if err := f.Value.Set(f.DefValue); err != nil {
		t.Fatalf("reset --%s: %v", name, err)
	}
	f.Changed = false
}

// TestScanBOMFlagErrorsStopBeforeUpload runs the real command line: every
// rejected --bom input returns an error (exit 1 in main.go) from
// PersistentPreRunE, before auth, so the API server sees no request at all.
func TestScanBOMFlagErrorsStopBeforeUpload(t *testing.T) {
	isolateHomeDir(t)
	var requests atomic.Int32
	server := testutil.NewTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	t.Setenv("ARMIS_API_URL", server.URL)
	t.Setenv("ARMIS_API_TOKEN", testToken)
	t.Setenv("ARMIS_TENANT_ID", testTenantID)

	repoDir := t.TempDir()
	tarball := filepath.Join(t.TempDir(), "image.tar")
	testhelpers.WriteMinimalTar(t, tarball)

	origColor, origTheme, origNoUpdate := colorFlag, themeFlag, noUpdateCheck
	colorFlag, themeFlag, noUpdateCheck = testColorNever, themeAuto, true
	t.Cleanup(func() {
		colorFlag, themeFlag, noUpdateCheck = origColor, origTheme, origNoUpdate
		rootCmd.SetArgs(nil)
	})

	rows := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"--bom=", []string{"scan", "repo", repoDir, "--bom="}, "--bom requires a value"},
		{"only empty items", []string{"scan", "repo", repoDir, "--bom", ","}, "--bom requires a value"},
		{"unknown type", []string{"scan", "repo", repoDir, "--bom", "aibom,xbom"}, `invalid --bom value "xbom"`},
		{"unknown format", []string{"scan", "repo", repoDir, "--bom", "cbom", "--bom-format", "xml"}, `invalid --bom-format value "xml"`},
		{"aibom with spdx-2.3", []string{"scan", "repo", repoDir, "--bom", "aibom", "--bom-format", "spdx-2.3"}, "the AI-BOM's SPDX form is spdx-3.0.1"},
		{"all with spdx on an image", []string{"scan", "image", "--tarball", tarball, "--bom", "all", "--bom-format", "spdx"}, "the Combined BOM has no SPDX form"},
		{"cbom with spdx-3.0.1", []string{"scan", "repo", repoDir, "--bom", "cbom", "--bom-format", "SPDX-3.0.1"}, "the CBOM has no SPDX form"},
		{"stdout with two types", []string{"scan", "repo", repoDir, "--bom", "cbom", "--bom", "aibom", "--bom-output", "-"}, "--bom-output - takes one BOM type, got 2: aibom,cbom"},
		{"output is a file", []string{"scan", "repo", repoDir, "--bom", "cbom", "--bom-output", tarball}, "not a directory"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, name := range []string{"bom", "bom-format", "bom-output"} {
					resetParsedFlag(t, scanCmd.PersistentFlags(), name)
				}
				resetParsedFlag(t, scanImageCmd.Flags(), "tarball")
				bomTypes = nil
			})
			rootCmd.SetArgs(row.args)
			err := Execute()
			if err == nil || !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, row.wantErr)
			}
			if n := requests.Load(); n != 0 {
				t.Fatalf("server saw %d requests, want none before the flag error", n)
			}
		})
	}
}

func TestWarnOnUnusedBOMFlags(t *testing.T) {
	origTypes, origFormat, origOutput := bomTypes, bomFormat, bomOutput
	t.Cleanup(func() { bomTypes, bomFormat, bomOutput = origTypes, origFormat, origOutput })

	rows := []struct {
		name     string
		types    []string
		bomFmt   string
		output   string
		want     []string
		wantNone bool
	}{
		{name: "defaults print nothing", bomFmt: scan.BOMFormatCycloneDX17, wantNone: true},
		{name: "format without --bom", bomFmt: scan.BOMFormatCycloneDX16, want: []string{"--bom-format is ignored without --bom flag"}},
		{name: "output without --bom", bomFmt: scan.BOMFormatCycloneDX17, output: "boms", want: []string{"--bom-output is ignored without --bom flag"}},
		{name: "both with --bom print nothing", types: []string{"aibom"}, bomFmt: scan.BOMFormatCycloneDX16, output: "boms", wantNone: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			bomTypes, bomFormat, bomOutput = row.types, row.bomFmt, row.output
			got := testutil.CaptureStderr(t, warnOnUnusedBOMFlags)
			if row.wantNone && got != "" {
				t.Errorf("expected no warning, got %q", got)
			}
			for _, w := range row.want {
				if !strings.Contains(got, w) {
					t.Errorf("stderr = %q, want it to contain %q", got, w)
				}
			}
		})
	}
}

func TestScanStatus_WarnsOnBOM(t *testing.T) {
	cleanup := setupStatusEnv(t, statusServer(t, "COMPLETED", nil))
	defer cleanup()
	origTypes := bomTypes
	t.Cleanup(func() { bomTypes = origTypes })

	bomTypes = []string{scan.BOMTypeAIBOM}
	var err error
	stderr := testutil.CaptureStderr(t, func() {
		_, err = runStatus(t, []string{"507f1f77bcf86cd799439011"})
	})
	if err != nil {
		t.Fatalf("scan status failed: %v", err)
	}
	if !strings.Contains(stderr, "--bom is ignored for `scan status`") {
		t.Errorf("stderr = %q, want the --bom warning", stderr)
	}
}

func TestScanSBOMRunE_WarnsOnBOM(t *testing.T) {
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{ScanID: "sbom-scan-bom"})
	setupScanRunEnv(t, serverURL)
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	bomTypes = []string{scan.BOMTypeCBOM}
	var err error
	stderr := testutil.CaptureStderr(t, func() {
		err = scanSBOMCmd.RunE(scanSBOMCmd, []string{sbomPath})
	})
	if err != nil {
		t.Fatalf("scan sbom failed: %v", err)
	}
	if !strings.Contains(stderr, "--bom is ignored for `scan sbom`") {
		t.Errorf("stderr = %q, want the --bom warning", stderr)
	}
}

// setupScanRunEnv points the scan commands at serverURL with Basic auth, as
// the RunE tests of scan repo and scan sbom do, and restores every global it
// touches, the BOM flags included.
func setupScanRunEnv(t *testing.T, serverURL string) {
	t.Helper()
	isolateHomeDir(t)
	t.Setenv("ARMIS_API_URL", serverURL)
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())

	origToken, origTenant, origClientID, origClientSecret := token, tenantID, clientID, clientSecret
	origFormat, origColor, origTheme, origNoUpdate := format, colorFlag, themeFlag, noUpdateCheck
	origNoProgress, origPoll, origFailOn, origOutputFile := noProgress, pollInterval, failOn, outputFile
	origTypes, origBOMFormat, origBOMOutput := bomTypes, bomFormat, bomOutput
	t.Cleanup(func() {
		token, tenantID, clientID, clientSecret = origToken, origTenant, origClientID, origClientSecret
		format, colorFlag, themeFlag, noUpdateCheck = origFormat, origColor, origTheme, origNoUpdate
		noProgress, pollInterval, failOn, outputFile = origNoProgress, origPoll, origFailOn, origOutputFile
		bomTypes, bomFormat, bomOutput = origTypes, origBOMFormat, origBOMOutput
	})

	token, tenantID, clientID, clientSecret = testToken, testTenantID, "", ""
	format, colorFlag, themeFlag, noUpdateCheck = agentFormatJSON, testColorNever, themeAuto, true
	noProgress, pollInterval, failOn, outputFile = true, 10*time.Millisecond, defaultFailOn(), ""
	bomTypes, bomFormat, bomOutput = nil, scan.BOMFormatCycloneDX17, ""
}
