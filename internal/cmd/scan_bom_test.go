package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
	"github.com/spf13/cobra"
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

func TestBOMExit(t *testing.T) {
	findingsErr := &output.ErrFindingsExceeded{ExitCode: 3}
	rows := []struct {
		name       string
		failures   []string
		err        error
		wantLabels []string // non-nil: want ErrBOMIncomplete with these labels
		wantErr    error
	}{
		{name: "no failure, no error", wantErr: nil},
		{name: "a --fail-on exit wins over a failed BOM", failures: []string{"aibom"}, err: findingsErr, wantErr: findingsErr},
		{name: "a failed BOM exits 2", failures: []string{"aibom", "all"}, wantLabels: []string{"AI-BOM", "Combined BOM"}},
		{name: "a --fail-on exit without BOM failures", err: findingsErr, wantErr: findingsErr},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := bomExit(&model.ScanResult{ScanID: "scan-9", BOMFailures: row.failures}, row.err)
			if row.wantLabels == nil {
				if got != row.wantErr {
					t.Fatalf("bomExit = %v, want %v", got, row.wantErr)
				}
				return
			}
			var bomErr *output.ErrBOMIncomplete
			if !errors.As(got, &bomErr) || !reflect.DeepEqual(bomErr.Labels, row.wantLabels) || bomErr.ScanID != "scan-9" {
				t.Fatalf("bomExit = %#v, want ErrBOMIncomplete with %v", got, row.wantLabels)
			}
			want := "scan completed but AI-BOM, Combined BOM could not be downloaded (scan ID: scan-9)"
			if bomErr.Error() != want {
				t.Errorf("message = %q, want %q", bomErr.Error(), want)
			}
		})
	}
	if err := bomExit(nil, nil); err != nil {
		t.Errorf("bomExit(nil, nil) = %v, want nil", err)
	}
}

// runRepoScanIn runs `scan repo repoDir` and returns its stdout, stderr and
// error. The caller sets up the mock API and the BOM globals.
func runRepoScanIn(t *testing.T, repoDir string) (stdout, stderr string, err error) {
	t.Helper()
	stderr = testutil.CaptureStderr(t, func() {
		stdout = captureStdout(t, func() {
			err = scanRepoCmd.RunE(scanRepoCmd, []string{repoDir})
		})
	})
	return stdout, stderr, err
}

// TestScanRepoRunE_BOMExitCodes covers the exit rows: a failed BOM exits 2
// unless --fail-on triggers, and an empty BOM exits as the same scan without
// --bom does.
func TestScanRepoRunE_BOMExitCodes(t *testing.T) {
	critical := []model.NormalizedFinding{
		testhelpers.CreateNormalizedFinding("f-1", "CRITICAL", "sql_injection", nil, []string{"CWE-89"}),
	}
	const emptyAIBOM = `{"bomFormat":"CycloneDX"}`
	rows := []struct {
		name     string
		findings []model.NormalizedFinding
		docs     map[string]string
		status   int
		// want is checked against the --bom run; wantSameAsNoBOM also runs the
		// scan without --bom and compares the exit error.
		wantBOMIncomplete bool
		wantFindings      bool
		wantSameAsNoBOM   bool
	}{
		{name: "failed type, --fail-on not hit", docs: map[string]string{"aibom_results": emptyAIBOM}, status: http.StatusNotFound, wantBOMIncomplete: true},
		{name: "failed type, --fail-on hit", findings: critical, docs: map[string]string{"aibom_results": emptyAIBOM}, status: http.StatusNotFound, wantFindings: true},
		{name: "empty AI-BOM, --fail-on not hit", docs: map[string]string{"aibom_results": emptyAIBOM}, wantSameAsNoBOM: true},
		{name: "empty AI-BOM, --fail-on hit", findings: critical, docs: map[string]string{"aibom_results": emptyAIBOM}, wantFindings: true, wantSameAsNoBOM: true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			config := testutil.MockAPIConfig{Findings: row.findings, BOMContent: row.docs, BOMDownloadStatus: row.status}
			setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, config))
			repoDir := createTestRepo(t)
			bomTypes, bomOutput = []string{scan.BOMTypeAIBOM}, t.TempDir()
			_, stderr, err := runRepoScanIn(t, repoDir)

			var bomErr *output.ErrBOMIncomplete
			var findingsErr *output.ErrFindingsExceeded
			switch {
			case row.wantBOMIncomplete:
				if !errors.As(err, &bomErr) || !reflect.DeepEqual(bomErr.Labels, []string{"AI-BOM"}) {
					t.Fatalf("error = %v, want ErrBOMIncomplete for AI-BOM", err)
				}
			case row.wantFindings:
				if !errors.As(err, &findingsErr) {
					t.Fatalf("error = %v, want ErrFindingsExceeded", err)
				}
			default:
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
			}
			if row.status == 0 && !strings.Contains(stderr, "No AI components found in "+repoDir) {
				t.Errorf("stderr = %q, want the empty AI-BOM line", stderr)
			}

			if row.wantSameAsNoBOM {
				bomTypes, bomOutput = nil, ""
				_, _, noBOMErr := runRepoScanIn(t, repoDir)
				if (err == nil) != (noBOMErr == nil) || errors.As(noBOMErr, &findingsErr) != row.wantFindings {
					t.Errorf("with --bom: %v; without: %v; want the same exit", err, noBOMErr)
				}
			}
		})
	}
}

func TestScanRepoRunE_BOMFiles(t *testing.T) {
	const cbomDoc = `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"name":"AES"}]}`

	t.Run("writes the file under --bom-output", func(t *testing.T) {
		dir := t.TempDir()
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
			BOMContent: map[string]string{"cbom_results": cbomDoc},
		}))
		repoDir := createTestRepo(t)
		bomTypes, bomOutput = []string{scan.BOMTypeCBOM}, dir
		if _, _, err := runRepoScanIn(t, repoDir); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.Base(repoDir)+"-bom-cbom.json")) //nolint:gosec // test path
		if err != nil {
			t.Fatalf("expected the CBOM file: %v", err)
		}
		if !bytes.Equal(data, scan.IndentJSON([]byte(cbomDoc))) {
			t.Errorf("file = %s, want the stored document pretty-printed", data)
		}
	})

	t.Run("stdout mode sends the report to stderr", func(t *testing.T) {
		t.Chdir(t.TempDir())
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
			BOMContent: map[string]string{"cbom_results": cbomDoc},
		}))
		repoDir := createTestRepo(t)
		bomTypes, bomOutput = []string{scan.BOMTypeCBOM}, scan.BOMOutputStdout
		stdout, stderr, err := runRepoScanIn(t, repoDir)
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if stdout != cbomDoc {
			t.Errorf("stdout = %q, want only the CBOM bytes", stdout)
		}
		if !strings.Contains(stderr, `"scan_id"`) || !strings.Contains(stderr, "CBOM written to stdout") {
			t.Errorf("stderr = %q, want the JSON report and the stdout line", stderr)
		}
	})

	t.Run("stdout mode with --output keeps the report in the file", func(t *testing.T) {
		report := filepath.Join(t.TempDir(), "report.json")
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
			BOMContent: map[string]string{"cbom_results": cbomDoc},
		}))
		repoDir := createTestRepo(t)
		bomTypes, bomOutput, outputFile = []string{scan.BOMTypeCBOM}, scan.BOMOutputStdout, report
		stdout, stderr, err := runRepoScanIn(t, repoDir)
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if stdout != cbomDoc {
			t.Errorf("stdout = %q, want only the CBOM bytes", stdout)
		}
		if strings.Contains(stderr, `"scan_id"`) {
			t.Errorf("the report went to stderr despite --output: %q", stderr)
		}
		if data, err := os.ReadFile(report); err != nil || !strings.Contains(string(data), `"scan_id"`) { //nolint:gosec // test path
			t.Errorf("report file = %q (%v), want the JSON report", data, err)
		}
	})

	t.Run("an older server without the key warns and exits 0", func(t *testing.T) {
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{}))
		repoDir := createTestRepo(t)
		bomTypes, bomOutput = []string{scan.BOMTypeAIBOM, scan.BOMTypeCBOM}, t.TempDir()
		_, stderr, err := runRepoScanIn(t, repoDir)
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		for _, w := range []string{"AI-BOM was requested but not available in results", "CBOM was requested but not available in results"} {
			if !strings.Contains(stderr, w) {
				t.Errorf("stderr = %q, want %q", stderr, w)
			}
		}
	})
}

func TestScanRepoRunE_BOMPartialUpload(t *testing.T) {
	const warning = "BOMs cover only the uploaded files"
	const aibom = `{"bomFormat":"CycloneDX","components":[{"name":"m"}]}`
	origIncludeFiles := includeFiles
	t.Cleanup(func() { includeFiles = origIncludeFiles })

	t.Run("--include-files with --bom warns", func(t *testing.T) {
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
			BOMContent: map[string]string{"aibom_results": aibom},
		}))
		repoDir := createTestRepo(t)
		includeFiles = []string{"main.go"}
		bomTypes, bomOutput = []string{scan.BOMTypeAIBOM}, t.TempDir()
		_, stderr, err := runRepoScanIn(t, repoDir)
		includeFiles = nil
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if !strings.Contains(stderr, warning) {
			t.Errorf("stderr = %q, want %q", stderr, warning)
		}
	})

	t.Run("--changed with --bom warns", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not available")
		}
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
			BOMContent: map[string]string{"aibom_results": aibom},
		}))
		repoDir := t.TempDir()
		for _, args := range [][]string{
			{"init"}, {"config", "user.email", "test@example.com"}, {"config", "user.name", "Test User"},
		} {
			if err := runTestGitCmd(repoDir, args...); err != nil {
				t.Fatalf("git %v: %v", args, err)
			}
		}
		if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		origChangedRef := changedRef
		changedRef = testChangedModeUncommitted
		if err := scanRepoCmd.Flags().Set("changed", testChangedModeUncommitted); err != nil {
			t.Fatalf("set --changed: %v", err)
		}
		t.Cleanup(func() {
			_ = scanRepoCmd.Flags().Set("changed", "")
			scanRepoCmd.Flags().Lookup("changed").Changed = false
			changedRef = origChangedRef
		})
		bomTypes, bomOutput = []string{scan.BOMTypeAIBOM}, t.TempDir()
		_, stderr, err := runRepoScanIn(t, repoDir)
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if !strings.Contains(stderr, warning) {
			t.Errorf("stderr = %q, want %q", stderr, warning)
		}
	})

	t.Run("a full upload does not warn", func(t *testing.T) {
		setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
			BOMContent: map[string]string{"aibom_results": aibom},
		}))
		repoDir := createTestRepo(t)
		bomTypes, bomOutput = []string{scan.BOMTypeAIBOM}, t.TempDir()
		_, stderr, err := runRepoScanIn(t, repoDir)
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		if strings.Contains(stderr, warning) {
			t.Errorf("stderr = %q, want no partial-upload warning", stderr)
		}
	})
}

func TestScanImageRunE_BOMTarball(t *testing.T) {
	const cbomDoc = `{"bomFormat":"CycloneDX","components":[{"name":"AES"}]}`
	setupScanRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		BOMContent: map[string]string{"cbom_results": cbomDoc},
	}))
	origTarball := tarballPath
	t.Cleanup(func() { tarballPath = origTarball })
	tarballPath = filepath.Join(t.TempDir(), "app.tar")
	testhelpers.WriteMinimalTar(t, tarballPath)

	dir := t.TempDir()
	bomTypes, bomOutput = []string{scan.BOMTypeCBOM}, dir
	var err error
	_ = testutil.CaptureStderr(t, func() {
		_ = captureStdout(t, func() { err = scanImageCmd.RunE(scanImageCmd, nil) })
	})
	if err != nil {
		t.Fatalf("scan image failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app-bom-cbom.json")); err != nil {
		t.Errorf("expected app-bom-cbom.json: %v", err)
	}
}

// TestRepoScan_CancelDuringBOMDownload checks that Ctrl+C during a BOM
// download ends the scan as cancelled (exit 130), not as a failed BOM (2).
func TestRepoScan_CancelDuringBOMDownload(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
		BOMContent: map[string]string{"aibom_results": `{"components":[]}`},
		OnBOMDownload: func(r *http.Request) {
			cancel()
			<-r.Context().Done() // hold the answer until the client gives up
		},
	})
	client, err := api.NewClient(serverURL, testutil.NewTestAuthProvider("test-token"), false, 0, api.WithAllowLocalURLs(true))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	scanner := repo.NewScanner(client, true, testTenantID, 500, false, time.Minute, false).
		WithPollInterval(10 * time.Millisecond).
		WithSBOMVEXOptions(&scan.SBOMVEXOptions{BOM: &scan.BOMOptions{
			Types: []string{scan.BOMTypeAIBOM}, Format: scan.BOMFormatCycloneDX17, Output: t.TempDir(),
		}})

	var result *model.ScanResult
	_ = testutil.CaptureStderr(t, func() { result, err = scanner.Scan(ctx, createTestRepo(t)) })
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan = %v, %v; want a cancelled scan", result, err)
	}
	_ = testutil.CaptureStderr(t, func() { err = handleScanError(ctx, err) })
	if !errors.Is(err, ErrScanCancelled) {
		t.Errorf("handleScanError = %v, want ErrScanCancelled", err)
	}
}

// TestScanHelpShowsBOMFlags renders `scan repo --help` and `scan image --help`:
// the three flags are visible, say the feature must be on for the tenant, and
// the examples show --bom.
func TestScanHelpShowsBOMFlags(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	output.SyncColors()
	const tenantNote = "BOM generation must be enabled for your tenant"

	for _, c := range []*cobra.Command{scanRepoCmd, scanImageCmd} {
		t.Run(c.Name(), func(t *testing.T) {
			var buf bytes.Buffer
			c.SetOut(&buf)
			t.Cleanup(func() { c.SetOut(nil) })
			c.HelpFunc()(c, nil)
			help := buf.String()

			for _, want := range []string{
				"--bom strings", "--bom-format string", "--bom-output string",
				`(default "cyclonedx-1.7")`, "sbom, aibom, cbom, all", "or - to write one BOM to stdout",
				"armis-cli scan " + c.Name() + " ",
			} {
				if !strings.Contains(help, want) {
					t.Errorf("help is missing %q:\n%s", want, help)
				}
			}
			if n := strings.Count(help, tenantNote); n != 3 {
				t.Errorf("help names the tenant requirement %d times, want once per flag", n)
			}
			for _, name := range []string{"bom", "bom-format", "bom-output"} {
				if f := c.InheritedFlags().Lookup(name); f == nil || f.Hidden {
					t.Errorf("--%s must be a visible flag", name)
				}
			}
			if !strings.Contains(c.Example, "--bom ") {
				t.Errorf("examples show no --bom:\n%s", c.Example)
			}
		})
	}
}
