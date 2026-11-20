package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// setUpRepoScan points the repo command at a mock API and a one-file repo,
// restoring every global it touches when the test ends.
func setUpRepoScan(t *testing.T, cfg testutil.MockAPIConfig) string {
	t.Helper()

	serverURL := testutil.GetMockServerURLWithConfig(t, cfg)
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	saved := struct {
		token, tenantID, clientID, clientSecret, format, color, theme string
		noUpdateCheck, noProgress                                     bool
		poll                                                          time.Duration
	}{token, tenantID, clientID, clientSecret, format, colorFlag, themeFlag, noUpdateCheck, noProgress, pollInterval}
	t.Cleanup(func() {
		token, tenantID, clientID, clientSecret = saved.token, saved.tenantID, saved.clientID, saved.clientSecret
		format, colorFlag, themeFlag = saved.format, saved.color, saved.theme
		noUpdateCheck, noProgress, pollInterval = saved.noUpdateCheck, saved.noProgress, saved.poll
		resetIncludeSBOMFilesFlag(t)
	})

	t.Setenv("ARMIS_API_URL", serverURL)
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
	return repoDir
}

func resetIncludeSBOMFilesFlag(t *testing.T) {
	t.Helper()
	flag := scanRepoCmd.Flags().Lookup("include-sbom-files")
	if err := flag.Value.Set("0"); err != nil {
		t.Fatalf("reset --include-sbom-files: %v", err)
	}
	flag.Changed = false
}

// scanBodyRecorder captures the last /ingest/scan body the mock API received.
type scanBodyRecorder struct {
	mu   sync.Mutex
	body []byte
}

func (r *scanBodyRecorder) record(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body = body
}

func (r *scanBodyRecorder) get() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body
}

func TestScanRepoRunE_IncludeSBOMFilesIsSentAndPartialScanWarns(t *testing.T) {
	recorder := &scanBodyRecorder{}
	repoDir := setUpRepoScan(t, testutil.MockAPIConfig{
		OnScanRequest: recorder.record,
		SBOMScan: map[string]interface{}{
			"sbom_scan_status":   "PARTIAL",
			"sbom_scan_reasons":  []string{"file_limit_exceeded"},
			"sbom_skipped_files": []map[string]string{{"path": "4x/x800_vms_sbom.json", "reason": "file_limit_exceeded"}},
			"sbom_skipped_count": 1,
		},
	})
	if err := scanRepoCmd.Flags().Set("include-sbom-files", "20"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	var runErr error
	stderr := testutil.CaptureStderr(t, func() {
		runErr = scanRepoCmd.RunE(scanRepoCmd, []string{repoDir})
	})
	if runErr != nil {
		t.Fatalf("a partial SBOM scan must not fail the command, got: %v", runErr)
	}

	var sent map[string]interface{}
	if err := json.Unmarshal(recorder.get(), &sent); err != nil {
		t.Fatalf("unmarshal /ingest/scan body %q: %v", recorder.get(), err)
	}
	if got := sent["include_sbom_files"]; got != float64(20) {
		t.Errorf("include_sbom_files = %v, want 20", got)
	}
	if !strings.Contains(stderr, "SBOM scan incomplete: 1 SBOM file(s) were not scanned") {
		t.Errorf("expected the SBOM warning on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, "4x/x800_vms_sbom.json") {
		t.Errorf("expected the skipped file on stderr, got: %q", stderr)
	}
}

func TestScanRepoRunE_WithoutTheFlagNoSBOMFieldIsSent(t *testing.T) {
	recorder := &scanBodyRecorder{}
	repoDir := setUpRepoScan(t, testutil.MockAPIConfig{OnScanRequest: recorder.record})

	if err := scanRepoCmd.RunE(scanRepoCmd, []string{repoDir}); err != nil {
		t.Fatalf("expected successful scan, got: %v", err)
	}

	if body := string(recorder.get()); strings.Contains(body, "include_sbom_files") {
		t.Errorf("include_sbom_files must be omitted without the flag, got body: %s", body)
	}
}

func TestScanRepoRunE_IncludeSBOMFilesOutOfRangeIsRejected(t *testing.T) {
	for _, value := range []string{"0", "-3", "1001", "2147483647"} {
		t.Run(value, func(t *testing.T) {
			t.Cleanup(func() { resetIncludeSBOMFilesFlag(t) })
			if err := scanRepoCmd.Flags().Set("include-sbom-files", value); err != nil {
				t.Fatalf("set flag: %v", err)
			}

			// No mock API: the check must fail before any network call.
			err := scanRepoCmd.RunE(scanRepoCmd, []string{t.TempDir()})

			if err == nil || !strings.Contains(err.Error(), "invalid --include-sbom-files value") {
				t.Fatalf("expected an --include-sbom-files validation error, got: %v", err)
			}
		})
	}
}

func TestIncludeSBOMFilesFlagParsing(t *testing.T) {
	t.Cleanup(func() { resetIncludeSBOMFilesFlag(t) })

	cmd := scanRepoCmd
	if err := cmd.ParseFlags([]string{"--include-sbom-files", "20", "."}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if includeSBOMFiles != 20 {
		t.Errorf("includeSBOMFiles = %d, want 20", includeSBOMFiles)
	}
	if args := cmd.Flags().Args(); len(args) != 1 || args[0] != "." {
		t.Errorf("path argument = %v, want [.]", args)
	}

	resetIncludeSBOMFilesFlag(t)
	if err := cmd.ParseFlags([]string{"--include-sbom-files"}); err == nil {
		t.Error("expected an error when --include-sbom-files has no value")
	}
}

func TestIncludeSBOMFilesIsARepoOnlyFlag(t *testing.T) {
	if scanRepoCmd.Flags().Lookup("include-sbom-files") == nil {
		t.Error("scan repo must have --include-sbom-files")
	}
	if scanImageCmd.Flags().Lookup("include-sbom-files") != nil {
		t.Error("scan image must not have --include-sbom-files")
	}
	if scanCmd.PersistentFlags().Lookup("include-sbom-files") != nil {
		t.Error("--include-sbom-files must not be shared by every scan subcommand")
	}
}

func TestIncludeSBOMFilesAcceptsTheServerMaximum(t *testing.T) {
	t.Cleanup(func() { resetIncludeSBOMFilesFlag(t) })
	if err := scanRepoCmd.Flags().Set("include-sbom-files", "1000"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	if err := validateIncludeSBOMFiles(scanRepoCmd); err != nil {
		t.Fatalf("expected 1000 to be accepted, got: %v", err)
	}
}
