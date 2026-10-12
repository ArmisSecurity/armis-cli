package cmd

import (
	"archive/tar"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

// minSeverityTestSeverities lists every severity from least to most severe.
var minSeverityTestSeverities = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// minSeverityFixture is the severity of each finding the mock server returns.
// MEDIUM is left out on purpose so some --fail-on sets don't trip, and the
// matrix covers scans that should pass as well as scans that should fail.
var minSeverityFixture = []string{"INFO", "LOW", "HIGH", "CRITICAL"}

// fixtureFindings returns one finding per minSeverityFixture entry.
func fixtureFindings() []model.NormalizedFinding {
	findings := make([]model.NormalizedFinding, 0, len(minSeverityFixture))
	for _, sev := range minSeverityFixture {
		findings = append(findings, testhelpers.CreateNormalizedFinding("finding-"+strings.ToLower(sev), sev, "test", nil, nil))
	}
	return findings
}

// severityIndex returns sev's position in minSeverityTestSeverities.
func severityIndex(sev string) int {
	for i, s := range minSeverityTestSeverities {
		if s == sev {
			return i
		}
	}
	return -1
}

// setupMinSeverityScan points the scan commands at serverURL and saves every
// global these tests touch, restoring them on cleanup.
func setupMinSeverityScan(t *testing.T, serverURL string) {
	t.Helper()

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
	originalMinSeverity := minSeverity
	originalExitCode := exitCode
	originalOutputFile := outputFile

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
		minSeverity = originalMinSeverity
		exitCode = originalExitCode
		outputFile = originalOutputFile
	})

	t.Setenv("ARMIS_API_URL", serverURL)
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token = testToken
	tenantID = testTenantID
	clientID = ""
	clientSecret = ""
	colorFlag = testColorNever
	themeFlag = themeAuto
	noUpdateCheck = true
	noProgress = true
	pollInterval = 10 * time.Millisecond
	exitCode = 1
}

// runRepoScan runs `scan repo` with the given flags and returns whether the
// --fail-on gate tripped plus the formatted output.
func runRepoScan(t *testing.T, repoPath, outFormat, minSev string, failOnSevs []string) (bool, string) {
	t.Helper()

	format = outFormat
	minSeverity = minSev
	failOn = append([]string(nil), failOnSevs...)
	outputFile = filepath.Join(t.TempDir(), "out.txt")

	err := scanRepoCmd.RunE(scanRepoCmd, []string{repoPath})
	failed := false
	if err != nil {
		var exceeded *output.ErrFindingsExceeded
		if !errors.As(err, &exceeded) {
			t.Fatalf("scan repo (format=%s, min=%q, fail-on=%v): unexpected error: %v", outFormat, minSev, failOnSevs, err)
		}
		failed = true
	}

	data, readErr := os.ReadFile(filepath.Clean(outputFile))
	if readErr != nil {
		t.Fatalf("read output: %v", readErr)
	}
	return failed, string(data)
}

// shownCount returns how many findings the formatted output contains.
func shownCount(t *testing.T, outFormat, out string) int {
	t.Helper()

	switch outFormat {
	case "json":
		var parsed struct {
			Findings []model.Finding `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("parse json: %v", err)
		}
		return len(parsed.Findings)
	case "sarif":
		var parsed struct {
			Runs []struct {
				Results []json.RawMessage `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("parse sarif: %v", err)
		}
		if len(parsed.Runs) != 1 {
			t.Fatalf("expected 1 sarif run, got %d", len(parsed.Runs))
		}
		return len(parsed.Runs[0].Results)
	case "junit":
		var parsed struct {
			Suites []struct {
				Tests int `xml:"tests,attr"`
			} `xml:"testsuite"`
		}
		if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("parse junit: %v", err)
		}
		if len(parsed.Suites) != 1 {
			t.Fatalf("expected 1 junit suite, got %d", len(parsed.Suites))
		}
		return parsed.Suites[0].Tests
	default:
		// The human summary dashboard prints "N findings".
		for n := 0; n <= len(minSeverityFixture); n++ {
			if strings.Contains(out, fmt.Sprintf("\n%d findings", n)) {
				return n
			}
		}
		t.Fatalf("no findings count in human output:\n%s", out)
		return -1
	}
}

// expectedShown returns how many fixture findings are at or above minSev.
func expectedShown(minSev string) int {
	count := 0
	for _, sev := range minSeverityFixture {
		if minSev == "" || severityIndex(sev) >= severityIndex(minSev) {
			count++
		}
	}
	return count
}

// expectedFailed reports whether any fixture finding matches failOnSevs.
func expectedFailed(failOnSevs []string) bool {
	for _, sev := range minSeverityFixture {
		for _, f := range failOnSevs {
			if sev == f {
				return true
			}
		}
	}
	return false
}

// TestScanRepo_MinSeverityNeverChangesFailOn locks in that --min-severity is
// display-only: for every --min-severity × --fail-on combination and every
// output format, the exit decision equals the one made without the filter,
// and the output holds exactly the findings at or above the threshold.
func TestScanRepo_MinSeverityNeverChangesFailOn(t *testing.T) {
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: fixtureFindings()})
	setupMinSeverityScan(t, serverURL)
	repoPath := createTestRepo(t)

	failOnSets := [][]string{{"INFO"}, {"LOW"}, {"MEDIUM"}, {"HIGH"}, {"CRITICAL"}, {"HIGH", "CRITICAL"}, {"LOW", "MEDIUM"}, {"MEDIUM", "CRITICAL"}}
	minSeverities := append([]string{""}, minSeverityTestSeverities...)
	formats := []string{"human", "json", "sarif", "junit"}

	for _, outFormat := range formats {
		for _, failOnSevs := range failOnSets {
			baselineFailed, _ := runRepoScan(t, repoPath, outFormat, "", failOnSevs)
			if baselineFailed != expectedFailed(failOnSevs) {
				t.Fatalf("%s/fail-on=%v without --min-severity: failed=%v, want %v", outFormat, failOnSevs, baselineFailed, expectedFailed(failOnSevs))
			}
			for _, minSev := range minSeverities {
				name := fmt.Sprintf("%s/fail-on=%s/min=%s", outFormat, strings.Join(failOnSevs, ","), minSev)
				t.Run(name, func(t *testing.T) {
					failed, out := runRepoScan(t, repoPath, outFormat, minSev, failOnSevs)
					if failed != baselineFailed {
						t.Errorf("--min-severity %q changed the --fail-on result: got failed=%v, want %v", minSev, failed, baselineFailed)
					}
					if got, want := shownCount(t, outFormat, out), expectedShown(minSev); got != want {
						t.Errorf("shown findings = %d, want %d", got, want)
					}
				})
			}
		}
	}
}

// TestScanRepo_MinSeverityJSONShowsOnlyThreshold checks the shown findings are
// the right ones and the summary reports what was hidden.
func TestScanRepo_MinSeverityJSONShowsOnlyThreshold(t *testing.T) {
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: fixtureFindings()})
	setupMinSeverityScan(t, serverURL)

	_, out := runRepoScan(t, createTestRepo(t), "json", "HIGH", []string{"CRITICAL"})

	var parsed model.ScanResult
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	for _, f := range parsed.Findings {
		if f.Severity != model.SeverityHigh && f.Severity != model.SeverityCritical {
			t.Errorf("finding %s with severity %s shown below --min-severity HIGH", f.ID, f.Severity)
		}
	}
	if parsed.Summary.Total != 2 {
		t.Errorf("summary total = %d, want 2", parsed.Summary.Total)
	}
	if parsed.Summary.HiddenBelowMinSeverity != 2 {
		t.Errorf("summary hidden_below_min_severity = %d, want 2", parsed.Summary.HiddenBelowMinSeverity)
	}
	if parsed.Summary.BySeverity[model.SeverityLow] != 0 {
		t.Errorf("summary by_severity still counts hidden LOW findings: %v", parsed.Summary.BySeverity)
	}
}

// TestScanRepo_MinSeverityWarnsWhenHiddenFindingsFail checks the stderr
// warning fires only when hidden findings trip --fail-on.
func TestScanRepo_MinSeverityWarnsWhenHiddenFindingsFail(t *testing.T) {
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: fixtureFindings()})
	setupMinSeverityScan(t, serverURL)
	repoPath := createTestRepo(t)

	tests := []struct {
		name        string
		minSev      string
		failOn      []string
		wantWarning string
	}{
		{name: "hidden HIGH trips fail-on", minSev: "CRITICAL", failOn: []string{"HIGH"}, wantWarning: "1 hidden finding below --min-severity CRITICAL match --fail-on"},
		{name: "two hidden findings trip fail-on", minSev: "HIGH", failOn: []string{"INFO", "LOW"}, wantWarning: "2 hidden findings below --min-severity HIGH match --fail-on"},
		{name: "fail-on only on shown findings", minSev: "HIGH", failOn: []string{"CRITICAL"}},
		{name: "no filter", minSev: "", failOn: []string{"LOW"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stderr := captureStderr(t, func() {
				runRepoScan(t, repoPath, "json", tt.minSev, tt.failOn)
			})
			if tt.wantWarning == "" {
				if strings.Contains(stderr, "--min-severity") {
					t.Errorf("unexpected --min-severity warning: %q", stderr)
				}
				return
			}
			if !strings.Contains(stderr, tt.wantWarning) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantWarning)
			}
		})
	}
}

// TestScanSBOM_MinSeverityKeepsFailOn checks the scan sbom wiring: the filter
// hides findings but the gate still trips on them.
func TestScanSBOM_MinSeverityKeepsFailOn(t *testing.T) {
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: fixtureFindings()})
	setupMinSeverityScan(t, serverURL)

	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	format = "json"
	minSeverity = "CRITICAL"
	failOn = []string{"LOW"}
	outputFile = filepath.Join(tmpDir, "out.json")

	err := scanSBOMCmd.RunE(scanSBOMCmd, []string{sbomPath})
	var exceeded *output.ErrFindingsExceeded
	if !errors.As(err, &exceeded) {
		t.Fatalf("expected --fail-on LOW to trip on a hidden LOW finding, got: %v", err)
	}

	data, readErr := os.ReadFile(filepath.Clean(outputFile))
	if readErr != nil {
		t.Fatalf("read output: %v", readErr)
	}
	if got := shownCount(t, "json", string(data)); got != 1 {
		t.Errorf("shown findings = %d, want 1 (CRITICAL only)", got)
	}
}

// writeMinimalTarball writes a one-file POSIX tar archive and returns its path.
func writeMinimalTarball(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatalf("create tarball: %v", err)
	}
	tw := tar.NewWriter(f)
	content := []byte("{}")
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(content)), Format: tar.FormatUSTAR}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close tarball: %v", err)
	}
	return path
}

// TestScanImage_MinSeverityKeepsFailOn checks the scan image wiring, using a
// --tarball so no docker daemon is needed.
func TestScanImage_MinSeverityKeepsFailOn(t *testing.T) {
	sampleTarball := writeMinimalTarball(t)

	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: fixtureFindings()})
	setupMinSeverityScan(t, serverURL)

	originalTarballPath := tarballPath
	t.Cleanup(func() { tarballPath = originalTarballPath })
	tarballPath = sampleTarball

	format = "json"
	minSeverity = "CRITICAL"
	failOn = []string{"LOW"}
	outputFile = filepath.Join(t.TempDir(), "out.json")

	err := scanImageCmd.RunE(scanImageCmd, nil)
	var exceeded *output.ErrFindingsExceeded
	if !errors.As(err, &exceeded) {
		t.Fatalf("expected --fail-on LOW to trip on a hidden LOW finding, got: %v", err)
	}

	data, readErr := os.ReadFile(filepath.Clean(outputFile))
	if readErr != nil {
		t.Fatalf("read output: %v", readErr)
	}
	if got := shownCount(t, "json", string(data)); got != 1 {
		t.Errorf("shown findings = %d, want 1 (CRITICAL only)", got)
	}
}
