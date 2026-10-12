package cmd

import (
	"archive/tar"
	"bytes"
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

// minSeverityLevels lists every severity from least to most severe.
var minSeverityLevels = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// minSeverityFixture is the severity of each test finding. MEDIUM is left out
// on purpose so some --fail-on sets don't trip, and the tests cover scans that
// should pass as well as scans that should fail.
var minSeverityFixture = []string{"INFO", "LOW", "HIGH", "CRITICAL"}

func severityIndex(sev string) int {
	for i, s := range minSeverityLevels {
		if s == sev {
			return i
		}
	}
	return -1
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

// expectedFailed reports whether any fixture finding matches failOn.
func expectedFailed(failOn []string) bool {
	for _, sev := range minSeverityFixture {
		for _, f := range failOn {
			if sev == f {
				return true
			}
		}
	}
	return false
}

// fixtureResult returns a scan result with one finding per minSeverityFixture entry.
func fixtureResult() *model.ScanResult {
	result := &model.ScanResult{ScanID: "scan-1", Status: "completed"}
	for _, sev := range minSeverityFixture {
		result.Findings = append(result.Findings, model.Finding{
			ID: "finding-" + strings.ToLower(sev), Title: sev + " finding", Severity: model.Severity(sev), Type: model.FindingTypeVulnerability,
		})
	}
	result.Summary = model.SummarizeFindings(result.Findings)
	return result
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
		if err := json.Unmarshal([]byte(out), &parsed); err != nil || len(parsed.Runs) != 1 {
			t.Fatalf("parse sarif (runs=%d): %v", len(parsed.Runs), err)
		}
		return len(parsed.Runs[0].Results)
	case "junit":
		var parsed struct {
			Suites []struct {
				Tests int `xml:"tests,attr"`
			} `xml:"testsuite"`
		}
		if err := xml.Unmarshal([]byte(out), &parsed); err != nil || len(parsed.Suites) != 1 {
			t.Fatalf("parse junit (suites=%d): %v", len(parsed.Suites), err)
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

// runFormatScanResult formats fixtureResult and reports whether the --fail-on
// gate tripped, plus the formatted output.
func runFormatScanResult(t *testing.T, outFormat, minSev string, failOn []string) (bool, string) {
	t.Helper()

	formatter, err := output.GetFormatter(outFormat)
	if err != nil {
		t.Fatalf("GetFormatter(%s): %v", outFormat, err)
	}
	var buf bytes.Buffer
	err = formatScanResult(formatter, fixtureResult(), &buf, output.FormatOptions{}, minSev, failOn)
	var exceeded *output.ErrFindingsExceeded
	if err != nil && !errors.As(err, &exceeded) {
		t.Fatalf("formatScanResult(format=%s, min=%q, fail-on=%v): %v", outFormat, minSev, failOn, err)
	}
	return err != nil, buf.String()
}

// TestFormatScanResult_MinSeverityNeverChangesFailOn locks in that
// --min-severity is display-only: for every --min-severity × --fail-on
// combination, the exit decision matches the fixture and is the same as
// without the filter.
func TestFormatScanResult_MinSeverityNeverChangesFailOn(t *testing.T) {
	forceNoColor(t)
	failOnSets := [][]string{{"INFO"}, {"LOW"}, {"MEDIUM"}, {"HIGH"}, {"CRITICAL"}, {"HIGH", "CRITICAL"}, {"LOW", "MEDIUM"}, {"MEDIUM", "CRITICAL"}}

	for _, failOn := range failOnSets {
		for _, minSev := range append([]string{""}, minSeverityLevels...) {
			t.Run(fmt.Sprintf("fail-on=%s/min=%s", strings.Join(failOn, ","), minSev), func(t *testing.T) {
				failed, _ := runFormatScanResult(t, "json", minSev, failOn)
				if want := expectedFailed(failOn); failed != want {
					t.Errorf("gate failed=%v, want %v", failed, want)
				}
			})
		}
	}
}

// TestFormatScanResult_MinSeverityFiltersEveryFormat checks each formatter
// shows exactly the findings at or above the threshold, except SARIF, which
// always gets every finding so GitHub code scanning never closes alerts.
func TestFormatScanResult_MinSeverityFiltersEveryFormat(t *testing.T) {
	forceNoColor(t)

	for _, outFormat := range []string{"human", "json", "sarif", "junit"} {
		for _, minSev := range append([]string{""}, minSeverityLevels...) {
			t.Run(outFormat+"/min="+minSev, func(t *testing.T) {
				_, out := runFormatScanResult(t, outFormat, minSev, nil)
				want := expectedShown(minSev)
				if outFormat == "sarif" {
					want = len(minSeverityFixture)
				}
				if got := shownCount(t, outFormat, out); got != want {
					t.Errorf("shown findings = %d, want %d", got, want)
				}
			})
		}
	}
}

// TestFormatScanResult_MinSeverityWarnings checks the stderr warnings: how many
// hidden findings trip --fail-on (quiet when only shown findings do), and that
// SARIF says the flag doesn't apply to it.
func TestFormatScanResult_MinSeverityWarnings(t *testing.T) {
	forceNoColor(t)

	tests := []struct {
		name        string
		format      string
		minSev      string
		failOn      []string
		wantWarning string
	}{
		{name: "hidden findings trip fail-on", format: "json", minSev: "HIGH", failOn: []string{"INFO", "LOW"},
			wantWarning: "2 hidden findings below --min-severity HIGH match --fail-on; the scan fails on them"},
		{name: "one hidden finding trips fail-on", format: "json", minSev: "HIGH", failOn: []string{"LOW"},
			wantWarning: "1 hidden finding below --min-severity HIGH matches --fail-on; the scan fails on it"},
		{name: "only shown findings trip fail-on", format: "json", minSev: "HIGH", failOn: []string{"CRITICAL"}},
		{name: "sarif ignores the flag", format: "sarif", minSev: "HIGH", failOn: []string{"INFO", "LOW"},
			wantWarning: "--min-severity is ignored for SARIF output; all findings are included"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stderr := captureStderr(t, func() {
				runFormatScanResult(t, tt.format, tt.minSev, tt.failOn)
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
			if tt.format == "sarif" && strings.Contains(stderr, "hidden") {
				t.Errorf("sarif hides nothing, but stderr = %q", stderr)
			}
		})
	}
}

// TestFormatScanResult_MinSeverityKeepsSuppressedFindings checks findings that
// .armisignore suppressed are left alone: they can't fail --fail-on, so they
// keep their own summary line and are not counted as hidden.
func TestFormatScanResult_MinSeverityKeepsSuppressedFindings(t *testing.T) {
	forceNoColor(t)

	result := &model.ScanResult{ScanID: "scan-1", Status: "completed"}
	for i := 0; i < 3; i++ {
		result.Findings = append(result.Findings, model.Finding{
			ID: fmt.Sprintf("low-%d", i), Severity: model.SeverityLow, Type: model.FindingTypeVulnerability, Suppressed: true,
		})
	}
	result.Summary = model.SummarizeFindings(result.Findings)

	for _, outFormat := range []string{"human", "json"} {
		t.Run(outFormat, func(t *testing.T) {
			formatter, err := output.GetFormatter(outFormat)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := formatScanResult(formatter, result, &buf, output.FormatOptions{}, "HIGH", []string{"LOW"}); err != nil {
				t.Fatalf("suppressed findings must not trip --fail-on: %v", err)
			}
			out := buf.String()
			if strings.Contains(out, "hidden") {
				t.Errorf("suppressed findings counted as hidden:\n%s", out)
			}
			if outFormat == "human" && !strings.Contains(out, "No active issues (3 suppressed by .armisignore)") {
				t.Errorf("want the .armisignore summary line, got:\n%s", out)
			}
			if outFormat == "json" && !strings.Contains(out, `"suppressed": 3`) {
				t.Errorf("want suppressed: 3 in JSON, got:\n%s", out)
			}
		})
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

// TestScanCommands_MinSeverityKeepsFailOn checks every scan command routes
// through formatScanResult: the filter hides findings from the output, but
// --fail-on still trips on them.
func TestScanCommands_MinSeverityKeepsFailOn(t *testing.T) {
	findings := make([]model.NormalizedFinding, 0, len(minSeverityFixture))
	for _, sev := range minSeverityFixture {
		findings = append(findings, testhelpers.CreateNormalizedFinding("finding-"+strings.ToLower(sev), sev, "test", nil, nil))
	}
	serverURL := testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{Findings: findings})

	originalToken, originalTenantID := token, tenantID
	originalClientID, originalClientSecret := clientID, clientSecret
	originalFormat, originalColorFlag, originalThemeFlag := format, colorFlag, themeFlag
	originalNoUpdateCheck, originalNoProgress := noUpdateCheck, noProgress
	originalPollInterval, originalExitCode := pollInterval, exitCode
	originalFailOn, originalMinSeverity := failOn, minSeverity
	originalOutputFile, originalTarballPath := outputFile, tarballPath
	t.Cleanup(func() {
		token, tenantID = originalToken, originalTenantID
		clientID, clientSecret = originalClientID, originalClientSecret
		format, colorFlag, themeFlag = originalFormat, originalColorFlag, originalThemeFlag
		noUpdateCheck, noProgress = originalNoUpdateCheck, originalNoProgress
		pollInterval, exitCode = originalPollInterval, originalExitCode
		failOn, minSeverity = originalFailOn, originalMinSeverity
		outputFile, tarballPath = originalOutputFile, originalTarballPath
	})

	t.Setenv("ARMIS_API_URL", serverURL)
	t.Setenv("ARMIS_CLIENT_ID", "")
	t.Setenv("ARMIS_CLIENT_SECRET", "")
	token, tenantID, clientID, clientSecret = testToken, testTenantID, "", ""
	colorFlag, themeFlag = testColorNever, themeAuto
	noUpdateCheck, noProgress = true, true
	pollInterval = 10 * time.Millisecond
	exitCode = 1

	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	commands := []struct {
		name  string
		run   func() error
		setup func()
	}{
		{name: "repo", run: func() error { return scanRepoCmd.RunE(scanRepoCmd, []string{createTestRepo(t)}) }},
		{name: "image", setup: func() { tarballPath = writeMinimalTarball(t) }, run: func() error { return scanImageCmd.RunE(scanImageCmd, nil) }},
		{name: "sbom", run: func() error { return scanSBOMCmd.RunE(scanSBOMCmd, []string{sbomPath}) }},
	}

	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			tarballPath = ""
			if c.setup != nil {
				c.setup()
			}
			format = "json"
			minSeverity = "CRITICAL"
			failOn = []string{"LOW"}
			outputFile = filepath.Join(t.TempDir(), "out.json")

			var exceeded *output.ErrFindingsExceeded
			if err := c.run(); !errors.As(err, &exceeded) {
				t.Fatalf("expected --fail-on LOW to trip on a hidden LOW finding, got: %v", err)
			}

			data, err := os.ReadFile(filepath.Clean(outputFile))
			if err != nil {
				t.Fatalf("read output: %v", err)
			}
			var parsed model.ScanResult
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("parse json: %v", err)
			}
			if len(parsed.Findings) != 1 || parsed.Findings[0].Severity != model.SeverityCritical {
				t.Errorf("shown findings = %+v, want only the CRITICAL one", parsed.Findings)
			}
			if parsed.Summary.HiddenBelowMinSeverity != 3 {
				t.Errorf("summary hidden_below_min_severity = %d, want 3", parsed.Summary.HiddenBelowMinSeverity)
			}
		})
	}
}
