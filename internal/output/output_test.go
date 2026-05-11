package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantErr  bool
		wantType interface{}
	}{
		{
			name:     "human formatter",
			format:   "human",
			wantErr:  false,
			wantType: &HumanFormatter{},
		},
		{
			name:     "json formatter",
			format:   "json",
			wantErr:  false,
			wantType: &JSONFormatter{},
		},
		{
			name:     "sarif formatter",
			format:   "sarif",
			wantErr:  false,
			wantType: &SARIFFormatter{},
		},
		{
			name:     "junit formatter",
			format:   "junit",
			wantErr:  false,
			wantType: &JUnitFormatter{},
		},
		{
			name:    "unsupported formatter",
			format:  "xml",
			wantErr: true,
		},
		{
			name:    "empty format",
			format:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter, err := GetFormatter(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetFormatter(%q) expected error, got nil", tt.format)
				}
			} else {
				if err != nil {
					t.Errorf("GetFormatter(%q) unexpected error: %v", tt.format, err)
				}
				if formatter == nil {
					t.Errorf("GetFormatter(%q) returned nil formatter", tt.format)
				}
			}
		})
	}
}

func TestShouldFail(t *testing.T) {
	tests := []struct {
		name             string
		findings         []model.Finding
		failOnSeverities []string
		expected         bool
	}{
		{
			name:             "no findings",
			findings:         []model.Finding{},
			failOnSeverities: []string{"CRITICAL", "HIGH"},
			expected:         false,
		},
		{
			name: "has critical finding and should fail on critical",
			findings: []model.Finding{
				{Severity: model.SeverityCritical},
			},
			failOnSeverities: []string{"CRITICAL"},
			expected:         true,
		},
		{
			name: "has high finding but only fail on critical",
			findings: []model.Finding{
				{Severity: model.SeverityHigh},
			},
			failOnSeverities: []string{"CRITICAL"},
			expected:         false,
		},
		{
			name: "has multiple findings with one matching",
			findings: []model.Finding{
				{Severity: model.SeverityLow},
				{Severity: model.SeverityMedium},
				{Severity: model.SeverityHigh},
			},
			failOnSeverities: []string{"HIGH", "CRITICAL"},
			expected:         true,
		},
		{
			name: "no matching severities",
			findings: []model.Finding{
				{Severity: model.SeverityLow},
				{Severity: model.SeverityInfo},
			},
			failOnSeverities: []string{"CRITICAL", "HIGH"},
			expected:         false,
		},
		{
			name: "empty fail on severities",
			findings: []model.Finding{
				{Severity: model.SeverityCritical},
			},
			failOnSeverities: []string{},
			expected:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.ScanResult{
				Findings: tt.findings,
			}

			shouldFail := ShouldFail(result, tt.failOnSeverities)
			if shouldFail != tt.expected {
				t.Errorf("ShouldFail() = %v, want %v", shouldFail, tt.expected)
			}
		})
	}
}

func TestShouldFail_CaseSensitive(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityHigh},
		},
	}

	if ShouldFail(result, []string{"high"}) {
		t.Error("ShouldFail should be case-sensitive and not match 'high' with 'HIGH'")
	}

	if !ShouldFail(result, []string{"HIGH"}) {
		t.Error("ShouldFail should match 'HIGH' with 'HIGH'")
	}
}

func TestCheckExit_ReturnsErrorOnMatchingSeverity(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityCritical},
		},
	}

	err := CheckExit(result, []string{"CRITICAL"}, 2)

	if err == nil {
		t.Error("CheckExit should return error when severity matches")
	}

	var findingsErr *ErrFindingsExceeded
	if !errors.As(err, &findingsErr) {
		t.Errorf("CheckExit should return *ErrFindingsExceeded, got %T", err)
	}
	if findingsErr.ExitCode != 2 {
		t.Errorf("ErrFindingsExceeded.ExitCode = %d, want 2", findingsErr.ExitCode)
	}
}

func TestCheckExit_ReturnsNilWhenNoMatch(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityLow},
		},
	}

	err := CheckExit(result, []string{"CRITICAL", "HIGH"}, 1)

	if err != nil {
		t.Errorf("CheckExit should return nil when severity does not match, got %v", err)
	}
}

func TestCheckExit_NormalizesExitCode(t *testing.T) {
	tests := []struct {
		name         string
		inputCode    int
		expectedCode int
	}{
		{"negative code normalizes to 1", -1, 1},
		{"code above 255 normalizes to 1", 256, 1},
		{"code 0 stays 0", 0, 0},
		{"code 255 stays 255", 255, 255},
		{"code 100 stays 100", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.ScanResult{
				Findings: []model.Finding{
					{Severity: model.SeverityCritical},
				},
			}

			err := CheckExit(result, []string{"CRITICAL"}, tt.inputCode)

			var findingsErr *ErrFindingsExceeded
			if !errors.As(err, &findingsErr) {
				t.Fatalf("CheckExit should return *ErrFindingsExceeded, got %T", err)
			}
			if findingsErr.ExitCode != tt.expectedCode {
				t.Errorf("CheckExit with code %d returned ExitCode %d, want %d",
					tt.inputCode, findingsErr.ExitCode, tt.expectedCode)
			}
		})
	}
}

func TestCheckExit_StdoutSyncError(t *testing.T) {
	// Save originals and restore after test
	originalStdoutSyncer := stdoutSyncer
	originalStderrWriter := stderrWriter
	defer func() {
		stdoutSyncer = originalStdoutSyncer
		stderrWriter = originalStderrWriter
	}()

	// Mock stdoutSyncer to return an error
	stdoutSyncer = func() error {
		return errors.New("sync failed")
	}

	// Capture stderr output
	var stderrBuf bytes.Buffer
	stderrWriter = &stderrBuf

	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityCritical},
		},
	}

	err := CheckExit(result, []string{"CRITICAL"}, 1)

	// Should still return error despite sync failure
	if err == nil {
		t.Error("CheckExit should return error even when stdout sync fails")
	}

	stderrOutput := stderrBuf.String()
	if stderrOutput == "" {
		t.Error("CheckExit should write warning to stderr when stdout sync fails")
	}
	if !bytes.Contains(stderrBuf.Bytes(), []byte("Warning")) {
		t.Errorf("stderr output should contain 'Warning', got: %s", stderrOutput)
	}
	if !bytes.Contains(stderrBuf.Bytes(), []byte("sync failed")) {
		t.Errorf("stderr output should contain error message, got: %s", stderrOutput)
	}
}

func TestShouldFail_SkipsSuppressedCritical(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityCritical, Suppressed: true},
			{Severity: model.SeverityLow},
		},
	}

	if ShouldFail(result, []string{"CRITICAL"}) {
		t.Error("ShouldFail should skip suppressed CRITICAL findings")
	}
}

func TestShouldFail_MixedSuppressedAndActive(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{
			{Severity: model.SeverityCritical, Suppressed: true},
			{Severity: model.SeverityHigh},
		},
	}

	if ShouldFail(result, []string{"CRITICAL"}) {
		t.Error("ShouldFail should not trigger on suppressed CRITICAL when only active HIGH exists")
	}
	if !ShouldFail(result, []string{"HIGH"}) {
		t.Error("ShouldFail should trigger on active HIGH")
	}
}

func TestFilterActiveFindings(t *testing.T) {
	findings := []model.Finding{
		{ID: "1", Suppressed: false},
		{ID: "2", Suppressed: true},
		{ID: "3", Suppressed: false},
	}
	active := FilterActiveFindings(findings)
	if len(active) != 2 {
		t.Fatalf("FilterActiveFindings returned %d, want 2", len(active))
	}
	if active[0].ID != "1" || active[1].ID != "3" {
		t.Errorf("unexpected active IDs: %s, %s", active[0].ID, active[1].ID)
	}
}

// TestSyncColors_Enabled verifies that SyncColors enables styling when cli colors are enabled.
func TestSyncColors_Enabled(t *testing.T) {
	// Enable colors via cli package
	cli.InitColors(cli.ColorModeAlways)

	// Sync should enable output package styles
	SyncColors()

	// Verify styles are set by checking that DefaultStyles is used
	s := GetStyles()
	// CriticalBadge should have padding and styling
	rendered := s.CriticalBadge.Render("TEST")

	// With ColorModeAlways, lipgloss forces ANSI output even in non-TTY
	// Check that output contains "TEST" and has ANSI codes (indicating style was applied)
	if !strings.Contains(rendered, "TEST") {
		t.Errorf("expected rendered badge to contain 'TEST', got %q", rendered)
	}
	// Either plain " TEST " (no color profile) or ANSI-styled output
	hasANSI := strings.Contains(rendered, "\033[")
	hasPlainPadding := rendered == " TEST "
	if !hasANSI && !hasPlainPadding {
		t.Errorf("expected rendered badge to have ANSI codes or plain padding, got %q", rendered)
	}
}

// TestSyncColors_Disabled verifies that SyncColors disables styling when cli colors are disabled.
func TestSyncColors_Disabled(t *testing.T) {
	// Disable colors via cli package
	cli.InitColors(cli.ColorModeNever)

	// Sync should disable output package styles
	SyncColors()

	// Verify NoColorStyles is used - badge should render without padding
	s := GetStyles()
	rendered := s.CriticalBadge.Render("TEST")
	// NoColorStyles uses plain style with no padding
	if rendered != "TEST" {
		t.Errorf("expected rendered badge to be plain 'TEST' when colors are disabled, got %q", rendered)
	}
}
