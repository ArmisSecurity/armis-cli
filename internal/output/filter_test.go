package output

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// newFilterTestResult returns one active finding per severity plus one
// suppressed LOW and one suppressed CRITICAL finding. The filter must keep
// both suppressed findings at every threshold.
func newFilterTestResult() *model.ScanResult {
	findings := []model.Finding{
		{ID: "info", Severity: model.SeverityInfo, Type: model.FindingTypeVulnerability, FindingCategory: "sast"},
		{ID: "low", Severity: model.SeverityLow, Type: model.FindingTypeSCA},
		{ID: "medium", Severity: model.SeverityMedium, Type: model.FindingTypeSecret, FindingCategory: "secrets"},
		{ID: "high", Severity: model.SeverityHigh, Type: model.FindingTypeVulnerability, FindingCategory: "sast"},
		{ID: "critical", Severity: model.SeverityCritical, Type: model.FindingTypeVulnerability, FindingCategory: "sast"},
		{ID: "low-suppressed", Severity: model.SeverityLow, Type: model.FindingTypeSCA, Suppressed: true},
		{ID: "critical-suppressed", Severity: model.SeverityCritical, Type: model.FindingTypeVulnerability, Suppressed: true},
	}
	return &model.ScanResult{
		ScanID:   "scan-1",
		Status:   "completed",
		Findings: findings,
		Summary: model.Summary{
			Total: 5,
			BySeverity: map[model.Severity]int{
				model.SeverityInfo: 1, model.SeverityLow: 1, model.SeverityMedium: 1,
				model.SeverityHigh: 1, model.SeverityCritical: 1,
			},
			ByType: map[model.FindingType]int{
				model.FindingTypeVulnerability: 3, model.FindingTypeSCA: 1, model.FindingTypeSecret: 1,
			},
			ByCategory:             map[string]int{"sast": 3, "secrets": 1},
			FilteredNonExploitable: 4,
			Suppressed:             2,
			ScannerSkipReason:      "file limit",
		},
		StartedAt: "2026-10-12T09:00:00Z",
		EndedAt:   "2026-10-12T09:01:00Z",
	}
}

func findingIDs(findings []model.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestFilterByMinSeverity(t *testing.T) {
	tests := []struct {
		name           string
		minSeverity    string
		wantIDs        []string
		wantTotal      int
		wantSuppressed int
		wantHidden     int
	}{
		{name: "INFO keeps everything", minSeverity: "INFO",
			wantIDs:   []string{"info", "low", "medium", "high", "critical", "low-suppressed", "critical-suppressed"},
			wantTotal: 5, wantSuppressed: 2, wantHidden: 0},
		{name: "LOW hides INFO", minSeverity: "LOW",
			wantIDs:   []string{"low", "medium", "high", "critical", "low-suppressed", "critical-suppressed"},
			wantTotal: 4, wantSuppressed: 2, wantHidden: 1},
		{name: "MEDIUM hides INFO and LOW, keeps suppressed LOW", minSeverity: "MEDIUM",
			wantIDs:   []string{"medium", "high", "critical", "low-suppressed", "critical-suppressed"},
			wantTotal: 3, wantSuppressed: 2, wantHidden: 2},
		{name: "HIGH", minSeverity: "HIGH",
			wantIDs:   []string{"high", "critical", "low-suppressed", "critical-suppressed"},
			wantTotal: 2, wantSuppressed: 2, wantHidden: 3},
		{name: "CRITICAL", minSeverity: "CRITICAL",
			wantIDs:   []string{"critical", "low-suppressed", "critical-suppressed"},
			wantTotal: 1, wantSuppressed: 2, wantHidden: 4},
		{name: "lowercase is normalized", minSeverity: "high",
			wantIDs:   []string{"high", "critical", "low-suppressed", "critical-suppressed"},
			wantTotal: 2, wantSuppressed: 2, wantHidden: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FilterByMinSeverity(newFilterTestResult(), tt.minSeverity)
			if err != nil {
				t.Fatalf("FilterByMinSeverity(%q): %v", tt.minSeverity, err)
			}

			if ids := findingIDs(got.Findings); !reflect.DeepEqual(ids, tt.wantIDs) {
				t.Errorf("findings = %v, want %v", ids, tt.wantIDs)
			}
			if got.Summary.Total != tt.wantTotal {
				t.Errorf("Summary.Total = %d, want %d", got.Summary.Total, tt.wantTotal)
			}
			if got.Summary.Suppressed != tt.wantSuppressed {
				t.Errorf("Summary.Suppressed = %d, want %d", got.Summary.Suppressed, tt.wantSuppressed)
			}
			if got.Summary.HiddenBelowMinSeverity != tt.wantHidden {
				t.Errorf("Summary.HiddenBelowMinSeverity = %d, want %d", got.Summary.HiddenBelowMinSeverity, tt.wantHidden)
			}

			bySeverityTotal := 0
			for sev, n := range got.Summary.BySeverity {
				if severityRank(sev) > severityRank(model.Severity(strings.ToUpper(tt.minSeverity))) {
					t.Errorf("Summary.BySeverity counts %d %s findings below %s", n, sev, tt.minSeverity)
				}
				bySeverityTotal += n
			}
			if bySeverityTotal != tt.wantTotal {
				t.Errorf("Summary.BySeverity sums to %d, want %d", bySeverityTotal, tt.wantTotal)
			}

			// Carried over unchanged
			if got.ScanID != "scan-1" || got.Status != "completed" || got.StartedAt == "" || got.EndedAt == "" {
				t.Errorf("scan metadata not carried over: %+v", got)
			}
			if got.Summary.FilteredNonExploitable != 4 || got.Summary.ScannerSkipReason != "file limit" {
				t.Errorf("summary metadata not carried over: %+v", got.Summary)
			}
		})
	}
}

func TestFilterByMinSeverity_RecomputesTypeAndCategory(t *testing.T) {
	got, err := FilterByMinSeverity(newFilterTestResult(), "HIGH")
	if err != nil {
		t.Fatal(err)
	}

	wantByType := map[model.FindingType]int{model.FindingTypeVulnerability: 2}
	if !reflect.DeepEqual(got.Summary.ByType, wantByType) {
		t.Errorf("ByType = %v, want %v", got.Summary.ByType, wantByType)
	}
	wantByCategory := map[string]int{"sast": 2}
	if !reflect.DeepEqual(got.Summary.ByCategory, wantByCategory) {
		t.Errorf("ByCategory = %v, want %v", got.Summary.ByCategory, wantByCategory)
	}
}

// TestFilterByMinSeverity_DoesNotMutateInput guards the display-only contract:
// CheckExit runs on the original result after the formatter has the copy.
func TestFilterByMinSeverity_DoesNotMutateInput(t *testing.T) {
	for _, minSeverity := range []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		t.Run(minSeverity, func(t *testing.T) {
			original := newFilterTestResult()
			before := newFilterTestResult()

			got, err := FilterByMinSeverity(original, minSeverity)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(original, before) {
				t.Errorf("FilterByMinSeverity(%s) mutated its input", minSeverity)
			}
			if got == original {
				t.Fatal("expected a new ScanResult, got the input pointer")
			}

			// Writing to the copy's maps must not reach the input.
			got.Summary.BySeverity[model.SeverityInfo] = 99
			got.Summary.ByType[model.FindingTypeLicense] = 99
			got.Summary.ByCategory["iac"] = 99
			if !reflect.DeepEqual(original, before) {
				t.Error("filtered summary shares maps with the input")
			}
		})
	}
}

func TestFilterByMinSeverity_NoFilter(t *testing.T) {
	result := newFilterTestResult()
	if got, err := FilterByMinSeverity(result, ""); err != nil || got != result {
		t.Errorf("expected empty --min-severity to return the input unchanged, got err %v", err)
	}
	if got, err := FilterByMinSeverity(nil, "HIGH"); err != nil || got != nil {
		t.Errorf("expected nil result to stay nil, got %+v, err %v", got, err)
	}
	// No findings stays nil so JSON keeps emitting "findings": null.
	if got, err := FilterByMinSeverity(&model.ScanResult{}, "HIGH"); err != nil || got.Findings != nil {
		t.Errorf("expected nil findings to stay nil, got %#v, err %v", got, err)
	}
}

func TestFilterByMinSeverity_RejectsUnknownSeverity(t *testing.T) {
	for _, minSeverity := range []string{"HIGHT", "urgent", " HIGH"} {
		if _, err := FilterByMinSeverity(newFilterTestResult(), minSeverity); err == nil {
			t.Errorf("FilterByMinSeverity(%q) = nil error, want an error", minSeverity)
		}
	}
}

func TestHiddenFailingWarning(t *testing.T) {
	tests := []struct {
		count int
		want  string
	}{
		{1, "1 hidden finding below --min-severity HIGH matches --fail-on; the scan fails on it"},
		{2, "2 hidden findings below --min-severity HIGH match --fail-on; the scan fails on them"},
	}
	for _, tt := range tests {
		if got := HiddenFailingWarning(tt.count, "HIGH"); got != tt.want {
			t.Errorf("HiddenFailingWarning(%d) = %q, want %q", tt.count, got, tt.want)
		}
	}
}
