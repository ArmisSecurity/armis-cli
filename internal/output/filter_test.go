package output

import (
	"reflect"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// newFilterTestResult returns one active finding per severity plus one
// suppressed LOW and one suppressed CRITICAL finding.
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
		{name: "MEDIUM hides INFO and LOW, suppressed included", minSeverity: "MEDIUM",
			wantIDs:   []string{"medium", "high", "critical", "critical-suppressed"},
			wantTotal: 3, wantSuppressed: 1, wantHidden: 3},
		{name: "HIGH", minSeverity: "HIGH",
			wantIDs:   []string{"high", "critical", "critical-suppressed"},
			wantTotal: 2, wantSuppressed: 1, wantHidden: 4},
		{name: "CRITICAL", minSeverity: "CRITICAL",
			wantIDs:   []string{"critical", "critical-suppressed"},
			wantTotal: 1, wantSuppressed: 1, wantHidden: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterByMinSeverity(newFilterTestResult(), tt.minSeverity)

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
				if severityRank(sev) > severityRank(model.Severity(tt.minSeverity)) {
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
	got := FilterByMinSeverity(newFilterTestResult(), "HIGH")

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

			got := FilterByMinSeverity(original, minSeverity)

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
			if ShouldFail(original, []string{"INFO"}) != ShouldFail(before, []string{"INFO"}) {
				t.Error("filtering changed the --fail-on result of the input")
			}
		})
	}
}

func TestFilterByMinSeverity_NoFilter(t *testing.T) {
	result := newFilterTestResult()
	if got := FilterByMinSeverity(result, ""); got != result {
		t.Error("expected empty --min-severity to return the input unchanged")
	}
	if got := FilterByMinSeverity(nil, "HIGH"); got != nil {
		t.Errorf("expected nil result to stay nil, got %+v", got)
	}
}

func TestHiddenFailingCount(t *testing.T) {
	tests := []struct {
		name        string
		minSeverity string
		failOn      []string
		want        int
	}{
		{name: "no filter", minSeverity: "", failOn: []string{"LOW"}, want: 0},
		{name: "fail-on only above threshold", minSeverity: "HIGH", failOn: []string{"CRITICAL"}, want: 0},
		{name: "fail-on at threshold is not hidden", minSeverity: "HIGH", failOn: []string{"HIGH"}, want: 0},
		{name: "one hidden level", minSeverity: "CRITICAL", failOn: []string{"HIGH"}, want: 1},
		{name: "suppressed hidden findings ignored", minSeverity: "HIGH", failOn: []string{"LOW"}, want: 1},
		{name: "several hidden levels", minSeverity: "CRITICAL", failOn: []string{"INFO", "LOW", "MEDIUM", "HIGH"}, want: 4},
		{name: "nothing matches", minSeverity: "CRITICAL", failOn: nil, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HiddenFailingCount(newFilterTestResult(), tt.minSeverity, tt.failOn); got != tt.want {
				t.Errorf("HiddenFailingCount(%q, %v) = %d, want %d", tt.minSeverity, tt.failOn, got, tt.want)
			}
		})
	}

	if got := HiddenFailingCount(nil, "HIGH", []string{"LOW"}); got != 0 {
		t.Errorf("HiddenFailingCount(nil) = %d, want 0", got)
	}
}
