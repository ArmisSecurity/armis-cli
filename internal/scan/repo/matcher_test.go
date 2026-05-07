package repo

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func TestMatchFinding(t *testing.T) {
	tests := []struct {
		name    string
		finding model.Finding
		config  *SuppressionConfig
		matched bool
		dirType DirectiveType
		value   string
	}{
		{
			name:    "nil config returns no match",
			finding: model.Finding{Severity: model.SeverityCritical},
			config:  nil,
			matched: false,
		},
		{
			name:    "empty config returns no match",
			finding: model.Finding{Severity: model.SeverityCritical},
			config:  NewSuppressionConfig(),
			matched: false,
		},
		{
			name:    "severity CRITICAL matches CRITICAL finding",
			finding: model.Finding{Severity: model.SeverityCritical},
			config: &SuppressionConfig{
				Severities: []SuppressionDirective{{Type: DirectiveSeverity, Value: "CRITICAL"}},
			},
			matched: true,
			dirType: DirectiveSeverity,
			value:   "CRITICAL",
		},
		{
			name:    "severity LOW does not match HIGH finding",
			finding: model.Finding{Severity: model.SeverityHigh},
			config: &SuppressionConfig{
				Severities: []SuppressionDirective{{Type: DirectiveSeverity, Value: "LOW"}},
			},
			matched: false,
		},
		{
			name:    "category sast matches VULNERABILITY type",
			finding: model.Finding{Type: model.FindingTypeVulnerability},
			config: &SuppressionConfig{
				Categories: []SuppressionDirective{{Type: DirectiveCategory, Value: "sast"}},
			},
			matched: true,
			dirType: DirectiveCategory,
			value:   "sast",
		},
		{
			name:    "category secrets matches SECRET type",
			finding: model.Finding{Type: model.FindingTypeSecret},
			config: &SuppressionConfig{
				Categories: []SuppressionDirective{{Type: DirectiveCategory, Value: "secrets"}},
			},
			matched: true,
			dirType: DirectiveCategory,
			value:   "secrets",
		},
		{
			name:    "category does not match unrelated type",
			finding: model.Finding{Type: model.FindingTypeSCA},
			config: &SuppressionConfig{
				Categories: []SuppressionDirective{{Type: DirectiveCategory, Value: "secrets"}},
			},
			matched: false,
		},
		{
			name:    "cwe 89 matches CWE-89 with description",
			finding: model.Finding{CWEs: []string{"CWE-89: Improper Neutralization of SQL"}},
			config: &SuppressionConfig{
				CWEs: []SuppressionDirective{{Type: DirectiveCWE, Value: "89"}},
			},
			matched: true,
			dirType: DirectiveCWE,
			value:   "89",
		},
		{
			name:    "cwe 79 matches bare CWE-79",
			finding: model.Finding{CWEs: []string{"CWE-79"}},
			config: &SuppressionConfig{
				CWEs: []SuppressionDirective{{Type: DirectiveCWE, Value: "79"}},
			},
			matched: true,
			dirType: DirectiveCWE,
			value:   "79",
		},
		{
			name:    "cwe 0 matches nothing",
			finding: model.Finding{CWEs: []string{"CWE-89"}},
			config: &SuppressionConfig{
				CWEs: []SuppressionDirective{{Type: DirectiveCWE, Value: "0"}},
			},
			matched: false,
		},
		{
			name:    "rule directive always returns no match",
			finding: model.Finding{ID: "test-123"},
			config: &SuppressionConfig{
				Rules: []SuppressionDirective{{Type: DirectiveRule, Value: "some-rule"}},
			},
			matched: false,
		},
		{
			name: "severity wins over category for same finding",
			finding: model.Finding{
				Severity: model.SeverityLow,
				Type:     model.FindingTypeVulnerability,
			},
			config: &SuppressionConfig{
				Severities: []SuppressionDirective{{Type: DirectiveSeverity, Value: "LOW"}},
				Categories: []SuppressionDirective{{Type: DirectiveCategory, Value: "sast"}},
			},
			matched: true,
			dirType: DirectiveSeverity,
			value:   "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchFinding(tt.finding, tt.config)
			if result.Matched != tt.matched {
				t.Fatalf("Matched = %v, want %v", result.Matched, tt.matched)
			}
			if tt.matched {
				if result.Directive.Type != tt.dirType {
					t.Errorf("Directive.Type = %q, want %q", result.Directive.Type, tt.dirType)
				}
				if result.Directive.Value != tt.value {
					t.Errorf("Directive.Value = %q, want %q", result.Directive.Value, tt.value)
				}
			}
		})
	}
}

func TestCweMatches(t *testing.T) {
	tests := []struct {
		name      string
		cwes      []string
		directive string
		want      bool
	}{
		{"CWE-89 with description vs 89", []string{"CWE-89: Improper Neutralization"}, "89", true},
		{"bare 79 vs 79", []string{"79"}, "79", true},
		{"invalid vs 89", []string{"invalid"}, "89", false},
		{"empty cwes", []string{}, "89", false},
		{"multiple cwes, second matches", []string{"CWE-20", "CWE-79"}, "79", true},
		{"lowercase cwe-78 matches", []string{"cwe-78"}, "78", true},
		{"mixed case Cwe-789 matches", []string{"Cwe-789"}, "789", true},
		{"whitespace trimmed", []string{" CWE-89 "}, "89", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cweMatches(tt.cwes, tt.directive)
			if got != tt.want {
				t.Errorf("cweMatches(%v, %q) = %v, want %v", tt.cwes, tt.directive, got, tt.want)
			}
		})
	}
}

func TestApplySuppression(t *testing.T) {
	t.Run("3 findings 2 match returns 2", func(t *testing.T) {
		findings := []model.Finding{
			{Severity: model.SeverityCritical, Type: model.FindingTypeVulnerability},
			{Severity: model.SeverityLow, Type: model.FindingTypeSCA},
			{Severity: model.SeverityLow, Type: model.FindingTypeSecret},
		}
		config := &SuppressionConfig{
			Severities: []SuppressionDirective{{Type: DirectiveSeverity, Value: "LOW"}},
		}

		count := ApplySuppression(findings, config)
		if count != 2 {
			t.Fatalf("ApplySuppression returned %d, want 2", count)
		}
		if findings[0].Suppressed {
			t.Error("findings[0] should not be suppressed")
		}
		if !findings[1].Suppressed || !findings[2].Suppressed {
			t.Error("findings[1] and findings[2] should be suppressed")
		}
		if findings[1].SuppressionInfo == nil || findings[1].SuppressionInfo.Type != "severity" {
			t.Error("findings[1] SuppressionInfo not set correctly")
		}
	})

	t.Run("empty config returns 0 no mutation", func(t *testing.T) {
		findings := []model.Finding{
			{Severity: model.SeverityCritical},
		}
		config := NewSuppressionConfig()

		count := ApplySuppression(findings, config)
		if count != 0 {
			t.Fatalf("ApplySuppression returned %d, want 0", count)
		}
		if findings[0].Suppressed {
			t.Error("finding should not be suppressed with empty config")
		}
	})

	t.Run("reason propagated from directive", func(t *testing.T) {
		findings := []model.Finding{
			{Severity: model.SeverityLow},
		}
		config := &SuppressionConfig{
			Severities: []SuppressionDirective{{
				Type:   DirectiveSeverity,
				Value:  "LOW",
				Reason: "accepted risk",
			}},
		}

		ApplySuppression(findings, config)
		if findings[0].SuppressionInfo.Reason != "accepted risk" {
			t.Errorf("Reason = %q, want %q", findings[0].SuppressionInfo.Reason, "accepted risk")
		}
	})
}

func TestRecomputeSummary(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical, Type: model.FindingTypeVulnerability, FindingCategory: "CODE_VULNERABILITY"},
		{Severity: model.SeverityLow, Type: model.FindingTypeSCA, Suppressed: true},
		{Severity: model.SeverityLow, Type: model.FindingTypeSCA, Suppressed: true},
	}

	summary := recomputeSummary(findings, 2, 5)

	if summary.Total != 1 {
		t.Errorf("Total = %d, want 1", summary.Total)
	}
	if summary.Suppressed != 2 {
		t.Errorf("Suppressed = %d, want 2", summary.Suppressed)
	}
	if summary.FilteredNonExploitable != 5 {
		t.Errorf("FilteredNonExploitable = %d, want 5", summary.FilteredNonExploitable)
	}
	if summary.BySeverity[model.SeverityCritical] != 1 {
		t.Errorf("BySeverity[CRITICAL] = %d, want 1", summary.BySeverity[model.SeverityCritical])
	}
	if summary.BySeverity[model.SeverityLow] != 0 {
		t.Errorf("BySeverity[LOW] = %d, want 0", summary.BySeverity[model.SeverityLow])
	}
}

func TestFilterActiveFindings(t *testing.T) {
	findings := []model.Finding{
		{ID: "1", Suppressed: false},
		{ID: "2", Suppressed: true},
		{ID: "3", Suppressed: false},
	}

	active := filterActiveFindings(findings)
	if len(active) != 2 {
		t.Fatalf("filterActiveFindings returned %d findings, want 2", len(active))
	}
	if active[0].ID != "1" || active[1].ID != "3" {
		t.Errorf("unexpected active findings: %v", active)
	}
}
