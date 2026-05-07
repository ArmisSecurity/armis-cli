package repo

import (
	"regexp"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

var cweIntPattern = regexp.MustCompile(`(?i)^CWE-(\d+)`)

// categoryToFindingType maps .armisignore category directive values to FindingType.
var categoryToFindingType = map[string]model.FindingType{
	"sast":    model.FindingTypeVulnerability,
	"secrets": model.FindingTypeSecret,
	"iac":     model.FindingTypeMisconfig,
	"sca":     model.FindingTypeSCA,
	"license": model.FindingTypeLicense,
}

// MatchResult describes the first directive that matched a finding.
type MatchResult struct {
	Matched   bool
	Directive SuppressionDirective
}

// MatchFinding returns the first matching suppression directive for a finding.
func MatchFinding(finding model.Finding, config *SuppressionConfig) MatchResult {
	if config == nil || config.IsEmpty() {
		return MatchResult{}
	}

	for _, d := range config.Severities {
		if strings.EqualFold(d.Value, string(finding.Severity)) {
			return MatchResult{Matched: true, Directive: d}
		}
	}

	for _, d := range config.Categories {
		expected, ok := categoryToFindingType[d.Value]
		if ok && finding.Type == expected {
			return MatchResult{Matched: true, Directive: d}
		}
	}

	for _, d := range config.CWEs {
		if cweMatches(finding.CWEs, d.Value) {
			return MatchResult{Matched: true, Directive: d}
		}
	}

	// rule: directives are no-ops until scanner_rule_id is available (ADR-0007)

	return MatchResult{}
}

// cweMatches checks if any of the finding's CWE identifiers match the directive value.
// The directive value is a bare integer string (e.g. "89").
// Finding CWEs may be in the format "CWE-89: Improper...", "cwe-89", or just "89".
// Matching is case-insensitive and whitespace-tolerant.
func cweMatches(findingCWEs []string, directiveValue string) bool {
	for _, cwe := range findingCWEs {
		trimmed := strings.TrimSpace(cwe)
		if matches := cweIntPattern.FindStringSubmatch(trimmed); len(matches) == 2 {
			if matches[1] == directiveValue {
				return true
			}
		} else if trimmed == directiveValue {
			return true
		}
	}
	return false
}

// ApplySuppression mutates findings in-place, marking matched findings as suppressed.
// Returns the count of suppressed findings.
func ApplySuppression(findings []model.Finding, config *SuppressionConfig) int {
	if config == nil || config.IsEmpty() {
		return 0
	}

	suppressed := 0
	for i := range findings {
		result := MatchFinding(findings[i], config)
		if result.Matched {
			findings[i].Suppressed = true
			findings[i].SuppressionInfo = &model.SuppressionInfo{
				Type:   string(result.Directive.Type),
				Value:  result.Directive.Value,
				Reason: result.Directive.Reason,
			}
			suppressed++
		}
	}
	return suppressed
}

// recomputeSummary rebuilds the Summary counting only active (non-suppressed) findings.
func recomputeSummary(findings []model.Finding, suppressed int, filteredNonExploitable int) model.Summary {
	summary := model.Summary{
		BySeverity:             make(map[model.Severity]int),
		ByType:                 make(map[model.FindingType]int),
		ByCategory:             make(map[string]int),
		Suppressed:             suppressed,
		FilteredNonExploitable: filteredNonExploitable,
	}

	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		summary.Total++
		summary.BySeverity[f.Severity]++
		summary.ByType[f.Type]++
		if f.FindingCategory != "" {
			summary.ByCategory[f.FindingCategory]++
		}
	}

	return summary
}
