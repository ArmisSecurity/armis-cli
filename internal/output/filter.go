package output

import "github.com/ArmisSecurity/armis-cli/internal/model"

// FilterByMinSeverity returns a copy of result holding only findings at or
// above minSeverity, with the summary recomputed over what remains. It never
// mutates result: --min-severity is display-only, so callers must keep passing
// the original result to CheckExit and hand only the copy to the formatter.
// An empty minSeverity (or a nil result) returns result unchanged.
func FilterByMinSeverity(result *model.ScanResult, minSeverity string) *model.ScanResult {
	if result == nil || minSeverity == "" {
		return result
	}

	threshold := severityRank(model.Severity(minSeverity))
	kept := make([]model.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if severityRank(f.Severity) <= threshold {
			kept = append(kept, f)
		}
	}

	filtered := *result
	filtered.Findings = kept
	filtered.Summary = model.Summary{
		BySeverity:             make(map[model.Severity]int),
		ByType:                 make(map[model.FindingType]int),
		ByCategory:             make(map[string]int),
		FilteredNonExploitable: result.Summary.FilteredNonExploitable,
		ScannerSkipReason:      result.Summary.ScannerSkipReason,
		HiddenBelowMinSeverity: len(result.Findings) - len(kept),
	}
	for _, f := range kept {
		if f.Suppressed {
			filtered.Summary.Suppressed++
			continue
		}
		filtered.Summary.Total++
		filtered.Summary.BySeverity[f.Severity]++
		filtered.Summary.ByType[f.Type]++
		if f.FindingCategory != "" {
			filtered.Summary.ByCategory[f.FindingCategory]++
		}
	}

	return &filtered
}

// HiddenFailingCount returns how many active (non-suppressed) findings fall
// below minSeverity yet match failOnSeverities. These findings fail the scan
// via --fail-on while being hidden from the output, so callers warn about them.
func HiddenFailingCount(result *model.ScanResult, minSeverity string, failOnSeverities []string) int {
	if result == nil || minSeverity == "" {
		return 0
	}

	failSet := make(map[string]bool, len(failOnSeverities))
	for _, sev := range failOnSeverities {
		failSet[sev] = true
	}

	threshold := severityRank(model.Severity(minSeverity))
	count := 0
	for _, f := range result.Findings {
		if f.Suppressed || severityRank(f.Severity) <= threshold {
			continue
		}
		if failSet[string(f.Severity)] {
			count++
		}
	}
	return count
}
