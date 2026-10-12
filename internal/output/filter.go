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

	// Unknown severities rank lowest (severityRank's fallback) and are hidden;
	// scan.MapSeverity maps them to INFO before they get here.
	threshold := severityRank(model.Severity(minSeverity))
	var kept []model.Finding
	for _, f := range result.Findings {
		if severityRank(f.Severity) <= threshold {
			kept = append(kept, f)
		}
	}

	filtered := *result
	filtered.Findings = kept
	filtered.Summary = model.SummarizeFindings(kept)
	filtered.Summary.FilteredNonExploitable = result.Summary.FilteredNonExploitable
	filtered.Summary.ScannerSkipReason = result.Summary.ScannerSkipReason
	filtered.Summary.HiddenBelowMinSeverity = len(result.Findings) - len(kept)

	return &filtered
}
