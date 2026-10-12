package output

import (
	"fmt"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// FilterByMinSeverity returns a copy of result without the active findings
// below minSeverity, with the summary recomputed over what remains. It never
// mutates result: --min-severity is display-only, so callers must keep passing
// the original result to CheckExit and hand only the copy to the formatter.
// Suppressed findings are kept as they are, since --fail-on never counts them
// and .armisignore already controls how they are shown. minSeverity is
// case-insensitive; an unknown value is an error. An empty minSeverity (or a
// nil result) returns result unchanged.
func FilterByMinSeverity(result *model.ScanResult, minSeverity string) (*model.ScanResult, error) {
	if result == nil || minSeverity == "" {
		return result, nil
	}

	threshold, ok := severityRanks[model.Severity(strings.ToUpper(minSeverity))]
	if !ok {
		return nil, fmt.Errorf("invalid minimum severity %q", minSeverity)
	}

	// Unknown finding severities rank lowest (severityRank's fallback) and are
	// hidden; scan.MapSeverity maps them to INFO before they get here.
	var kept []model.Finding
	for _, f := range result.Findings {
		if f.Suppressed || severityRank(f.Severity) <= threshold {
			kept = append(kept, f)
		}
	}

	filtered := *result
	filtered.Findings = kept
	filtered.Summary = model.SummarizeFindings(kept)
	filtered.Summary.Suppressed = result.Summary.Suppressed
	filtered.Summary.FilteredNonExploitable = result.Summary.FilteredNonExploitable
	filtered.Summary.ScannerSkipReason = result.Summary.ScannerSkipReason
	filtered.Summary.HiddenBelowMinSeverity = len(result.Findings) - len(kept)

	return &filtered, nil
}

// HiddenFailingWarning is the stderr warning shown when findings hidden by
// --min-severity still trip --fail-on.
// Example: "2 hidden findings below --min-severity HIGH match --fail-on; the scan fails on them"
func HiddenFailingWarning(count int, minSeverity string) string {
	verb, pronoun := "match", "them"
	if count == 1 {
		verb, pronoun = "matches", "it"
	}
	return fmt.Sprintf("%d hidden %s below --min-severity %s %s --fail-on; the scan fails on %s",
		count, pluralize("finding", count), minSeverity, verb, pronoun)
}
