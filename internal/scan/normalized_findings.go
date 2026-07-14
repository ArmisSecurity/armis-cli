// Shared helpers for turning /normalized-results into a *model.ScanResult
// suitable for the formatters and --fail-on gate.
//
// This code was previously duplicated across internal/scan/image,
// internal/scan/repo, and internal/scan/sbomcpe; the SBOM unification work
// (PPSC-1136) needed a fourth caller and lifted the helpers here.

package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// BuildScanResult converts a slice of normalized findings into the
// *model.ScanResult shape the CLI's formatters and --fail-on gate consume.
func BuildScanResult(
	scanID string,
	normalizedFindings []model.NormalizedFinding,
	debug bool,
	includeNonExploitable bool,
) *model.ScanResult {
	findings, filteredCount := ConvertNormalizedFindings(normalizedFindings, debug, includeNonExploitable)

	summary := model.Summary{
		Total:                  len(findings),
		BySeverity:             make(map[model.Severity]int),
		ByType:                 make(map[model.FindingType]int),
		ByCategory:             make(map[string]int),
		FilteredNonExploitable: filteredCount,
	}
	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByType[f.Type]++
		if f.FindingCategory != "" {
			summary.ByCategory[f.FindingCategory]++
		}
	}

	return &model.ScanResult{
		ScanID:   scanID,
		Findings: findings,
		Summary:  summary,
	}
}

// ConvertNormalizedFindings translates the backend NormalizedFinding into the
// CLI-facing Finding model, filtering out empties and non-exploitable findings
// when requested. Returns the filtered slice and the count of items dropped by
// the exploitability filter (so callers can surface that in the summary).
func ConvertNormalizedFindings(
	normalizedFindings []model.NormalizedFinding, debug bool, includeNonExploitable bool,
) ([]model.Finding, int) {
	var findings []model.Finding
	filteredCount := 0

	for i, nf := range normalizedFindings {
		if IsEmptyFinding(nf) {
			continue
		}

		if !includeNonExploitable && ShouldFilterByExploitability(nf.NormalizedTask.Labels) {
			filteredCount++
			continue
		}

		if debug {
			debugCopy := nf
			if debugCopy.NormalizedTask.ExtraData.CodeLocation.Snippet != nil {
				masked := util.MaskSecretInLine(*debugCopy.NormalizedTask.ExtraData.CodeLocation.Snippet)
				debugCopy.NormalizedTask.ExtraData.CodeLocation.Snippet = &masked
			}
			if len(debugCopy.NormalizedTask.ExtraData.CodeLocation.CodeSnippetLines) > 0 {
				debugCopy.NormalizedTask.ExtraData.CodeLocation.CodeSnippetLines =
					util.MaskSecretInLines(debugCopy.NormalizedTask.ExtraData.CodeLocation.CodeSnippetLines)
			}
			if debugCopy.NormalizedTask.ExtraData.Fix != nil {
				debugCopy.NormalizedTask.ExtraData.Fix = MaskFixSecrets(debugCopy.NormalizedTask.ExtraData.Fix)
			}
			rawJSON, err := json.Marshal(debugCopy)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\n=== DEBUG: Finding #%d JSON Marshal Error: %v ===\n\n", i+1, err)
			} else {
				fmt.Fprintf(os.Stderr, "\n=== DEBUG: Finding #%d Raw JSON ===\n%s\n=== END DEBUG ===\n\n", i+1, string(rawJSON))
			}
		}

		finding := model.Finding{
			ID:                      nf.NormalizedTask.FindingID,
			Severity:                MapSeverity(nf.NormalizedRemediation.ToolSeverity),
			Description:             nf.NormalizedRemediation.Description,
			CVEs:                    nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs,
			CWEs:                    nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs,
			OWASPCategories:         nf.NormalizedRemediation.VulnerabilityTypeMetadata.OWASPCategories,
			LongDescriptionMarkdown: nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown,
			URLs:                    nf.NormalizedRemediation.VulnerabilityTypeMetadata.URLs,
		}

		if finding.Description == "" {
			if nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown != "" {
				finding.Description = nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown
			} else if nf.NormalizedTask.LongDescription != nil {
				finding.Description = *nf.NormalizedTask.LongDescription
			}
		}

		finding.Description = CleanDescription(finding.Description)

		if nf.NormalizedRemediation.FindingCategory != nil {
			if category, ok := nf.NormalizedRemediation.FindingCategory.(string); ok {
				finding.FindingCategory = category
			}
		}

		loc := nf.NormalizedTask.ExtraData.CodeLocation
		if loc.FileName != nil {
			finding.File = *loc.FileName
		}
		if loc.StartLine != nil {
			finding.StartLine = *loc.StartLine
		}
		if loc.EndLine != nil {
			finding.EndLine = *loc.EndLine
		}
		if loc.StartCol != nil {
			finding.StartColumn = *loc.StartCol
		}
		if loc.EndCol != nil {
			finding.EndColumn = *loc.EndCol
		}

		if len(loc.CodeSnippetLines) > 0 {
			finding.CodeSnippet = strings.Join(loc.CodeSnippetLines, "\n")
		} else if loc.Snippet != nil {
			finding.CodeSnippet = *loc.Snippet
		}

		if loc.SnippetStartLine != nil {
			finding.SnippetStartLine = *loc.SnippetStartLine
		}

		if nf.NormalizedTask.ExtraData.Fix != nil {
			finding.Fix = nf.NormalizedTask.ExtraData.Fix
		}
		if nf.NormalizedTask.ExtraData.FindingValidation != nil {
			finding.Validation = nf.NormalizedTask.ExtraData.FindingValidation
		}

		finding.Type = DeriveFindingType(
			len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) > 0,
			loc.HasSecret,
			finding.FindingCategory,
		)

		if loc.HasSecret && finding.CodeSnippet != "" {
			finding.CodeSnippet = util.MaskSecretInLine(finding.CodeSnippet)
		}
		if loc.HasSecret && finding.Fix != nil {
			finding.Fix = MaskFixSecrets(finding.Fix)
		}

		finding.Title = GenerateFindingTitle(&finding)
		findings = append(findings, finding)
	}

	return findings, filteredCount
}

// CleanDescription strips internal-only annotation lines that leak into some
// backend descriptions (Code_location, Code Blob, Confidence).
func CleanDescription(desc string) string {
	lines := strings.Split(desc, "\n")
	var cleaned []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Code_location -") ||
			strings.HasPrefix(line, "Code Blob -") ||
			strings.HasPrefix(line, "Confidence -") {
			continue
		}
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}
	return strings.Join(cleaned, " ")
}

// IsEmptyFinding reports whether a NormalizedFinding carries no user-facing
// content and can be dropped from the CLI output.
func IsEmptyFinding(nf model.NormalizedFinding) bool {
	hasDescription := nf.NormalizedRemediation.Description != "" ||
		nf.NormalizedRemediation.VulnerabilityTypeMetadata.LongDescriptionMarkdown != "" ||
		(nf.NormalizedTask.LongDescription != nil && *nf.NormalizedTask.LongDescription != "")

	hasCVEsOrCWEs := len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CVEs) > 0 ||
		len(nf.NormalizedRemediation.VulnerabilityTypeMetadata.CWEs) > 0

	hasCategory := nf.NormalizedRemediation.FindingCategory != nil

	return !hasDescription && !hasCVEsOrCWEs && !hasCategory
}
