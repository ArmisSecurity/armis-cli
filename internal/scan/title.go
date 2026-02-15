// Package scan provides shared utilities for security scanning operations.
package scan

import (
	"fmt"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// GenerateFindingTitle creates a descriptive title for findings.
// Priority: SCA with CVE > OWASP category title > Secret type > Description > Category.
func GenerateFindingTitle(finding *model.Finding) string {
	// SCA findings - prioritize CVE information
	if finding.Type == model.FindingTypeSCA && len(finding.CVEs) > 0 {
		title := finding.CVEs[0]
		if len(finding.CVEs) > 1 {
			title += fmt.Sprintf(" (+%d more)", len(finding.CVEs)-1)
		}
		return title
	}

	// Use OWASP category title if available (from API response)
	if len(finding.OWASPCategories) > 0 && finding.OWASPCategories[0].Title != "" {
		title := finding.OWASPCategories[0].Title
		if len(finding.CWEs) > 0 {
			title += fmt.Sprintf(" (%s)", finding.CWEs[0])
		}
		return title
	}

	// Secrets - indicate secret type
	if finding.Type == model.FindingTypeSecret {
		return "Exposed Secret"
	}

	// Fallback - use first sentence of description (no length limit; human formatter wraps)
	if finding.Description != "" {
		firstLine := strings.Split(finding.Description, "\n")[0]

		// Extract first sentence if present (cleaner titles)
		if idx := strings.Index(firstLine, ". "); idx > 0 {
			firstLine = firstLine[:idx]
		} else {
			// Remove trailing period if present (single-sentence descriptions)
			firstLine = strings.TrimSuffix(firstLine, ".")
		}

		return firstLine
	}

	// Last resort - formatted category
	if finding.FindingCategory != "" {
		return util.FormatCategory(finding.FindingCategory)
	}

	return "Security Finding"
}
