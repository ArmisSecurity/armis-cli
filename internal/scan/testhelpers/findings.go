// Package testhelpers provides shared test utilities for scan packages.
package testhelpers

import (
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// CreateNormalizedFinding creates a NormalizedFinding for testing with the given parameters.
func CreateNormalizedFinding(id, severity, category string, cves, cwes []string) model.NormalizedFinding {
	return CreateNormalizedFindingFull(id, severity, category, cves, cwes, nil)
}

// CreateNormalizedFindingWithLabels creates a NormalizedFinding for testing with labels.
func CreateNormalizedFindingWithLabels(id, severity, category string, cves []string, labels []model.Label) model.NormalizedFinding {
	return CreateNormalizedFindingFull(id, severity, category, cves, nil, labels)
}

// CreateNormalizedFindingFull creates a NormalizedFinding for testing with all parameters.
func CreateNormalizedFindingFull(id, severity, category string, cves, cwes []string, labels []model.Label) model.NormalizedFinding {
	return model.NormalizedFinding{
		NormalizedTask: model.NormalizedTask{
			FindingID: id,
			Labels:    labels,
		},
		NormalizedRemediation: model.NormalizedRemediation{
			ToolSeverity:    severity,
			Description:     "Test description for " + id,
			FindingCategory: category,
			VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
				CVEs: cves,
				CWEs: cwes,
			},
		},
	}
}
