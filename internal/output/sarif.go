package output

import (
	"encoding/json"
	"io"

	"github.com/silk-security/Moose-CLI/internal/model"
)

type SARIFFormatter struct{}

type sarifReport struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	InformationUri string `json:"informationUri"`
	Version        string `json:"version"`
}

type sarifResult struct {
	RuleID  string              `json:"ruleId"`
	Level   string              `json:"level"`
	Message sarifMessage        `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func (f *SARIFFormatter) Format(result *model.ScanResult, w io.Writer) error {
	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Armis Security Scanner",
						InformationUri: "https://armis.com",
						Version:        "1.0.0",
					},
				},
				Results: convertToSarifResults(result.Findings),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func convertToSarifResults(findings []model.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))

	for _, finding := range findings {
		result := sarifResult{
			RuleID: finding.ID,
			Level:  severityToSarifLevel(finding.Severity),
			Message: sarifMessage{
				Text: finding.Title + ": " + finding.Description,
			},
		}

		if finding.File != "" {
			location := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: finding.File,
					},
				},
			}

			if finding.Line > 0 {
				location.PhysicalLocation.Region = &sarifRegion{
					StartLine:   finding.Line,
					StartColumn: finding.Column,
				}
			}

			result.Locations = []sarifLocation{location}
		}

		results = append(results, result)
	}

	return results
}

func severityToSarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow, model.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
