package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// SARIFFormatter formats scan results as SARIF JSON.
type SARIFFormatter struct{}

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string               `json:"id"`
	ShortDescription     sarifMessage         `json:"shortDescription"`
	DefaultConfiguration sarifRuleConfig      `json:"defaultConfiguration,omitempty"`
	Properties           *sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	SecuritySeverity string `json:"security-severity"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties *sarifResultProperties `json:"properties,omitempty"`
}

type sarifResultProperties struct {
	Severity    string                     `json:"severity"`
	Type        string                     `json:"type,omitempty"`
	CodeSnippet string                     `json:"codeSnippet,omitempty"`
	CVEs        []string                   `json:"cves,omitempty"`
	CWEs        []string                   `json:"cwes,omitempty"`
	Package     string                     `json:"package,omitempty"`
	Version     string                     `json:"version,omitempty"`
	FixVersion  string                     `json:"fixVersion,omitempty"`
	Fix         *sarifFixProperties        `json:"fix,omitempty"`
	Validation  *sarifValidationProperties `json:"validation,omitempty"`
}

type sarifFixProperties struct {
	IsValid         bool   `json:"isValid"`
	Explanation     string `json:"explanation,omitempty"`
	Recommendations string `json:"recommendations,omitempty"`
	Patch           string `json:"patch,omitempty"`
	Feedback        string `json:"feedback,omitempty"`
}

type sarifValidationProperties struct {
	IsValid           bool   `json:"isValid"`
	Confidence        int    `json:"confidence"`
	ValidatedSeverity string `json:"validatedSeverity,omitempty"`
	TaintPropagation  string `json:"taintPropagation,omitempty"`
	Exposure          *int   `json:"exposure,omitempty"`
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

// Format formats the scan result as SARIF JSON.
func (f *SARIFFormatter) Format(result *model.ScanResult, w io.Writer) error {
	rules, ruleIndexMap := buildRules(result.Findings)
	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Armis Security Scanner",
						InformationURI: "https://armis.com",
						Version:        "1.0.0",
						Rules:          rules,
					},
				},
				Results: convertToSarifResults(result.Findings, ruleIndexMap),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// buildRules creates SARIF rules from findings, deduplicating by rule ID.
// Returns the rules array and a map of rule ID to index.
func buildRules(findings []model.Finding) ([]sarifRule, map[string]int) {
	ruleIndexMap := make(map[string]int)
	var rules []sarifRule

	for _, finding := range findings {
		if _, exists := ruleIndexMap[finding.ID]; !exists {
			ruleIndexMap[finding.ID] = len(rules)
			rules = append(rules, sarifRule{
				ID: finding.ID,
				ShortDescription: sarifMessage{
					Text: finding.Title,
				},
				DefaultConfiguration: sarifRuleConfig{
					Level: severityToSarifLevel(finding.Severity),
				},
				Properties: &sarifRuleProperties{
					SecuritySeverity: severityToSecurityScore(finding.Severity),
				},
			})
		}
	}

	return rules, ruleIndexMap
}

// maxSarifResultsCapacity is the maximum initial capacity for SARIF results slice
// to prevent resource exhaustion from extremely large finding lists (CWE-770).
const maxSarifResultsCapacity = 10000

func convertToSarifResults(findings []model.Finding, ruleIndexMap map[string]int) []sarifResult {
	// Cap the initial capacity to prevent excessive memory allocation (CWE-770)
	capacity := len(findings)
	if capacity > maxSarifResultsCapacity {
		capacity = maxSarifResultsCapacity
	}
	results := make([]sarifResult, 0, capacity)

	for _, finding := range findings {
		result := sarifResult{
			RuleID:    finding.ID,
			RuleIndex: ruleIndexMap[finding.ID],
			Level:     severityToSarifLevel(finding.Severity),
			Message: sarifMessage{
				Text: finding.Title + ": " + finding.Description,
			},
			Properties: &sarifResultProperties{
				Severity:    string(finding.Severity),
				Type:        string(finding.Type),
				CodeSnippet: util.MaskSecretInLine(finding.CodeSnippet), // Defense-in-depth: always sanitize
				CVEs:        finding.CVEs,
				CWEs:        finding.CWEs,
				Package:     finding.Package,
				Version:     finding.Version,
				FixVersion:  finding.FixVersion,
			},
		}

		// Add fix properties if available
		if finding.Fix != nil {
			result.Properties.Fix = &sarifFixProperties{
				IsValid:         finding.Fix.IsValid,
				Explanation:     finding.Fix.Explanation,
				Recommendations: finding.Fix.Recommendations,
				Feedback:        finding.Fix.Feedback,
			}
			if finding.Fix.Patch != nil {
				result.Properties.Fix.Patch = *finding.Fix.Patch
			}
		}

		// Add validation properties if available
		if finding.Validation != nil {
			result.Properties.Validation = &sarifValidationProperties{
				IsValid:          finding.Validation.IsValid,
				Confidence:       finding.Validation.Confidence,
				TaintPropagation: string(finding.Validation.TaintPropagation),
				Exposure:         finding.Validation.Exposure,
			}
			if finding.Validation.ValidatedSeverity != nil {
				result.Properties.Validation.ValidatedSeverity = *finding.Validation.ValidatedSeverity
			}
		}

		if finding.File != "" {
			// Sanitize file path to prevent path traversal in SARIF output
			sanitizedFile, err := util.SanitizePath(finding.File)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not sanitize file path for finding %s: %v\n", finding.ID, err)
				// Use finding ID to ensure unique placeholder paths in SARIF output
				sanitizedFile = fmt.Sprintf("unknown-%s", finding.ID)
			}
			location := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: sanitizedFile,
					},
				},
			}

			if finding.StartLine > 0 {
				location.PhysicalLocation.Region = &sarifRegion{
					StartLine:   finding.StartLine,
					StartColumn: finding.StartColumn,
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

// severityToSecurityScore maps severity to CVSS-style scores for GitHub Code Scanning.
// GitHub uses these scores to categorize findings:
// - Over 9.0: Critical
// - 7.0 to 8.9: High
// - 4.0 to 6.9: Medium
// - 0.1 to 3.9: Low
func severityToSecurityScore(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "2.0"
	case model.SeverityInfo:
		return "0.0"
	default:
		return "0.0"
	}
}

// FormatWithOptions formats the scan result as SARIF JSON with custom options.
func (f *SARIFFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, _ FormatOptions) error {
	return f.Format(result, w)
}
