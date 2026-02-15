package output

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// JUnitFormatter formats scan results as JUnit XML.
type JUnitFormatter struct{}

type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Time     string          `xml:"time,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// defaultFailOnSeverities is used when no FailOnSeverities are specified
var defaultFailOnSeverities = []string{string(model.SeverityCritical), string(model.SeverityHigh)}

// Format formats the scan result as JUnit XML.
// Uses default failure severities (CRITICAL, HIGH) for backward compatibility.
func (f *JUnitFormatter) Format(result *model.ScanResult, w io.Writer) error {
	return f.formatWithSeverities(result, w, defaultFailOnSeverities)
}

// FormatWithOptions formats the scan result as JUnit XML with custom options.
// If FailOnSeverities is specified in options, those severities are used to determine
// test failures. Otherwise, defaults to CRITICAL and HIGH.
func (f *JUnitFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
	severities := opts.FailOnSeverities
	if len(severities) == 0 {
		severities = defaultFailOnSeverities
	}
	return f.formatWithSeverities(result, w, severities)
}

func (f *JUnitFormatter) formatWithSeverities(result *model.ScanResult, w io.Writer, failOnSeverities []string) error {
	suites := junitTestSuites{
		Suites: []junitTestSuite{
			{
				Name:     "Armis Security Scan",
				Tests:    len(result.Findings),
				Failures: countFailuresWithSeverities(result.Findings, failOnSeverities),
				Errors:   0,
				Time:     "0",
				Cases:    convertToJUnitCasesWithSeverities(result.Findings, failOnSeverities),
			},
		},
	}

	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")

	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}

	return encoder.Encode(suites)
}

// isFailureSeverity checks if a severity should be treated as a test failure
func isFailureSeverity(severity string, failOnSeverities []string) bool {
	severityUpper := strings.ToUpper(severity)
	for _, s := range failOnSeverities {
		if strings.ToUpper(s) == severityUpper {
			return true
		}
	}
	return false
}

func convertToJUnitCasesWithSeverities(findings []model.Finding, failOnSeverities []string) []junitTestCase {
	cases := make([]junitTestCase, 0, len(findings))

	for _, finding := range findings {
		testCase := junitTestCase{
			Name:      finding.Title,
			Classname: string(finding.Type),
			Time:      "0",
		}

		if isFailureSeverity(string(finding.Severity), failOnSeverities) {
			location, err := util.SanitizePath(finding.File)
			if err != nil {
				location = "unknown"
			}
			if finding.StartLine > 0 {
				location = fmt.Sprintf("%s:%d", location, finding.StartLine)
			}

			testCase.Failure = &junitFailure{
				Message: finding.Title,
				Type:    string(finding.Severity),
				Content: fmt.Sprintf("%s\nLocation: %s\nDescription: %s", finding.Title, location, finding.Description),
			}
		}

		cases = append(cases, testCase)
	}

	return cases
}

func countFailuresWithSeverities(findings []model.Finding, failOnSeverities []string) int {
	count := 0
	for _, finding := range findings {
		if isFailureSeverity(string(finding.Severity), failOnSeverities) {
			count++
		}
	}
	return count
}
