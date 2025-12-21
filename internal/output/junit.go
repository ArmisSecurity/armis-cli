package output

import (
        "encoding/xml"
        "fmt"
        "io"

        "github.com/ArmisSecurity/armis-cli/internal/model"
        "github.com/ArmisSecurity/armis-cli/internal/util"
)

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
        Name      string          `xml:"name,attr"`
        Classname string          `xml:"classname,attr"`
        Time      string          `xml:"time,attr"`
        Failure   *junitFailure   `xml:"failure,omitempty"`
}

type junitFailure struct {
        Message string `xml:"message,attr"`
        Type    string `xml:"type,attr"`
        Content string `xml:",chardata"`
}

func (f *JUnitFormatter) Format(result *model.ScanResult, w io.Writer) error {
        suites := junitTestSuites{
                Suites: []junitTestSuite{
                        {
                                Name:     "Armis Security Scan",
                                Tests:    len(result.Findings),
                                Failures: countFailures(result.Findings),
                                Errors:   0,
                                Time:     "0",
                                Cases:    convertToJUnitCases(result.Findings),
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

func convertToJUnitCases(findings []model.Finding) []junitTestCase {
        cases := make([]junitTestCase, 0, len(findings))

        for _, finding := range findings {
                testCase := junitTestCase{
                        Name:      finding.Title,
                        Classname: string(finding.Type),
                        Time:      "0",
                }

                if finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh {
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

func countFailures(findings []model.Finding) int {
        count := 0
        for _, finding := range findings {
                if finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh {
                        count++
                }
        }
        return count
}

func (f *JUnitFormatter) FormatWithOptions(result *model.ScanResult, w io.Writer, opts FormatOptions) error {
        return f.Format(result, w)
}
