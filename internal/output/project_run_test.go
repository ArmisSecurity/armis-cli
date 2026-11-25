package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
)

func serverSuppressed(directive, value, source string) model.Finding {
	return model.Finding{
		Severity: model.SeverityLow, Suppressed: true,
		SuppressionInfo: &model.SuppressionInfo{Type: directive, Value: value, Source: source, Reason: "Armis " + source + " scan filter"},
	}
}

func TestServerSuppressionLine(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityHigh},
		serverSuppressed("severity_threshold", "LOW", "project"),
		serverSuppressed("severity_threshold", "LOW", "project"),
		serverSuppressed("cwe", "79", "tenant"),
		serverSuppressed("severity_threshold", "LOW", "project"),
		{Severity: model.SeverityLow, Suppressed: true, SuppressionInfo: &model.SuppressionInfo{Type: "severity", Value: "LOW", Source: "armisignore"}},
	}
	got := ServerSuppressionLine(findings)
	want := "Armis scan filters suppressed 4 findings (3 below the project's LOW threshold, 1 by the tenant's CWEs)"
	if got != want {
		t.Errorf("line = %q\nwant   %q", got, want)
	}
	if got := ServerSuppressionLine(findings[:1]); got != "" {
		t.Errorf("no server suppression, line = %q", got)
	}
	if got := ServerSuppressionLine([]model.Finding{serverSuppressed("category", "secrets", "tenant")}); got != "Armis scan filters suppressed 1 finding (1 by the tenant's categories)" {
		t.Errorf("one finding, line = %q", got)
	}
}

func TestSuppressionSummaryText_CountsTheServersFilters(t *testing.T) {
	findings := []model.Finding{
		serverSuppressed("cwe", "79", "tenant"),
		serverSuppressed("severity_threshold", "LOW", "project"),
		{Suppressed: true, SuppressionInfo: &model.SuppressionInfo{Type: "severity", Value: "LOW", Source: "armisignore"}},
		{Suppressed: true, SuppressionInfo: &model.SuppressionInfo{Type: "inline", Source: suppressionSourceInline}},
	}
	got := suppressionSummaryText(findings)
	want := "2 suppressed by Armis scan filters, 1 suppressed by .armisignore, 1 suppressed by inline comments"
	if got != want {
		t.Errorf("text = %q\nwant   %q", got, want)
	}
}

func TestRenderFinding_LabelsTheServersSuppression(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncColors()
	finding := serverSuppressed("severity_threshold", "LOW", "project")
	finding.Title = "A low finding"

	var buf bytes.Buffer
	renderFinding(&buf, finding, FormatOptions{ShowSuppressed: true})

	out := buf.String()
	if !strings.Contains(out, "[SUPPRESSED by Armis scan filters] severity_threshold:LOW -- Armis project scan filter") {
		t.Errorf("output lacks the server's label:\n%s", out)
	}
}

func TestHumanSummary_PrintsTheServersSuppressionLine(t *testing.T) {
	cli.InitColors(cli.ColorModeNever)
	SyncColors()
	findings := []model.Finding{
		{ID: "a", Severity: model.SeverityHigh, Title: "A high finding", Type: model.FindingTypeVulnerability},
		serverSuppressed("severity_threshold", "LOW", "project"),
	}
	result := &model.ScanResult{ScanID: "scan-1", Status: "completed", Findings: findings, Summary: model.SummarizeFindings(findings)}

	var buf bytes.Buffer
	if err := (&HumanFormatter{}).FormatWithOptions(result, &buf, FormatOptions{}); err != nil {
		t.Fatalf("format: %v", err)
	}
	// The summary box wraps long lines.
	flat := strings.Join(strings.Fields(buf.String()), " ")
	if !strings.Contains(flat, "Armis scan filters suppressed 1 finding (1 below the project's LOW threshold)") {
		t.Errorf("output lacks the server's line:\n%s", buf.String())
	}
}

func TestCheckTruncation(t *testing.T) {
	truncated := func(least model.Severity, findings ...model.Finding) *model.ScanResult {
		return &model.ScanResult{ScanID: "scan-1", Findings: findings,
			Truncated: &model.ResultsTruncation{Kept: 50_000, Total: 61_000, LeastSevereKept: least}}
	}
	high := model.Finding{Severity: model.SeverityHigh}
	suppressedHigh := model.Finding{Severity: model.SeverityHigh, Suppressed: true}
	for _, tt := range []struct {
		name       string
		result     *model.ScanResult
		failOn     []string
		wantLevels []string
	}{
		{"a level the kept findings decide passes", truncated(model.SeverityHigh, high), []string{"CRITICAL"}, nil},
		{"a level the dropped ones could hold is open", truncated(model.SeverityHigh, high), []string{"MEDIUM"}, []string{"MEDIUM"}},
		{"the least severe level kept is open too", truncated(model.SeverityHigh, suppressedHigh), []string{"CRITICAL", "HIGH"}, []string{"HIGH"}},
		{"kept findings that fail --fail-on decide it", truncated(model.SeverityHigh, high), []string{"HIGH", "LOW"}, nil},
		{"no --fail-on passes", truncated(model.SeverityLow, high), nil, nil},
		{"a run kept whole passes", &model.ScanResult{Findings: []model.Finding{high}}, []string{"LOW"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckTruncation(tt.result, tt.failOn)
			var truncatedErr *ErrResultsTruncated
			if tt.wantLevels == nil {
				if err != nil {
					t.Errorf("err = %v, want none", err)
				}
				return
			}
			if !errors.As(err, &truncatedErr) || strings.Join(truncatedErr.Levels, ",") != strings.Join(tt.wantLevels, ",") {
				t.Fatalf("err = %v, want levels %v", err, tt.wantLevels)
			}
			if !strings.Contains(err.Error(), "Armis kept the 50000 most severe of the scan's 61000 findings") {
				t.Errorf("message = %q", err.Error())
			}
		})
	}
}
