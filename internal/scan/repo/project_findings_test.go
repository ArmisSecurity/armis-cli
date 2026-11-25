package repo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
)

// runFixture reads testdata/project_run_findings.json: one row of each type,
// as the AppSec findings route serves it with expand=detail.
func runFixture(t *testing.T) []model.RunFinding {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "project_run_findings.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var rows []model.RunFinding
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return rows
}

// TestConvertProjectRunFindings_Golden pins the mapping of each type's row.
// Regenerate with UPDATE_GOLDEN=1 go test ./internal/scan/repo/ -run Golden.
func TestConvertProjectRunFindings_Golden(t *testing.T) {
	findings, filtered := convertProjectRunFindings(runFixture(t), false, false)
	if filtered != 0 {
		t.Errorf("filtered = %d, want 0", filtered)
	}
	got, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "project_run_findings.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("mapped findings differ from %s:\n%s", golden, got)
	}
}

// normalizedTwins are the normalized findings an unpublished scan reads for
// the fixture's rows, in the same order: what the legacy route serves for the
// same findings.
func normalizedTwins() []model.NormalizedFinding {
	str := func(s string) *string { return &s }
	num := func(n int) *int { return &n }
	exploitability := []model.Label{{Description: "Exploitability Level", Value: "armis_appsec:exploitability:high"}}
	return []model.NormalizedFinding{
		{
			NormalizedRemediation: model.NormalizedRemediation{
				Description:     "User input reaches a raw SQL query. Use parameters.",
				FindingCategory: "CODE_VULNERABILITY",
				ToolSeverity:    "HIGH",
				VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
					CWEs:                    []string{"CWE-89"},
					LongDescriptionMarkdown: "## Why\nThe id reaches the query.",
					OWASPCategories:         []model.OWASPCategory{{ID: "A03:2021", Title: "Injection"}},
					URLs:                    []string{"https://cwe.mitre.org/data/definitions/89.html"},
				},
			},
			NormalizedTask: model.NormalizedTask{
				FindingID: "engine-sast-1",
				Labels:    exploitability,
				ExtraData: model.ExtraData{
					CodeLocation: model.CodeLocation{
						FileName: str("src/db/orders.ts"), StartLine: num(21), EndLine: num(22),
						// The normalized path joins the snippet's lines; the raw
						// snippet, which the history keeps, ends its last line.
						Snippet:          str("const q = `SELECT * FROM orders WHERE id = ${id}`;\n"),
						CodeSnippetLines: []string{"const q = `SELECT * FROM orders WHERE id = ${id}`;"},
						SnippetStartLine: num(19),
					},
					Fix: &model.Fix{Explanation: "Bind the id as a parameter.", Patch: str("-raw\n+bound"), IsValid: new(true)},
					FindingValidation: &model.FindingValidation{
						IsValid: new(true), Confidence: 90, TaintPropagation: model.TaintReachable,
						Exposure: num(6), Explanation: "The route is public.",
					},
				},
			},
		},
		{
			NormalizedRemediation: model.NormalizedRemediation{
				Description:     "Prototype pollution in xml2js.",
				FindingCategory: "CODE_PACKAGE_VULNERABILITY",
				ToolSeverity:    "CRITICAL",
				VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
					CVEs: []string{"CVE-2023-0842", "CVE-2023-0843", "CVE-2023-0844"},
					URLs: []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-0842"},
				},
			},
			NormalizedTask: model.NormalizedTask{
				FindingID: "engine-sca-1",
				ExtraData: model.ExtraData{CodeLocation: model.CodeLocation{
					FileName: str("package-lock.json"), StartLine: num(18), EndLine: num(18),
					Snippet: str(`"xml2js": "0.4.19"`), SnippetStartLine: num(18),
				}},
			},
		},
		{
			NormalizedRemediation: model.NormalizedRemediation{
				Description:     "AWS access token found.",
				FindingCategory: "SECRET_EXPOSURE",
				ToolSeverity:    "CRITICAL",
			},
			NormalizedTask: model.NormalizedTask{
				FindingID: "engine-secret-1",
				ExtraData: model.ExtraData{CodeLocation: model.CodeLocation{
					FileName: str("deploy/env.sh"), StartLine: num(7), EndLine: num(7), HasSecret: true,
				}},
			},
		},
		{
			NormalizedRemediation: model.NormalizedRemediation{
				Description:     "S3 bucket has no server-side encryption.",
				FindingCategory: "INFRA_AS_CODE_MISCONFIGURATION",
				ToolSeverity:    "MEDIUM",
				VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
					CWEs: []string{"CWE-311"},
					URLs: []string{"https://docs.example/ckv_aws_19"},
				},
			},
			NormalizedTask: model.NormalizedTask{
				FindingID: "engine-iac-1",
				ExtraData: model.ExtraData{CodeLocation: model.CodeLocation{
					FileName: str("infra/main.tf"), StartLine: num(4), EndLine: num(9),
					Snippet: str(`resource "aws_s3_bucket" "assets" {`), SnippetStartLine: num(4),
				}},
			},
		},
		{
			NormalizedRemediation: model.NormalizedRemediation{
				Description:     "A restricted license.",
				FindingCategory: "LICENSE_COMPLIANCE",
				ToolSeverity:    "LOW",
			},
			NormalizedTask: model.NormalizedTask{
				FindingID: "engine-license-1",
				ExtraData: model.ExtraData{CodeLocation: model.CodeLocation{
					FileName: str("package.json"), StartLine: num(12),
				}},
			},
		},
		{
			// A SAST finding whose code holds a secret.
			NormalizedRemediation: model.NormalizedRemediation{
				Description:     "Private Key detected.",
				FindingCategory: "CODE_VULNERABILITY",
				ToolSeverity:    "HIGH",
				VulnerabilityTypeMetadata: model.VulnerabilityTypeMetadata{
					CWEs:                    []string{"CWE-798: Use of Hard-coded Credentials"},
					LongDescriptionMarkdown: "Code_location - 'certs/server.key'",
					URLs:                    []string{"https://cwe.mitre.org/data/definitions/798"},
				},
			},
			NormalizedTask: model.NormalizedTask{
				FindingID: "engine-sast-secret-1",
				ExtraData: model.ExtraData{CodeLocation: model.CodeLocation{
					FileName: str("certs/server.key"), StartLine: num(1), EndLine: num(2),
					Snippet: str("the key (placeholder)"), SnippetStartLine: num(1), HasSecret: true,
				}},
			},
		},
	}
}

// keptFields is what of a finding the history keeps, for comparing the two
// paths: a secret's text, code and fix are left out, as the history drops
// them.
type keptFields struct {
	Type                    model.FindingType
	Severity                model.Severity
	File                    string
	StartLine, EndLine      int
	CodeSnippet             string
	SnippetStartLine        int
	CVEs, CWEs              []string
	FindingCategory         string
	Description             string
	LongDescriptionMarkdown string
	URLs                    []string
	FixExplanation          string
	FixPatch                string
	Validation              string
}

func kept(f model.Finding) keptFields {
	k := keptFields{
		Type: f.Type, Severity: f.Severity, File: f.File, StartLine: f.StartLine, EndLine: f.EndLine,
		CodeSnippet: f.CodeSnippet, SnippetStartLine: f.SnippetStartLine, CVEs: f.CVEs, CWEs: f.CWEs,
		FindingCategory: f.FindingCategory, Description: f.Description,
		LongDescriptionMarkdown: f.LongDescriptionMarkdown, URLs: f.URLs,
	}
	if f.Type == model.FindingTypeSecret {
		k.Description, k.LongDescriptionMarkdown, k.CodeSnippet, k.SnippetStartLine = "", "", "", 0
		f.Fix = nil
	}
	if f.Fix != nil {
		k.FixExplanation = f.Fix.Explanation
		if f.Fix.Patch != nil {
			k.FixPatch = *f.Fix.Patch
		}
	}
	if v := f.Validation; v != nil {
		exposure := -1
		if v.Exposure != nil {
			exposure = *v.Exposure
		}
		// The history doesn't keep whether the verifier held it valid.
		k.Validation = fmt.Sprintf("%s|%s|%d|%d", v.TaintPropagation, v.Explanation, v.Confidence, exposure)
	}
	return k
}

func TestConvertProjectRunFindings_MatchesTheNormalizedPath(t *testing.T) {
	run, _ := convertProjectRunFindings(runFixture(t), false, false)
	normalized, _ := convertNormalizedFindings(normalizedTwins(), false, false)
	if len(run) != len(normalized) {
		t.Fatalf("mapped %d run findings and %d normalized ones", len(run), len(normalized))
	}
	for i := range run {
		got, want := kept(run[i]), kept(normalized[i])
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("finding %d (%s):\n run        %s\n normalized %s", i, run[i].Type, gotJSON, wantJSON)
		}
	}
}

// sarifResults are the ruleId and location of each SARIF result for findings.
func sarifResults(t *testing.T, findings []model.Finding) []string {
	t.Helper()
	// Suppression is compared elsewhere: SARIF leaves suppressed findings out.
	active := make([]model.Finding, len(findings))
	for i, f := range findings {
		f.Suppressed, f.SuppressionInfo = false, nil
		active[i] = f
	}
	var buf bytes.Buffer
	result := &model.ScanResult{ScanID: "scan-1", Findings: active, Summary: model.SummarizeFindings(active)}
	if err := (&output.SARIFFormatter{}).Format(result, &buf); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	var out []string
	for _, r := range sarif.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		out = append(out, fmt.Sprintf("%s@%s:%d", r.RuleID, loc.ArtifactLocation.URI, loc.Region.StartLine))
	}
	return out
}

// TestConvertProjectRunFindings_KeepsSARIFAlertsStable: a pipeline that starts
// publishing uploads the same ruleIds and locations, so code scanning matches
// its alerts instead of closing and reopening them.
func TestConvertProjectRunFindings_KeepsSARIFAlertsStable(t *testing.T) {
	run, _ := convertProjectRunFindings(runFixture(t), false, false)
	normalized, _ := convertNormalizedFindings(normalizedTwins(), false, false)
	got, want := sarifResults(t, run), sarifResults(t, normalized)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("SARIF results differ:\n run        %v\n normalized %v", got, want)
	}
}

func TestConvertProjectRunFindings_TheServersSuppressions(t *testing.T) {
	findings, _ := convertProjectRunFindings(runFixture(t), false, false)
	byID := map[string]model.Finding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	for id, want := range map[string]model.SuppressionInfo{
		"f_1d82b5e30f6c4a9b7d2e8f3c0a5b1d74": {Type: "severity_threshold", Value: "HIGH", Reason: "Armis project scan filter", Source: "project"},
		"f_3fa4d7052b8e6c1d9f4a0b5e2c7d3f96": {Type: "cwe", Value: "311", Reason: "Armis tenant scan filter", Source: "tenant"},
	} {
		got := byID[id]
		if !got.Suppressed || got.SuppressionInfo == nil || *got.SuppressionInfo != want {
			t.Errorf("%s: suppressed=%v info=%+v, want %+v", id, got.Suppressed, got.SuppressionInfo, want)
		}
	}
	if f := byID["f_0c71a4d29e5b3f8a6c1d7e2b9f4a0c63"]; f.Suppressed || f.SuppressionInfo != nil {
		t.Errorf("an unsuppressed row came out suppressed: %+v", f.SuppressionInfo)
	}
}

func TestConvertProjectRunFindings_LeavesOutLowExploitability(t *testing.T) {
	level := func(l string) *string { return &l }
	rows := []model.RunFinding{
		{FindingID: "f_low", Type: "sast", Severity: "high", Detail: &model.RunFindingDetail{Exploitability: level("low")}},
		{FindingID: "f_medium", Type: "sast", Severity: "high", Detail: &model.RunFindingDetail{Exploitability: level("medium")}},
		{FindingID: "f_high", Type: "sast", Severity: "high", Detail: &model.RunFindingDetail{Exploitability: level("high")}},
		{FindingID: "f_none", Type: "sast", Severity: "high", Detail: &model.RunFindingDetail{}},
	}
	findings, filtered := convertProjectRunFindings(rows, false, false)
	if filtered != 2 || len(findings) != 2 || findings[0].ID != "f_high" || findings[1].ID != "f_none" {
		t.Errorf("kept %+v, filtered %d", findings, filtered)
	}
	findings, filtered = convertProjectRunFindings(rows, false, true)
	if filtered != 0 || len(findings) != 4 {
		t.Errorf("--include-non-exploitable kept %d, filtered %d", len(findings), filtered)
	}
}

func TestConvertProjectRunFindings_MasksASecretsCode(t *testing.T) {
	// A placeholder in the shape the masker knows (token_ and 20 characters).
	// armis:ignore cwe:798 reason: a made-up, non-functional test value; the test asserts that it is masked out of the patch
	const placeholder = "token_NOTAREALTOKENEXAMPLE0000"
	patch := "-API_TOKEN=" + placeholder + "\n+API_TOKEN=${API_TOKEN}"
	// A secret, and a SAST finding the history wrote as one: its evidence
	// says its snippet is hidden as sensitive.
	for _, row := range []struct{ kind, hidden, category string }{
		{"secret", "", "SECRET_EXPOSURE"},
		{"sast", model.SnippetHiddenSensitive, "CODE_VULNERABILITY"},
	} {
		rows := []model.RunFinding{{
			FindingID: "f_" + row.kind, Type: row.kind, Severity: "critical",
			Detail: &model.RunFindingDetail{
				Evidence: &model.RunFindingEvidence{
					Kind:                row.kind,
					Snippet:             &model.RunFindingSnippet{Code: "API_TOKEN=" + placeholder},
					SnippetHiddenReason: row.hidden,
				},
				Remediation: &model.RunFindingRemediation{Patch: &patch},
			},
		}}
		findings, _ := convertProjectRunFindings(rows, false, false)
		if len(findings) != 1 {
			t.Fatalf("%s: findings = %+v", row.kind, findings)
		}
		f := findings[0]
		if f.CodeSnippet != "" {
			t.Errorf("%s: a secret's snippet was kept: %q", row.kind, f.CodeSnippet)
		}
		if f.Fix == nil || f.Fix.Patch == nil || strings.Contains(*f.Fix.Patch, placeholder) {
			t.Errorf("%s: a secret's patch was not masked: %+v", row.kind, f.Fix)
		}
		if f.Type != model.FindingTypeSecret || f.FindingCategory != row.category {
			t.Errorf("%s: type = %s, category = %s", row.kind, f.Type, f.FindingCategory)
		}
	}
}

func TestConvertProjectRunFindings_ASnippetWithoutItsLastLineEnd(t *testing.T) {
	start := 4
	rows := []model.RunFinding{{
		FindingID: "f_iac", Type: "iac", Severity: "medium",
		Detail: &model.RunFindingDetail{Evidence: &model.RunFindingEvidence{
			Kind:    "iac",
			Snippet: &model.RunFindingSnippet{Code: "resource \"a\" \"b\" {\n  acl = \"public\"\n\n", StartLine: &start},
		}},
	}}
	findings, _ := convertProjectRunFindings(rows, false, false)
	// One line end goes, as the normalized path joins the lines: a blank
	// last line stays.
	if got := findings[0].CodeSnippet; got != "resource \"a\" \"b\" {\n  acl = \"public\"\n" {
		t.Errorf("snippet = %q", got)
	}
	if findings[0].Type != model.FindingTypeMisconfig {
		t.Errorf("type = %s", findings[0].Type)
	}
}

func TestConvertProjectRunFindings_ARowWithoutItsDetailKeepsTheRow(t *testing.T) {
	line := 3
	rows := []model.RunFinding{{
		FindingID: "f_bare", Type: "sca", Severity: "unknown", Title: "",
		Asset:    &model.RunFindingAsset{Name: "lodash", Type: "package"},
		Location: &model.RunFindingLocation{Path: "package.json", Line: &line},
	}}
	findings, _ := convertProjectRunFindings(rows, false, false)
	f := findings[0]
	if f.Severity != model.SeverityInfo || f.File != "package.json" || f.StartLine != 3 || f.Package != "lodash" || f.Title == "" {
		t.Errorf("finding = %+v", f)
	}
}

func TestApplySuppression_LeavesTheServersSuppressions(t *testing.T) {
	findings, _ := convertProjectRunFindings(runFixture(t), false, false)
	config := NewSuppressionConfig()
	config.Add(SuppressionDirective{Type: DirectiveSeverity, Value: "CRITICAL", Reason: "local"})

	local := ApplySuppression(findings, config)

	// The SCA finding the project's threshold suppressed keeps its reason; the
	// secret, which no server filter suppressed, is suppressed locally.
	if local != 1 {
		t.Errorf("suppressed locally %d, want 1", local)
	}
	for _, f := range findings {
		switch f.ID {
		case "f_1d82b5e30f6c4a9b7d2e8f3c0a5b1d74":
			if f.SuppressionInfo.Source != "project" {
				t.Errorf("the server's suppression was replaced: %+v", f.SuppressionInfo)
			}
		case "f_2e93c6f41a7d5b0c8e3f9a4d1b6c2e85":
			if !f.Suppressed || f.SuppressionInfo.Source != "armisignore" {
				t.Errorf("the secret wasn't suppressed locally: %+v", f.SuppressionInfo)
			}
		}
	}
}

// A suppression from a source a newer server adds is still the server's: it
// keeps the source and reads as an Armis scan filter's.
func TestConvertProjectRunFindings_KeepsAnUnknownSuppressionSource(t *testing.T) {
	rows := []model.RunFinding{{
		FindingID: "f_1", Type: "sast", Severity: "low", Detail: &model.RunFindingDetail{},
		Suppression: &model.RunFindingSuppression{Source: "org", Directive: "severity_threshold", Value: "MEDIUM"},
	}}
	findings, _ := convertProjectRunFindings(rows, false, false)
	want := model.SuppressionInfo{Type: "severity_threshold", Value: "MEDIUM", Reason: "Armis scan filter", Source: "org"}
	if len(findings) != 1 || !findings[0].Suppressed || findings[0].SuppressionInfo == nil || *findings[0].SuppressionInfo != want {
		t.Errorf("findings = %+v, want one suppressed with %+v", findings, want)
	}
}
