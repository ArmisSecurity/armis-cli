package repo

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// The types of a recorded run's findings (model.RunFinding.Type).
const (
	runTypeSAST      = "sast"
	runTypeSCA       = "sca"
	runTypeSecret    = "secret"
	runTypeIaC       = "iac"
	runTypeLicense   = "license"
	runTypeContainer = "container"
)

// recordedRunCategory is the finding category of a recorded run's finding,
// by its type. The history keeps no category, so a finding gets the one
// /ingest/normalized-results serves for findings of its type. Its type,
// SARIF ruleId and category: matches then come out as for the same finding
// of an unpublished scan. (An IaC finding the normalizer filed as a
// POLICY_VIOLATION is the one exception: it comes out as
// INFRA_AS_CODE_MISCONFIGURATION.)
var recordedRunCategory = map[string]string{
	runTypeSAST:      "CODE_VULNERABILITY",
	runTypeSCA:       "CODE_PACKAGE_VULNERABILITY",
	runTypeSecret:    "SECRET_EXPOSURE",
	runTypeIaC:       "INFRA_AS_CODE_MISCONFIGURATION",
	runTypeLicense:   "LICENSE_COMPLIANCE",
	runTypeContainer: "CONTAINER_VULNERABILITY",
}

// serverSuppressionReason is the reason a finding the project's filters
// suppressed shows, by the filter's source; a source a newer server adds
// shows serverSuppressionReasonOther.
var serverSuppressionReason = map[string]string{
	"tenant":  "Armis tenant scan filter",
	"project": "Armis project scan filter",
}

const serverSuppressionReasonOther = "Armis scan filter"

// convertProjectRunFindings maps a recorded run's findings, as the AppSec
// findings route serves them with their detail, to the CLI's findings. A
// finding of low or medium exploitability is left out unless
// includeNonExploitable; the second result counts those. The findings the
// project's filters suppressed come out suppressed, with their filter.
func convertProjectRunFindings(rows []model.RunFinding, debug bool, includeNonExploitable bool) ([]model.Finding, int) {
	var findings []model.Finding
	filtered := 0
	for i := range rows {
		row := &rows[i]
		detail := row.Detail
		if detail == nil {
			detail = &model.RunFindingDetail{}
		}
		if !includeNonExploitable && detail.Exploitability != nil && scan.IsHiddenExploitability(*detail.Exploitability) {
			filtered++
			continue
		}
		finding := runFinding(row, detail)
		if debug {
			debugRunFinding(i, finding)
		}
		findings = append(findings, finding)
	}
	return findings, filtered
}

// runFinding maps one row and its detail. What the history doesn't keep
// stays empty: columns, fix proposals and OWASP titles. Whether the verifier
// held the finding or its fix valid stays unknown (a nil IsValid), so the
// output leaves it out rather than say false.
func runFinding(row *model.RunFinding, detail *model.RunFindingDetail) model.Finding {
	// A secret by its type, or a finding of another type whose code holds
	// one: the history wrote it as a secret, as the normalized path's
	// has_secret has it.
	secret := row.Type == runTypeSecret ||
		(detail.Evidence != nil && detail.Evidence.SnippetHiddenReason == model.SnippetHiddenSensitive)
	category := recordedRunCategory[row.Type]
	finding := model.Finding{
		ID:                      row.FindingID,
		Severity:                scan.MapSeverity(row.Severity),
		Title:                   row.Title,
		CVEs:                    nonEmpty(detail.Identifiers.CVEs),
		CWEs:                    nonEmpty(detail.Identifiers.CWEs),
		FindingCategory:         category,
		OWASPCategories:         owaspCategories(detail.Identifiers.OWASP),
		LongDescriptionMarkdown: deref(detail.DetailsMarkdown),
		URLs:                    nonEmpty(detail.References),
	}

	// As for an unpublished scan: the description, else the narrative.
	description := deref(detail.Description)
	if description == "" {
		description = finding.LongDescriptionMarkdown
	}
	finding.Description = cleanDescription(description)

	if loc := detail.Location; loc != nil && loc.Path != "" {
		finding.File = loc.Path
		finding.StartLine = derefInt(loc.StartLine)
		finding.EndLine = derefInt(loc.EndLine)
	} else if loc := row.Location; loc != nil {
		finding.File = loc.Path
		finding.StartLine = derefInt(loc.Line)
	}

	if snippet := evidenceSnippet(detail.Evidence); snippet != nil && !secret {
		// The history keeps the scanner's snippet, which ends its last line;
		// the normalized path joins the snippet's lines, without that end.
		finding.CodeSnippet = strings.TrimSuffix(snippet.Code, "\n")
		finding.SnippetStartLine = derefInt(snippet.StartLine)
	}

	if asset := row.Asset; asset != nil && asset.Type == "package" {
		finding.Package = asset.Name
		finding.Version = deref(asset.Version)
	}

	if r := detail.Remediation; r != nil {
		finding.FixVersion = deref(r.FixVersion)
		if r.Summary != nil || r.Patch != nil {
			finding.Fix = &model.Fix{Explanation: deref(r.Summary)}
			if r.Patch != nil {
				patch := *r.Patch
				finding.Fix.Patch = &patch
			}
		}
	}
	finding.Validation = runValidation(detail.Evidence)

	finding.Type = scan.DeriveFindingType(len(finding.CVEs) > 0, secret, category)

	// The history keeps no secret's code or fix; masked anyway, as for an
	// unpublished scan.
	if secret {
		if finding.CodeSnippet != "" {
			finding.CodeSnippet = util.MaskSecretInLine(finding.CodeSnippet)
		}
		if finding.Fix != nil {
			finding.Fix = scan.MaskFixSecrets(finding.Fix)
		}
	}

	if s := row.Suppression; s != nil {
		reason, known := serverSuppressionReason[s.Source]
		if !known {
			reason = serverSuppressionReasonOther
		}
		finding.Suppressed = true
		finding.SuppressionInfo = &model.SuppressionInfo{
			Type:   s.Directive,
			Value:  s.Value,
			Reason: reason,
			Source: s.Source,
		}
	}

	if finding.Title == "" {
		finding.Title = generateFindingTitle(&finding)
	}
	return finding
}

// evidenceSnippet is a finding's code: a SAST or IaC finding's snippet, or
// the manifest line that declares an SCA finding's package.
func evidenceSnippet(evidence *model.RunFindingEvidence) *model.RunFindingSnippet {
	if evidence == nil {
		return nil
	}
	if evidence.Snippet != nil {
		return evidence.Snippet
	}
	if evidence.Manifest != nil {
		return evidence.Manifest.Snippet
	}
	return nil
}

// runValidation is a SAST finding's validation, from its evidence; nil when
// the evidence holds none, as for a finding no verifier saw.
func runValidation(evidence *model.RunFindingEvidence) *model.FindingValidation {
	if evidence == nil || evidence.Kind != runTypeSAST {
		return nil
	}
	var validation model.FindingValidation
	known := false
	if r := evidence.Reachability; r != nil {
		switch r.Verdict {
		case "reachable":
			validation.TaintPropagation = model.TaintReachable
			known = true
		case "not_reachable":
			validation.TaintPropagation = model.TaintNotReachable
			known = true
		}
		if r.Exposure != nil {
			exposure := *r.Exposure
			validation.Exposure = &exposure
			known = true
		}
	}
	if evidence.Confidence != nil {
		validation.Confidence = int(math.Round(*evidence.Confidence))
		known = true
	}
	if v := evidence.Verification; v != nil && v.Explanation != nil {
		validation.Explanation = *v.Explanation
		known = true
	}
	if !known {
		return nil
	}
	return &validation
}

// owaspCategories are a finding's OWASP categories, by id: the history keeps
// no titles.
func owaspCategories(ids []string) []model.OWASPCategory {
	if len(ids) == 0 {
		return nil
	}
	categories := make([]model.OWASPCategory, 0, len(ids))
	for _, id := range ids {
		categories = append(categories, model.OWASPCategory{ID: id})
	}
	return categories
}

// debugRunFinding prints a mapped finding under --debug, its secrets masked.
func debugRunFinding(i int, finding model.Finding) {
	finding.CodeSnippet = util.MaskSecretInLine(finding.CodeSnippet)
	finding.Fix = scan.MaskFixSecrets(finding.Fix)
	raw, err := json.Marshal(finding)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n=== DEBUG: Project run finding #%d JSON Marshal Error: %v ===\n\n", i+1, err)
		return
	}
	fmt.Fprintf(os.Stderr, "\n=== DEBUG: Project run finding #%d ===\n%s\n=== END DEBUG ===\n\n", i+1, util.MaskForDebug(raw))
}

// nonEmpty is s, or nil for none, as the normalized path leaves a list it
// has nothing for.
func nonEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(n *int) int {
	if n == nil {
		return 0
	}
	return *n
}
