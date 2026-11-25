package model

// A recorded project run's findings, as the AppSec findings route serves them:
// GET /api/v1/appsec/projects/{project_id}/scans/{run_id}/findings with
// expand=detail. Only the fields the CLI reads are declared; the API may add
// others, which are ignored.

// The empty states of a run's findings list (RunFindingsPage.EmptyState).
const (
	// RunFindingsNotFinished: the run, or its findings history, is still being
	// written.
	RunFindingsNotFinished = "not_finished"
	// RunFindingsRunFailed: the run failed; it has no findings to read.
	RunFindingsRunFailed = "run_failed"
	// RunFindingsNotRecorded: the server keeps no findings history for the
	// run, so its findings are read the legacy way.
	RunFindingsNotRecorded = "not_recorded"
	// RunFindingsNoFindings: the run found nothing.
	RunFindingsNoFindings = "no_findings"
)

// RunFindingsPage is one page of a run's findings list.
type RunFindingsPage struct {
	Data       []RunFinding          `json:"data"`
	Pagination RunFindingsPagination `json:"pagination"`
	// Counts is null when the run has no recorded findings.
	Counts *RunFindingCounts `json:"counts"`
	// Truncated: the run had more findings than the history keeps, which
	// then kept the most severe.
	Truncated  bool                   `json:"truncated"`
	EmptyState *RunFindingsEmptyState `json:"empty_state"`
}

// EmptyReason is the page's empty state, "" for a run with findings. A
// reason the CLI doesn't know reads as RunFindingsNotRecorded, so a newer
// server's state takes the legacy read rather than passing on nothing.
func (p *RunFindingsPage) EmptyReason() string {
	if p.EmptyState == nil {
		return ""
	}
	switch p.EmptyState.Reason {
	case RunFindingsNotFinished, RunFindingsRunFailed, RunFindingsNoFindings:
		return p.EmptyState.Reason
	default:
		return RunFindingsNotRecorded
	}
}

// RunFindingsPagination is the page-number pagination of a run's findings.
type RunFindingsPagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// RunFindingCounts are a run's finding counts: Total its unsuppressed
// findings, Suppressed the rest, and Matching what the list's filters
// select (with suppressed=include, every finding the history kept).
type RunFindingCounts struct {
	Total      int `json:"total"`
	Matching   int `json:"matching"`
	Suppressed int `json:"suppressed"`
}

// RunFindingsEmptyState says why a run lists no findings.
type RunFindingsEmptyState struct {
	Reason string `json:"reason"`
}

// RunFinding is one row of a run's findings list, with the detail
// expand=detail embeds.
type RunFinding struct {
	// FindingID is the AppSec finding id ("f_..."), the same in every run.
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
	// Type is sast, sca, secret, iac, license or container; "" for none.
	Type string `json:"type"`
	// Severity is critical, high, medium, low or unknown.
	Severity    string                 `json:"severity"`
	Asset       *RunFindingAsset       `json:"asset"`
	Location    *RunFindingLocation    `json:"location"`
	Suppression *RunFindingSuppression `json:"suppression"`
	Detail      *RunFindingDetail      `json:"detail"`
}

// RunFindingAsset is what a finding was found in; for a package, its name
// and version.
type RunFindingAsset struct {
	Name    string  `json:"name"`
	Version *string `json:"version"`
	// Type is source, iac, manifest, sbom, package or container.
	Type string `json:"type"`
}

// RunFindingLocation is a row's file and line.
type RunFindingLocation struct {
	Path string `json:"path"`
	Line *int   `json:"line"`
}

// RunFindingSuppression says which of the project's filters suppressed a
// finding: Source tenant or project; Directive severity_threshold,
// severity, category or cwe; Value the threshold, severity, category or CWE
// id it matched.
type RunFindingSuppression struct {
	Source    string `json:"source"`
	Directive string `json:"directive"`
	Value     string `json:"value"`
}

// RunFindingDetail is the finding's detail, as the finding route serves it
// without the run's own parts.
type RunFindingDetail struct {
	// Description is null for a secret.
	Description *string `json:"description"`
	// DetailsMarkdown is the scanner's narrative; null for a secret and for
	// scanners with none.
	DetailsMarkdown *string                   `json:"details_markdown"`
	Location        *RunFindingDetailLocation `json:"location"`
	Identifiers     RunFindingIdentifiers     `json:"identifiers"`
	// Exploitability is low, medium, high or null.
	Exploitability *string                `json:"exploitability"`
	Evidence       *RunFindingEvidence    `json:"evidence"`
	Remediation    *RunFindingRemediation `json:"remediation"`
	// References are the advisory, license or rule pages the scanner linked.
	References []string `json:"references"`
}

// RunFindingDetailLocation is a finding's file and lines.
type RunFindingDetailLocation struct {
	Path      string `json:"path"`
	StartLine *int   `json:"start_line"`
	EndLine   *int   `json:"end_line"`
}

// RunFindingIdentifiers are a finding's identifiers: CWEs as "CWE-89", OWASP
// categories as "A03:2021".
type RunFindingIdentifiers struct {
	CVEs  []string `json:"cves"`
	CWEs  []string `json:"cwes"`
	OWASP []string `json:"owasp"`
}

// SnippetHiddenSensitive is the RunFindingEvidence.SnippetHiddenReason of a
// finding that holds a secret.
const SnippetHiddenSensitive = "sensitive"

// RunFindingEvidence is the evidence of any kind (Kind sast, sca, secret,
// iac, license or container), with the fields the CLI reads; each kind sets
// its own.
type RunFindingEvidence struct {
	Kind string `json:"kind"`
	// Snippet is a SAST or IaC finding's code; a secret has none.
	Snippet *RunFindingSnippet `json:"snippet"`
	// SnippetHiddenReason is SnippetHiddenSensitive for a secret's evidence,
	// and for a SAST or IaC finding the history wrote as a secret: one whose
	// code holds a secret.
	SnippetHiddenReason string `json:"snippet_hidden_reason"`
	// Manifest is an SCA finding's manifest line.
	Manifest *RunFindingManifest `json:"manifest"`
	// Reachability, Confidence (0-100) and Verification are a SAST
	// finding's validation.
	Reachability *RunFindingReachability `json:"reachability"`
	Confidence   *float64                `json:"confidence"`
	Verification *RunFindingVerification `json:"verification"`
}

// RunFindingSnippet is a stretch of code and the lines it starts and ends on.
type RunFindingSnippet struct {
	Code      string `json:"code"`
	StartLine *int   `json:"start_line"`
	EndLine   *int   `json:"end_line"`
}

// RunFindingManifest is the manifest line that declares an SCA finding's
// package.
type RunFindingManifest struct {
	Snippet *RunFindingSnippet `json:"snippet"`
}

// RunFindingReachability is whether the vulnerable code can be reached:
// Verdict reachable, not_reachable or unknown.
type RunFindingReachability struct {
	Verdict  string `json:"verdict"`
	Exposure *int   `json:"exposure"`
}

// RunFindingVerification is the AI verifier's explanation.
type RunFindingVerification struct {
	Explanation *string `json:"explanation"`
}

// RunFindingRemediation is how to fix a finding. A secret has no summary
// and no patch.
type RunFindingRemediation struct {
	Summary    *string `json:"summary"`
	Patch      *string `json:"patch"`
	FixVersion *string `json:"fix_version"`
}
