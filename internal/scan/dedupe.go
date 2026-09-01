package scan

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

// DeduplicateFindings collapses findings that describe the same defect at the same
// place.
//
// The backend can emit several normalized findings for one line: a scan of a file
// containing a single `subprocess.run(..., shell=True)` returns two findings at the
// same file, line and start column, both carrying CWE-78, differing only in the
// prose of their title and description and in the end column. They are the same
// defect with the same fix, and reporting both inflates finding counts, doubles the
// suppression work needed to silence one issue, and makes any per-finding triage
// look twice as large as it is.
//
// Identity is (file, start line, start column, severity, CWE set). End column is
// deliberately excluded: the duplicates disagree on it by a character, which is
// exactly why keying on the full span does not collapse them. Two genuinely
// different defects on one line -- different CWE, or different severity -- keep
// their own entries.
//
// Within a group the finding with the lexicographically smallest ID is kept, so the
// choice does not depend on the order the pages of results arrived in and repeated
// scans of the same commit report the same finding.
func DeduplicateFindings(findings []model.Finding) []model.Finding {
	if len(findings) < 2 {
		return findings
	}

	type group struct {
		index   int    // position of the kept finding in the output
		keptID  string // ID of the finding currently kept for this key
		finding model.Finding
	}

	groups := make(map[string]*group, len(findings))
	order := make([]*group, 0, len(findings))

	for _, f := range findings {
		if !dedupable(f) {
			order = append(order, &group{index: len(order), keptID: f.ID, finding: f})
			continue
		}
		key := dedupeKey(f)
		g, seen := groups[key]
		if !seen {
			g = &group{index: len(order), keptID: f.ID, finding: f}
			groups[key] = g
			order = append(order, g)
			continue
		}
		if f.ID < g.keptID {
			g.keptID = f.ID
			g.finding = f
		}
	}

	out := make([]model.Finding, 0, len(order))
	for _, g := range order {
		out = append(out, g.finding)
	}
	return out
}

// dedupable reports whether a finding is a code-level defect anchored at a
// specific line, the only shape the backend duplicates and the only shape where a
// shared location plus a shared CWE means "the same problem".
//
// Package findings are excluded deliberately: several CVEs in one dependency share
// a manifest location (or carry no location at all) while being genuinely
// different findings, so collapsing them would lose real results.
func dedupable(f model.Finding) bool {
	return f.File != "" && f.StartLine > 0 && len(f.CVEs) == 0
}

// dedupeKey builds the identity used by DeduplicateFindings. CWEs are reduced to
// their identifiers and sorted, so two orderings of the same set produce one key.
func dedupeKey(f model.Finding) string {
	cwes := make([]string, 0, len(f.CWEs))
	for _, cwe := range f.CWEs {
		cwes = append(cwes, cweIdentifier(cwe))
	}
	sort.Strings(cwes)

	var b strings.Builder
	b.WriteString(f.File)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(f.StartLine))
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(f.StartColumn))
	b.WriteByte(0)
	b.WriteString(string(f.Severity))
	b.WriteByte(0)
	b.WriteString(strings.Join(cwes, "|"))
	return b.String()
}

// cweIdentifier reduces a CWE string to its identifier.
//
// The backend spells the same CWE differently across findings -- the duplicates
// this collapses arrive as "CWE-78: ... ('OS Command Injection')" and
// "CWE-78: ... ('Command Injection')" -- so the descriptive tail cannot be part of
// the identity. A string with no recognisable identifier is returned unchanged
// rather than dropped, so it still distinguishes findings.
func cweIdentifier(cwe string) string {
	if idx := strings.IndexByte(cwe, ':'); idx > 0 {
		head := strings.TrimSpace(cwe[:idx])
		if cweIDPattern.MatchString(head) {
			return strings.ToUpper(head)
		}
	}
	if cweIDPattern.MatchString(strings.TrimSpace(cwe)) {
		return strings.ToUpper(strings.TrimSpace(cwe))
	}
	return cwe
}

var cweIDPattern = regexp.MustCompile(`^(?i:cwe)-[0-9]+$`)
