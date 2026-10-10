package scan

import (
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
// Identity is (file, start line, start column, severity, type, finding category,
// CWE set). End column is deliberately excluded: the duplicates disagree on it by a
// character, which is exactly why keying on the full span does not collapse them.
// Two genuinely different defects on one line -- different CWE, different severity,
// or a different type -- keep their own entries. Type and finding category are part
// of identity because a hard-coded credential in a config file is commonly reported
// both as an exposed secret and as a misconfiguration at the same file, line and
// column with equal severity and no CWE; without them the two collapse and the
// exposed secret is as likely as not to be the one discarded.
//
// Within a group the finding with the lexicographically smallest ID is kept, so the
// choice does not depend on the order the pages of results arrived in and repeated
// scans of the same commit report the same finding.
func DeduplicateFindings(findings []model.Finding) []model.Finding {
	if len(findings) < 2 {
		return findings
	}

	// Output order is the append order of the order slice; a group only ever needs
	// to know which finding it is currently keeping.
	type group struct {
		keptID  string // ID of the finding currently kept for this key
		finding model.Finding
	}

	groups := make(map[string]*group, len(findings))
	order := make([]*group, 0, len(findings))

	for _, f := range findings {
		if !dedupable(f) {
			order = append(order, &group{keptID: f.ID, finding: f})
			continue
		}
		key := dedupeKey(f)
		g, seen := groups[key]
		if !seen {
			g = &group{keptID: f.ID, finding: f}
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
//
// A start column or a CWE is also required. Both are absent from some backend
// payloads, and file+line+severity+type alone is not specific enough to call two
// findings the same defect -- two different secrets on one line would collapse into
// one. Requiring a discriminator keeps the key as specific as it is documented to
// be, at the cost of leaving a genuine duplicate uncollapsed when the payload
// carries neither.
func dedupable(f model.Finding) bool {
	if f.File == "" || f.StartLine <= 0 || len(f.CVEs) != 0 {
		return false
	}
	return f.StartColumn > 0 || len(f.CWEs) > 0
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
	b.WriteString(string(f.Type))
	b.WriteByte(0)
	b.WriteString(normalizeFindingCategory(f.FindingCategory))
	b.WriteByte(0)
	b.WriteString(strings.Join(cwes, "|"))
	return b.String()
}

// cweIdentifier reduces a CWE string to its identifier, using the same parser as
// .armisignore suppression matching.
//
// The backend spells the same CWE differently across findings -- the duplicates
// this collapses arrive as "CWE-78: ... ('OS Command Injection')" and
// "CWE-78: ... ('Command Injection')" -- so the descriptive tail cannot be part of
// the identity. A string with no recognisable identifier is returned trimmed rather
// than dropped, so it still distinguishes findings.
func cweIdentifier(cwe string) string {
	if number, ok := CWENumber(cwe); ok {
		return "CWE-" + number
	}
	return strings.TrimSpace(cwe)
}
