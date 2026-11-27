package project

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeLabels(t *testing.T) {
	got, err := NormalizeLabels([]string{" Team-Payments , pci", "PCI", "", " , ", "team-payments"})
	if err != nil || !slices.Equal(got, []string{"team-payments", "pci"}) {
		t.Errorf("NormalizeLabels = %q, %v", got, err)
	}
	if got, err := NormalizeLabels(nil); err != nil || got != nil {
		t.Errorf("no labels = %q, %v", got, err)
	}

	many := make([]string, MaxLabels+1)
	for i := range many {
		many[i] = fmt.Sprintf("l%d", i)
	}
	for name, raw := range map[string][]string{
		"too long":          {strings.Repeat("a", MaxLabelLength+1)},
		"too many":          many,
		"a control char":    {"team\x07"},
		"one of many, long": {"ok", strings.Repeat("b", MaxLabelLength+1)},
	} {
		if _, err := NormalizeLabels(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := NormalizeLabels([]string{strings.Repeat("a", MaxLabelLength)}); err != nil {
		t.Errorf("a label of exactly %d characters: %v", MaxLabelLength, err)
	}
}

func TestSameLabels(t *testing.T) {
	if !SameLabels([]string{"PCI", "team"}, []string{"team", "pci"}) {
		t.Error("the same labels in another order and case should match")
	}
	if SameLabels([]string{"pci"}, []string{"pci", "team"}) || SameLabels([]string{"pci"}, nil) {
		t.Error("different labels matched")
	}
	if !SameLabels(nil, []string{}) {
		t.Error("no labels should match no labels")
	}
}

func TestParseCWE(t *testing.T) {
	for in, want := range map[string]int{"79": 79, "CWE-79": 79, "cwe-0079": 79, " 1333 ": 1333, "9999": 9999, "1": 1} {
		if got, err := ParseCWE(in); err != nil || got != want {
			t.Errorf("ParseCWE(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"0", "10000", "-1", "CWE-", "CWE79", "abc", "", "7.9"} {
		if _, err := ParseCWE(in); err == nil {
			t.Errorf("ParseCWE(%q): expected an error", in)
		}
	}
}

func TestParseCWEs(t *testing.T) {
	got, err := ParseCWEs("CWE-89, 79,, 89 ,cwe-79")
	if err != nil || !slices.Equal(got, []int{79, 89}) {
		t.Errorf("ParseCWEs = %v, %v", got, err)
	}
	if got, err := ParseCWEs(" "); err != nil || got != nil {
		t.Errorf("an empty list = %v, %v", got, err)
	}
	if _, err := ParseCWEs("79, nope"); err == nil {
		t.Error("an invalid id should fail the list")
	}
	ids := make([]string, MaxSetupCWEs+1)
	for i := range ids {
		ids[i] = fmt.Sprint(i + 1)
	}
	if _, err := ParseCWEs(strings.Join(ids, ",")); err == nil {
		t.Errorf("%d CWEs: expected an error", len(ids))
	}
}

func TestParsePathExcludes(t *testing.T) {
	got, err := ParsePathExcludes("node_modules/, *.generated.go\n dist/ \n\n!dist/keep.txt, node_modules/")
	want := []string{"node_modules/", "*.generated.go", "dist/", "!dist/keep.txt"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("ParsePathExcludes = %q, %v; want %q", got, err, want)
	}
	for name, in := range map[string]string{
		"a comment":           "#build",
		"a severity line":     "severity:LOW",
		"a directive in caps": "CWE:79",
		"a rule line":         "rule:G304",
		"too long":            strings.Repeat("a", MaxPathExcludeLength+1),
		"a control character": "dist/\x1b[2J",
	} {
		if _, err := ParsePathExcludes(in); err == nil {
			t.Errorf("%s (%q): expected an error", name, in)
		}
	}
	patterns := make([]string, MaxPathExcludes+1)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("dir%d/", i)
	}
	if _, err := ParsePathExcludes(strings.Join(patterns, ",")); err == nil {
		t.Errorf("%d patterns: expected an error", len(patterns))
	}
}

func TestParseSeverityAndCategory(t *testing.T) {
	if s, err := ParseSeverity(" low "); err != nil || s != "LOW" {
		t.Errorf("ParseSeverity = %q, %v", s, err)
	}
	if c, err := ParseCategory("IaC"); err != nil || c != "iac" {
		t.Errorf("ParseCategory = %q, %v", c, err)
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("an unknown severity should fail")
	}
	if _, err := ParseCategory("secret"); err == nil {
		t.Error("an unknown category should fail (it is secrets)")
	}
}

func TestFilters_HiddenSeverities(t *testing.T) {
	for _, tt := range []struct {
		f    Filters
		want []string
	}{
		{Filters{MinSeverity: "MEDIUM"}, []string{"LOW", "INFO"}},
		{Filters{MinSeverity: "CRITICAL"}, []string{"HIGH", "MEDIUM", "LOW", "INFO"}},
		{Filters{MinSeverity: "INFO"}, nil},
		{Filters{}, nil},
		{Filters{MinSeverity: "MEDIUM", Severities: []string{"LOW", "CRITICAL"}}, []string{"CRITICAL", "LOW", "INFO"}},
		{Filters{Severities: []string{"HIGH"}}, []string{"HIGH"}},
	} {
		if got := tt.f.HiddenSeverities(); !slices.Equal(got, tt.want) {
			t.Errorf("%+v: HiddenSeverities = %q, want %q", tt.f, got, tt.want)
		}
	}
}

func TestFilters_Lines(t *testing.T) {
	f := Filters{
		MinSeverity:  "MEDIUM",
		PathExcludes: []string{"node_modules/", "*.generated.go"},
		Severities:   []string{"CRITICAL"},
		Categories:   []string{"license"},
		CWEs:         []int{79, 1333},
	}
	want := []string{
		"# armis-cli project setup: payments-api, 2026-11-26",
		"# Path excludes — kept out of the scan entirely",
		"node_modules/",
		"*.generated.go",
		"",
		"# Suppression directives — still scanned, hidden from reports & --fail-on",
		"# Minimum severity MEDIUM (hides LOW, INFO)",
		"severity:CRITICAL",
		"severity:LOW",
		"severity:INFO",
		"category:license",
		"cwe:79",
		"cwe:1333",
		"# end armis-cli project setup",
	}
	if got := f.Lines("payments-api", "2026-11-26"); !slices.Equal(got, want) {
		t.Errorf("Lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Each part on its own, and none.
	if got := (Filters{PathExcludes: []string{"dist/"}}).Lines("p", "d"); len(got) != 4 || got[2] != "dist/" {
		t.Errorf("excludes only = %q", got)
	}
	if got := (Filters{CWEs: []int{79}}).Lines("p", "d"); len(got) != 4 || got[2] != "cwe:79" {
		t.Errorf("a CWE only = %q", got)
	}
	if got := (Filters{MinSeverity: "INFO"}).Lines("p", "d"); got != nil {
		t.Errorf("a minimum of INFO writes nothing, got %q", got)
	}
	if !(Filters{}).Empty() || (Filters{Categories: []string{"sca"}}).Empty() {
		t.Error("Empty is wrong")
	}
}

// Every line a setup writes must read back as what it means, through the
// parser .armisignore uses.
func TestFilters_LinesAreValidArmisignore(t *testing.T) {
	f := Filters{MinSeverity: "HIGH", PathExcludes: []string{"a/", "!a/b"}, Categories: Categories, CWEs: []int{79}}
	for _, line := range f.Lines("p", "d") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		isDirective := slices.ContainsFunc(directivePrefixes, func(p string) bool { return strings.HasPrefix(lower, p) })
		if isDirective == slices.Contains(f.PathExcludes, line) {
			t.Errorf("%q is read as the wrong kind of line", line)
		}
	}
}

func TestErrSetupCancelled_Wraps(t *testing.T) {
	if !errors.Is(fmt.Errorf("form: %w", ErrSetupCancelled), ErrSetupCancelled) {
		t.Error("a wrapped cancel should still be ErrSetupCancelled")
	}
}
