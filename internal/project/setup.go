package project

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ErrSetupCancelled means the user cancelled a first-time project setup: no
// project was created, and the scan must stop before anything is uploaded.
var ErrSetupCancelled = errors.New("project setup cancelled")

// The limits of a project's labels (the API's tags), after NormalizeLabels.
const (
	MaxLabels      = 20
	MaxLabelLength = 64
)

// The limits of the filters a setup writes to .armisignore: the CLI keeps at
// most 100 directives of each type, and a longer pattern is a mistake.
const (
	MaxSetupCWEs         = 100
	MaxPathExcludes      = 200
	MaxPathExcludeLength = 1024
	maxCWE               = 9999
)

// Severities are the severities a setup can hide, most severe first, as
// .armisignore names them.
var Severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// Categories are the scanner categories a setup can hide, as .armisignore's
// category: directives name them.
var Categories = []string{"sast", "secrets", "iac", "sca", "license"}

// DefaultMinSeverity is the minimum severity a setup proposes, as the AppSec
// UI's CLI project wizard does.
const DefaultMinSeverity = "MEDIUM"

// Setup is what a first-time project setup decided: the labels the project is
// created with, and the filters to write to the repository's .armisignore.
// The filters are never sent to Armis: the repository's .armisignore is the
// one place a CLI project's filters live.
type Setup struct {
	Labels  []string
	Filters Filters
}

// Filters are the Scan Filters of the AppSec UI's CLI project wizard, which a
// setup writes to .armisignore.
type Filters struct {
	// MinSeverity hides the findings below it; "" and INFO hide none.
	MinSeverity  string
	PathExcludes []string
	// Severities, Categories and CWEs are the findings to suppress.
	Severities []string
	Categories []string
	CWEs       []int
}

// HiddenSeverities are the severities the filters hide, those below
// MinSeverity and those suppressed, most severe first, each once.
func (f Filters) HiddenSeverities() []string {
	hidden := map[string]bool{}
	if i := slices.Index(Severities, f.MinSeverity); i >= 0 {
		for _, s := range Severities[i+1:] {
			hidden[s] = true
		}
	}
	for _, s := range f.Severities {
		hidden[s] = true
	}
	var out []string
	for _, s := range Severities {
		if hidden[s] {
			out = append(out, s)
		}
	}
	return out
}

// Empty reports whether the filters would write nothing.
func (f Filters) Empty() bool {
	return len(f.PathExcludes) == 0 && len(f.HiddenSeverities()) == 0 &&
		len(f.Categories) == 0 && len(f.CWEs) == 0
}

// setupMarker opens the block a setup writes to .armisignore; setupEnd closes it.
const (
	setupMarker = "# armis-cli project setup:"
	setupEnd    = "# end armis-cli project setup"
)

// Lines are the filters as the .armisignore block a setup writes, laid out as
// the AppSec UI's generated .armisignore, between markers that name the
// project and the date. CWEs are written as cwe:<n>, which every CLI reads.
// Empty filters write no lines.
func (f Filters) Lines(projectName, date string) []string {
	if f.Empty() {
		return nil
	}
	lines := []string{fmt.Sprintf("%s %s, %s", setupMarker, projectName, date)}
	if len(f.PathExcludes) > 0 {
		lines = append(lines, "# Path excludes — kept out of the scan entirely")
		lines = append(lines, f.PathExcludes...)
	}
	hidden := f.HiddenSeverities()
	if len(hidden) > 0 || len(f.Categories) > 0 || len(f.CWEs) > 0 {
		if len(f.PathExcludes) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "# Suppression directives — still scanned, hidden from reports & --fail-on")
		if below := belowMinimum(f.MinSeverity); len(below) > 0 {
			lines = append(lines, fmt.Sprintf("# Minimum severity %s (hides %s)", f.MinSeverity, strings.Join(below, ", ")))
		}
		for _, s := range hidden {
			lines = append(lines, "severity:"+s)
		}
		for _, c := range f.Categories {
			lines = append(lines, "category:"+c)
		}
		for _, n := range f.CWEs {
			lines = append(lines, "cwe:"+strconv.Itoa(n))
		}
	}
	return append(lines, setupEnd)
}

// belowMinimum are the severities below min, most severe first.
func belowMinimum(minSeverity string) []string {
	i := slices.Index(Severities, minSeverity)
	if i < 0 {
		return nil
	}
	return Severities[i+1:]
}

// NormalizeLabels splits labels on commas, trims and lower-cases them, and
// drops empty ones and repeats, as the API normalizes a project's tags. It
// fails past the API's limits, so a create never fails on them.
func NormalizeLabels(raw []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			label := strings.ToLower(strings.TrimSpace(part))
			if label == "" || seen[label] {
				continue
			}
			if len(label) > MaxLabelLength {
				return nil, fmt.Errorf("label %q is longer than %d characters", label, MaxLabelLength)
			}
			if strings.ContainsFunc(label, isControl) {
				return nil, fmt.Errorf("label %q holds a control character", label)
			}
			seen[label] = true
			out = append(out, label)
		}
	}
	if len(out) > MaxLabels {
		return nil, fmt.Errorf("%d labels: a project takes at most %d", len(out), MaxLabels)
	}
	return out, nil
}

// SameLabels reports whether two label lists hold the same labels, in any
// order, once normalized.
func SameLabels(a, b []string) bool {
	na, errA := NormalizeLabels(a)
	nb, errB := NormalizeLabels(b)
	if errA != nil || errB != nil || len(na) != len(nb) {
		return false
	}
	sort.Strings(na)
	sort.Strings(nb)
	return slices.Equal(na, nb)
}

// ParseSeverity reads a severity, in any case, as one of Severities.
func ParseSeverity(v string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	if !slices.Contains(Severities, s) {
		return "", fmt.Errorf("unknown severity %q (one of %s)", v, strings.Join(Severities, ", "))
	}
	return s, nil
}

// ParseCategory reads a scanner category, in any case, as one of Categories.
func ParseCategory(v string) (string, error) {
	c := strings.ToLower(strings.TrimSpace(v))
	if !slices.Contains(Categories, c) {
		return "", fmt.Errorf("unknown category %q (one of %s)", v, strings.Join(Categories, ", "))
	}
	return c, nil
}

// ParseCWE reads a CWE id: 79, CWE-79 or cwe-79, from 1 to 9999, as the AppSec
// API reads one.
func ParseCWE(v string) (int, error) {
	digits := strings.TrimSpace(v)
	if len(digits) > 4 && strings.EqualFold(digits[:4], "CWE-") {
		digits = digits[4:]
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 || n > maxCWE {
		return 0, fmt.Errorf("invalid CWE %q (a number from 1 to %d, such as 79 or CWE-79)", strings.TrimSpace(v), maxCWE)
	}
	return n, nil
}

// ParseCWEs reads a comma-separated list of CWE ids, sorted and each once.
func ParseCWEs(v string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(v, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		n, err := ParseCWE(part)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > MaxSetupCWEs {
		return nil, fmt.Errorf("%d CWEs: .armisignore keeps at most %d", len(out), MaxSetupCWEs)
	}
	sort.Ints(out)
	return out, nil
}

// ParsePathExcludes splits gitignore patterns on commas and line ends, trimmed
// and each once, in the order given (a later pattern wins in .armisignore).
func ParsePathExcludes(v string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(v, "\n") {
		for _, part := range strings.Split(line, ",") {
			p := strings.TrimSpace(part)
			if p == "" || seen[p] {
				continue
			}
			if err := ValidatePathExclude(p); err != nil {
				return nil, err
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) > MaxPathExcludes {
		return nil, fmt.Errorf("%d path excludes: a setup writes at most %d", len(out), MaxPathExcludes)
	}
	return out, nil
}

// directivePrefixes are .armisignore's directive prefixes: a root-file line
// that starts with one is read as a directive, never as a path pattern.
var directivePrefixes = []string{"rule:", "category:", "severity:", "cwe:"}

// ValidatePathExclude refuses what .armisignore would not read as the path
// pattern meant: a comment, a directive, a control character, or a pattern too
// long.
func ValidatePathExclude(p string) error {
	switch {
	case p == "":
		return errors.New("empty path exclude")
	case len(p) > MaxPathExcludeLength:
		return fmt.Errorf("path exclude %.40q… is longer than %d characters", p, MaxPathExcludeLength)
	case strings.HasPrefix(p, "#"):
		return fmt.Errorf("path exclude %q starts with #, which .armisignore reads as a comment (write \\# for a file named so)", p)
	case strings.ContainsFunc(p, isControl):
		return fmt.Errorf("path exclude %q holds a control character", p)
	}
	lower := strings.ToLower(p)
	for _, prefix := range directivePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("path exclude %q would be read as a %s directive", p, strings.TrimSuffix(prefix, ":"))
		}
	}
	return nil
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}
