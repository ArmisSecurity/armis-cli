// Package supplychain implements supply chain package age policy enforcement.
package supplychain

import (
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
)

type Policy struct {
	MinReleaseAge time.Duration
	Exclusions    []string
	FailOpen      bool
}

func DefaultPolicy() Policy {
	return Policy{
		MinReleaseAge: 72 * time.Hour,
	}
}

type Violation struct {
	Name            string
	Version         string
	PublishTime     time.Time
	Age             time.Duration
	PolicyThreshold time.Duration
	Severity        model.Severity
}

func ClassifySeverity(age, threshold time.Duration) model.Severity {
	if age < 24*time.Hour {
		return model.SeverityHigh
	}
	if age < threshold {
		return model.SeverityMedium
	}
	return model.SeverityLow
}

func (p Policy) IsExcluded(name string) bool {
	for _, pattern := range p.Exclusions {
		// Use path.Match (always forward-slash) rather than filepath.Match so
		// scoped package names like "@scope/name" match consistently across
		// platforms; filepath.Match treats '/' as a separator only on some OSes.
		matched, err := path.Match(pattern, name)
		if err != nil {
			// A malformed glob (path.ErrBadPattern) can never produce a
			// meaningful match. Fail safe by treating it as "not excluded" so a
			// bad exclusion entry never silently bypasses the age check; the
			// package is still verified against the registry.
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	last := s[len(s)-1]
	switch last {
	case 'd':
		n, err := parseFiniteNonNegativeFloat(s, s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	case 'w':
		n, err := parseFiniteNonNegativeFloat(s, s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return time.Duration(n * float64(7*24*time.Hour)), nil
	default:
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return d, nil
	}
}

// parseFiniteNonNegativeFloat parses the numeric portion of a custom 'd'/'w'
// duration. strconv.ParseFloat accepts "NaN", "Inf", and signed variants, any of
// which would yield a nonsensical policy (e.g. "NaNd" → duration 0, silently
// disabling enforcement). Reject non-finite and negative values so a min-age can
// only ever be a real, non-negative span. orig is the full duration string, used
// only for error context.
func parseFiniteNonNegativeFloat(orig, num string) (float64, error) {
	n, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", orig, err)
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("invalid duration %q: must be a finite number", orig)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid duration %q: must not be negative", orig)
	}
	return n, nil
}

func ViolationToFinding(v Violation, lockfilePath string) model.Finding {
	return model.Finding{
		ID:              fmt.Sprintf("SUPPLY_CHAIN_AGE/%s@%s", v.Name, v.Version),
		Type:            model.FindingTypeSCA,
		Severity:        v.Severity,
		Title:           fmt.Sprintf("Recently published package: %s@%s (published %s ago)", v.Name, v.Version, formatAge(v.Age)),
		Description:     fmt.Sprintf("Package %s@%s was published %s ago, which is less than the minimum release age policy of %s.", v.Name, v.Version, formatAge(v.Age), formatAge(v.PolicyThreshold)),
		File:            lockfilePath,
		Package:         v.Name,
		Version:         v.Version,
		FindingCategory: "SUPPLY_CHAIN_AGE",
	}
}

func formatAge(d time.Duration) string {
	if d >= 24*time.Hour {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) % 24
		if hours == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, hours)
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
