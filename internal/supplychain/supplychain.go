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

// TransitivePolicy selects what the proxy does with a young *transitive*
// dependency (one not declared in the root manifest). It is the security knob
// behind WS5: the default keeps today's hard-block behavior, and the opt-in
// warn mode trades a sliver of protection on indirect deps for a build that
// completes. Direct dependencies are ALWAYS blocked regardless of this setting
// — that is where typosquat/dependency-confusion risk concentrates and where
// the developer has direct control.
type TransitivePolicy string

const (
	// TransitivePolicyBlock strips young transitive versions exactly like young
	// direct versions. This is the default — no opt-in, no posture change.
	TransitivePolicyBlock TransitivePolicy = "block"
	// TransitivePolicyWarn lets a young transitive dependency through with a
	// warning instead of stripping it, so the parent's version range stays
	// satisfiable and the install succeeds. Gated behind explicit config/env.
	TransitivePolicyWarn TransitivePolicy = "warn"
)

// ParseTransitivePolicy maps a config/env string to a TransitivePolicy. It is
// fail-safe: an empty or unrecognized value resolves to block, so a typo can
// never silently weaken the control into warn mode.
func ParseTransitivePolicy(s string) TransitivePolicy {
	if strings.EqualFold(strings.TrimSpace(s), string(TransitivePolicyWarn)) {
		return TransitivePolicyWarn
	}
	return TransitivePolicyBlock
}

type Policy struct {
	MinReleaseAge time.Duration
	Exclusions    []string
	FailOpen      bool
	// TransitivePolicy is the block/warn knob for young transitive deps. The
	// zero value ("") is treated as block by the proxy, so an unset policy keeps
	// the secure default.
	TransitivePolicy TransitivePolicy
}

func DefaultPolicy() Policy {
	return Policy{
		MinReleaseAge:    72 * time.Hour,
		TransitivePolicy: TransitivePolicyBlock,
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
		return scaleToDuration(s, n, float64(24*time.Hour))
	case 'w':
		n, err := parseFiniteNonNegativeFloat(s, s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return scaleToDuration(s, n, float64(7*24*time.Hour))
	default:
		d, err := time.ParseDuration(s)
		if err != nil {
			// Don't wrap time.ParseDuration's error: it repeats `invalid duration
			// %q` verbatim, producing a doubled message. Give an actionable hint
			// about accepted formats instead.
			return 0, fmt.Errorf("invalid duration %q: use a number with a unit like 72h, 3d, or 1w", s)
		}
		// time.ParseDuration accepts signed values (e.g. "-72h"). A negative
		// min-age is nonsensical and would effectively disable age enforcement,
		// so reject it the same way the custom d/w paths reject negatives.
		if d < 0 {
			return 0, fmt.Errorf("invalid duration %q: must not be negative", s)
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

// scaleToDuration multiplies a finite, non-negative count by a per-unit
// nanosecond scale and converts to time.Duration, rejecting results that exceed
// the int64 nanosecond range. A float64 too large for time.Duration would, on a
// float→int conversion, produce an implementation-defined result that can wrap
// to a negative or tiny duration — silently enfeebling min-age enforcement (e.g.
// "200000d"). math.MaxInt64 is not exactly representable in float64 and rounds up
// to 2^63, so the boundary check must be ">=" to also exclude exactly 2^63 ns.
// orig is the full duration string, used only for error context.
func scaleToDuration(orig string, n, scale float64) (time.Duration, error) {
	ns := n * scale
	if ns >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("invalid duration %q: exceeds maximum representable duration", orig)
	}
	return time.Duration(ns), nil
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
