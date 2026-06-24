package supplychain

import (
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ConstraintConflict is one transitive-incompatibility the age filter caused:
// every version of Dep that satisfied a dependent's declared Range was younger
// than the policy and got removed, so npm can no longer resolve Dep for ByPkg
// and the install fails. This is the canonical case WS1's empty-fallback
// heuristic cannot catch — an older surviving version of Dep exists, it just
// doesn't satisfy Range.
type ConstraintConflict struct {
	// Dep is the dependency npm could not resolve (e.g. "scheduler").
	Dep string
	// Range is the version range that became unsatisfiable (e.g. "^0.24.0").
	Range string
	// ByPkg is the package that declared the range (e.g. "react-dom").
	ByPkg string
}

// EvaluateConstraints runs the WS2 one-hop conflict check AFTER the package
// manager has exited. By then every metadata document has flowed through the
// filter and both accumulators are fully populated, so the result is
// deterministic regardless of the order requests arrived in. A recover() guards
// the whole pass: a semver-library bug or unexpected input can never panic into
// the already-finished install — at worst the diagnostic is silently skipped.
//
// A conflict is reported only when BOTH hold for a (Dep, Range) pair:
//   - no SURVIVING version of Dep satisfies Range (npm has nothing to resolve), and
//   - some REMOVED version of Dep DID satisfy Range (the filter is what made it
//     unsatisfiable).
//
// The second clause is what makes the attribution honest: a range like
// "^99.0.0" that never matched any published version is not our doing, so it is
// not reported. Ranges that fail to parse as a semver constraint (npm: aliases,
// git+/file:/URL specs, "latest", workspace protocols) are SKIPPED — fail-open
// on the diagnostic, never a false conflict.
func (p *Proxy) EvaluateConstraints() (conflicts []ConstraintConflict) {
	defer func() {
		if r := recover(); r != nil {
			// Swallow: the install already finished; a broken diagnostic must not
			// turn into a crash. Return whatever was accumulated before the panic.
			conflicts = nil
		}
	}()

	// Snapshot the accumulators under their locks, then evaluate off-lock. The
	// snapshot maps are not pre-sized: their contents are already materialized in
	// the source maps (each entry was bounded by one filtered metadata response),
	// so a length hint would only mirror an already-bounded size, not gate growth.
	p.requiredRangesMu.Lock()
	required := make(map[string][]requiredRange)
	for dep, ranges := range p.requiredRanges {
		required[dep] = append([]requiredRange(nil), ranges...)
	}
	p.requiredRangesMu.Unlock()

	if len(required) == 0 {
		return nil
	}

	p.keptVersionsMu.Lock()
	kept := make(map[string][]string)
	for dep, vers := range p.keptVersions {
		kept[dep] = append([]string(nil), vers...)
	}
	p.keptVersionsMu.Unlock()

	// Removed versions per package, recorded by the filter. Used to confirm the
	// range WAS satisfiable before the age filter ran — the second clause that
	// keeps attribution honest (a never-satisfiable range is not our doing).
	p.removedVersionsMu.Lock()
	removed := make(map[string][]string)
	for dep, vers := range p.removedVersions {
		removed[dep] = append([]string(nil), vers...)
	}
	p.removedVersionsMu.Unlock()

	// Dedup identical (dep, range, byPkg) triples — a range declared by many
	// surviving versions of the same dependent would otherwise repeat.
	seen := make(map[ConstraintConflict]bool)
	for dep, ranges := range required {
		keptVers := parseVersions(kept[dep])
		removedVers := parseVersions(removed[dep])
		for _, rr := range ranges {
			if isWildcardRange(rr.Range) {
				// A pure wildcard ("*", "x", "latest", "") matches any version, so it
				// can never be made unsatisfiable by a version pin — if nothing
				// survived, that is the no-fallback case WS1 already names, not a
				// constraint conflict. Skip it to avoid double-reporting.
				continue
			}
			constraint, err := semver.NewConstraint(rr.Range)
			if err != nil {
				continue // unparseable specifier → fail-open, never a conflict
			}
			if anySatisfies(keptVers, constraint) {
				continue // a surviving version still satisfies → no conflict
			}
			if !anySatisfies(removedVers, constraint) {
				continue // nothing we removed satisfied it either → not our doing
			}
			c := ConstraintConflict{Dep: dep, Range: rr.Range, ByPkg: rr.ByPkg}
			if seen[c] {
				continue
			}
			seen[c] = true
			conflicts = append(conflicts, c)
		}
	}

	// Deterministic order so the summary and report read identically run to run.
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Dep != conflicts[j].Dep {
			return conflicts[i].Dep < conflicts[j].Dep
		}
		if conflicts[i].Range != conflicts[j].Range {
			return conflicts[i].Range < conflicts[j].Range
		}
		return conflicts[i].ByPkg < conflicts[j].ByPkg
	})
	return conflicts
}

// isWildcardRange reports whether a dependency specifier matches any version
// and so can never be the cause of a pin-based transitive break. Covers the
// bare wildcards npm accepts ("*", "x", "X", "latest") and the empty string.
func isWildcardRange(rng string) bool {
	switch strings.TrimSpace(rng) {
	case "", "*", "x", "X", "latest":
		return true
	}
	return false
}

// parseVersions parses a slice of raw version strings into semver values,
// dropping any that do not parse (a malformed entry simply does not count toward
// satisfaction). semver.NewVersion is lenient (tolerates a leading "v", missing
// patch, etc.), matching what npm accepts in a versions map.
func parseVersions(raw []string) []*semver.Version {
	// armis:ignore cwe:770 cwe:401 reason:raw originates from npm metadata bodies capped at maxProxyResponseSize (20MB) by io.LimitReader at proxy.go (oversize rejected with 502), and the accumulators feeding it are capped at maxConstraintEntries (50000) distinct keys; len(raw) is bounded, not attacker-controlled-unbounded — same trust model as the sibling suppressions in proxy.go
	out := make([]*semver.Version, 0, len(raw))
	for _, s := range raw {
		v, err := semver.NewVersion(s)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

// anySatisfies reports whether any version in vers satisfies the constraint.
func anySatisfies(vers []*semver.Version, constraint *semver.Constraints) bool {
	for _, v := range vers {
		if constraint.Check(v) {
			return true
		}
	}
	return false
}
