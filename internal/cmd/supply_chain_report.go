package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

// envSCReport names the path the wrap path writes its machine-readable
// compliance report to. A wrap command cannot take a --flag (DisableFlagParsing
// forwards every flag to the underlying PM), so the report is requested via this
// env var, matching the ARMIS_SUPPLY_CHAIN_SKIP / ARMIS_SUPPLY_CHAIN convention.
// The value "-" writes to stderr.
const envSCReport = "ARMIS_SUPPLY_CHAIN_REPORT"

// install_status values for the compliance report. statusOK means the package
// manager completed (or the audit passed); statusFailed means it did not.
const (
	statusOK     = "ok"
	statusFailed = "failed"
)

// complianceReport is the audit document enterprise security teams need to prove
// no young package entered a build ("checked N, blocked M, here is the policy").
// It is intentionally a flat, stable JSON shape so CI can gate on it with jq.
type complianceReport struct {
	// Policy is the effective policy the run enforced.
	Policy reportPolicy `json:"policy"`
	// Mode is the enforcement mechanism: "proxy" (npm/pip live filtering) or
	// "pre-install" (lockfile audit before the build runs).
	Mode string `json:"mode"`
	// Ecosystem is the package manager's ecosystem (npm, pip, …).
	Ecosystem string `json:"ecosystem"`
	// Checked is how many packages the proxy inspected (proxy mode) or the audit
	// covered (pre-install mode).
	Checked int `json:"checked"`
	// Blocked lists every version the control withheld.
	Blocked []reportBlocked `json:"blocked"`
	// Resolved lists the safe fallback versions the proxy repointed to.
	Resolved []reportResolved `json:"resolved"`
	// WarnedThrough lists young transitive dependencies allowed through under the
	// warn-on-transitive policy (WS5). Always present (possibly empty) so a
	// security team can audit exactly which freshly-published packages entered the
	// build by policy rather than being blocked. Empty under the default block
	// policy.
	WarnedThrough []reportWarned `json:"warned_through"`
	// Conflicts lists the one-hop transitive incompatibilities the age filter
	// caused (WS2). npm-family only.
	Conflicts []reportConflict `json:"conflicts"`
	// InstallStatus is "ok" when the package manager completed (or the audit
	// passed), "failed" otherwise.
	InstallStatus string `json:"install_status"`
}

type reportPolicy struct {
	MinAge           string   `json:"min_age"`
	Exclusions       []string `json:"exclusions"`
	FailOpen         bool     `json:"fail_open"`
	TransitivePolicy string   `json:"transitive_policy"`
}

type reportBlocked struct {
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	AgeHours float64 `json:"age_hours"`
}

type reportResolved struct {
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	AgeHours float64 `json:"age_hours"`
}

type reportWarned struct {
	Name     string  `json:"name"`
	Version  string  `json:"version"`
	AgeHours float64 `json:"age_hours"`
}

type reportConflict struct {
	Dep   string `json:"dep"`
	Range string `json:"range"`
	ByPkg string `json:"by_pkg"`
}

// reportInput carries everything the wrap path knows after a run so the report
// can be assembled in one place. It is mode-agnostic: the pre-install path fills
// the same fields from a check.Result-derived view.
type reportInput struct {
	Policy        supplychain.Policy
	Mode          string
	Ecosystem     string
	Checked       int
	Blocked       []supplychain.BlockedPackage
	Resolved      []supplychain.InstalledPackage
	Warned        []supplychain.WarnedPackage
	Conflicts     []supplychain.ConstraintConflict
	InstallStatus string
}

// buildComplianceReport assembles the JSON report from a run's observed state.
// It collapses blocked versions to one row per (name, version), sorts every
// slice for deterministic output, and guarantees non-nil slices so the JSON
// always carries arrays (never null) — friendlier for jq gating.
func buildComplianceReport(in reportInput) complianceReport {
	rep := complianceReport{
		Policy: reportPolicy{
			MinAge:           in.Policy.MinReleaseAge.String(),
			Exclusions:       in.Policy.Exclusions,
			FailOpen:         in.Policy.FailOpen,
			TransitivePolicy: string(transitivePolicyOrDefault(in.Policy.TransitivePolicy)),
		},
		Mode:          in.Mode,
		Ecosystem:     in.Ecosystem,
		Checked:       in.Checked,
		Blocked:       make([]reportBlocked, 0, len(in.Blocked)),
		Resolved:      make([]reportResolved, 0, len(in.Resolved)),
		WarnedThrough: make([]reportWarned, 0, len(in.Warned)),
		Conflicts:     make([]reportConflict, 0, len(in.Conflicts)),
		InstallStatus: in.InstallStatus,
	}
	if rep.Policy.Exclusions == nil {
		rep.Policy.Exclusions = []string{}
	}

	// Dedup blocked rows on (name, version): the proxy can record the same
	// version more than once across requests.
	seenBlocked := make(map[string]bool, len(in.Blocked))
	for _, b := range in.Blocked {
		ver := b.Version
		if b.DisplayVersion != "" {
			ver = b.DisplayVersion
		}
		key := b.Name + "@" + ver
		if seenBlocked[key] {
			continue
		}
		seenBlocked[key] = true
		rep.Blocked = append(rep.Blocked, reportBlocked{Name: b.Name, Version: ver, AgeHours: hours(b.Age)})
	}

	// armis:ignore cwe:770 cwe:401 reason:in.Resolved/Warned/Conflicts come from the proxy accumulators (proxy.Allowed/Warned/EvaluateConstraints), each populated one entry per package actually processed during the real install from npm metadata capped at 20MB by io.LimitReader and bounded to maxConstraintEntries keys; not attacker-controlled-unbounded — same trust model as the cwe:770 suppressions in proxy.go
	for _, r := range in.Resolved {
		rep.Resolved = append(rep.Resolved, reportResolved{Name: r.Name, Version: r.Version, AgeHours: hours(r.Age)})
	}
	// armis:ignore cwe:770 cwe:401 reason:in.Warned is proxy.Warned() — bounded by the proxy's 20MB-capped metadata reads and maxConstraintEntries; see the Resolved loop above
	for _, w := range in.Warned {
		rep.WarnedThrough = append(rep.WarnedThrough, reportWarned{Name: w.Name, Version: w.Version, AgeHours: hours(w.Age)})
	}
	// armis:ignore cwe:770 cwe:401 reason:in.Conflicts is EvaluateConstraints() output — bounded by the proxy's 20MB-capped metadata reads and maxConstraintEntries; see the Resolved loop above
	for _, c := range in.Conflicts {
		rep.Conflicts = append(rep.Conflicts, reportConflict{Dep: c.Dep, Range: c.Range, ByPkg: c.ByPkg})
	}

	// Sort by (Name, Version) so the output is byte-stable for CI diffing/jq
	// gating. Name alone is not enough: npm can resolve several versions of the
	// same package in one tree, and a Name-only sort would leave same-name entries
	// in insertion order, which varies across runs.
	sort.Slice(rep.Blocked, func(i, j int) bool {
		if rep.Blocked[i].Name != rep.Blocked[j].Name {
			return rep.Blocked[i].Name < rep.Blocked[j].Name
		}
		return rep.Blocked[i].Version < rep.Blocked[j].Version
	})
	sort.Slice(rep.Resolved, func(i, j int) bool {
		if rep.Resolved[i].Name != rep.Resolved[j].Name {
			return rep.Resolved[i].Name < rep.Resolved[j].Name
		}
		return rep.Resolved[i].Version < rep.Resolved[j].Version
	})
	sort.Slice(rep.WarnedThrough, func(i, j int) bool {
		if rep.WarnedThrough[i].Name != rep.WarnedThrough[j].Name {
			return rep.WarnedThrough[i].Name < rep.WarnedThrough[j].Name
		}
		return rep.WarnedThrough[i].Version < rep.WarnedThrough[j].Version
	})
	// Conflicts arrive already sorted from EvaluateConstraints.

	return rep
}

// transitivePolicyOrDefault normalizes the zero value ("") to the secure block
// default so the report never shows an empty transitive policy.
func transitivePolicyOrDefault(tp supplychain.TransitivePolicy) supplychain.TransitivePolicy {
	if tp == supplychain.TransitivePolicyWarn {
		return supplychain.TransitivePolicyWarn
	}
	return supplychain.TransitivePolicyBlock
}

// hours converts a duration to fractional hours rounded to two decimals — a
// stable, tooling-friendly unit for the report (avoids leaking Go's duration
// string format into a machine document).
func hours(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(int64(d.Hours()*100+0.5)) / 100
}

// writeComplianceReport marshals the report and writes it to the path named by
// ARMIS_SUPPLY_CHAIN_REPORT. The value "-" writes the raw JSON to stderr with no
// prefix, so it stays machine-readable when redirected (the human summary the
// scPrefix marks is kept on a separate stream). A write error is reported but
// never fails the build — the install already finished; a missing audit file is
// a degraded state the user can act on, not a reason to break the run.
func writeComplianceReport(path string, rep complianceReport) {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s supply-chain: could not encode compliance report: %v\n", scPrefix, err)
		return
	}

	if path == "-" {
		fmt.Fprintf(os.Stderr, "%s\n", data)
		return
	}

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is the user-supplied ARMIS_SUPPLY_CHAIN_REPORT value naming a file on their own machine where the audit document is written (same trust model as scan's --output); no trust boundary is crossed
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // user-named report path in their own environment
		fmt.Fprintf(os.Stderr, "%s supply-chain: could not write compliance report to %s: %v\n", scPrefix, path, err)
	}
}
