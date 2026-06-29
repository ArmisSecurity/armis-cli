// Package check implements lockfile auditing for package age policy violations.
package check

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/registry"
)

// protocolFile and protocolLink are URL schemes used in lockfiles to denote
// local path and symlink dependencies. Shared across npm, pnpm, yarn, and bun parsers.
const (
	protocolFile = "file:"
	protocolLink = "link:"
)

type Result struct {
	Violations []supplychain.Violation
	Warnings   []string
	Checked    int
	Skipped    int

	// RegistryViolations lists npm-family packages whose lockfile-recorded
	// resolved URL host does not match the approved registry (PPSC-994). It is
	// populated only when an approved RegistryURL is threaded in and the
	// ecosystem records a per-package source URL; it is always empty for
	// ecosystems that do not (poetry/pdm/uv/pip, maven/gradle).
	RegistryViolations []RegistryViolation
	// RegistryChecked is the number of packages whose resolved URL could be
	// compared against the approved registry (those with a parseable host). It
	// scopes the coverage count ("12 npm packages checked") honestly.
	RegistryChecked int
}

// RegistryViolation records a package resolved from a registry host other than
// the approved one. The host fields are bare hosts (with port) for a compact,
// actionable message.
type RegistryViolation struct {
	Name         string
	Version      string
	ResolvedHost string
	ApprovedHost string
}

// registryFn resolves publish dates for a set of packages in an ecosystem. It
// is the seam queryRegistry satisfies in production; tests inject a closure that
// returns controlled timestamps (or errors) so the RunCheck pipeline can be
// exercised without real network calls.
type registryFn func(ctx context.Context, ecosystem supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult

func RunCheck(ctx context.Context, policy supplychain.Policy, lockfilePath string, baseLockfilePath string) (*Result, error) {
	return runCheck(ctx, policy, lockfilePath, baseLockfilePath, queryRegistry, "")
}

// RunCheckWithRegistry is RunCheck plus an approved registry URL (PPSC-994).
// When registryURL is non-empty: age checks query THAT registry (not the public
// one) via queryRegistryWithURL, and npm-family packages whose lockfile resolved
// URL points at a different host are flagged as RegistryViolations. An empty
// registryURL is exactly RunCheck. The caller is responsible for having
// validated registryURL via supplychain.ValidateRegistryURL.
func RunCheckWithRegistry(ctx context.Context, policy supplychain.Policy, lockfilePath, baseLockfilePath, registryURL string) (*Result, error) {
	fn := queryRegistry
	if registryURL != "" {
		fn = queryRegistryWithURL(registryURL)
	}
	return runCheck(ctx, policy, lockfilePath, baseLockfilePath, fn, registryURL)
}

// runCheck is the testable core. registryURL is variadic so the many existing
// age-only tests (which pass no URL) keep compiling; only the new
// registry-divergence tests pass it. At most one value is meaningful.
func runCheck(ctx context.Context, policy supplychain.Policy, lockfilePath string, baseLockfilePath string, queryRegistryFn registryFn, registryURLArg ...string) (*Result, error) {
	var registryURL string
	if len(registryURLArg) > 0 {
		registryURL = registryURLArg[0]
	}
	ecosystem := detectEcosystemFromPath(lockfilePath)

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI auditing the user's own project; lockfilePath comes from lockfile auto-detection or an explicit --lockfile flag the user controls, not untrusted network input (readLockfile also size-bounds the read)
	entries, err := parseLockfile(ecosystem, lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("parsing lockfile: %w", err)
	}

	if baseLockfilePath != "" {
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:base lockfile path is produced internally by detectBaseLockfile (a temp file from git show) or an explicit --base-lockfile flag the user controls, not untrusted network input
		baseEntries, err := parseLockfile(ecosystem, baseLockfilePath)
		if err != nil {
			return nil, fmt.Errorf("parsing base lockfile: %w", err)
		}
		entries = diffEntries(entries, baseEntries)
	}

	var toCheck []registry.PackageRequest
	var skipped int
	for _, e := range entries {
		if policy.IsExcluded(e.Name) {
			skipped++
			continue
		}
		toCheck = append(toCheck, registry.PackageRequest{Name: e.Name, Version: e.Version})
	}

	// Registry-divergence flagging is independent of the age query: it reads the
	// lockfile's resolved URLs, so it runs even when there are no age violations
	// (and even when toCheck is empty after exclusions).
	regViolations, regChecked := detectRegistryDivergence(ecosystem, entries, registryURL)

	if len(toCheck) == 0 {
		return &Result{
			Skipped:            skipped,
			RegistryViolations: regViolations,
			RegistryChecked:    regChecked,
		}, nil
	}

	results := queryRegistryFn(ctx, ecosystem, toCheck)

	now := time.Now()
	var violations []supplychain.Violation
	var warnings []string

	for _, r := range results {
		if r.Err != nil {
			// armis:ignore cwe:209 reason:local CLI surfacing a registry-query error to the user running it is intended diagnostics; there is no remote attacker to leak internals to
			warnings = append(warnings, fmt.Sprintf("could not check %s@%s: %v", r.Name, r.Version, r.Err))
			continue
		}

		age := now.Sub(r.PublishTime)
		if age < policy.MinReleaseAge {
			violations = append(violations, supplychain.Violation{
				Name:            r.Name,
				Version:         r.Version,
				PublishTime:     r.PublishTime,
				Age:             age,
				PolicyThreshold: policy.MinReleaseAge,
				Severity:        supplychain.ClassifySeverity(age, policy.MinReleaseAge),
			})
		}
	}

	return &Result{
		Violations:         violations,
		Warnings:           warnings,
		Checked:            len(toCheck),
		Skipped:            skipped,
		RegistryViolations: regViolations,
		RegistryChecked:    regChecked,
	}, nil
}

// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI auditing the user's own project; path comes from lockfile auto-detection or an explicit --lockfile flag the user controls, not untrusted input crossing a trust boundary; readLockfile also size-bounds the read
func parseLockfile(ecosystem supplychain.Ecosystem, path string) ([]PackageEntry, error) {
	switch ecosystem {
	case supplychain.EcosystemPNPM:
		return ParsePNPMLockfile(path)
	case supplychain.EcosystemBun:
		return ParseBunLockfile(path)
	case supplychain.EcosystemYarn:
		return ParseYarnLockfile(path)
	case supplychain.EcosystemPip:
		return ParsePipRequirements(path)
	case supplychain.EcosystemPoetry:
		return ParsePoetryLockfile(path)
	case supplychain.EcosystemPipfile:
		return ParsePipfileLock(path)
	case supplychain.EcosystemPDM:
		return ParsePDMLockfile(path)
	case supplychain.EcosystemUV:
		return ParseUVLockfile(path)
	case supplychain.EcosystemMaven:
		return ParseMavenDeps(path)
	case supplychain.EcosystemGradle:
		return ParseGradleLockfile(path)
	default:
		return ParseNPMLockfile(path)
	}
}

func queryRegistry(ctx context.Context, ecosystem supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
	switch ecosystem {
	case supplychain.EcosystemPip, supplychain.EcosystemPoetry, supplychain.EcosystemPipfile, supplychain.EcosystemPDM, supplychain.EcosystemUV:
		client := registry.NewPyPIClient()
		return client.GetPublishDates(ctx, packages)
	case supplychain.EcosystemMaven, supplychain.EcosystemGradle:
		client := registry.NewMavenClient()
		return client.GetPublishDates(ctx, packages)
	default:
		client := registry.NewClient()
		return client.GetPublishDates(ctx, packages)
	}
}

// queryRegistryWithURL returns a registryFn that resolves publish dates from a
// configured approved registry instead of the public one (E6). For npm-family
// ecosystems it points the npm metadata client at registryURL; for PyPI-family
// it points the PyPI client there. registryURL must already be validated by the
// caller (supplychain.ValidateRegistryURL). Maven/Gradle stay on the public
// client — they are audit-path only and not routable in v1.
func queryRegistryWithURL(registryURL string) registryFn {
	return func(ctx context.Context, ecosystem supplychain.Ecosystem, packages []registry.PackageRequest) []registry.QueryResult {
		switch ecosystem {
		case supplychain.EcosystemPip, supplychain.EcosystemUV:
			client := registry.NewPyPIClientWithHTTP(nil, registryURL)
			return client.GetPublishDates(ctx, packages)
		case supplychain.EcosystemMaven, supplychain.EcosystemGradle,
			supplychain.EcosystemPoetry, supplychain.EcosystemPipfile, supplychain.EcosystemPDM:
			// Not routable in v1: fall back to the default public clients.
			return queryRegistry(ctx, ecosystem, packages)
		default:
			client := registry.NewClientWithHTTP(nil, registryURL)
			return client.GetPublishDates(ctx, packages)
		}
	}
}

// isNPMFamily reports whether an ecosystem records a per-package resolved
// registry URL in its lockfile and is therefore eligible for the
// non-approved-registry check. v1 covers exactly the npm-family formats; every
// other ecosystem (PyPI-family, Maven/Gradle) records no per-package source URL
// and is explicitly NOT covered.
func isNPMFamily(eco supplychain.Ecosystem) bool {
	switch eco {
	case supplychain.EcosystemNPM, supplychain.EcosystemPNPM, supplychain.EcosystemBun, supplychain.EcosystemYarn:
		return true
	default:
		return false
	}
}

// detectRegistryDivergence flags npm-family packages whose lockfile-recorded
// resolved URL host differs from the approved registry host. It returns the
// violations and the count of packages it could actually compare (those with a
// parseable resolved host) — the honest coverage denominator. It is a no-op
// (nil, 0) when registryURL is empty, the ecosystem is not npm-family, or the
// approved URL has no parseable host.
func detectRegistryDivergence(eco supplychain.Ecosystem, entries []PackageEntry, registryURL string) ([]RegistryViolation, int) {
	if registryURL == "" || !isNPMFamily(eco) {
		return nil, 0
	}
	approvedURL, err := url.Parse(registryURL)
	if err != nil || approvedURL.Host == "" {
		return nil, 0
	}
	approvedHost := strings.ToLower(approvedURL.Host)

	var violations []RegistryViolation
	checked := 0
	for _, e := range entries {
		if e.Resolved == "" {
			continue // no recorded source URL → cannot compare (not counted)
		}
		ru, err := url.Parse(e.Resolved)
		if err != nil || ru.Host == "" {
			continue
		}
		checked++
		host := strings.ToLower(ru.Host)
		if host != approvedHost {
			violations = append(violations, RegistryViolation{
				Name:         e.Name,
				Version:      e.Version,
				ResolvedHost: host,
				ApprovedHost: approvedHost,
			})
		}
	}
	return violations, checked
}

// DetectEcosystemFromPath classifies a lockfile path to its ecosystem using the
// same suffix rules RunCheck applies internally. Exported so callers outside the
// package (e.g. the check command's ecosystem-scoping gate) classify a lockfile
// exactly as the audit will, including the requirements*.txt special cases.
func DetectEcosystemFromPath(path string) supplychain.Ecosystem {
	return detectEcosystemFromPath(path)
}

func detectEcosystemFromPath(path string) supplychain.Ecosystem {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, "pnpm-lock.yaml"):
		return supplychain.EcosystemPNPM
	case strings.HasSuffix(lower, "bun.lock"):
		return supplychain.EcosystemBun
	case strings.HasSuffix(lower, "yarn.lock") || strings.HasSuffix(lower, "yarn-berry.lock"):
		return supplychain.EcosystemYarn
	case strings.HasSuffix(lower, "poetry.lock"):
		return supplychain.EcosystemPoetry
	case strings.HasSuffix(lower, "pipfile.lock"):
		return supplychain.EcosystemPipfile
	case strings.HasSuffix(lower, "pdm.lock"):
		return supplychain.EcosystemPDM
	case strings.HasSuffix(lower, "uv.lock"):
		return supplychain.EcosystemUV
	case strings.HasSuffix(lower, "pom.xml"):
		return supplychain.EcosystemMaven
	case strings.HasSuffix(lower, "gradle.lockfile"):
		return supplychain.EcosystemGradle
	case isRequirementsFile(lower):
		return supplychain.EcosystemPip
	default:
		return supplychain.EcosystemNPM
	}
}

// isRequirementsFile reports whether a lowercased path is a pip requirements
// file. It matches the conventional layouts — a "requirements*.txt" basename
// (requirements.txt, requirements-dev.txt) or any *.txt under a "requirements/"
// directory split — rather than a loose "requirements" substring, so unrelated
// files like "myrequirements.txt" are not misclassified as a pinned lockfile
// (which would parse empty and yield a false "all clear"). The .txt guard also
// keeps pip-tools input files (requirements.in, which hold unpinned specifiers
// ParsePipRequirements would silently drop) out.
func isRequirementsFile(lowerPath string) bool {
	if !strings.HasSuffix(lowerPath, ".txt") {
		return false
	}
	slashed := filepath.ToSlash(lowerPath)
	base := filepath.Base(slashed)
	if strings.HasPrefix(base, "requirements") {
		return true
	}
	return strings.Contains(slashed, "requirements/")
}

func diffEntries(current, base []PackageEntry) []PackageEntry {
	baseSet := make(map[string]bool, len(base))
	for _, e := range base {
		baseSet[e.Name+"@"+e.Version] = true
	}

	var newEntries []PackageEntry
	for _, e := range current {
		if !baseSet[e.Name+"@"+e.Version] {
			newEntries = append(newEntries, e)
		}
	}
	return newEntries
}
