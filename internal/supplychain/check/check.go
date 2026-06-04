// Package check implements lockfile auditing for package age policy violations.
package check

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/registry"
)

type Result struct {
	Violations []supplychain.Violation
	Warnings   []string
	Checked    int
	Skipped    int
}

func RunCheck(ctx context.Context, policy supplychain.Policy, lockfilePath string, baseLockfilePath string) (*Result, error) {
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

	if len(toCheck) == 0 {
		return &Result{Skipped: skipped}, nil
	}

	results := queryRegistry(ctx, ecosystem, toCheck)

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
		Violations: violations,
		Warnings:   warnings,
		Checked:    len(toCheck),
		Skipped:    skipped,
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
