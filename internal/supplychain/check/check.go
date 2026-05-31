// Package check implements lockfile auditing for package age policy violations.
package check

import (
	"context"
	"fmt"
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

	entries, err := parseLockfile(ecosystem, lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("parsing lockfile: %w", err)
	}

	if baseLockfilePath != "" {
		baseEntries, err := parseLockfile(ecosystem, baseLockfilePath)
		if err != nil {
			return nil, fmt.Errorf("parsing base lockfile: %w", err)
		}
		entries = diffEntries(entries, baseEntries)
	}

	var toCheck []struct{ Name, Version string }
	var skipped int
	for _, e := range entries {
		if policy.IsExcluded(e.Name) {
			skipped++
			continue
		}
		toCheck = append(toCheck, struct{ Name, Version string }{e.Name, e.Version})
	}

	if len(toCheck) == 0 {
		return &Result{Skipped: skipped}, nil
	}

	results := queryRegistry(ctx, ecosystem, toCheck)

	now := time.Now()
	var violations []supplychain.Violation
	var warnings []string
	rateLimitCount := 0

	for _, r := range results {
		if r.Err != nil {
			if strings.Contains(r.Err.Error(), "rate limited") || strings.Contains(r.Err.Error(), "429") {
				rateLimitCount++
				continue
			}
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

	if rateLimitCount > 0 {
		warnings = append(warnings, fmt.Sprintf("registry rate-limited %d request(s) — re-run with --fail-open or try again later", rateLimitCount))
	}

	return &Result{
		Violations: violations,
		Warnings:   warnings,
		Checked:    len(toCheck),
		Skipped:    skipped,
	}, nil
}

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
	case supplychain.EcosystemPipfile:
		return ParsePipfileLock(path)
	case supplychain.EcosystemPoetry:
		return ParsePoetryLockfile(path)
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

func queryRegistry(ctx context.Context, ecosystem supplychain.Ecosystem, packages []struct{ Name, Version string }) []registry.QueryResult {
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
	case strings.HasSuffix(lower, "pom.xml"):
		return supplychain.EcosystemMaven
	case strings.HasSuffix(lower, "gradle.lockfile"):
		return supplychain.EcosystemGradle
	case strings.HasSuffix(lower, "poetry.lock"):
		return supplychain.EcosystemPoetry
	case strings.HasSuffix(lower, "pipfile.lock"):
		return supplychain.EcosystemPipfile
	case strings.HasSuffix(lower, "pdm.lock"):
		return supplychain.EcosystemPDM
	case strings.HasSuffix(lower, "uv.lock"):
		return supplychain.EcosystemUV
	case strings.Contains(lower, "requirements"):
		return supplychain.EcosystemPip
	default:
		return supplychain.EcosystemNPM
	}
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
