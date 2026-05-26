// Package check implements lockfile auditing for package age policy violations.
package check

import (
	"context"
	"fmt"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/protect"
	"github.com/ArmisSecurity/armis-cli/internal/protect/registry"
)

type Result struct {
	Violations []protect.Violation
	Warnings   []string
	Checked    int
	Skipped    int
}

func RunCheck(ctx context.Context, policy protect.Policy, lockfilePath string, baseLockfilePath string) (*Result, error) {
	entries, err := ParseNPMLockfile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("parsing lockfile: %w", err)
	}

	if baseLockfilePath != "" {
		baseEntries, err := ParseNPMLockfile(baseLockfilePath)
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

	client := registry.NewClient()
	results := client.GetPublishDates(ctx, toCheck)

	now := time.Now()
	var violations []protect.Violation
	var warnings []string

	for _, r := range results {
		if r.Err != nil {
			warnings = append(warnings, fmt.Sprintf("could not check %s@%s: %v", r.Name, r.Version, r.Err))
			continue
		}

		age := now.Sub(r.PublishTime)
		if age < policy.MinReleaseAge {
			violations = append(violations, protect.Violation{
				Name:            r.Name,
				Version:         r.Version,
				PublishTime:     r.PublishTime,
				Age:             age,
				PolicyThreshold: policy.MinReleaseAge,
				Severity:        protect.ClassifySeverity(age, policy.MinReleaseAge),
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
