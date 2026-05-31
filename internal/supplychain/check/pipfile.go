package check

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}

// ParsePipfileLock parses a Pipfile.lock (JSON format from pipenv).
func ParsePipfileLock(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from lockfile detection
	if err != nil {
		return nil, fmt.Errorf("reading Pipfile.lock: %w", err)
	}

	var lockfile pipfileLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing Pipfile.lock: %w", err)
	}

	seen := make(map[string]bool)
	var entries []PackageEntry

	for name, pkg := range lockfile.Default {
		entry := pipfileEntryToPackage(name, pkg)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	for name, pkg := range lockfile.Develop {
		entry := pipfileEntryToPackage(name, pkg)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	return entries, nil
}

func pipfileEntryToPackage(name string, pkg pipfilePackage) *PackageEntry {
	version := pkg.Version
	if version == "" {
		return nil
	}

	// Strip == prefix
	version = strings.TrimPrefix(version, "==")
	if version == "" {
		return nil
	}

	// Skip non-pinned versions
	if strings.ContainsAny(version, "><!~*") {
		return nil
	}

	normalized := normalizePipName(name)
	return &PackageEntry{
		Name:    normalized,
		Version: version,
	}
}

