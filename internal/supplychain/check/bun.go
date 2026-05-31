package check

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type bunLockfile struct {
	Packages map[string][]interface{} `json:"packages"`
}

var trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

func ParseBunLockfile(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // lockfile detection path
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	// bun.lock uses trailing commas (JSONC); strip them for standard JSON parsing
	cleaned := trailingCommaRe.ReplaceAll(data, []byte("$1"))

	var lockfile bunLockfile
	if err := json.Unmarshal(cleaned, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing bun lockfile: %w", err)
	}

	if lockfile.Packages == nil {
		return nil, nil
	}

	var entries []PackageEntry
	for key, tuple := range lockfile.Packages {
		if key == "" {
			continue
		}

		name, version := parseBunPackageKey(key, tuple)
		if name == "" || version == "" {
			continue
		}

		if shouldSkipBunPackage(tuple) {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    name,
			Version: version,
		})
	}

	return entries, nil
}

func parseBunPackageKey(key string, tuple []interface{}) (string, string) {
	// bun.lock tuple format: ["name@version", "registry-url-or-empty", {deps}, "integrity"]
	// First element contains "name@version"
	if len(tuple) > 0 {
		if resolved, ok := tuple[0].(string); ok && resolved != "" {
			if idx := strings.LastIndex(resolved, "@"); idx > 0 {
				return resolved[:idx], resolved[idx+1:]
			}
		}
	}

	return "", ""
}

func shouldSkipBunPackage(tuple []interface{}) bool {
	if len(tuple) < 2 {
		return false
	}
	if resolved, ok := tuple[1].(string); ok {
		if strings.HasPrefix(resolved, "git+") ||
			strings.HasPrefix(resolved, "file:") ||
			strings.HasPrefix(resolved, "link:") ||
			strings.HasPrefix(resolved, "workspace:") {
			return true
		}
	}
	return false
}
