package check

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type bunLockfile struct {
	Packages map[string][]interface{} `json:"packages"`
}

var trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

// ParseBunLockfile parses a bun.lock (JSONC) into package entries.
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParseBunLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	// bun.lock uses trailing commas (JSONC); strip them for standard JSON parsing
	cleaned := trailingCommaRe.ReplaceAll(data, []byte("$1"))

	var lockfile bunLockfile
	// armis:ignore cwe:770 cwe:502 reason:cleaned is size-bounded by readLockfile and unmarshalled into a typed struct from the user's own lockfile; no untrusted-data deserialization risk
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
			Name:     name,
			Version:  version,
			Resolved: bunResolvedURL(tuple),
		})
	}

	return entries, nil
}

// bunResolvedURL returns the registry URL recorded for a bun.lock entry (the
// tuple's second element), or "" when absent. bun records a full tarball URL
// here for registry packages, which is what the non-approved-registry check
// compares against the approved host.
func bunResolvedURL(tuple []interface{}) string {
	if len(tuple) < 2 {
		return ""
	}
	if resolved, ok := tuple[1].(string); ok {
		return resolved
	}
	return ""
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
			strings.HasPrefix(resolved, protocolFile) ||
			strings.HasPrefix(resolved, protocolLink) ||
			strings.HasPrefix(resolved, "workspace:") {
			return true
		}
	}
	return false
}
