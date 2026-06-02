package check

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PackageEntry struct {
	Name    string
	Version string
}

type packageLockFile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]packageLockInfo `json:"packages"`
}

type packageLockInfo struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
}

// ParseNPMLockfile parses an npm package-lock.json into package entries.
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParseNPMLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var lockfile packageLockFile
	// armis:ignore cwe:770 cwe:502 reason:data is size-bounded by readLockfile and unmarshalled into a typed struct from the user's own lockfile; no untrusted-data deserialization risk
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing lockfile: %w", err)
	}

	if lockfile.Packages == nil {
		return nil, fmt.Errorf("lockfile has no packages field (lockfileVersion %d not supported)", lockfile.LockfileVersion)
	}

	var entries []PackageEntry
	for key, info := range lockfile.Packages {
		if key == "" {
			continue
		}

		if info.Link {
			continue
		}

		if shouldSkipResolved(info.Resolved) {
			continue
		}

		name := extractPackageName(key)
		if name == "" {
			continue
		}

		if info.Version == "" {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    name,
			Version: info.Version,
		})
	}

	return entries, nil
}

func extractPackageName(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx == -1 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}

func shouldSkipResolved(resolved string) bool {
	if resolved == "" {
		return false
	}
	for _, prefix := range []string{"git+", "git://", "git@", "file:", "link:"} {
		if strings.HasPrefix(resolved, prefix) {
			return true
		}
	}
	return false
}
