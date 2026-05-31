package check

import (
	"encoding/json"
	"fmt"
	"os"
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

func ParseNPMLockfile(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is from lockfile detection, not user URL input
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	var lockfile packageLockFile
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
