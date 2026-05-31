package check

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type uvLockfile struct {
	Package []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string   `toml:"name"`
	Version string   `toml:"version"`
	Source  uvSource `toml:"source"`
}

type uvSource struct {
	Type string `toml:"type"`
	URL  string `toml:"url"`
}

// ParseUVLockfile parses a uv.lock file (TOML format).
func ParseUVLockfile(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from lockfile detection
	if err != nil {
		return nil, fmt.Errorf("reading uv.lock: %w", err)
	}

	var lockfile uvLockfile
	if err := toml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing uv.lock: %w", err)
	}

	var entries []PackageEntry
	for _, pkg := range lockfile.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		if shouldSkipUVSource(pkg.Source) {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(pkg.Name),
			Version: pkg.Version,
		})
	}

	return entries, nil
}

func shouldSkipUVSource(source uvSource) bool {
	t := strings.ToLower(source.Type)
	return t == "git" || t == "path" || t == "directory"
}
