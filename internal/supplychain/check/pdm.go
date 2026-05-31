package check

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type pdmLockfile struct {
	Package []pdmPackage `toml:"package"`
}

type pdmPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// ParsePDMLockfile parses a pdm.lock file (TOML format).
func ParsePDMLockfile(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from lockfile detection
	if err != nil {
		return nil, fmt.Errorf("reading pdm.lock: %w", err)
	}

	var lockfile pdmLockfile
	if err := toml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing pdm.lock: %w", err)
	}

	var entries []PackageEntry
	for _, pkg := range lockfile.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(pkg.Name),
			Version: pkg.Version,
		})
	}

	return entries, nil
}
