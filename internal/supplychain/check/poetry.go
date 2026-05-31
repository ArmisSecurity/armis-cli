package check

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type poetryLockfile struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name    string       `toml:"name"`
	Version string       `toml:"version"`
	Source  poetrySource `toml:"source"`
}

type poetrySource struct {
	Type string `toml:"type"`
	URL  string `toml:"url"`
}

// ParsePoetryLockfile parses a poetry.lock file (TOML format).
func ParsePoetryLockfile(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from lockfile detection
	if err != nil {
		return nil, fmt.Errorf("reading poetry.lock: %w", err)
	}

	var lockfile poetryLockfile
	if err := toml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing poetry.lock: %w", err)
	}

	var entries []PackageEntry
	for _, pkg := range lockfile.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		if shouldSkipPoetrySource(pkg.Source) {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(pkg.Name),
			Version: pkg.Version,
		})
	}

	return entries, nil
}

func shouldSkipPoetrySource(source poetrySource) bool {
	switch strings.ToLower(source.Type) {
	case "git", "directory", "file", "url":
		return true
	}
	return false
}
