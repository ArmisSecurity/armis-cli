package check

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type pnpmLockfile struct {
	LockfileVersion string                     `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackageInfo `yaml:"packages"`
}

type pnpmPackageInfo struct {
	Resolution pnpmResolution `yaml:"resolution"`
	Version    string         `yaml:"version"`
}

type pnpmResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
	Type      string `yaml:"type"`
}

func ParsePNPMLockfile(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // lockfile detection path
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	var lockfile pnpmLockfile
	if err := yaml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing pnpm lockfile: %w", err)
	}

	if lockfile.Packages == nil {
		return nil, nil
	}

	var entries []PackageEntry
	for key, info := range lockfile.Packages {
		if shouldSkipPnpmPackage(key, info) {
			continue
		}

		name, version := parsePnpmPackageKey(key, info)
		if name == "" || version == "" {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    name,
			Version: version,
		})
	}

	return entries, nil
}

func parsePnpmPackageKey(key string, info pnpmPackageInfo) (string, string) {
	// pnpm v9+ format: /@scope/name@version or /name@version
	// pnpm v6 format: /name/version or /@scope/name/version
	key = strings.TrimPrefix(key, "/")

	if key == "" {
		return "", ""
	}

	// Strip peer dep suffixes before parsing: debug@2.6.9(@types/node@20.10.0) or lodash@4.17.21_peer@1.0.0
	cleanKey := stripPeerFromKey(key)

	if strings.HasPrefix(cleanKey, "@") {
		// Scoped: @scope/name@version
		parts := strings.SplitN(cleanKey, "/", 2)
		if len(parts) < 2 {
			return "", ""
		}
		scope := parts[0]
		rest := parts[1]

		// v9+: name@version
		if idx := strings.Index(rest, "@"); idx > 0 {
			return scope + "/" + rest[:idx], rest[idx+1:]
		}

		// v6: name/version
		subparts := strings.SplitN(rest, "/", 2)
		if len(subparts) == 2 {
			return scope + "/" + subparts[0], subparts[1]
		}
		return "", ""
	}

	// Unscoped: name@version (v9+) or name/version (v6)
	if idx := strings.Index(cleanKey, "@"); idx > 0 {
		return cleanKey[:idx], cleanKey[idx+1:]
	}

	parts := strings.SplitN(cleanKey, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	if info.Version != "" {
		return cleanKey, info.Version
	}

	return "", ""
}

func stripPeerFromKey(key string) string {
	// Remove parenthesized peer info: debug@2.6.9(@types/node@20.10.0) -> debug@2.6.9
	if idx := strings.Index(key, "("); idx > 0 {
		key = key[:idx]
	}
	// Remove underscore peer info that appears AFTER the version segment.
	// pnpm format: name@version_peerinfo (e.g., lodash@4.17.21_tslib@2.0.0)
	// Must not strip underscores from package names (e.g., is_glob@4.0.3).
	// Find the first @digit that starts the version (after scope for scoped pkgs).
	searchFrom := 0
	if strings.HasPrefix(key, "@") {
		if slashIdx := strings.Index(key, "/"); slashIdx > 0 {
			searchFrom = slashIdx
		}
	}
	versionStart := -1
	for i := searchFrom; i < len(key)-1; i++ {
		if key[i] == '@' && key[i+1] >= '0' && key[i+1] <= '9' {
			versionStart = i
			break
		}
	}
	if versionStart > 0 {
		versionPart := key[versionStart:]
		if idx := strings.Index(versionPart, "_"); idx > 0 {
			key = key[:versionStart+idx]
		}
	}
	return key
}

func stripPeerSuffix(version string) string {
	// pnpm appends peer dep info: 1.0.0_peer@version
	if idx := strings.Index(version, "_"); idx > 0 {
		return version[:idx]
	}
	// pnpm v9 uses parentheses: 1.0.0(@types/node@20.0.0)
	if idx := strings.Index(version, "("); idx > 0 {
		return version[:idx]
	}
	return version
}

func shouldSkipPnpmPackage(key string, info pnpmPackageInfo) bool {
	if strings.HasPrefix(key, "file:") || strings.HasPrefix(key, "link:") {
		return true
	}
	if info.Resolution.Type == "directory" || info.Resolution.Type == "git" {
		return true
	}
	tarball := info.Resolution.Tarball
	if strings.HasPrefix(tarball, "file:") || strings.Contains(tarball, ".git") {
		return true
	}
	return false
}
