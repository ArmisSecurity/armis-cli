package check

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ParsePipRequirements(path string) ([]PackageEntry, error) {
	f, err := os.Open(path) //nolint:gosec // lockfile detection path
	if err != nil {
		return nil, fmt.Errorf("reading requirements file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var entries []PackageEntry
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "-") {
			continue
		}

		if shouldSkipPipLine(line) {
			continue
		}

		name, version := parsePipRequirement(line)
		if name == "" || version == "" {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(name),
			Version: version,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning requirements file: %w", err)
	}

	return entries, nil
}

func parsePipRequirement(line string) (string, string) {
	// Remove extras: package[extra1,extra2]==version
	if idx := strings.Index(line, "["); idx > 0 {
		end := strings.Index(line, "]")
		if end > idx {
			line = line[:idx] + line[end+1:]
		}
	}

	// Remove environment markers: package==version ; python_version >= "3.8"
	if idx := strings.Index(line, ";"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}

	// Remove hashes: --hash=sha256:...
	if idx := strings.Index(line, " \\"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}

	// Only support pinned versions (==)
	if parts := strings.SplitN(line, "==", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	return "", ""
}

func shouldSkipPipLine(line string) bool {
	// Skip VCS and local installs
	if strings.HasPrefix(line, "git+") ||
		strings.HasPrefix(line, "svn+") ||
		strings.HasPrefix(line, "hg+") ||
		strings.HasPrefix(line, "bzr+") {
		return true
	}
	if strings.HasPrefix(line, "/") || strings.HasPrefix(line, ".") {
		return true
	}
	if strings.Contains(line, "@ file://") || strings.Contains(line, "@ git+") {
		return true
	}
	return false
}

func normalizePipName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
