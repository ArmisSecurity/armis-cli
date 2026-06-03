package check

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain/registry"
)

// Lockfile "source.type" values that mark a package as NOT resolving from a
// package index (PyPI). The pdm, poetry, and uv parsers each match the subset
// their lockfile format actually emits via shouldSkip*Source; centralizing the
// literals here keeps those sets from silently drifting apart.
const (
	sourceTypeGit       = "git"
	sourceTypeVCS       = "vcs"
	sourceTypeDirectory = "directory"
	sourceTypePath      = "path"
	sourceTypeFile      = "file"
	sourceTypeURL       = "url"
)

// ParsePipRequirements parses a pip requirements.txt into package entries.
// Only pinned (==) requirements are considered; VCS, local, and unpinned
// entries are skipped.
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParsePipRequirements(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var entries []PackageEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// A single requirements.txt line can carry many "--hash=sha256:..." entries
	// or long URLs and exceed bufio.Scanner's default 64KB token limit, which
	// would otherwise surface as scanner.Err() = "token too long" and turn a
	// valid lockfile into a hard failure. Allow one line to grow up to the same
	// maxLockfileSize cap readLockfile already enforces, so parsing stays robust
	// without reintroducing an unbounded allocation.
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLockfileSize)

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

// normalizePipName canonicalizes a package name read from a Python lockfile.
// It delegates to registry.NormalizePyPIName so lockfile parsing and the PyPI
// query path share one PEP 503 normalization rule and can never drift apart.
func normalizePipName(name string) string {
	return registry.NormalizePyPIName(name)
}
