package check

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseGradleLockfile parses a Gradle lockfile (gradle.lockfile).
// Format: one dependency per line as "group:artifact:version=hash" after a header.
func ParseGradleLockfile(path string) ([]PackageEntry, error) {
	f, err := os.Open(path) //nolint:gosec // path from lockfile detection
	if err != nil {
		return nil, fmt.Errorf("reading gradle lockfile: %w", err)
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	var entries []PackageEntry
	headerPassed := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// The header line "empty=" signals end of preamble in some formats
		if !headerPassed {
			if strings.Contains(line, "=") && !strings.Contains(line, ":") {
				// Metadata line like "empty="
				continue
			}
			headerPassed = true
		}

		// Expected: group:artifact:version=hash
		eqIdx := strings.Index(line, "=")
		gav := line
		if eqIdx > 0 {
			gav = line[:eqIdx]
		}

		parts := strings.Split(gav, ":")
		if len(parts) < 3 {
			continue
		}

		group := parts[0]
		artifact := parts[1]
		version := parts[2]

		if group == "" || artifact == "" || version == "" {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    group + ":" + artifact,
			Version: version,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning gradle lockfile: %w", err)
	}

	return entries, nil
}
