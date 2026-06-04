package check

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// ParseGradleLockfile parses a Gradle lockfile (gradle.lockfile).
// Format: one dependency per line as "group:artifact:version=hash" after a header.
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParseGradleLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Gradle lockfile lines carry a long resolution hash after "=", so raise the
	// scanner's per-line cap. data is already size-bounded by readLockfile.
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLockfileSize)

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
