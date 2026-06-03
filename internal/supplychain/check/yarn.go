package check

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseYarnLockfile parses both yarn v1 (classic) and v2+ (berry) lockfiles.
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParseYarnLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	if isBerryLockfile(data) {
		return parseYarnBerry(data)
	}
	return parseYarnClassic(data)
}

func isBerryLockfile(data []byte) bool {
	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.Contains(string(head), "__metadata:")
}

// parseYarnBerry handles yarn v2+ (berry) lockfiles which are YAML.
func parseYarnBerry(data []byte) ([]PackageEntry, error) {
	var raw map[string]interface{}
	// armis:ignore cwe:502 cwe:770 reason:yaml.v3 Unmarshal into a generic map does not execute code or construct arbitrary types; input is the user's own lockfile (size-bounded by readLockfile), not untrusted data crossing a trust boundary
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing yarn berry lockfile: %w", err)
	}

	var entries []PackageEntry
	for key, val := range raw {
		if key == "__metadata" {
			continue
		}

		info, ok := val.(map[string]interface{})
		if !ok {
			continue
		}

		version, _ := info["version"].(string)
		if version == "" {
			continue
		}

		resolution, _ := info["resolution"].(string)
		if shouldSkipYarnResolution(resolution) {
			continue
		}

		name := extractBerryPackageName(key)
		if name == "" {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    name,
			Version: version,
		})
	}

	return entries, nil
}

func extractBerryPackageName(key string) string {
	// Berry keys look like: "name@npm:^1.0.0" or "@scope/name@npm:^1.0.0"
	// Multiple descriptors separated by ", "
	parts := strings.SplitN(key, ",", 2)
	descriptor := strings.TrimSpace(parts[0])

	// Remove quotes
	descriptor = strings.Trim(descriptor, "\"")

	// Find the protocol separator (@npm:, @patch:, etc.)
	atNpm := strings.Index(descriptor, "@npm:")
	if atNpm > 0 {
		return descriptor[:atNpm]
	}

	// For scoped packages: @scope/name@npm:
	if strings.HasPrefix(descriptor, "@") {
		// Find the second @ which is the version/protocol separator
		rest := descriptor[1:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx == -1 {
			return ""
		}
		afterSlash := rest[slashIdx+1:]
		atIdx := strings.Index(afterSlash, "@")
		if atIdx == -1 {
			return ""
		}
		return descriptor[:1+slashIdx+1+atIdx]
	}

	// Unscoped: name@protocol:
	atIdx := strings.Index(descriptor, "@")
	if atIdx > 0 {
		return descriptor[:atIdx]
	}

	return ""
}

func shouldSkipYarnResolution(resolution string) bool {
	for _, proto := range []string{"workspace:", "link:", "file:", "portal:", "patch:", "exec:"} {
		if strings.Contains(resolution, proto) {
			return true
		}
	}
	return false
}

// parseYarnClassic handles yarn v1 lockfiles.
// Format:
//
//	"pkg@^1.0.0, pkg@>=1.2.0":
//	  version "1.2.3"
//	  resolved "https://..."
//	  integrity sha512-...
var yarnV1HeaderRe = regexp.MustCompile(`^"?(@?[^@"]+)@`)
var yarnV1VersionRe = regexp.MustCompile(`^\s+version\s+"([^"]+)"`)

func parseYarnClassic(data []byte) ([]PackageEntry, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	var entries []PackageEntry
	var currentName string
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Package header line (no leading whitespace)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			name := extractClassicPackageName(line)
			if name != "" && !shouldSkipClassicProtocol(line) {
				currentName = name
			} else {
				currentName = ""
			}
			continue
		}

		// Version line (indented)
		if currentName != "" {
			if matches := yarnV1VersionRe.FindStringSubmatch(line); matches != nil {
				version := matches[1]
				key := currentName + "@" + version
				if !seen[key] {
					seen[key] = true
					entries = append(entries, PackageEntry{
						Name:    currentName,
						Version: version,
					})
				}
				currentName = ""
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning yarn lockfile: %w", err)
	}

	return entries, nil
}

func extractClassicPackageName(line string) string {
	matches := yarnV1HeaderRe.FindStringSubmatch(line)
	if matches == nil {
		return ""
	}
	return matches[1]
}

func shouldSkipClassicProtocol(line string) bool {
	for _, proto := range []string{"workspace:", "link:", "file:", "portal:", "https://", "http://", "git+", "git://", "git@"} {
		if strings.Contains(line, proto) {
			return true
		}
	}
	return false
}
