package supplychain

import (
	"os"
	"strings"
)

// NpmrcFileName is the project-local npm config file that `supply-chain init
// --mode npmrc` annotates and `supply-chain uninit` cleans.
const NpmrcFileName = ".npmrc"

// NpmrcMarkerComment is the comment line `supply-chain init --mode npmrc`
// appends to a project's .npmrc. The registry override itself is applied
// dynamically by `supply-chain wrap` at install time; this line is only a
// marker so the annotation can be detected (idempotent re-init) and later
// removed (uninit). It carries no trailing newline — the writer adds its own
// separator.
const NpmrcMarkerComment = "# armis-cli supply-chain: registry override applied at install time via 'supply-chain wrap'"

// npmrcMarkerFragment is the stable text that identifies an armis-cli
// supply-chain marker line, independent of the comment's exact wording.
// Matching on this fragment (rather than the full NpmrcMarkerComment) keeps
// detection robust if the comment text is ever reworded and still cleans
// markers written by older versions. It is anchored to the start of the comment
// body by isNpmrcMarkerLine — see there for why a bare substring match is unsafe.
const npmrcMarkerFragment = "armis-cli supply-chain"

// isNpmrcMarkerLine reports whether a single .npmrc line is an armis-cli
// supply-chain marker. A marker is a comment line — after optional leading
// whitespace it begins with '#' — whose comment body starts with the marker
// fragment. Anchoring to the start of the comment, rather than matching the
// fragment anywhere on the line, is what keeps detection from false-positively
// firing on a user comment that merely *mentions* armis-cli supply-chain in
// prose (e.g. "# managed by armis-cli supply-chain") or on a config value that
// happens to contain the fragment (e.g. "_authToken=armis-cli supply-chain-…").
// Either false positive would silently block re-init or, worse, delete the
// user's own line on uninit. A reworded marker still matches, since every
// marker we write leads with the fragment.
func isNpmrcMarkerLine(line string) bool {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "#")
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(rest), npmrcMarkerFragment)
}

// HasNpmrcMarker reports whether content (the bytes of an .npmrc) already
// carries an armis-cli supply-chain marker line. init uses this to stay
// idempotent (it has already read the file for its trailing-newline check).
func HasNpmrcMarker(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if isNpmrcMarkerLine(line) {
			return true
		}
	}
	return false
}

// NpmrcFileHasMarker reports whether the .npmrc at path carries an armis-cli
// supply-chain marker line. A missing or unreadable file reports false (nothing
// to clean). uninit uses this for its --dry-run preview, mirroring shell.go's
// path-based HasInjection.
func NpmrcFileHasMarker(path string) bool {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is the project-local .npmrc in the user's own working directory; reading it to report cleanup status is the purpose of `supply-chain uninit --dry-run`
	content, err := os.ReadFile(path) //nolint:gosec // project .npmrc in current working directory
	if err != nil {
		return false
	}
	return HasNpmrcMarker(content)
}

// RemoveNpmrcMarker strips any armis-cli supply-chain marker line(s) from the
// .npmrc at path, preserving every other line and the file's permissions. It
// returns true when the file was changed. A missing file is not an error
// (nothing to remove). This mirrors removeFromFile/removeBlock for shell RC
// files so init's write side and uninit's strip side stay symmetric.
func RemoveNpmrcMarker(path string) (bool, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is the project-local .npmrc in the user's own working directory; editing it is the purpose of `supply-chain uninit`
	content, err := os.ReadFile(path) //nolint:gosec // project .npmrc in current working directory
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !HasNpmrcMarker(content) {
		return false, nil
	}

	// Preserve the file's existing permissions. If the stat fails (it just read
	// fine, so this is near-impossible), fall back to the restrictive 0o600
	// rather than a world-readable 0o644: an .npmrc commonly carries registry
	// auth tokens, so the safe default for this file is owner-only.
	perm := os.FileMode(0o600)
	if info, statErr := os.Stat(path); statErr == nil {
		perm = info.Mode().Perm()
	}

	cleaned := removeNpmrcMarkerLines(string(content))
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is the project-local .npmrc in the user's own working directory; writing it is the purpose of `supply-chain uninit`
	if err := os.WriteFile(path, []byte(cleaned), perm); err != nil { //nolint:gosec // project .npmrc
		return false, err
	}
	return true, nil
}

// removeNpmrcMarkerLines drops every marker line from content and returns the
// remainder. A file reduced to nothing is returned empty (not a lone newline);
// otherwise the result is normalized to a single trailing newline, matching the
// shell RC cleanup in removeBlock.
func removeNpmrcMarkerLines(content string) string {
	lines := strings.Split(content, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if isNpmrcMarkerLine(line) {
			continue
		}
		result = append(result, line)
	}

	text := strings.TrimRight(strings.Join(result, "\n"), "\n")
	if text == "" {
		return ""
	}
	return text + "\n"
}
