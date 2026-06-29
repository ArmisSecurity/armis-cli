package supplychain

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ─── npmrc marker management (init --mode npmrc / uninit) ───

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

// ─── npmrc auth-token extraction (custom artifactory, PPSC-994) ───

// tokenCharset is the set of characters a resolved auth token may contain
// before it is placed in an `Authorization: Bearer <token>` header. npm/Nexus
// tokens are URL-safe base64-ish strings; this set covers them plus the
// punctuation real tokens use. A token failing this check is REJECTED, never
// sanitized (S4/E5): silently stripping a character would forward a corrupted
// credential (guaranteeing an opaque 401), and the check is what stops a
// header-injection payload smuggled through a ${VAR} from reaching the header
// writer. sanitizeHeaderValue only removes CR/LF; this is the positive guard.
var tokenCharset = regexp.MustCompile(`^[A-Za-z0-9+/=._~-]+$`)

// envVarRef matches a plain ${VAR} reference. v1 supports ONLY this bare form —
// not ${VAR:-default} or nested expansion — because Nexus's `npm config` output
// uses the plain form and supporting shell-style defaults would invite the
// parser to diverge from what npm itself resolves. A name follows the POSIX
// identifier rule ([A-Za-z_][A-Za-z0-9_]*).
var envVarRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// authTokenMarker is the .npmrc key suffix that introduces a bearer token. The
// key has the shape `//<host>[<path>]/:_authToken=<value>`; everything left of
// the marker is the registry reference the token authenticates.
//
// armis:ignore cwe:798 reason:this is the literal .npmrc KEY NAME the parser searches for, not a credential value; no secret is embedded
const authTokenMarker = ":_authToken=" //nolint:gosec // G101: this is a config key name, not a hardcoded credential

// NpmrcAuthToken extracts the bearer token configured for upstream from one or
// more .npmrc file contents (project first, then user/global — earlier entries
// win, matching npm's project-over-home precedence). It looks for the
// host-AND-path-scoped key first (the form Nexus/Artifactory emit, e.g.
// `//nexus.corp/repository/npm-group/:_authToken=`) and falls back to the bare
// host-scoped key (`//nexus.corp/:_authToken=`).
//
// Returns:
//   - (token, true, nil)  — a usable token was found, interpolated, validated.
//   - ("", false, nil)    — no token is configured for this upstream (no auth).
//   - ("", false, err)    — a token was found but is unusable: an unset ${VAR}
//     or a value that fails the safe charset. This is a HARD error the caller
//     surfaces; it must not fall through to an unauthenticated request that
//     would 401 with a confusing message.
func NpmrcAuthToken(contents []string, upstream *url.URL) (string, bool, error) {
	if upstream == nil {
		return "", false, nil
	}

	hostPathKey, hostKey := npmrcKeyCandidates(upstream)

	for _, content := range contents {
		tokens := parseNpmrcTokens(content)
		raw, ok := tokens[hostPathKey]
		if !ok {
			raw, ok = tokens[hostKey]
		}
		if !ok {
			continue
		}
		resolved, err := resolveNpmrcToken(raw)
		if err != nil {
			return "", false, err
		}
		return resolved, true, nil
	}

	return "", false, nil
}

// ReadNpmrcAuthToken is NpmrcAuthToken sourced from the developer's real .npmrc
// files: the project file in projectDir (highest precedence) then the user file
// at ~/.npmrc. Missing files are skipped silently — absent native config simply
// means "no token," which is a valid no-auth state, not an error.
func ReadNpmrcAuthToken(projectDir string, upstream *url.URL) (string, bool, error) {
	var contents []string
	candidates := []string{filepath.Join(projectDir, ".npmrc")}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".npmrc"))
	}
	for _, path := range candidates {
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:reading the developer's own .npmrc from their project dir and home dir to forward their own credential; paths are a fixed ".npmrc" leaf joined to the user-controlled project/home dir, not untrusted input crossing a trust boundary, and the read is size-bounded below
		data, err := os.ReadFile(path) //nolint:gosec // developer's own .npmrc
		if err != nil {
			continue
		}
		// Bound the read so a pathological .npmrc cannot exhaust memory.
		if len(data) > maxConfigSize {
			data = data[:maxConfigSize]
		}
		contents = append(contents, string(data))
	}
	return NpmrcAuthToken(contents, upstream)
}

// npmrcKeyCandidates derives the two .npmrc registry-reference keys to look up
// for an upstream: the host+path-scoped form and the bare host form. Both are
// normalized to a trailing slash, matching how npm writes them.
func npmrcKeyCandidates(upstream *url.URL) (hostPath, host string) {
	h := upstream.Host
	p := strings.TrimSuffix(upstream.Path, "/")
	hostPath = "//" + h + p + "/"
	host = "//" + h + "/"
	return hostPath, host
}

// parseNpmrcTokens scans .npmrc content and returns a map of registry-reference
// key (e.g. "//host/path/") to the raw, un-interpolated token value. Lines that
// are blank, comments (# or ;), or not _authToken assignments are ignored. The
// token value is split on the FIRST "=" after the marker so a base64 token
// containing "=" padding is preserved intact (E8).
func parseNpmrcTokens(content string) map[string]string {
	tokens := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.Index(line, authTokenMarker)
		if idx < 0 {
			continue
		}
		key := line[:idx]
		value := line[idx+len(authTokenMarker):]
		// Strip optional surrounding quotes npm tolerates around the value.
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" || value == "" {
			continue
		}
		// Normalize the key to a trailing slash so "//host" and "//host/" match.
		if !strings.HasSuffix(key, "/") {
			key += "/"
		}
		tokens[key] = value
	}
	return tokens
}

// resolveNpmrcToken interpolates any plain ${VAR} references against the
// environment and then validates the result against the safe charset. An unset
// referenced variable or a value containing header-hostile characters is a hard
// error (reject, don't sanitize — S4/E5).
func resolveNpmrcToken(raw string) (string, error) {
	var missing string
	resolved := envVarRef.ReplaceAllStringFunc(raw, func(ref string) string {
		name := envVarRef.FindStringSubmatch(ref)[1]
		val, ok := os.LookupEnv(name)
		if !ok {
			if missing == "" {
				missing = name
			}
			return ""
		}
		return val
	})
	if missing != "" {
		return "", fmt.Errorf("registry auth token references ${%s}, which is not set in the environment", missing)
	}
	if !tokenCharset.MatchString(resolved) {
		return "", fmt.Errorf("registry auth token contains characters outside the allowed set [A-Za-z0-9+/=._~-] and was rejected (it is not sanitized); check the _authToken in your .npmrc")
	}
	return resolved, nil
}

// IndexURLBasicAuth extracts userinfo embedded in a pip/uv index URL
// (https://user:token@nexus.corp/...) and returns the value for an
// `Authorization: Basic` header credential (the raw "user:password" string,
// pre-base64). It returns ("", false, nil) when the URL carries no userinfo,
// and a hard error when the decoded credential contains header-hostile bytes
// (CR/LF) — the basic-auth analogue of the token-charset reject.
func IndexURLBasicAuth(rawIndexURL string) (string, bool, error) {
	u, err := url.Parse(strings.TrimSpace(rawIndexURL))
	if err != nil || u.User == nil {
		return "", false, nil
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	cred := user + ":" + pass
	if strings.ContainsAny(cred, "\r\n") {
		return "", false, fmt.Errorf("index-url credentials contain invalid characters and were rejected")
	}
	return cred, true, nil
}
