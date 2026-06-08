// Package supplychain implements supply chain age enforcement for npm packages.
package supplychain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const (
	markerStart = "# >>> armis-cli supply-chain >>>"
	markerEnd   = "# <<< armis-cli supply-chain <<<"
)

// cliBinaryName is the armis-cli executable name. resolveCliPath embeds it in
// the generated wrappers (preferring this bare, PATH-resolved name so upgrades
// stay transparent) and uses it to probe $PATH; centralizing the literal keeps
// the two in sync.
const cliBinaryName = "armis-cli"

// goosWindows is runtime.GOOS on Windows. Centralized so the several
// platform guards across this package (and its tests) share one literal.
const goosWindows = "windows"

// validPMName bounds package-manager names to a safe shell identifier: a
// lowercase letter followed by lowercase letters, digits, or hyphens, with an
// optional trailing `.<digits>` version suffix so versioned pip variants
// (pip3.11, pip3.12) survive sanitization. The generated wrapper uses each name
// both as a shell function name and as a literal command argument; a dot that
// is only ever followed by digits is not a shell metacharacter, so this still
// guarantees no metacharacter (`;`, backtick, `$`, quotes, whitespace) can be
// interpolated into the script written to a user's RC file. bash and zsh accept
// dotted function names; if a given shell rejects one the wrapper for that
// variant simply has no effect, which is no worse than leaving it unwrapped.
var validPMName = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[0-9]+)?$`)

// maxPMNames caps how many package-manager wrappers a single generated script
// can contain. The real universe is tiny (npm, pnpm, bun, yarn), so this
// generous limit never rejects a legitimate name, but it bounds the script
// builder's growth so an exported caller passing an arbitrarily long name list
// cannot drive an unbounded allocation (CWE-770).
const maxPMNames = 16

// sanitizePMNames drops any package-manager name that is not a safe shell
// identifier and caps the result at maxPMNames. This is the single chokepoint
// that every wrapper generator runs its input through, so a malformed or
// attacker-influenced name can never reach the script-building Fprintf calls
// below, and an oversized list can never grow the builder without limit.
func sanitizePMNames(pms []string) []string {
	var safe []string
	for _, pm := range pms {
		if len(safe) >= maxPMNames {
			break
		}
		if validPMName.MatchString(pm) {
			safe = append(safe, pm)
		}
	}
	return safe
}

type Shell struct {
	Name   string
	RCFile string
}

func DetectShells() []Shell {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var shells []Shell

	// RC paths are the current user's own home dir (os.UserHomeDir) joined with
	// hardcoded shell filenames; configuring the user's own shell is the purpose
	// of `supply-chain init`, and $HOME is not a trust boundary for a local CLI.
	candidates := []Shell{
		// armis:ignore cwe:22 cwe:73 reason:home is the current user's own $HOME joined with a hardcoded filename; configuring the user's own shell RC is the purpose of `supply-chain init`
		{Name: "bash", RCFile: filepath.Join(home, ".bashrc")},
		// armis:ignore cwe:22 cwe:73 reason:home is the current user's own $HOME joined with a hardcoded filename; configuring the user's own shell RC is the purpose of `supply-chain init`
		{Name: "zsh", RCFile: filepath.Join(home, ".zshrc")},
		// armis:ignore cwe:22 cwe:73 reason:home is the current user's own $HOME joined with hardcoded path segments; configuring the user's own shell RC is the purpose of `supply-chain init`
		{Name: "fish", RCFile: filepath.Join(home, ".config", "fish", "config.fish")},
	}

	currentShell := filepath.Base(os.Getenv("SHELL"))

	for _, s := range candidates {
		if s.Name == currentShell {
			shells = append([]Shell{s}, shells...)
		} else if fileExists(s.RCFile) {
			shells = append(shells, s)
		}
	}

	return shells
}

func GenerateWrapper(shell string, pms []string) string {
	cli := resolveCliPath()
	switch shell {
	case "fish":
		return generateFishWrapper(pms, cli)
	default:
		return generatePosixWrapper(pms, cli)
	}
}

// generatePosixWrapper builds the bash/zsh wrapper block for the given PMs.
// armis:ignore cwe:770 reason:sanitizePMNames caps the name list at maxPMNames (16), so the string builder cannot grow without bound; pms also originates from local lockfile detection (≤4 ecosystems) rather than untrusted input
func generatePosixWrapper(pms []string, cli string) string {
	safeCli := shellQuote(cli)
	var b strings.Builder
	b.WriteString(markerStart + "\n")
	for _, pm := range sanitizePMNames(pms) {
		// The `command -v` guard makes the wrapper fail-closed: if armis-cli is
		// not resolvable at invocation time (e.g. a stale absolute path left by a
		// package-manager upgrade), the wrapper warns loudly on stderr and runs the
		// real package manager un-wrapped rather than failing the command outright.
		// armis:ignore cwe:78 reason:pm is constrained to ^[a-z][a-z0-9-]*(\.[0-9]+)?$ by sanitizePMNames, so any dot is followed only by digits (not a shell metacharacter); safeCli is shellQuote-escaped; command -v is used only for presence detection and its output is discarded
		fmt.Fprintf(&b,
			"%s() {\n"+
				"  if command -v %s >/dev/null 2>&1; then\n"+
				"    command %s supply-chain wrap %s \"$@\"\n"+
				"  else\n"+
				"    printf '[armis] armis-cli not found - running %s WITHOUT supply-chain enforcement\\n' >&2\n"+
				"    command %s \"$@\"\n"+
				"  fi\n"+
				"}\n",
			pm, safeCli, safeCli, pm, pm, pm)
	}
	b.WriteString(markerEnd + "\n")
	return b.String()
}

// generateFishWrapper builds the fish wrapper block for the given PMs.
// armis:ignore cwe:770 reason:sanitizePMNames caps the name list at maxPMNames (16), so the string builder cannot grow without bound; pms also originates from local lockfile detection (≤4 ecosystems) rather than untrusted input
func generateFishWrapper(pms []string, cli string) string {
	safeCli := shellQuote(cli)
	var b strings.Builder
	b.WriteString(markerStart + "\n")
	for _, pm := range sanitizePMNames(pms) {
		// The `command -q` guard makes the wrapper fail-closed: if armis-cli is
		// not resolvable at invocation time (e.g. a stale absolute path left by a
		// package-manager upgrade), the wrapper warns loudly on stderr and runs the
		// real package manager un-wrapped rather than failing the command outright.
		// fish's `command` builtin has no POSIX `-v`; `-q`/`--query` (fish 3.0+) is
		// the native presence check and emits no output, so no redirect is needed.
		// armis:ignore cwe:78 reason:pm is constrained to ^[a-z][a-z0-9-]*(\.[0-9]+)?$ by sanitizePMNames, so any dot is followed only by digits (not a shell metacharacter); safeCli is shellQuote-escaped; command -q is used only for presence detection and its output is discarded
		fmt.Fprintf(&b,
			"function %s\n"+
				"  if command -q %s\n"+
				"    command %s supply-chain wrap %s $argv\n"+
				"  else\n"+
				"    printf '[armis] armis-cli not found - running %s WITHOUT supply-chain enforcement\\n' >&2\n"+
				"    command %s $argv\n"+
				"  end\n"+
				"end\n",
			pm, safeCli, safeCli, pm, pm, pm)
	}
	b.WriteString(markerEnd + "\n")
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// resolveCliPath returns the most upgrade-proof reference to the armis-cli
// binary to embed in the generated shell wrapper functions.
//
// Priority order:
//  1. The bare name "armis-cli" when it is resolvable on $PATH. The shell
//     re-resolves the name on every invocation, so a package-manager upgrade
//     (e.g. `brew upgrade armis-cli`, which moves the binary into a new
//     versioned directory) is transparent — the wrapper never embeds a
//     version-pinned path that a later upgrade would delete.
//  2. Otherwise the stable absolute path from filepath.Abs(os.Executable()).
//     We deliberately do NOT call filepath.EvalSymlinks here: on a Homebrew
//     install os.Executable() reports the stable /opt/homebrew/bin/armis-cli
//     symlink, and resolving it would pin the wrapper to the versioned Cellar
//     path (…/Cellar/armis-cli/<version>/bin/armis-cli) that `brew upgrade`
//     removes, breaking every wrapped package manager.
//  3. The literal "armis-cli" if os.Executable() fails — better a PATH-resolved
//     name than nothing.
func resolveCliPath() string {
	// armis:ignore cwe:426 cwe:427 reason:cliBinaryName is the hardcoded literal "armis-cli", not user input; supply-chain init configures the current user's own interactive shell, whose $PATH is not a trust boundary for a local CLI. The generated wrapper already resolves the package manager itself by bare name (e.g. `command npm`), so embedding the bare armis-cli name adds no search-path exposure the shell does not already have — an attacker able to write to a $PATH dir could shadow npm/pip directly.
	if IsOnPath(cliBinaryName) {
		return cliBinaryName
	}
	exe, err := os.Executable()
	if err != nil {
		return cliBinaryName
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return exe
	}
	return abs
}

func InjectFunctions(shells []Shell, pms []string) ([]string, error) {
	var modified []string
	for _, s := range shells {
		wrapper := GenerateWrapper(s.Name, pms)
		changed, err := injectIntoFile(s.RCFile, wrapper)
		if err != nil {
			return modified, fmt.Errorf("injecting into %s: %w", s.RCFile, err)
		}
		if changed {
			modified = append(modified, s.RCFile)
		}
	}
	return modified, nil
}

func injectIntoFile(path, block string) (bool, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); editing the user's RC file is the purpose of `supply-chain init`
	content, err := os.ReadFile(path) //nolint:gosec // user's own RC file
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	perm := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		perm = info.Mode().Perm()
	}

	text := string(content)

	if strings.Contains(text, markerStart) {
		cleaned := removeBlock(text)
		text = cleaned
	}

	if !strings.HasSuffix(text, "\n") && len(text) > 0 {
		text += "\n"
	}
	text += "\n" + block

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, err
	}

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); writing the user's RC file is the purpose of `supply-chain init`
	if err := os.WriteFile(path, []byte(text), perm); err != nil { //nolint:gosec // shell RC file
		return false, err
	}
	return true, nil
}

func RemoveFunctions(shells []Shell) ([]string, error) {
	var modified []string
	for _, s := range shells {
		changed, err := removeFromFile(s.RCFile)
		if err != nil {
			return modified, fmt.Errorf("removing from %s: %w", s.RCFile, err)
		}
		if changed {
			modified = append(modified, s.RCFile)
		}
	}
	return modified, nil
}

func removeFromFile(path string) (bool, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); editing the user's RC file is the purpose of `supply-chain uninit`
	content, err := os.ReadFile(path) //nolint:gosec // user's own RC file
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	text := string(content)
	if !strings.Contains(text, markerStart) {
		return false, nil
	}

	perm := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		perm = info.Mode().Perm()
	}

	cleaned := removeBlock(text)
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); writing the user's RC file is the purpose of `supply-chain uninit`
	if err := os.WriteFile(path, []byte(cleaned), perm); err != nil { //nolint:gosec // shell RC file
		return false, err
	}
	return true, nil
}

func removeBlock(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inBlock := false

	for _, line := range lines {
		if strings.TrimSpace(line) == markerStart {
			inBlock = true
			continue
		}
		if strings.TrimSpace(line) == markerEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			result = append(result, line)
		}
	}

	text := strings.Join(result, "\n")
	text = strings.TrimRight(text, "\n") + "\n"
	return text
}

func EvalCommand(pms []string) string {
	return generatePosixWrapper(pms, resolveCliPath())
}

func HasInjection(path string) bool {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); reading the user's RC file to report injection status is the purpose of `supply-chain status`
	content, err := os.ReadFile(path) //nolint:gosec // user's own RC file
	if err != nil {
		return false
	}
	return strings.Contains(string(content), markerStart)
}

// HasCurrentInjection reports whether path already contains the exact wrapper
// block that would be written for the given shell and PMs. Unlike HasInjection,
// which only checks for the marker, this verifies the content matches so callers
// can skip the prompt when nothing would change (same binary path, same PM set).
func HasCurrentInjection(path, shell string, pms []string) bool {
	// armis:ignore cwe:22 cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); reading the user's RC file to check injection status is safe
	content, err := os.ReadFile(path) //nolint:gosec // user's own RC file
	if err != nil {
		return false
	}
	return strings.Contains(string(content), GenerateWrapper(shell, pms))
}

func fileExists(path string) bool {
	_, err := os.Stat(path) //nolint:gosec // path is a shell RC file under the user's own $HOME (see DetectShells)
	return err == nil
}

// pipExecutable matches pip, pip3, and versioned variants like pip3.11 / pip3.12,
// so a project that pins a specific interpreter still gets every pip on PATH wrapped.
var pipExecutable = regexp.MustCompile(`^pip3?(\.[0-9]+)?$`)

// IsPipVariant reports whether name is pip or a versioned pip variant (pip3,
// pip3.11, pip3.12). Every variant resolves to PyPI and shares one enforcement
// policy, so callers canonicalize variants to "pip" for policy decisions while
// still executing the exact binary the user invoked (pip3.12 must install into
// the Python 3.12 environment, not a generic pip). The pattern is strict
// (letters, digits, a single dotted numeric suffix), so it also bounds the
// value that downstream exec.LookPath callers may treat as a trusted PM name.
func IsPipVariant(name string) bool {
	return pipExecutable.MatchString(name)
}

// pipVariant captures the optional major and minor version numbers out of a
// validated pip variant name (pip3.11 → ["3", "11"]; pip3 → ["3", ""]).
var pipVariant = regexp.MustCompile(`^pip(3(?:\.([0-9]+))?)?$`)

// CanonicalPipVariant reconstructs a pip variant command name from its numeric
// components, breaking any taint that may be associated with the caller's input
// string. It returns ("", false) when name does not match the pip variant
// pattern. The returned name is built entirely from integer literals and
// strconv-formatted ints, so it is safe to pass directly to exec.LookPath
// without a CWE-426 taint concern.
func CanonicalPipVariant(name string) (string, bool) {
	m := pipVariant.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	// m[1] is the "3" or "3.NN" suffix (may be empty for bare "pip").
	// m[2] is the minor version digits (may be empty).
	if m[1] == "" {
		return "pip", true
	}
	if m[2] == "" {
		return "pip3", true
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return "", false
	}
	// Reject non-canonical minor versions (e.g. "011"): reconstructing the name
	// from the integer would produce a different command than the user invoked.
	if strconv.Itoa(minor) != m[2] {
		return "", false
	}
	return fmt.Sprintf("pip3.%d", minor), true
}

// maxScanPathResults caps the number of distinct matches scanPathExecutables
// will collect. In normal use the supported PM set is ~15 names, so 128 is
// far above any realistic ceiling while still bounding memory when $PATH
// contains unusual directories.
const maxScanPathResults = 128

// scanPathExecutables walks every directory on $PATH and returns the
// deduplicated, sorted set of entry names for which match(name) is true and
// (on Unix) the file carries at least one execute bit. It is the single place
// the PATH traversal, dedup, and execute-bit semantics live, shared by
// DetectPipVariants and DetectInstalledPMs so the two cannot drift apart.
// Returns nil when PATH is unset or nothing matches; callers decide their own
// fallback.
func scanPathExecutables(match func(name string) bool) []string {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	seen := make(map[string]bool)
	const readDirChunk = 32 // entries per ReadDir call; small enough to avoid large allocs
	for _, dir := range filepath.SplitList(pathEnv) {
		if len(seen) >= maxScanPathResults {
			break
		}
		// Stream directory entries in chunks so we stop reading as soon as
		// maxScanPathResults is reached, without loading the full listing into
		// memory. This bounds both CPU and memory for large PATH entries like
		// /usr/bin or network mounts.
		f, err := os.Open(dir) //nolint:gosec // dir comes from PATH, not user input
		if err != nil {
			continue
		}
		for len(seen) < maxScanPathResults {
			entries, err := f.ReadDir(readDirChunk)
			for _, entry := range entries {
				if len(seen) >= maxScanPathResults {
					break
				}
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				// On Windows, executables carry extensions from PATHEXT (typically
				// .exe, .cmd, .bat, .com). Strip only those known executable extensions
				// so that pip.exe and pip3.cmd match the same patterns as bare pip /
				// pip3 on Unix. filepath.Ext must NOT be used here — it returns the last
				// dot-separated suffix, so pip3.12 would lose ".12" and match as "pip3".
				if runtime.GOOS == goosWindows {
					if ext := strings.ToLower(filepath.Ext(name)); ext == ".exe" || ext == ".cmd" || ext == ".bat" || ext == ".com" {
						name = strings.TrimSuffix(name, filepath.Ext(name))
					}
				}
				if !match(name) {
					continue
				}
				// On Unix, a matching entry on PATH with no execute bit (a stray data
				// file or a non-exec script) would yield a wrapper that later fails at
				// exec.LookPath with a confusing error, so require at least one execute
				// bit before treating it as a real command. Info() reports the entry's
				// own mode (lstat semantics); a symlink to a real binary keeps its
				// 0o777 link bits and so still passes, matching what the user can run.
				//
				// Skip this check on Windows: there is no execute-bit concept there
				// (executability is governed by file extension via PATHEXT), and
				// os.FileMode.Perm never sets 0o111, so the filter would reject every
				// real binary and collapse detection to nothing.
				if runtime.GOOS != goosWindows {
					info, err := entry.Info()
					if err != nil || info.Mode().Perm()&0o111 == 0 {
						continue
					}
				}
				seen[name] = true
			}
			if err != nil { // io.EOF or real error — either way, done with this dir
				break
			}
		}
		f.Close() //nolint:errcheck,gosec // read-only, close error is not actionable
	}

	if len(seen) == 0 {
		return nil
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// DetectPipVariants scans $PATH for pip executables (pip, pip3, pip3.11, …) and
// returns a deduplicated, sorted list of the command names found. pip installs
// under several names depending on how Python was set up, and a shell wrapper
// only shadows the exact name the user types, so all present variants must be
// wrapped. Falls back to ["pip"] when none are found or PATH is unset.
func DetectPipVariants() []string {
	variants := scanPathExecutables(pipExecutable.MatchString)
	if len(variants) == 0 {
		return []string{"pip"}
	}
	return variants
}

// DetectInstalledPMs returns the deduplicated, sorted set of supported package
// managers found on $PATH.
//
// Fixed names (npm, pnpm, bun, yarn, uv, poetry, pipenv, pdm, mvn, gradle) are
// resolved via exec.LookPath — a single stat per name, no directory enumeration.
// Pip variants (pip, pip3, pip3.11, …) are found via scanPathExecutables because
// they install under interpreter-specific names that must be enumerated.
//
// `supply-chain init` uses PATH-based detection rather than CWD lockfile
// detection because the injected shell functions are global — they shadow the
// command in every directory, not just the project init ran in.
// Returns nil when nothing is found or PATH is unset; the caller supplies the
// fallback.
func DetectInstalledPMs(names []string) []string {
	seen := make(map[string]bool)

	// Fixed-name PMs: exec.LookPath is O(PATH-dirs) with early-exit and no
	// ReadDir — strictly cheaper than directory enumeration for known names.
	// The returned path is discarded (_); only `n` (the hardcoded input name)
	// is added to `seen`, so no attacker-controlled path reaches any sink.
	for _, n := range names {
		// armis:ignore cwe:426 cwe:427 reason:the resolved path is intentionally discarded; only the hardcoded input name n is used, so no untrusted path flows to any execution sink
		if _, err := exec.LookPath(n); err == nil {
			seen[n] = true
		}
	}

	// Pip variants require enumeration because the names are not fixed
	// (pip3.11, pip3.12, …). scanPathExecutables handles dedup and execute-bit.
	for _, v := range scanPathExecutables(pipExecutable.MatchString) {
		seen[v] = true
	}

	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

// IsOnPath reports whether the named fixed-binary is present on $PATH.
// It uses exec.LookPath (one stat per PATH dir, no directory enumeration) and
// discards the resolved path so no untrusted value flows to any execution sink.
// armis:ignore cwe:426 cwe:427 reason:resolved path is intentionally discarded; only the hardcoded input name is used
func IsOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
