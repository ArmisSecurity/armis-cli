// Package supplychain implements supply chain age enforcement for npm packages.
package supplychain

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	markerStart = "# >>> armis-cli supply-chain >>>"
	markerEnd   = "# <<< armis-cli supply-chain <<<"
)

// validPMName bounds package-manager names to a safe shell identifier: a
// lowercase letter followed by lowercase letters, digits, or hyphens. The
// generated wrapper uses each name both as a shell function name and as a
// literal command argument, so restricting it to this character set guarantees
// no shell metacharacter (`;`, backtick, `$`, quotes, whitespace) can ever be
// interpolated into the script written to a user's RC file.
var validPMName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// sanitizePMNames drops any package-manager name that is not a safe shell
// identifier. This is the single chokepoint that every wrapper generator runs
// its input through, so a malformed or attacker-influenced name can never reach
// the script-building Fprintf calls below.
func sanitizePMNames(pms []string) []string {
	var safe []string
	for _, pm := range pms {
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

func generatePosixWrapper(pms []string, cli string) string {
	safeCli := shellQuote(cli)
	var b strings.Builder
	b.WriteString(markerStart + "\n")
	for _, pm := range sanitizePMNames(pms) {
		// armis:ignore cwe:78 reason:pm is constrained to ^[a-z][a-z0-9-]*$ by sanitizePMNames; safeCli is shellQuote-escaped
		fmt.Fprintf(&b, "%s() {\n  command %s supply-chain wrap %s \"$@\"\n}\n", pm, safeCli, pm)
	}
	b.WriteString(markerEnd + "\n")
	return b.String()
}

func generateFishWrapper(pms []string, cli string) string {
	safeCli := shellQuote(cli)
	var b strings.Builder
	b.WriteString(markerStart + "\n")
	for _, pm := range sanitizePMNames(pms) {
		// armis:ignore cwe:78 reason:pm is constrained to ^[a-z][a-z0-9-]*$ by sanitizePMNames; safeCli is shellQuote-escaped
		fmt.Fprintf(&b, "function %s\n  command %s supply-chain wrap %s $argv\nend\n", pm, safeCli, pm)
	}
	b.WriteString(markerEnd + "\n")
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func resolveCliPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "armis-cli"
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return exe
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}
	return resolved
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
	// armis:ignore cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); editing the user's RC file is the purpose of `supply-chain init`
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

	// armis:ignore cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); writing the user's RC file is the purpose of `supply-chain init`
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
	// armis:ignore cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); editing the user's RC file is the purpose of `supply-chain uninit`
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
	// armis:ignore cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); writing the user's RC file is the purpose of `supply-chain uninit`
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
	// armis:ignore cwe:73 reason:path is a shell RC file under the current user's own $HOME (see DetectShells); reading the user's RC file to report injection status is the purpose of `supply-chain status`
	content, err := os.ReadFile(path) //nolint:gosec // user's own RC file
	if err != nil {
		return false
	}
	return strings.Contains(string(content), markerStart)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
