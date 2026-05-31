// Package supplychain implements supply chain age enforcement for npm packages.
package supplychain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	markerStart = "# >>> armis-cli supply-chain >>>"
	markerEnd   = "# <<< armis-cli supply-chain <<<"
)

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

	candidates := []Shell{
		{Name: "bash", RCFile: filepath.Join(home, ".bashrc")},
		{Name: "zsh", RCFile: filepath.Join(home, ".zshrc")},
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
	var b strings.Builder
	b.WriteString(markerStart + "\n")
	for _, pm := range pms {
		fmt.Fprintf(&b, "%s() {\n  command '%s' supply-chain wrap %s \"$@\"\n}\n", pm, cli, pm)
	}
	b.WriteString(markerEnd + "\n")
	return b.String()
}

func generateFishWrapper(pms []string, cli string) string {
	var b strings.Builder
	b.WriteString(markerStart + "\n")
	for _, pm := range pms {
		fmt.Fprintf(&b, "function %s\n  command '%s' supply-chain wrap %s $argv\nend\n", pm, cli, pm)
	}
	b.WriteString(markerEnd + "\n")
	return b.String()
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
	content, err := os.ReadFile(path) //nolint:gosec // user's own RC file
	if err != nil && !os.IsNotExist(err) {
		return false, err
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

	if err := os.WriteFile(path, []byte(text), 0o644); err != nil { //nolint:gosec // shell RC file
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

	cleaned := removeBlock(text)
	if err := os.WriteFile(path, []byte(cleaned), 0o644); err != nil { //nolint:gosec // shell RC file
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
