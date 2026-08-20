package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const codexMCPServerName = "armis_scanner"

var codexSectionHeader = codexSectionHeaderFor(codexMCPServerName)

// codexSectionHeaderFor returns the TOML table header for an MCP server.
func codexSectionHeaderFor(serverName string) string {
	return "[mcp_servers." + serverName + "]"
}

// codexConfigPathOverride allows tests to inject a custom path.
var codexConfigPathOverride string

// CodexConfigPath returns the path to Codex CLI's config.toml.
func CodexConfigPath() string {
	if codexConfigPathOverride != "" {
		return codexConfigPathOverride
	}
	return homeDir(".codex", "config.toml")
}

// IsCodexDetected returns true if the ~/.codex/ directory exists.
func IsCodexDetected() bool {
	p := CodexConfigPath()
	if p == "" {
		return false
	}
	_, err := os.Stat(filepath.Dir(p))
	return err == nil
}

// RegisterCodexMCP adds or updates the [mcp_servers.armis_scanner] section
// in Codex CLI's config.toml.
func RegisterCodexMCP(pluginDir string) error {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:pluginDir validated absolute + filepath.Clean below; configPath is ~/.codex/config.toml from os.UserHomeDir (hardcoded segments)
	if !filepath.IsAbs(pluginDir) {
		return fmt.Errorf("plugin directory must be an absolute path: %s", pluginDir)
	}

	// Sanitize: resolve symlink-like components (e.g. "..") to prevent
	// path traversal when the stored path is later used by Codex CLI.
	// Cleaning here — before scannerEntry derives the interpreter and script
	// paths from it — is what keeps ".." out of the written config.
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:pluginDir validated absolute above; filepath.Clean here only normalizes
	pluginDir = filepath.Clean(pluginDir)

	entry := scannerEntry(pluginDir)
	// scannerEntry returns the JSON editors' hyphenated mcpServerName
	// ("armis-appsec"); Codex's config uses the underscored codexMCPServerName
	// ("armis_scanner"), so it must be substituted before registering.
	entry.name = codexMCPServerName
	return RegisterCodexEntry(entry)
}

// RegisterCodexEntry adds or updates one [mcp_servers.<name>] section in Codex
// CLI's config.toml, leaving other sections untouched.
//
// entry.command must be absolute: Codex launches it directly, and this function
// is also called straight from the knowledge installer, so it cannot rely on a
// caller having validated the path.
func RegisterCodexEntry(entry mcpEntry) error {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:entry.command validated absolute here; callers derive it from a cleaned plugin dir; configPath is ~/.codex/config.toml from os.UserHomeDir (hardcoded segments)
	if !filepath.IsAbs(entry.command) {
		return fmt.Errorf("server command must be an absolute path: %s", entry.command)
	}

	configPath := CodexConfigPath()
	if configPath == "" {
		return fmt.Errorf("codex config path not available on this platform")
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	content, err := readFileOrEmpty(configPath)
	if err != nil {
		return err
	}

	header := codexSectionHeaderFor(entry.name)
	// armis:ignore cwe:78 cwe:94 reason:buildCodexSectionFor does not execute commands — it builds a TOML config string with tomlQuote-escaped values
	newSection := buildCodexSectionFor(entry.name, entry.command, entry.args)
	updated := replaceTOMLSection(content, header, newSection)

	return writeFileAtomic(configPath, updated)
}

// DeregisterCodexMCP removes the [mcp_servers.armis_scanner] section
// from Codex CLI's config.toml. Returns true if a section was actually removed.
func DeregisterCodexMCP() (bool, error) {
	configPath := CodexConfigPath()
	if configPath == "" {
		return false, nil
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return false, nil
	}

	content, err := readFileOrEmpty(configPath)
	if err != nil {
		return false, err
	}

	updated := removeTOMLSection(content, codexSectionHeader)
	if updated == content {
		return false, nil
	}

	return true, writeFileAtomic(configPath, updated)
}

func buildCodexSectionFor(serverName, command string, args []string) string {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		// armis:ignore cwe:78 cwe:94 reason:values are only embedded in a TOML config string, never executed; tomlQuote escapes them
		quoted = append(quoted, tomlQuote(a))
	}
	return fmt.Sprintf("%s\ncommand = %s\nargs = [%s]\n",
		codexSectionHeaderFor(serverName),
		tomlQuote(command),
		strings.Join(quoted, ", "),
	)
}

// replaceTOMLSection replaces an existing section or appends a new one.
func replaceTOMLSection(content, header, newSection string) string {
	start, end := findTOMLSectionBounds(content, header)
	if start == -1 {
		// Append: ensure trailing newline before new section
		trimmed := strings.TrimRight(content, "\n")
		if trimmed == "" {
			return newSection
		}
		return trimmed + "\n\n" + newSection
	}
	// Replace existing section
	return content[:start] + newSection + content[end:]
}

// removeTOMLSection removes a section from the TOML content.
func removeTOMLSection(content, header string) string {
	start, end := findTOMLSectionBounds(content, header)
	if start == -1 {
		return content
	}

	before := content[:start]
	after := content[end:]

	// Clean up: remove extra blank lines at the join point
	before = strings.TrimRight(before, "\n")
	after = strings.TrimLeft(after, "\n")

	if before == "" && after == "" {
		return ""
	}
	if before == "" {
		return after
	}
	if after == "" {
		return before + "\n"
	}
	return before + "\n\n" + after
}

// findTOMLSectionBounds locates a section in the content.
// Returns (startByte, endByte) of the section including its header line.
// Returns (-1, -1) if not found.
func findTOMLSectionBounds(content, header string) (int, int) {
	lines := strings.Split(content, "\n")
	startLine := -1

	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			startLine = i
			break
		}
	}
	if startLine == -1 {
		return -1, -1
	}

	// Find the end: next line starting with '[' (a new section header)
	endLine := len(lines)
	for i := startLine + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if len(trimmed) > 0 && trimmed[0] == '[' {
			endLine = i
			break
		}
	}

	// Skip trailing blank lines within the section
	for endLine > startLine+1 && strings.TrimSpace(lines[endLine-1]) == "" {
		endLine--
	}

	// Calculate byte offsets using character positions in the original content.
	// Each line except the very last has a \n separator (strings.Split consumed them).
	// When content ends with \n, Split produces a trailing empty element — the \n
	// between the second-to-last and last element accounts for the trailing newline.
	lastLine := len(lines) - 1

	startByte := 0
	for i := 0; i < startLine; i++ {
		startByte += len(lines[i])
		if i < lastLine {
			startByte++ // \n separator
		}
	}
	endByte := 0
	for i := 0; i < endLine; i++ {
		endByte += len(lines[i])
		if i < lastLine {
			endByte++ // \n separator
		}
	}

	return startByte, endByte
}

// tomlQuote wraps a string in double quotes with proper escaping.
func tomlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func readFileOrEmpty(path string) (string, error) {
	// armis:ignore cwe:22 reason:path from known config location (homeDir + hardcoded segments)
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(b), nil
}

func writeFileAtomic(path, content string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := f.Name()

	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath from os.CreateTemp in controlled dir
		return fmt.Errorf("writing config: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath from os.CreateTemp in controlled dir
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath from os.CreateTemp in controlled dir
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil { // #nosec G703 -- atomic write to known config path
		_ = os.Remove(tmpPath) // #nosec G703 -- tmpPath from os.CreateTemp in controlled dir
		return fmt.Errorf("renaming config: %w", err)
	}
	return nil
}

// removeCodexSection removes one [mcp_servers.<name>] section from a Codex
// config file. Returns whether a section was actually removed.
func removeCodexSection(configPath, serverName string) (bool, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return false, nil
	}

	content, err := readFileOrEmpty(configPath)
	if err != nil {
		return false, err
	}

	header := codexSectionHeaderFor(serverName)
	start, end := findTOMLSectionBounds(content, header)
	if start == -1 {
		return false, nil
	}

	updated := content[:start] + content[end:]
	if err := writeFileAtomic(configPath, updated); err != nil {
		return false, err
	}
	return true, nil
}
