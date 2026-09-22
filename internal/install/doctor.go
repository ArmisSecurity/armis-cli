package install

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// knowledgeJSONIdentifier and knowledgeCodexIdentifier are the substrings used
// to spot a knowledge-bridge entry in an editor config, mirroring how
// mcpServerName/codexMCPServerName identify the scanner. The knowledge server
// name carries an env suffix (e.g. "armis-knowledge-dev"), so exact-key checks
// don't work here — a substring match does, the same way agentdetect matches
// the scanner's identifier.
const (
	knowledgeJSONIdentifier  = "armis-knowledge"
	knowledgeCodexIdentifier = "armis_knowledge"
)

// DefaultHandshakeTimeout bounds how long RunDoctor waits for an MCP server to
// answer the initialize handshake before reporting it as unresponsive.
const DefaultHandshakeTimeout = 10 * time.Second

// CheckStatus is the outcome of a single doctor check.
type CheckStatus string

const (
	StatusOK   CheckStatus = "ok"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

// DoctorCheck is one diagnostic result reported by RunDoctor.
type DoctorCheck struct {
	Component string      `json:"component"`
	Name      string      `json:"name"`
	Status    CheckStatus `json:"status"`
	Detail    string      `json:"detail"`
}

// DoctorReport is the full set of diagnostic results from RunDoctor.
type DoctorReport struct {
	Checks []DoctorCheck `json:"checks"`
}

func (r *DoctorReport) add(component, name string, status CheckStatus, detail string) {
	r.Checks = append(r.Checks, DoctorCheck{Component: component, Name: name, Status: status, Detail: detail})
}

// HasFailures reports whether any check in the report failed.
func (r *DoctorReport) HasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// DoctorOptions configures RunDoctor.
type DoctorOptions struct {
	// Handshake, when true, spawns each registered MCP server and performs a
	// live JSON-RPC initialize handshake over stdio.
	Handshake bool
	// Timeout bounds how long the handshake waits for a response. Defaults to
	// DefaultHandshakeTimeout when zero.
	Timeout time.Duration
}

// RunDoctor inspects everything armis-cli install may have registered — the
// shared scanner plugin, the knowledge bridge, and every editor config
// recorded in the install manifest — and, when requested, spawns each MCP
// server to confirm it actually answers a protocol handshake.
func RunDoctor(opts DoctorOptions) *DoctorReport {
	report := &DoctorReport{}

	ei := NewEditorInstaller()
	manifest := ReadManifest(ei.PluginDir())
	if manifest == nil {
		report.add("install", "manifest", StatusFail,
			fmt.Sprintf("no install manifest found at %s — run: armis-cli install", ei.PluginDir()))
		return report
	}

	checkScannerPlugin(report, ei, opts)
	checkManifestEditors(report, "scanner", mcpServerName, manifest.Editors)
	checkClaudeSection(report, "scanner", manifest.Claude, pluginName)
	checkCodexSection(report, "scanner", manifest.Codex, codexMCPServerName)

	if manifest.Knowledge != nil {
		checkKnowledgePlugin(report, manifest.Knowledge, opts)
		checkManifestEditors(report, "knowledge", knowledgeJSONIdentifier, manifest.Knowledge.Editors)
		checkClaudeSection(report, "knowledge", manifest.Knowledge.Claude, knowledgeJSONIdentifier)
		checkCodexSection(report, "knowledge", manifest.Knowledge.Codex, knowledgeCodexIdentifier)
	}

	return report
}

func checkScannerPlugin(report *DoctorReport, ei *EditorInstaller, opts DoctorOptions) {
	const component = "scanner"

	if v := ei.GetInstalledVersion(); v == "" {
		report.add(component, "plugin version", StatusWarn, "no installed version recorded")
	} else {
		report.add(component, "plugin version", StatusOK, "v"+v)
	}

	pythonPath := venvPython(ei.PluginDir())
	if !isExecutableFile(pythonPath) {
		report.add(component, "python venv", StatusFail, fmt.Sprintf("missing or not executable: %s", pythonPath))
		return
	}
	report.add(component, "python venv", StatusOK, pythonPath)

	serverPy := filepath.Join(ei.PluginDir(), "server.py")
	if _, err := os.Stat(serverPy); err != nil {
		report.add(component, "server script", StatusFail, fmt.Sprintf("missing: %s", serverPy))
		return
	}
	report.add(component, "server script", StatusOK, serverPy)

	env := checkCredentials(report, component, ei.EnvFilePath())

	if opts.Handshake {
		runHandshakeCheck(report, component, pythonPath, []string{serverPy}, env, opts.Timeout)
	}
}

func checkKnowledgePlugin(report *DoctorReport, k *ManifestKnowledge, opts DoctorOptions) {
	const component = "knowledge"

	if k.SHA != "" {
		report.add(component, "bridge commit", StatusOK, k.SHA)
	}

	found := false
	for _, sub := range []string{"prod", "stage", "dev"} {
		envDir := filepath.Join(k.PluginDir, sub)
		bridge := filepath.Join(envDir, "bridge.py")
		if _, err := os.Stat(bridge); err != nil {
			continue
		}
		found = true

		// Fetch extracts the whole knowledge repo (see EnvDir's doc comment),
		// so every environment's bridge.py lands on disk even though only the
		// one the user actually chose gets a venv (createPluginVenv is only
		// called for that EnvDir). A sibling env with bridge.py but no .venv/
		// at all was never installed here — skip it rather than reporting a
		// false failure; only flag a venv as broken once it was set up.
		if _, err := os.Stat(filepath.Join(envDir, ".venv")); err != nil {
			continue
		}

		subComponent := component + " " + sub
		pythonPath := venvPython(envDir)
		if !isExecutableFile(pythonPath) {
			report.add(subComponent, "python venv", StatusFail, fmt.Sprintf("missing or not executable: %s", pythonPath))
			continue
		}
		report.add(subComponent, "python venv", StatusOK, pythonPath)

		env := checkCredentials(report, subComponent, filepath.Join(envDir, ".env"))

		if opts.Handshake {
			runHandshakeCheck(report, subComponent, pythonPath, []string{bridge}, env, opts.Timeout)
		}
	}
	if !found {
		report.add(component, "bridge", StatusFail, fmt.Sprintf("no bridge.py found under %s", k.PluginDir))
	}
}

// checkCredentials validates envFile carries both required credentials and
// returns its contents for reuse by a following live handshake.
func checkCredentials(report *DoctorReport, component, envFile string) map[string]string {
	env, err := parseEnvFile(envFile)
	if err != nil {
		report.add(component, "credentials", StatusWarn, fmt.Sprintf("%s: %v", envFile, err))
		return env
	}
	if env["ARMIS_CLIENT_ID"] == "" || env["ARMIS_CLIENT_SECRET"] == "" {
		report.add(component, "credentials", StatusWarn,
			fmt.Sprintf("ARMIS_CLIENT_ID/ARMIS_CLIENT_SECRET not set in %s", envFile))
		return env
	}
	report.add(component, "credentials", StatusOK, "configured")
	return env
}

// checkManifestEditors verifies, for every editor the manifest recorded a
// registration for, that the config file still exists, still contains an
// entry matching identifier, and that the entry's command still exists on
// disk. That last check matters most on Windows, where a profile rename, a
// drive-letter change, or a reinstall into a new plugin dir leaves editors
// pointing at a command path that no longer resolves — the entry is still
// present by name, so a name-only check would report this as healthy.
func checkManifestEditors(report *DoctorReport, component, identifier string, editors map[EditorID]ManifestEntry) {
	for id, entry := range editors {
		name := string(id)
		if ed, ok := EditorByID(id); ok {
			name = ed.Name
		}

		if _, err := os.Stat(entry.ConfigFile); err != nil {
			report.add(component, name, StatusFail, fmt.Sprintf("config file %s: %v", entry.ConfigFile, err))
			continue
		}

		command, found := lookupEntryCommand(entry.ConfigFile, entry.Format, identifier)
		if !found {
			report.add(component, name, StatusWarn,
				fmt.Sprintf("registered at %s but entry not found — was it edited or removed?", entry.ConfigFile))
			continue
		}
		if command != "" && !isExecutableFile(command) {
			report.add(component, name, StatusFail,
				fmt.Sprintf("entry found in %s but its command does not exist: %s — likely stale after a reinstall or profile/home directory change; re-run armis-cli install", entry.ConfigFile, command))
			continue
		}
		report.add(component, name, StatusOK, entry.ConfigFile)
	}
}

func checkClaudeSection(report *DoctorReport, component string, claude *ManifestClaude, pluginKeyPrefix string) {
	if claude == nil {
		return
	}
	if _, err := os.Stat(claude.CacheDir); err != nil {
		report.add(component, "Claude Code", StatusFail, fmt.Sprintf("cache dir missing: %s", claude.CacheDir))
		return
	}

	installed, enabled := claudeRegistryStatus(homeDir(".claude"), pluginKeyPrefix)
	switch {
	case !installed:
		report.add(component, "Claude Code", StatusWarn, "not found in installed_plugins.json — re-run install")
	case !enabled:
		report.add(component, "Claude Code", StatusWarn, "installed but not enabled in settings.json")
	default:
		report.add(component, "Claude Code", StatusOK, claude.CacheDir)
	}
}

// readBoundedConfigFile reads path the same way editors.go's
// readJSONFileAsMap/readYAMLFileAsMap do: reject non-regular files (devices,
// FIFOs, symlinks to either) and cap the size at maxEditorConfigSize before
// reading, so a doctor check can't block or exhaust memory on a config path
// that isn't the plain file it's expected to be (CWE-770).
func readBoundedConfigFile(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", clean)
	}
	if info.Size() > maxEditorConfigSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", clean, maxEditorConfigSize)
	}
	// armis:ignore cwe:22 cwe:770 reason:path from the install manifest/known config locations; regular-file and size checks above bound the read
	return os.ReadFile(clean) //nolint:gosec
}

// claudeRegistryStatus reports whether any plugin key containing
// pluginKeyPrefix is recorded as installed and/or enabled in Claude Code's
// own registry files.
func claudeRegistryStatus(claudeDir, pluginKeyPrefix string) (installed, enabled bool) {
	prefix := strings.ToLower(pluginKeyPrefix)

	instFile := filepath.Join(claudeDir, "plugins", "installed_plugins.json")
	if b, err := readBoundedConfigFile(instFile); err == nil {
		var data struct {
			Plugins map[string]json.RawMessage `json:"plugins"`
		}
		if json.Unmarshal(b, &data) == nil {
			for k := range data.Plugins {
				if strings.Contains(strings.ToLower(k), prefix) {
					installed = true
					break
				}
			}
		}
	}

	settingsFile := filepath.Join(claudeDir, "settings.json")
	if b, err := readBoundedConfigFile(settingsFile); err == nil {
		var data struct {
			EnabledPlugins map[string]bool `json:"enabledPlugins"`
		}
		if json.Unmarshal(b, &data) == nil {
			for k, v := range data.EnabledPlugins {
				if v && strings.Contains(strings.ToLower(k), prefix) {
					enabled = true
					break
				}
			}
		}
	}
	return installed, enabled
}

func checkCodexSection(report *DoctorReport, component string, codex *ManifestCodex, identifier string) {
	if codex == nil {
		return
	}
	content, err := readBoundedConfigFile(codex.ConfigFile)
	if err != nil {
		report.add(component, "Codex CLI", StatusFail, fmt.Sprintf("config file %s: %v", codex.ConfigFile, err))
		return
	}
	if !strings.Contains(strings.ToLower(string(content)), strings.ToLower(identifier)) {
		report.add(component, "Codex CLI", StatusWarn,
			fmt.Sprintf("registered at %s but entry not found — was it edited or removed?", codex.ConfigFile))
		return
	}
	report.add(component, "Codex CLI", StatusOK, codex.ConfigFile)
}

// lookupEntryCommand finds the server entry matching identifier in configFile
// (read per the manifest's recorded format) and returns the command path it
// declares. found is true as soon as a matching entry name exists, even when
// command comes back empty because the format stores it somewhere this
// function doesn't understand — callers must treat an empty command as
// "unknown", not "missing".
func lookupEntryCommand(configFile, format, identifier string) (command string, found bool) {
	identifier = strings.ToLower(identifier)

	matchEntry := func(servers map[string]interface{}) (map[string]interface{}, bool) {
		for k, v := range servers {
			if strings.Contains(strings.ToLower(k), identifier) {
				m, _ := v.(map[string]interface{})
				return m, true
			}
		}
		return nil, false
	}

	switch format {
	case configFormatVSCode:
		servers, _ := readJSONFileAsMap(configFile)["servers"].(map[string]interface{})
		entry, ok := matchEntry(servers)
		if !ok {
			return "", false
		}
		cmd, _ := entry[jsonKeyCommand].(string)
		return cmd, true
	case configFormatZed:
		servers, _ := readJSONFileAsMap(configFile)["context_servers"].(map[string]interface{})
		entry, ok := matchEntry(servers)
		if !ok {
			return "", false
		}
		cmdObj, _ := entry[jsonKeyCommand].(map[string]interface{})
		cmd, _ := cmdObj[jsonKeyPath].(string)
		return cmd, true
	case configFormatContinue:
		list, _ := readYAMLFileAsMap(configFile)["mcpServers"].([]interface{})
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if n, _ := m["name"].(string); strings.Contains(strings.ToLower(n), identifier) {
				cmd, _ := m[jsonKeyCommand].(string)
				return cmd, true
			}
		}
		return "", false
	default: // "mcpServers"
		servers, _ := readJSONFileAsMap(configFile)["mcpServers"].(map[string]interface{})
		entry, ok := matchEntry(servers)
		if !ok {
			return "", false
		}
		cmd, _ := entry[jsonKeyCommand].(string)
		return cmd, true
	}
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == osWindows {
		return true
	}
	return info.Mode()&0o111 != 0
}

// parseEnvFile reads a "KEY=VALUE" per line .env file, as written by
// writeEnvFromEnvironment/WriteEnvFromValues.
func parseEnvFile(path string) (map[string]string, error) {
	b, err := readBoundedConfigFile(path)
	if err != nil {
		return nil, err
	}
	env := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return env, nil
}

// handshakeResult carries the identity the MCP server reported in its
// initialize response.
type handshakeResult struct {
	ServerName    string
	ServerVersion string
}

type mcpInitResult struct {
	ServerInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

func runHandshakeCheck(report *DoctorReport, component, command string, args []string, env map[string]string, timeout time.Duration) {
	res, stderrTail, err := mcpHandshake(command, args, env, timeout)
	if err != nil {
		detail := err.Error()
		if stderrTail != "" {
			detail += " — stderr: " + stderrTail
		}
		report.add(component, "live handshake", StatusFail, detail)
		return
	}
	detail := "responded to initialize"
	if res.ServerName != "" {
		detail = fmt.Sprintf("%s v%s responded", res.ServerName, res.ServerVersion)
	}
	report.add(component, "live handshake", StatusOK, detail)
}

// mcpHandshake spawns command as an MCP stdio server, sends a single
// "initialize" JSON-RPC request, and waits up to timeout for a response line.
// The process is always killed and waited-on before returning, so stderr can
// be read back safely (os/exec only finishes copying stderr into the buffer
// once Wait returns).
func mcpHandshake(command string, args []string, env map[string]string, timeout time.Duration) (*handshakeResult, string, error) {
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}

	// armis:ignore cwe:78 cwe:88 reason:command/args come from the CLI's own recorded install paths (venv interpreter + server script), not user input
	cmd := exec.Command(command, args...) //nolint:gosec // command/args are the CLI's own recorded install paths
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, "", fmt.Errorf("opening stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", fmt.Errorf("opening stdout: %w", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("starting process: %w", err)
	}

	result, opErr := communicateInitialize(stdin, stdout, timeout)

	// armis:ignore cwe:404 reason:best-effort cleanup of a short-lived diagnostic subprocess we just spawned
	_ = cmd.Process.Kill()
	// On the timeout path, communicateInitialize's reader goroutine may still
	// be blocked reading stdout when we get here. os/exec's docs warn it is
	// "incorrect to call Wait before all reads from the pipe have completed"
	// because Wait closes this same pipe as part of its own cleanup — close
	// it here first so the unblock is explicit and ordered rather than racing
	// Wait's internal close.
	_ = stdout.Close()
	_ = cmd.Wait()

	if opErr != nil {
		return nil, stderrTail(&stderrBuf), opErr
	}
	return result, "", nil
}

func communicateInitialize(stdin io.WriteCloser, stdout io.ReadCloser, timeout time.Duration) (*handshakeResult, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "armis-cli-doctor", "version": "1.0"},
		},
	}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	type readOutcome struct {
		line []byte
		err  error
	}
	lineCh := make(chan readOutcome, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		l, rerr := reader.ReadBytes('\n')
		lineCh <- readOutcome{l, rerr}
	}()

	if _, err := stdin.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("writing initialize request: %w", err)
	}

	select {
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for response after %s", timeout)
	case out := <-lineCh:
		if len(out.line) == 0 {
			if out.err != nil {
				return nil, fmt.Errorf("no response: %w", out.err)
			}
			return nil, fmt.Errorf("no response")
		}
		var rpc struct {
			Result *mcpInitResult `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out.line, &rpc); err != nil {
			return nil, fmt.Errorf("invalid response: %w", err)
		}
		if rpc.Error != nil {
			return nil, fmt.Errorf("server returned error: %s", rpc.Error.Message)
		}
		if rpc.Result == nil {
			return nil, fmt.Errorf("response missing result")
		}
		return &handshakeResult{
			ServerName:    rpc.Result.ServerInfo.Name,
			ServerVersion: rpc.Result.ServerInfo.Version,
		}, nil
	}
}

func stderrTail(buf *bytes.Buffer) string {
	s := strings.TrimSpace(buf.String())
	const maxLen = 300
	if len(s) > maxLen {
		s = s[len(s)-maxLen:]
	}
	return s
}
