package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const componentVSCode = "vscode"

// vscodeVariant is one VS Code build whose user data lives under Root
// (e.g. %APPDATA%\Code - Insiders).
type vscodeVariant struct {
	Name string
	Root string
}

// vscodeVariants lists the VS Code builds to inspect. A var so tests can point
// it at a temp directory instead of the real %APPDATA%.
var vscodeVariants = func() []vscodeVariant {
	var out []vscodeVariant
	for _, v := range []struct{ dir, name string }{
		{"Code", editorNameVSCode},
		{"Code - Insiders", "VS Code Insiders"},
		{"VSCodium", "VSCodium"},
	} {
		if root := appSupportPath(v.dir); root != "" {
			out = append(out, vscodeVariant{Name: v.name, Root: root})
		}
	}
	return out
}

// vscodePolicyQuery returns the output of `reg query` for a VS Code Group
// Policy key, or "" when the key doesn't exist. A var so tests can stub it.
var vscodePolicyQuery = func(key string) string {
	if runtime.GOOS != osWindows {
		return ""
	}
	// armis:ignore cwe:78 reason:fixed binary and fixed registry key constants
	out, err := exec.Command("reg", "query", key).Output() //nolint:gosec // constant arguments
	if err != nil {
		return ""
	}
	return string(out)
}

// vscodeSource is one VS Code config file that can declare MCP servers.
type vscodeSource struct {
	Label string // "user", "profile Work", "workspace", ...
	Path  string
	// ServersKey locates the servers map: mcp.json keeps it at "servers",
	// settings.json nests it under "mcp".
	InSettings bool
}

// vscodeFound is an armis entry located in a vscodeSource.
type vscodeFound struct {
	Source vscodeSource
	Launch serverLaunch
}

// checkVSCode runs the VS Code/Copilot-specific checks. It looks beyond the
// single config file the manifest records, because the common reasons Copilot
// doesn't show the server are all elsewhere: a different VS Code build
// (Insiders), a profile with its own mcp.json, a duplicate stale entry in a
// workspace or settings.json, MCP or agent mode being disabled by a setting
// or Group Policy, or organization Copilot policy.
func checkVSCode(d *doctorRun, pluginDir string, registered bool) {
	report := d.report
	workspace := d.workspaceDir()

	var detected []vscodeVariant
	for _, v := range vscodeVariants() {
		if info, err := os.Stat(filepath.Join(v.Root, "User")); err == nil && info.IsDir() {
			detected = append(detected, v)
		}
	}
	if len(detected) == 0 && !registered {
		return
	}

	snippet := vscodeSnippet(pluginDir)
	for _, v := range detected {
		checkVSCodeVariant(d, v, workspace, pluginDir, snippet)
	}
	checkVSCodeWorkspace(d, workspace)
	checkVSCodePolicy(report)

	report.add(componentVSCode, "Copilot", StatusInfo, "can't be verified from this machine").
		hint(strings.Join([]string{
			"If every check above passes but Copilot Chat doesn't use the Armis tools:",
			"1. Switch Copilot Chat to Agent mode (the mode picker under the chat input) — tools are only used in Agent mode.",
			"2. Click the tools icon in the chat input and make sure armis-appsec and its tools are ticked.",
			"3. Run \"MCP: List Servers\" from the Command Palette, select armis-appsec, and choose Start Server (accept the trust prompt if shown). \"Show Output\" there shows VS Code's own log for the server.",
			"4. On a Copilot Business/Enterprise seat, the \"MCP servers in Copilot\" policy must be enabled by your GitHub organization admin (it is off by default). If it's off, VS Code shows the server but Copilot won't call it.",
		}, "\n"))
}

func checkVSCodeVariant(d *doctorRun, v vscodeVariant, workspace, pluginDir, snippet string) {
	report := d.report
	userDir := filepath.Join(v.Root, "User")
	userMCP := filepath.Join(userDir, "mcp.json")

	sources := []vscodeSource{{Label: "user mcp.json", Path: userMCP}}
	profileNames := vscodeProfileNames(v.Root)
	profileDirs, _ := filepath.Glob(filepath.Join(userDir, "profiles", "*"))
	sort.Strings(profileDirs)
	for _, dir := range profileDirs {
		id := filepath.Base(dir)
		name := profileNames[id]
		if name == "" {
			name = id
		}
		sources = append(sources, vscodeSource{Label: "profile \"" + name + "\" mcp.json", Path: filepath.Join(dir, "mcp.json")})
	}
	sources = append(sources, vscodeSource{Label: "user settings.json", Path: filepath.Join(userDir, "settings.json"), InSettings: true})

	var found []vscodeFound
	var profilesWithout []vscodeSource
	for _, src := range sources {
		obj, exists, err := readJSONCObject(src.Path)
		if !exists {
			continue
		}
		if err != nil {
			if !d.manifestConfigs[filepath.Clean(src.Path)] {
				report.add(componentVSCode, v.Name+" config", StatusFail, fmt.Sprintf("%s is not valid JSONC: %v", src.Path, err)).
					hint(v.Name + " ignores a file it can't parse, so no servers in it load. Fix the syntax (often a missing or extra comma), then re-run this doctor.")
			}
			continue
		}
		servers := vscodeServers(obj, src.InSettings)
		name, entry, ok := findServer(servers, mcpServerName)
		if !ok {
			if strings.HasPrefix(src.Label, "profile") && len(servers) > 0 {
				profilesWithout = append(profilesWithout, src)
			}
			continue
		}
		launch := vscodeLaunch(entry, workspace)
		found = append(found, vscodeFound{Source: src, Launch: launch})
		report.artifact(fmt.Sprintf("vscode/%s/%s-entry.json", sanitizeArtifactName(v.Name), strings.TrimSuffix(sanitizeArtifactName(src.Label), ".json")),
			launchArtifact(src.Path+" → "+name, launch))
	}

	switch {
	case len(found) == 0:
		c := report.add(componentVSCode, v.Name, StatusWarn, "installed, but armis-appsec isn't registered in any of its MCP configs")
		if v.Name == editorNameVSCode {
			c.hint("Run: armis-cli install (and select VS Code)")
		} else {
			c.hint("If you use " + v.Name + ", add this to the \"servers\" object in " + userMCP + ":\n" + snippet)
		}
	case len(found) > 1:
		labels := make([]string, 0, len(found))
		for _, f := range found {
			labels = append(labels, f.Source.Label)
		}
		report.add(componentVSCode, v.Name+" duplicates", StatusWarn,
			fmt.Sprintf("armis-appsec is registered %d times (%s)", len(found), strings.Join(labels, ", "))).
			hint(v.Name + " starts every copy; a stale one fails and Copilot shows an error or duplicate tools. Keep only the entry in " + userMCP + " and delete the others.")
	}

	for _, f := range found {
		if d.manifestConfigs[filepath.Clean(f.Source.Path)] {
			continue // already checked and probed by checkManifestEditors
		}
		name := v.Name + " (" + f.Source.Label + ")"
		if f.Launch.Command == "" {
			report.addEditor(componentVSCode, name, StatusFail, f.Source.Path+": entry has no command").
				hint(v.Name + " can't start an entry with no command. Delete it from " + f.Source.Path + ", or replace it with:\n" + snippet)
			continue
		}
		if !isExecutableFile(f.Launch.Command) {
			report.addEditor(componentVSCode, name, StatusFail,
				fmt.Sprintf("%s: command does not exist: %s", f.Source.Path, f.Launch.Command)).
				hint("This entry is stale. Delete it from " + f.Source.Path + ", or replace it with:\n" + snippet)
			continue
		}
		report.addEditor(componentVSCode, name, StatusOK, f.Source.Path)
		if d.opts.Handshake {
			d.probe(componentVSCode, name, f.Launch)
		}
	}

	if len(found) > 0 {
		for _, p := range profilesWithout {
			report.add(componentVSCode, v.Name+" profile", StatusWarn,
				fmt.Sprintf("%s has its own MCP servers but not armis-appsec", p.Label)).
				hint("If you use that VS Code profile, Copilot won't see the server there. Add this to the \"servers\" object in " + p.Path + ":\n" + snippet)
		}
	}

	checkVSCodeSettings(report, v, filepath.Join(userDir, "settings.json"))
	checkVSCodeLog(report, v)
}

// checkVSCodeWorkspace flags a workspace-level entry, which shadows or
// duplicates the user-level one only while that folder is open.
func checkVSCodeWorkspace(d *doctorRun, workspace string) {
	if workspace == "" {
		return
	}
	for _, src := range []vscodeSource{
		{Label: "workspace .vscode/mcp.json", Path: filepath.Join(workspace, ".vscode", "mcp.json")},
		{Label: "workspace .vscode/settings.json", Path: filepath.Join(workspace, ".vscode", "settings.json"), InSettings: true},
	} {
		obj, exists, err := readJSONCObject(src.Path)
		if !exists {
			continue
		}
		if err != nil {
			if !d.manifestConfigs[filepath.Clean(src.Path)] {
				d.report.add(componentVSCode, src.Label, StatusFail, fmt.Sprintf("%s is not valid JSONC: %v", src.Path, err)).
					hint("VS Code ignores a workspace config it can't parse, so no servers in it load — including armis-appsec if it's registered there. Fix the syntax (often a missing or extra comma), then re-run this doctor.")
			}
			continue
		}
		if _, entry, ok := findServer(vscodeServers(obj, src.InSettings), mcpServerName); ok {
			launch := vscodeLaunch(entry, workspace)
			status, detail := StatusWarn, src.Path+" also registers armis-appsec"
			if launch.Command != "" && !isExecutableFile(launch.Command) {
				status, detail = StatusFail, fmt.Sprintf("%s registers armis-appsec with a command that does not exist: %s", src.Path, launch.Command)
			}
			d.report.add(componentVSCode, src.Label, status, detail).
				hint("Workspace entries apply only in this folder and run alongside the user-level one. Remove it from " + src.Path + " unless you need a per-project override.")
		}
	}
}

// checkVSCodeSettings reports settings that stop Copilot from using MCP
// servers at all, independent of whether the server itself is healthy.
func checkVSCodeSettings(report *DoctorReport, v vscodeVariant, path string) {
	obj, exists, err := readJSONCObject(path)
	if !exists || err != nil {
		return
	}
	relevant := make(map[string]interface{})
	for k, val := range obj {
		if strings.HasPrefix(k, "chat.") || k == "mcp" || strings.HasPrefix(k, "github.copilot") {
			relevant[k] = val
		}
	}
	if b, err := json.MarshalIndent(relevant, "", "  "); err == nil {
		report.artifact("vscode/"+sanitizeArtifactName(v.Name)+"/settings-chat.json", string(b))
	}

	name := v.Name + " settings"
	var problems []string
	if enabled, ok := obj["chat.mcp.enabled"].(bool); ok && !enabled {
		problems = append(problems, `"chat.mcp.enabled": false turns MCP support off`)
	}
	switch access, _ := obj["chat.mcp.access"].(string); access {
	case "none":
		problems = append(problems, `"chat.mcp.access": "none" blocks all MCP servers`)
	case "registry":
		problems = append(problems, `"chat.mcp.access": "registry" only allows servers from the MCP registry, which blocks locally installed servers like armis-appsec`)
	}
	if enabled, ok := obj["chat.agent.enabled"].(bool); ok && !enabled {
		problems = append(problems, `"chat.agent.enabled": false disables Agent mode, and Copilot only calls MCP tools in Agent mode`)
	}
	if len(problems) > 0 {
		report.add(componentVSCode, name, StatusFail, strings.Join(problems, "; ")).
			hint("Remove or change these settings in " + path + " (or via Settings → search \"mcp\" / \"agent\"), then reload VS Code.")
		return
	}
	report.add(componentVSCode, name, StatusOK, "MCP and Agent mode not disabled")
}

// Windows Group Policy keys VS Code reads its policies from.
var vscodePolicyKeys = []string{
	`HKLM\SOFTWARE\Policies\Microsoft\VSCode`,
	`HKCU\SOFTWARE\Policies\Microsoft\VSCode`,
}

// checkVSCodePolicy reports Group Policy settings that disable MCP or Agent
// mode. Policy wins over user settings and is greyed out in the Settings UI,
// which is why users can't tell why the server never appears.
func checkVSCodePolicy(report *DoctorReport) {
	if runtime.GOOS != osWindows {
		return
	}
	var problems []string
	anyPolicy := false
	for _, key := range vscodePolicyKeys {
		out := vscodePolicyQuery(key)
		if out == "" {
			continue
		}
		anyPolicy = true
		report.artifact("vscode/group-policy.txt", report.Artifacts["vscode/group-policy.txt"]+out+"\n")
		problems = append(problems, policyProblems(key, parseRegQuery(out))...)
	}
	switch {
	case len(problems) > 0:
		report.add(componentVSCode, "group policy", StatusFail, strings.Join(problems, "; ")).
			hint("Your organization's Group Policy disables this, and it can't be overridden locally. Ask IT to allow MCP servers in VS Code (the ChatMCP / ChatAgentMode policies).")
	case anyPolicy:
		report.add(componentVSCode, "group policy", StatusOK, "VS Code policies present, none restrict MCP")
	default:
		report.add(componentVSCode, "group policy", StatusOK, "no VS Code Group Policy set")
	}
}

// parseRegQuery parses `reg query` output lines of the form
// "    Name    REG_TYPE    Value" into a name → value map.
func parseRegQuery(out string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "REG_") {
			continue
		}
		values[fields[0]] = strings.Join(fields[2:], " ")
	}
	return values
}

func policyProblems(key string, values map[string]string) []string {
	var problems []string
	disabled := func(v string) bool {
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "0x0" || v == "0" || v == "false" || v == "none"
	}
	for name, val := range values {
		switch name {
		case "ChatMCP":
			if disabled(val) || strings.EqualFold(val, "registry") {
				problems = append(problems, fmt.Sprintf("%s\\ChatMCP = %s blocks locally installed MCP servers", key, val))
			}
		case "ChatAgentMode":
			if disabled(val) {
				problems = append(problems, fmt.Sprintf("%s\\ChatAgentMode = %s disables Agent mode", key, val))
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// vscodeLogRE matches VS Code's per-server MCP log files, e.g.
// mcpServer.mcp.config.usrlocal.armis-appsec.log.
var vscodeLogRE = regexp.MustCompile(`(?i)^mcpServer\..*` + regexp.QuoteMeta(mcpServerName) + `.*\.log$`)

// checkVSCodeLog surfaces VS Code's own log for the server — what the user
// would otherwise have to find via "MCP: List Servers → Show Output".
func checkVSCodeLog(report *DoctorReport, v vscodeVariant) {
	path, mod := latestVSCodeServerLog(filepath.Join(v.Root, "logs"))
	name := v.Name + " log"
	if path == "" {
		report.add(componentVSCode, name, StatusInfo, "no VS Code log for armis-appsec yet — VS Code has not tried to start the server").
			hint("Open Copilot Chat in Agent mode, or run \"MCP: List Servers\" → armis-appsec → Start Server, then re-run this doctor.")
		return
	}
	b, err := readBoundedConfigFile(path)
	if err != nil {
		return
	}
	content := tail(string(b), 32<<10)
	if content == "" {
		report.add(componentVSCode, name, StatusInfo, "VS Code created a log for armis-appsec but it's empty: "+path).
			hint("VS Code registered the server but hasn't logged a start attempt. Run \"MCP: List Servers\" → armis-appsec → Start Server, then re-run this doctor.")
		return
	}
	report.artifact("vscode/"+sanitizeArtifactName(v.Name)+"/mcp-server.log", content+"\n")

	lastErr := lastVSCodeError(content)
	age := time.Since(mod).Round(time.Minute)
	if lastErr != "" {
		report.add(componentVSCode, name, StatusWarn, fmt.Sprintf("last error (log updated %s ago): %s", age, truncate(lastErr, 300))).
			hint("Full log: " + path)
		return
	}
	report.add(componentVSCode, name, StatusOK, fmt.Sprintf("no errors since the last start (log updated %s ago)", age))
}

// latestVSCodeServerLog finds the most recently modified armis MCP server log
// across VS Code's session log directories.
func latestVSCodeServerLog(logsDir string) (string, time.Time) {
	sessions, err := os.ReadDir(logsDir)
	if err != nil {
		return "", time.Time{}
	}
	// Session dirs are timestamped (20260916T172015); the newest few are
	// enough and bound the walk on machines with long log histories.
	names := make([]string, 0, len(sessions))
	for _, s := range sessions {
		if s.IsDir() {
			names = append(names, s.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > 5 {
		names = names[:5]
	}

	var best string
	var bestMod time.Time
	for _, n := range names {
		windows, _ := filepath.Glob(filepath.Join(logsDir, n, "window*"))
		for _, w := range windows {
			entries, _ := os.ReadDir(w)
			for _, e := range entries {
				if e.IsDir() || !vscodeLogRE.MatchString(e.Name()) {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				if info.ModTime().After(bestMod) {
					best, bestMod = filepath.Join(w, e.Name()), info.ModTime()
				}
			}
		}
	}
	return best, bestMod
}

// lastVSCodeError returns the last [error] line logged after the most recent
// successful start, or "" if the server was running cleanly.
func lastVSCodeError(log string) string {
	lines := strings.Split(log, "\n")
	lastErr := ""
	for _, line := range lines {
		l := strings.ToLower(line)
		switch {
		case strings.Contains(l, "connection state: running"):
			lastErr = ""
		case strings.Contains(l, "[error]"):
			lastErr = strings.TrimSpace(line)
		}
	}
	return lastErr
}

// vscodeProfileNames maps profile directory IDs to their display names, read
// from VS Code's global storage.
func vscodeProfileNames(root string) map[string]string {
	names := make(map[string]string)
	obj, exists, err := readJSONCObject(filepath.Join(root, "User", "globalStorage", "storage.json"))
	if !exists || err != nil {
		return names
	}
	profiles, _ := obj["userDataProfiles"].([]interface{})
	for _, p := range profiles {
		m, _ := p.(map[string]interface{})
		loc, _ := m["location"].(string)
		name, _ := m[jsonKeyName].(string)
		if loc != "" && name != "" {
			names[filepath.Base(loc)] = name
		}
	}
	return names
}

// readJSONCObject reads a JSONC file into a map. exists is false when the file
// isn't there; err is set when it exists but can't be read or parsed.
func readJSONCObject(path string) (obj map[string]interface{}, exists bool, err error) {
	b, err := readBoundedConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	stripped := stripJSONC(b)
	if len(strings.TrimSpace(string(stripped))) == 0 {
		return map[string]interface{}{}, true, nil
	}
	if err := json.Unmarshal(stripped, &obj); err != nil {
		return nil, true, err
	}
	if obj == nil {
		return nil, true, fmt.Errorf("top-level value is not an object")
	}
	return obj, true, nil
}

// vscodeServers returns the servers map from an mcp.json object or, for
// settings.json, from its nested "mcp" object.
func vscodeServers(obj map[string]interface{}, inSettings bool) map[string]interface{} {
	if inSettings {
		mcp, _ := obj["mcp"].(map[string]interface{})
		obj = mcp
	}
	servers, _ := obj["servers"].(map[string]interface{})
	return servers
}

func findServer(servers map[string]interface{}, identifier string) (string, map[string]interface{}, bool) {
	keys := make([]string, 0, len(servers))
	for k := range servers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k), strings.ToLower(identifier)) {
			m, _ := servers[k].(map[string]interface{})
			return k, m, true
		}
	}
	return "", nil, false
}

// vscodeLaunch converts a VS Code server entry into the launch VS Code
// performs: variables expanded, envFile loaded, and inline env layered on top.
func vscodeLaunch(entry map[string]interface{}, workspace string) serverLaunch {
	cmd, _ := entry[jsonKeyCommand].(string)
	envFile, _ := entry["envFile"].(string)
	l := serverLaunch{
		Command: expandVSCodeVars(cmd, workspace),
		EnvFile: expandVSCodeVars(envFile, workspace),
	}
	for _, a := range stringSlice(entry[jsonKeyArgs]) {
		l.Args = append(l.Args, expandVSCodeVars(a, workspace))
	}
	env := make(map[string]string)
	if l.EnvFile != "" {
		if fileEnv, err := parseEnvFile(l.EnvFile); err == nil {
			for k, v := range fileEnv {
				env[k] = v
			}
		}
	}
	for k, v := range stringMap(entry["env"]) {
		env[k] = expandVSCodeVars(v, workspace)
	}
	if len(env) > 0 {
		l.Env = env
	}
	return l
}

var vscodeVarRE = regexp.MustCompile(`\$\{([^}]+)\}`)

// expandVSCodeVars resolves the VS Code variables that commonly appear in MCP
// entries. Unknown variables are left as-is.
func expandVSCodeVars(s, workspace string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return vscodeVarRE.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		switch {
		case name == "userHome":
			if h, err := os.UserHomeDir(); err == nil {
				return h
			}
		case name == "workspaceFolder" && workspace != "":
			return workspace
		case name == "pathSeparator" || name == "/":
			return string(filepath.Separator)
		case strings.HasPrefix(name, "env:"):
			return os.Getenv(strings.TrimPrefix(name, "env:"))
		}
		return m
	})
}

// vscodeSnippet renders the entry `armis-cli install` writes for VS Code, for
// users to paste into a config the CLI doesn't manage.
func vscodeSnippet(pluginDir string) string {
	e := scannerEntry(pluginDir)
	b, err := json.MarshalIndent(map[string]interface{}{
		e.name: map[string]interface{}{
			jsonKeyType:    "stdio",
			jsonKeyCommand: e.command,
			jsonKeyArgs:    e.args,
			"envFile":      e.envFile,
		},
	}, "", "  ")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	return strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
}

// launchArtifact records how an entry launches the server for the support
// bundle. Env values are omitted — only names are kept.
func launchArtifact(source string, l serverLaunch) string {
	keys := make([]string, 0, len(l.Env))
	for k := range l.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, _ := json.MarshalIndent(map[string]interface{}{
		jsonKeySource:  source,
		jsonKeyCommand: l.Command,
		jsonKeyArgs:    l.Args,
		"envFile":      l.EnvFile,
		"envKeys":      keys,
	}, "", "  ")
	return string(b) + "\n"
}

var artifactNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeArtifactName makes s safe as a single zip path segment.
func sanitizeArtifactName(s string) string {
	return strings.Trim(artifactNameRE.ReplaceAllString(s, "-"), "-")
}

// systemInfo describes the machine for the support bundle. Proxy-related
// variables are included because they explain most network failures; any
// credentials embedded in a proxy URL are masked.
func systemInfo() string {
	var b strings.Builder
	fmt.Fprintf(&b, "os: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "time: %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, k := range []string{envHTTPSProxy, "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
		"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "APPSEC_ENV", "APPSEC_API_URL", "ARMIS_API_URL", "ARMIS_REGION"} {
		if v := os.Getenv(k); v != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, maskURLUserinfo(v))
		}
	}
	for _, k := range []string{"ARMIS_CLIENT_ID", "ARMIS_CLIENT_SECRET", "ARMIS_API_TOKEN"} {
		state := "not set"
		if os.Getenv(k) != "" {
			state = "set"
		}
		fmt.Fprintf(&b, "%s: %s (in this shell)\n", k, state)
	}
	return b.String()
}

var urlUserinfoRE = regexp.MustCompile(`://[^/@\s]+@`)

func maskURLUserinfo(s string) string {
	return urlUserinfoRE.ReplaceAllString(s, "://***@")
}
