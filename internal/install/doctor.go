package install

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// maxHandshakeLineSize bounds a single line read from a spawned MCP server's
// stdout during the doctor's live handshake — generous for a JSON-RPC
// initialize response, but small enough to stop a broken or hostile server
// process from growing the read buffer without limit (CWE-770).
const maxHandshakeLineSize = 1 << 20 // 1 MB

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

// networkProbeTimeout bounds the server-runtime network probe.
const networkProbeTimeout = 30 * time.Second

// CheckStatus is the outcome of a single doctor check.
type CheckStatus string

// ComponentInstall is the component of the check reporting a missing install
// manifest.
const ComponentInstall = "install"

const (
	StatusOK   CheckStatus = "ok"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
	// StatusInfo carries guidance for things the doctor can't verify locally
	// (e.g. organization-level Copilot policy). It never affects the exit code.
	StatusInfo CheckStatus = "info"
)

// FixAction names a repair `mcp doctor --fix` can perform for a check.
type FixAction string

const (
	FixNone FixAction = ""
	// FixReregister rewrites the editor registrations recorded in the manifest.
	FixReregister FixAction = "reregister"
	// FixReinstall re-downloads the plugin and rebuilds its venv, then
	// re-registers every editor.
	FixReinstall FixAction = "reinstall"
	// FixSetProxy writes a proxy the doctor verified works into the plugin's
	// .env, so the server uses it on its next start.
	FixSetProxy FixAction = "set-proxy"
	// FixBlocked marks a check that --fix cannot safely repair and that
	// blocks FixReregister/FixReinstall for every editor: re-registering
	// reads the editor's config as a map first, and a config that fails to
	// parse reads back as empty, so writing it out again would drop every
	// other server the user configured in that file.
	FixBlocked FixAction = "blocked"
)

// DoctorCheck is one diagnostic result reported by RunDoctor.
type DoctorCheck struct {
	Component   string      `json:"component"`
	Name        string      `json:"name"`
	Status      CheckStatus `json:"status"`
	Detail      string      `json:"detail"`
	Remediation string      `json:"remediation,omitempty"`
	Fix         FixAction   `json:"fix,omitempty"`
}

// hint attaches remediation text a user can act on without support.
func (c *DoctorCheck) hint(remediation string) *DoctorCheck {
	c.Remediation = remediation
	return c
}

// fix marks the check as repairable by `mcp doctor --fix`.
func (c *DoctorCheck) fix(action FixAction, remediation string) *DoctorCheck {
	c.Fix = action
	c.Remediation = remediation
	return c
}

// DoctorReport is the full set of diagnostic results from RunDoctor.
type DoctorReport struct {
	Checks []DoctorCheck `json:"checks"`
	// Artifacts holds raw diagnostic material (full server stderr, config
	// excerpts, log tails) for the support bundle. Keyed by bundle file name.
	// Kept out of the JSON report, which stays a concise list of checks.
	Artifacts map[string]string `json:"-"`
	// envFix holds the .env update FixSetProxy applies.
	envFix *envFix
	// secrets are credential values seen during the run, scrubbed verbatim
	// from everything written to the support bundle.
	secrets []string
}

// add appends a check and returns it so a hint or fix can be attached. The
// pointer is only valid until the next add.
func (r *DoctorReport) add(component, name string, status CheckStatus, detail string) *DoctorCheck {
	r.Checks = append(r.Checks, DoctorCheck{Component: component, Name: name, Status: status, Detail: detail})
	return &r.Checks[len(r.Checks)-1]
}

func (r *DoctorReport) artifact(name, content string) {
	if r.Artifacts == nil {
		r.Artifacts = make(map[string]string)
	}
	r.Artifacts[name] = content
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

// HasProblems reports whether any check failed or warned.
func (r *DoctorReport) HasProblems() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail || c.Status == StatusWarn {
			return true
		}
	}
	return false
}

// Fixes returns the distinct repairs `--fix` can apply for failing or warning
// checks. FixReinstall subsumes FixReregister, so at most one of the two is
// returned; FixSetProxy is independent and comes first.
func (r *DoctorReport) Fixes() []FixAction {
	var out []FixAction
	var reregister, reinstall, setProxy bool
	for _, c := range r.Checks {
		if c.Status != StatusFail && c.Status != StatusWarn {
			continue
		}
		switch c.Fix {
		case FixReinstall:
			reinstall = true
		case FixReregister:
			reregister = true
		case FixSetProxy:
			setProxy = r.envFix != nil
		}
	}
	if setProxy {
		out = append(out, FixSetProxy)
	}
	if !r.HasBlockedRegistration() {
		switch {
		case reinstall:
			out = append(out, FixReinstall)
		case reregister:
			out = append(out, FixReregister)
		}
	}
	return out
}

// HasBlockedRegistration reports whether any check is marked FixBlocked,
// meaning at least one editor's config file failed to parse. Reregistering
// any editor goes through the same manifest-wide update, so this blocks
// FixReregister/FixReinstall entirely rather than risk rewriting that
// editor's config from an empty map.
func (r *DoctorReport) HasBlockedRegistration() bool {
	for _, c := range r.Checks {
		if (c.Status == StatusFail || c.Status == StatusWarn) && c.Fix == FixBlocked {
			return true
		}
	}
	return false
}

// envFix is a verified set of variables to add to a .env file.
type envFix struct {
	EnvFile string
	Vars    [][2]string
}

// ApplyEnvFix performs FixSetProxy: it writes the verified variables into the
// plugin's .env, keeping everything else in the file. It returns a
// description of the change with credentials masked.
func (r *DoctorReport) ApplyEnvFix() (string, error) {
	if r.envFix == nil {
		return "", nil
	}
	if err := SetEnvFileVars(r.envFix.EnvFile, r.envFix.Vars); err != nil {
		return "", fmt.Errorf("updating %s: %w", r.envFix.EnvFile, err)
	}
	parts := make([]string, 0, len(r.envFix.Vars))
	for _, kv := range r.envFix.Vars {
		parts = append(parts, kv[0]+"="+maskURLUserinfo(kv[1]))
	}
	return fmt.Sprintf("set %s in %s", strings.Join(parts, ", "), r.envFix.EnvFile), nil
}

// DoctorOptions configures RunDoctor.
type DoctorOptions struct {
	// Handshake, when true, spawns each registered MCP server and runs a live
	// MCP session over stdio (initialize, tools/list, a diagnostic tool call),
	// and runs the network checks.
	Handshake bool
	// Timeout bounds how long the handshake waits for a response. Defaults to
	// DefaultHandshakeTimeout when zero.
	Timeout time.Duration
	// AuthCheck, when set and Handshake is true, verifies the scanner's client
	// credentials against the Armis API. Injected by the caller so this
	// package stays independent of the auth client.
	AuthCheck func(ctx context.Context, clientID, clientSecret string) error
	// WorkspaceDir is where a workspace-level .vscode/mcp.json is looked for.
	// Defaults to the current directory.
	WorkspaceDir string
}

// doctorRun carries state shared by the checks of a single RunDoctor call.
type doctorRun struct {
	report *DoctorReport
	opts   DoctorOptions
	// probes caches live-session outcomes by launch, so an editor entry that
	// launches exactly what an earlier check already ran isn't spawned twice.
	probes map[string]*probeOutcome
	// manifestConfigs are config files already covered by manifest checks,
	// so VS Code discovery doesn't report them twice.
	manifestConfigs map[string]bool
}

// workspaceDir returns opts.WorkspaceDir, defaulting to the current directory.
func (d *doctorRun) workspaceDir() string {
	if d.opts.WorkspaceDir != "" {
		return d.opts.WorkspaceDir
	}
	wd, _ := os.Getwd()
	return wd
}

type probeOutcome struct {
	label string // component/name of the check that ran it
	ok    bool
}

func newDoctorRun(opts DoctorOptions) *doctorRun {
	return &doctorRun{
		report:          &DoctorReport{},
		opts:            opts,
		probes:          make(map[string]*probeOutcome),
		manifestConfigs: make(map[string]bool),
	}
}

// RunDoctor inspects everything armis-cli install may have registered — the
// shared scanner plugin, the knowledge bridge, and every editor config
// recorded in the install manifest — and, when requested, spawns each MCP
// server to confirm it actually answers a protocol handshake and serves tools.
// VS Code gets extra checks (all install variants and profiles, workspace
// configs, chat settings, Group Policy, and its MCP logs) since Copilot's MCP
// support has the most ways to silently not load a server.
func RunDoctor(opts DoctorOptions) *DoctorReport {
	d := newDoctorRun(opts)
	report := d.report

	ei := NewEditorInstaller()
	report.artifact("system.txt", systemInfo())
	manifest := ReadManifest(ei.PluginDir())
	if manifest == nil {
		report.add(ComponentInstall, "manifest", StatusFail,
			fmt.Sprintf("no install manifest found at %s", ei.PluginDir())).
			hint("Run: armis-cli install")
		checkVSCode(d, ei.PluginDir(), false)
		return report
	}
	if b, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		report.artifact("manifest.json", string(b))
	}
	for _, e := range manifest.Editors {
		d.manifestConfigs[filepath.Clean(e.ConfigFile)] = true
	}

	checkScannerPlugin(d, ei)
	checkManifestEditors(d, "scanner", mcpServerName, manifest.Editors)
	checkClaudeSection(report, "scanner", manifest.Claude, pluginName)
	checkCodexSection(report, "scanner", manifest.Codex, codexMCPServerName)

	if manifest.Knowledge != nil {
		checkKnowledgePlugin(d, manifest.Knowledge)
		checkManifestEditors(d, "knowledge", knowledgeJSONIdentifier, manifest.Knowledge.Editors)
		checkClaudeSection(report, "knowledge", manifest.Knowledge.Claude, knowledgeJSONIdentifier)
		checkCodexSection(report, "knowledge", manifest.Knowledge.Codex, knowledgeCodexIdentifier)
	}

	_, hasVSCode := manifest.Editors[EditorVSCode]
	checkVSCode(d, ei.PluginDir(), hasVSCode)

	return report
}

// checkScannerPlugin verifies the scanner's files, venv, and credentials and,
// when enabled, runs the live session and network checks.
func checkScannerPlugin(d *doctorRun, ei *EditorInstaller) {
	const component = "scanner"
	report := d.report
	pythonPath := venvPython(ei.PluginDir())
	serverPy := filepath.Join(ei.PluginDir(), "server.py")

	if v := ei.GetInstalledVersion(); v == "" {
		report.add(component, "plugin version", StatusWarn, "no installed version recorded").
			fix(FixReinstall, "Reinstall the plugin: armis-cli mcp doctor --fix")
	} else {
		report.add(component, "plugin version", StatusOK, "v"+v)
	}

	if !isExecutableFile(pythonPath) {
		report.add(component, "python venv", StatusFail, fmt.Sprintf("missing or not executable: %s", pythonPath)).
			fix(FixReinstall, "Rebuild the venv: armis-cli mcp doctor --fix")
		return
	}
	if !checkVenvBase(report, component, filepath.Join(ei.PluginDir(), ".venv")) {
		return
	}
	report.add(component, "python venv", StatusOK, pythonPath)

	if _, err := os.Stat(serverPy); err != nil {
		report.add(component, "server script", StatusFail, fmt.Sprintf("missing: %s", serverPy)).
			fix(FixReinstall, "Reinstall the plugin: armis-cli mcp doctor --fix")
		return
	}
	report.add(component, "server script", StatusOK, serverPy)

	env := checkCredentials(report, component, ei.EnvFilePath())

	// Plugin versions that keep their own log write it here; include the
	// recent part in the support bundle.
	if b, err := readBoundedConfigFile(filepath.Join(ei.PluginDir(), "logs", "server.log")); err == nil && len(b) > 0 {
		report.artifact("scanner/server.log", tail(string(b), 64<<10)+"\n")
	}

	if d.opts.Handshake {
		// The canonical check launches with the .env merged in, which is what
		// VS Code does via envFile; editors without envFile rely on the server
		// loading .env itself, which it does from its own directory.
		d.probe(component, "", serverLaunch{Command: pythonPath, Args: []string{serverPy}, EnvFile: ei.EnvFilePath(), Env: env})
		checkServerNetwork(d, component, pythonPath, env, ei.EnvFilePath())
		checkAuth(d, component, env)
	}
}

// checkVenvBase verifies the interpreter a venv was created from still
// exists. A venv's python.exe on Windows is a thin launcher that execs the
// base interpreter recorded in pyvenv.cfg; uninstalling or upgrading that
// Python leaves a venv whose python.exe exists but can't start ("No Python
// at ..."). Returns false after reporting a failure.
func checkVenvBase(report *DoctorReport, component, venvDir string) bool {
	cfgPath := filepath.Join(venvDir, "pyvenv.cfg")
	b, err := readBoundedConfigFile(cfgPath)
	if err != nil {
		return true // older/unusual venvs may lack it; the handshake still catches a broken one
	}
	report.artifact(sanitizeArtifactName(component)+"/pyvenv.cfg", string(b))
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "home" {
			continue
		}
		home := strings.TrimSpace(v)
		if home == "" {
			return true
		}
		if _, err := os.Stat(home); err != nil {
			report.add(component, "python venv", StatusFail,
				fmt.Sprintf("the venv's base Python (%s) no longer exists — Python was likely uninstalled or upgraded", home)).
				fix(FixReinstall, "Rebuild the venv against a current Python: armis-cli mcp doctor --fix")
			return false
		}
	}
	return true
}

func checkKnowledgePlugin(d *doctorRun, k *ManifestKnowledge) {
	const component = "knowledge"
	report := d.report

	if k.SHA != "" {
		report.add(component, "bridge commit", StatusOK, k.SHA)
	}

	found := false
	venvFound := false
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
		venvFound = true

		subComponent := component + " " + sub
		pythonPath := venvPython(envDir)
		if !isExecutableFile(pythonPath) {
			report.add(subComponent, "python venv", StatusFail, fmt.Sprintf("missing or not executable: %s", pythonPath)).
				fix(FixReinstall, "Rebuild the venv: armis-cli mcp doctor --fix")
			continue
		}
		if !checkVenvBase(report, subComponent, filepath.Join(envDir, ".venv")) {
			continue
		}
		report.add(subComponent, "python venv", StatusOK, pythonPath)

		envFile := filepath.Join(envDir, ".env")
		env := checkCredentials(report, subComponent, envFile)

		if d.opts.Handshake {
			d.probe(subComponent, "", serverLaunch{Command: pythonPath, Args: []string{bridge}, EnvFile: envFile, Env: env})
		}
	}
	switch {
	case !found:
		report.add(component, "bridge", StatusFail, fmt.Sprintf("no bridge.py found under %s", k.PluginDir)).
			fix(FixReinstall, "Reinstall Armis Knowledge: armis-cli mcp doctor --fix")
	case !venvFound:
		report.add(component, "python venv", StatusFail, fmt.Sprintf("bridge.py found under %s but no environment has a .venv — install may have failed", k.PluginDir)).
			fix(FixReinstall, "Reinstall Armis Knowledge: armis-cli mcp doctor --fix")
	}
}

// credentialsHint is how a user re-enters client credentials without support.
const credentialsHint = "Re-enter your client ID and secret with: armis-cli install --interactive " +
	"(or set ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET in this file). " +
	"If you sign in with SSO instead, you can ignore this."

// checkCredentials validates envFile carries both required credentials and
// returns its contents for reuse by a following live handshake.
func checkCredentials(report *DoctorReport, component, envFile string) map[string]string {
	env, err := parseEnvFile(envFile)
	if err != nil {
		report.add(component, "credentials", StatusWarn, fmt.Sprintf("%s: %v", envFile, err)).hint(credentialsHint)
		return env
	}
	keys := make([]string, 0, len(env))
	for k, v := range env {
		keys = append(keys, k)
		switch {
		case isSecretKey(k) && v != "":
			report.secrets = append(report.secrets, v)
		case strings.Contains(strings.ToUpper(k), "PROXY") && v != "" && maskURLUserinfo(v) != v:
			// Only the credentials embedded in a proxy URL are secret; the
			// host/port on their own are useful diagnostic detail worth
			// keeping readable in the bundle.
			report.secrets = append(report.secrets, v)
		}
	}
	sort.Strings(keys)
	report.artifact(sanitizeArtifactName(component)+"/env-keys.txt",
		"Variables set in "+envFile+" (values omitted):\n"+strings.Join(keys, "\n")+"\n")

	if raw, rerr := readBoundedConfigFile(envFile); rerr == nil && bytes.HasPrefix(raw, utf8BOM) {
		report.add(component, "credentials file", StatusWarn,
			fmt.Sprintf("%s starts with a UTF-8 byte-order mark", envFile)).
			hint("Some editors and the server's .env loader misread the first variable when a BOM is present. Re-save the file as \"UTF-8\" (not \"UTF-8 with BOM\").")
	}
	if env["ARMIS_CLIENT_ID"] == "" || env["ARMIS_CLIENT_SECRET"] == "" {
		report.add(component, "credentials", StatusWarn,
			fmt.Sprintf("ARMIS_CLIENT_ID/ARMIS_CLIENT_SECRET not set in %s", envFile)).hint(credentialsHint)
		return env
	}
	report.add(component, "credentials", StatusOK, "configured")
	return env
}

// checkAuth exchanges the scanner's client credentials for a token, proving
// they're valid for this tenant before the user ever reaches a tool call.
func checkAuth(d *doctorRun, component string, env map[string]string) {
	if d.opts.AuthCheck == nil || env["ARMIS_CLIENT_ID"] == "" || env["ARMIS_CLIENT_SECRET"] == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), networkProbeTimeout)
	defer cancel()
	if err := d.opts.AuthCheck(ctx, env["ARMIS_CLIENT_ID"], env["ARMIS_CLIENT_SECRET"]); err != nil {
		msg := err.Error()
		c := d.report.add(component, "authentication", StatusFail, msg)
		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "401") || strings.Contains(lower, "403") ||
			strings.Contains(lower, "invalid") || strings.Contains(lower, "unauthorized"):
			c.hint("The client ID/secret were rejected. They may be revoked, expired, or for another tenant. " + credentialsHint)
		case strings.Contains(lower, "x509") || strings.Contains(lower, "certificate"):
			c.hint("TLS verification failed. Your network may be intercepting HTTPS; ask IT for the corporate root CA to be installed in the Windows certificate store.")
		default:
			c.hint("Check network access to the Armis API from this machine (proxy, firewall, VPN).")
		}
		return
	}
	d.report.add(component, "authentication", StatusOK, "client credentials accepted")
}

// checkServerNetwork runs the network probe with the server's own Python
// runtime, which is where TLS-inspection and proxy problems actually bite.
func checkServerNetwork(d *doctorRun, component, python string, env map[string]string, envFile string) {
	if caFile := firstNonEmpty(env["SSL_CERT_FILE"], os.Getenv("SSL_CERT_FILE")); caFile != "" {
		// armis:ignore cwe:22 reason:stat-only existence check of the user's own SSL_CERT_FILE setting
		if _, err := os.Stat(caFile); err != nil { //nolint:gosec // stat-only check of the user's own setting
			d.report.add(component, "CA bundle", StatusFail, fmt.Sprintf("SSL_CERT_FILE points to a missing file: %s", caFile)).
				hint("Fix the SSL_CERT_FILE path in " + envFile + " (or your environment) to point at your organization's root CA PEM file.")
		}
	}
	url := serverAPIURL(env)
	out, err := networkProbe(python, env, url, networkProbeTimeout)
	d.report.artifact(sanitizeArtifactName(component)+"/network-probe.txt", fmt.Sprintf("GET %s\n%s\n", url, out))
	if err != nil {
		c := d.report.add(component, "server network", StatusFail, fmt.Sprintf("%s: %s", url, truncate(err.Error(), 300)))
		c.hint(networkHint(err.Error(), envFile))
		if isConnectFailure(err.Error()) && !hasProxyEnv(env) {
			tryProxyFix(d, c, python, env, envFile, url)
		}
		return
	}
	d.report.add(component, "server network", StatusOK, fmt.Sprintf("%s reachable from the server's Python runtime (%s)", url, out))
}

// tryProxyFix handles the most common corporate-network failure: Python
// ignores the OS proxy settings the browser and CLI use. If the OS has a
// proxy configured and the probe succeeds through it, the check becomes
// auto-fixable by writing that proxy to .env. Nothing is written here.
func tryProxyFix(d *doctorRun, c *DoctorCheck, python string, env map[string]string, envFile, url string) {
	proxy := systemProxyLookup(python)
	if proxy == "" {
		return
	}
	withProxy := make(map[string]string, len(env)+1)
	for k, v := range env {
		withProxy[k] = v
	}
	withProxy[envHTTPSProxy] = proxy
	out, err := networkProbe(python, withProxy, url, networkProbeTimeout)
	masked := maskURLUserinfo(proxy)
	if masked != proxy {
		d.report.secrets = append(d.report.secrets, proxy)
	}
	d.report.artifact("scanner/network-probe-system-proxy.txt", fmt.Sprintf("GET %s via %s\n%s\n", url, masked, out))
	if err != nil {
		c.hint(c.Remediation + "\nThe system proxy " + masked + " was tried and also failed: " + truncate(err.Error(), 200))
		return
	}
	d.report.envFix = &envFix{EnvFile: envFile, Vars: [][2]string{{envHTTPSProxy, proxy}}}
	c.fix(FixSetProxy, "Your system proxy "+masked+" works but the MCP server doesn't use it. "+
		"armis-cli mcp doctor --fix adds HTTPS_PROXY="+masked+" to "+envFile+"; then restart VS Code.")
}

// probe runs a live MCP session for launch and reports the handshake, tool
// listing, and diagnostic tool call as checks. label prefixes the check names
// ("" for the plugin's own launch, the editor name for an editor's entry). A
// launch identical to one already probed is reported by reference instead of
// being spawned again.
func (d *doctorRun) probe(component, label string, launch serverLaunch) {
	report := d.report
	named := func(n string) string {
		if label == "" {
			return n
		}
		return label + " " + n
	}

	key := launch.key()
	if prev, ok := d.probes[key]; ok {
		status := StatusOK
		if !prev.ok {
			status = StatusFail
		}
		report.add(component, named("launch"), status, "same launch command as "+prev.label+" (see above)")
		return
	}
	outcome := &probeOutcome{label: component + " / " + named("live handshake")}
	d.probes[key] = outcome

	start := time.Now()
	res, stderr, err := mcpHandshake(launch.Command, launch.Args, launch.Env, d.opts.Timeout)
	elapsed := time.Since(start).Round(100 * time.Millisecond)
	if stderr != "" {
		report.artifact("stderr/"+sanitizeArtifactName(component+" "+named("live handshake"))+".txt",
			"$ "+launch.commandLine()+"\n\n"+stderr+"\n")
	}
	if err != nil {
		detail := err.Error()
		if stderr != "" {
			detail += " — stderr: " + tail(stderr, 300)
		}
		hint, action := launchHint(err, stderr, launch)
		report.add(component, named("live handshake"), StatusFail, detail).fix(action, hint)
		return
	}
	outcome.ok = true

	detail := "responded to initialize"
	if res.ServerName != "" {
		detail = res.ServerName + " responded"
		if res.ServerVersion != "" {
			detail = fmt.Sprintf("%s v%s responded", res.ServerName, res.ServerVersion)
		}
	}
	detail += " in " + elapsed.String()
	if elapsed > slowStartThreshold {
		report.add(component, named("live handshake"), StatusWarn, detail+" (slow start)").
			hint("Slow starts are usually antivirus scanning the venv. If your editor gives up before the server is ready, ask IT to exclude " + filepath.Dir(filepath.Dir(filepath.Dir(launch.Command))) + " from real-time scanning.")
	} else {
		report.add(component, named("live handshake"), StatusOK, detail)
	}

	switch {
	case res.ToolsErr != nil:
		outcome.ok = false
		report.add(component, named("tools"), StatusFail, "tools/list failed: "+res.ToolsErr.Error()).
			hint(launchHintText(res.ToolsErr, stderr, launch))
	case len(res.Tools) == 0:
		outcome.ok = false
		report.add(component, named("tools"), StatusFail, "server started but exposes no tools").
			fix(FixReinstall, "Reinstall the plugin: armis-cli mcp doctor --fix")
	default:
		report.add(component, named("tools"), StatusOK, fmt.Sprintf("%d tools: %s", len(res.Tools), strings.Join(res.Tools, ", ")))
	}

	switch {
	case res.DebugErr != nil:
		outcome.ok = false
		report.add(component, named("tool call"), StatusFail, debugConfigTool+" failed: "+truncate(res.DebugErr.Error(), 300)).
			hint(launchHintText(res.DebugErr, stderr, launch))
	case res.DebugConfig != "":
		report.artifact(sanitizeArtifactName(component)+"/debug_config.txt", res.DebugConfig+"\n")
		report.add(component, named("tool call"), StatusOK, debugConfigTool+" succeeded — "+summarizeDebugConfig(res.DebugConfig))
	}
}

func launchHintText(err error, stderr string, launch serverLaunch) string {
	h, _ := launchHint(err, stderr, launch)
	return h
}

// summarizeDebugConfig pulls the lines of debug_config output most useful at
// a glance into a single line.
func summarizeDebugConfig(out string) string {
	var parts []string
	for _, line := range strings.Split(out, "\n") {
		for _, p := range []string{"Auth method:", "API URL:", "Env:"} {
			if strings.HasPrefix(strings.TrimSpace(line), p) {
				parts = append(parts, strings.TrimSpace(line))
			}
		}
	}
	if len(parts) == 0 {
		return truncate(strings.ReplaceAll(strings.TrimSpace(out), "\n", "; "), 120)
	}
	return strings.Join(parts, "; ")
}

// checkManifestEditors verifies, for every editor the manifest recorded a
// registration for, that the config file still exists, still contains an
// entry matching identifier, and that the entry's command still exists on
// disk. That last check matters most on Windows, where a profile rename, a
// drive-letter change, or a reinstall into a new plugin dir leaves editors
// pointing at a command path that no longer resolves — the entry is still
// present by name, so a name-only check would report this as healthy.
//
// With handshakes enabled it then launches exactly what the editor's config
// says (command, args, envFile, env) rather than what the manifest expects,
// since that's what the editor will actually run.
func checkManifestEditors(d *doctorRun, component, identifier string, editors map[EditorID]ManifestEntry) {
	report := d.report
	ids := make([]EditorID, 0, len(editors))
	for id := range editors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		entry := editors[id]
		name := string(id)
		if ed, ok := EditorByID(id); ok {
			name = ed.Name
		}

		// readBoundedConfigFile applies the same regular-file and size guards as
		// readJSONFileAsMap/readYAMLFileAsMap, so a non-regular or oversized
		// config is reported here rather than silently read as empty by
		// lookupEntry below and misreported as "entry not found".
		content, err := readBoundedConfigFile(entry.ConfigFile)
		if err != nil {
			report.add(component, name, StatusFail, fmt.Sprintf("config file %s: %v", entry.ConfigFile, err)).
				fix(FixReregister, "Re-register the server: armis-cli mcp doctor --fix")
			continue
		}
		// readJSONFileAsMap/readYAMLFileAsMap also return an empty map on a
		// parse error, so a corrupted or non-object config (null, an array,
		// invalid YAML, ...) would otherwise fall through to the same "entry
		// not found" warning as a genuinely edited-out entry. Catch that case
		// explicitly. JSON configs are parsed as JSONC: VS Code's mcp.json
		// allows comments and trailing commas.
		var obj map[string]interface{}
		var parseErr error
		if entry.Format == configFormatContinue {
			parseErr = yaml.Unmarshal(content, &obj)
		} else {
			parseErr = json.Unmarshal(stripJSONC(content), &obj)
		}
		// Both unmarshalers accept a top-level `null` without error (obj just
		// stays nil), so an err-only check would miss it — require a non-nil
		// object too.
		if parseErr == nil && obj == nil {
			parseErr = fmt.Errorf("top-level value is not an object")
		}
		if parseErr != nil {
			// Not auto-fixable: re-registering would start from an empty map
			// and drop every other server the user configured in this file.
			report.add(component, name, StatusFail, fmt.Sprintf("config file %s is not valid: %v", entry.ConfigFile, parseErr)).
				fix(FixBlocked, name+" ignores the whole file when it can't be parsed, so no servers in it load. Fix the syntax (often a missing or extra comma), then re-run this doctor.")
			continue
		}

		launch, found := lookupEntry(entry.ConfigFile, entry.Format, identifier, d.workspaceDir())
		if !found {
			report.add(component, name, StatusWarn,
				fmt.Sprintf("registered at %s but entry not found — was it edited or removed?", entry.ConfigFile)).
				fix(FixReregister, "Re-register the server: armis-cli mcp doctor --fix")
			continue
		}
		report.artifact(fmt.Sprintf("editors/%s-%s-entry.json", sanitizeArtifactName(component), id), launchArtifact(entry.ConfigFile, launch))
		// lookupEntry understands every format the installer writes, so an
		// entry with no command here can't be started by the editor.
		if launch.Command == "" {
			report.add(component, name, StatusFail,
				fmt.Sprintf("entry found in %s but it has no command", entry.ConfigFile)).
				fix(FixReregister, "Re-register the server: armis-cli mcp doctor --fix")
			continue
		}
		if !isExecutableFile(launch.Command) {
			report.add(component, name, StatusFail,
				fmt.Sprintf("entry found in %s but its command does not exist: %s — likely stale after a reinstall or profile/home directory change", entry.ConfigFile, launch.Command)).
				fix(FixReregister, "Point the entry at the current install: armis-cli mcp doctor --fix")
			continue
		}
		if launch.EnvFile != "" {
			if _, err := os.Stat(launch.EnvFile); err != nil {
				report.add(component, name, StatusFail,
					fmt.Sprintf("entry in %s references an envFile that does not exist: %s", entry.ConfigFile, launch.EnvFile)).
					fix(FixReregister, "Point the entry at the current install: armis-cli mcp doctor --fix")
				continue
			}
		}
		report.add(component, name, StatusOK, entry.ConfigFile)

		if d.opts.Handshake {
			d.probe(component, name, launch)
		}
	}
}

func checkClaudeSection(report *DoctorReport, component string, claude *ManifestClaude, pluginKeyPrefix string) {
	if claude == nil {
		return
	}
	if _, err := os.Stat(claude.CacheDir); err != nil {
		report.add(component, "Claude Code", StatusFail, fmt.Sprintf("cache dir missing: %s", claude.CacheDir)).
			fix(FixReregister, "Reinstall the Claude Code plugin: armis-cli mcp doctor --fix")
		return
	}

	installed, enabled := claudeRegistryStatus(homeDir(".claude"), pluginKeyPrefix)
	switch {
	case !installed:
		report.add(component, "Claude Code", StatusWarn, "not found in installed_plugins.json").
			fix(FixReregister, "Reinstall the Claude Code plugin: armis-cli mcp doctor --fix")
	case !enabled:
		report.add(component, "Claude Code", StatusWarn, "installed but not enabled in settings.json").
			hint("Enable it in Claude Code with /plugin, or re-run: armis-cli mcp doctor --fix")
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
	if claudeDir == "" {
		return false, false
	}
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
		report.add(component, "Codex CLI", StatusFail, fmt.Sprintf("config file %s: %v", codex.ConfigFile, err)).
			fix(FixReregister, "Re-register the server: armis-cli mcp doctor --fix")
		return
	}
	if !strings.Contains(strings.ToLower(string(content)), strings.ToLower(identifier)) {
		report.add(component, "Codex CLI", StatusWarn,
			fmt.Sprintf("registered at %s but entry not found — was it edited or removed?", codex.ConfigFile)).
			fix(FixReregister, "Re-register the server: armis-cli mcp doctor --fix")
		return
	}
	report.add(component, "Codex CLI", StatusOK, codex.ConfigFile)
}

// lookupEntryCommand finds the server entry matching identifier in configFile
// and returns the command path it declares. See lookupEntry.
func lookupEntryCommand(configFile, format, identifier string) (command string, found bool) {
	l, found := lookupEntry(configFile, format, identifier, "")
	return l.Command, found
}

// lookupEntry finds the server entry matching identifier in configFile (read
// per the manifest's recorded format) and returns how it launches the server.
// found is true as soon as a matching entry name exists, even when the entry
// has no command. workspace resolves ${workspaceFolder} in VS Code entries.
func lookupEntry(configFile, format, identifier, workspace string) (serverLaunch, bool) {
	identifier = strings.ToLower(identifier)

	matchEntry := func(servers map[string]interface{}) (map[string]interface{}, bool) {
		keys := make([]string, 0, len(servers))
		for k := range servers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(strings.ToLower(k), identifier) {
				m, _ := servers[k].(map[string]interface{})
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
			return serverLaunch{}, false
		}
		return vscodeLaunch(entry, workspace), true
	case configFormatZed:
		servers, _ := readJSONFileAsMap(configFile)["context_servers"].(map[string]interface{})
		entry, ok := matchEntry(servers)
		if !ok {
			return serverLaunch{}, false
		}
		cmdObj, _ := entry[jsonKeyCommand].(map[string]interface{})
		cmd, _ := cmdObj[jsonKeyPath].(string)
		return serverLaunch{Command: cmd, Args: stringSlice(cmdObj[jsonKeyArgs]), Env: stringMap(cmdObj["env"])}, true
	case configFormatContinue:
		list, _ := readYAMLFileAsMap(configFile)["mcpServers"].([]interface{})
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if n, _ := m["name"].(string); strings.Contains(strings.ToLower(n), identifier) {
				cmd, _ := m[jsonKeyCommand].(string)
				return serverLaunch{Command: cmd, Args: stringSlice(m[jsonKeyArgs]), Env: stringMap(m["env"])}, true
			}
		}
		return serverLaunch{}, false
	default: // "mcpServers"
		servers, _ := readJSONFileAsMap(configFile)["mcpServers"].(map[string]interface{})
		entry, ok := matchEntry(servers)
		if !ok {
			return serverLaunch{}, false
		}
		cmd, _ := entry[jsonKeyCommand].(string)
		return serverLaunch{Command: cmd, Args: stringSlice(entry[jsonKeyArgs]), Env: stringMap(entry["env"])}, true
	}
}

func stringSlice(v interface{}) []string {
	list, _ := v.([]interface{})
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringMap(v interface{}) map[string]string {
	m, _ := v.(map[string]interface{})
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
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
// writeEnvFromEnvironment/WriteEnvFromValues. A leading UTF-8 BOM is ignored
// so a file re-saved by a Windows editor still parses.
func parseEnvFile(path string) (map[string]string, error) {
	b, err := readBoundedConfigFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, utf8BOM)
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

// isSecretKey reports whether an env var name likely holds a credential.
func isSecretKey(k string) bool {
	k = strings.ToUpper(k)
	for _, marker := range []string{"SECRET", "TOKEN", "PASSWORD", "CLIENT_ID", "API_KEY"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
