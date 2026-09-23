package install

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubVSCode points the VS Code checks at variants (nil for none) and
// disables the Group Policy lookup for the duration of the test.
func stubVSCode(t *testing.T, variants []vscodeVariant) {
	t.Helper()
	origVariants, origPolicy := vscodeVariants, vscodePolicyQuery
	vscodeVariants = func() []vscodeVariant { return variants }
	vscodePolicyQuery = func(string) string { return "" }
	t.Cleanup(func() { vscodeVariants, vscodePolicyQuery = origVariants, origPolicy })
}

// helperLaunch launches this test binary as a fake MCP server in mode.
func helperLaunch(mode string) serverLaunch {
	return serverLaunch{Command: os.Args[0], Env: map[string]string{"ARMIS_TEST_MCP_HELPER": mode}}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
}

// checkMap indexes checks by "component/name". Later checks with the same key
// overwrite earlier ones.
func checkMap(r *DoctorReport) map[string]DoctorCheck {
	m := make(map[string]DoctorCheck)
	for _, c := range r.Checks {
		m[c.Component+"/"+c.Name] = c
	}
	return m
}

func wantStatus(t *testing.T, checks map[string]DoctorCheck, key string, want CheckStatus) DoctorCheck {
	t.Helper()
	c, ok := checks[key]
	if !ok {
		t.Fatalf("no check %q; got %v", key, checkKeys(checks))
	}
	if c.Status != want {
		t.Errorf("check %q status = %s, want %s (detail: %s)", key, c.Status, want, c.Detail)
	}
	return c
}

func checkKeys(checks map[string]DoctorCheck) []string {
	keys := make([]string, 0, len(checks))
	for k := range checks {
		keys = append(keys, k)
	}
	return keys
}

func TestStripJSONC(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"line comment", "{\n// c\n\"a\": 1\n}", "{\n\n\"a\": 1\n}"},
		{"block comment", `{/* c */"a": 1}`, `{"a": 1}`},
		{"trailing comma object", `{"a": 1,}`, `{"a": 1}`},
		{"trailing comma array", `[1, 2, ]`, `[1, 2 ]`},
		{"trailing comma before comment", "{\"a\": 1, // c\n}", "{\"a\": 1 \n}"},
		{"bom", "\xEF\xBB\xBF{}", `{}`},
		{"url in string", `{"u": "http://x/*y*/"}`, `{"u": "http://x/*y*/"}`},
		{"escaped quote", `{"s": "a\"//b"}`, `{"s": "a\"//b"}`},
		{"comma in string", `{"s": ",}"}`, `{"s": ",}"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(stripJSONC([]byte(tt.in))); got != tt.want {
				t.Errorf("stripJSONC(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRegisterVSCodePreservesJSONCServers pins the install bug: a hand-edited
// mcp.json with a comment used to parse as empty, so registering dropped every
// other server in it.
func TestRegisterVSCodePreservesJSONCServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	mustWrite(t, path, "\xEF\xBB\xBF{\n  // my servers\n  \"servers\": {\n    \"other\": {\"command\": \"node\"},\n  },\n}\n")

	if err := registerVSCodeFormat(path, scannerEntry("/plugin")); err != nil {
		t.Fatalf("registerVSCodeFormat() error = %v", err)
	}
	servers, _ := readJSONFileAsMap(path)["servers"].(map[string]interface{})
	if _, ok := servers["other"]; !ok {
		t.Errorf("servers = %v, want the existing \"other\" server preserved", servers)
	}
	if _, ok := servers[mcpServerName]; !ok {
		t.Errorf("servers = %v, want %s added", servers, mcpServerName)
	}
}

func TestLookupEntryVSCodeLaunch(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	mustWrite(t, envFile, "ARMIS_CLIENT_ID=id\nFROM_FILE=1\n")
	path := filepath.Join(dir, "mcp.json")
	mustWrite(t, path, `{
  // comment
  "servers": {
    "armis-appsec": {
      "command": "/bin/python",
      "args": ["${pathSeparator}server.py"],
      "envFile": "`+filepath.ToSlash(envFile)+`",
      "env": {"FROM_FILE": "2", "EXTRA": "x"},
    },
  },
}`)

	l, ok := lookupEntry(path, configFormatVSCode, mcpServerName)
	if !ok {
		t.Fatal("lookupEntry() found = false")
	}
	if l.Command != "/bin/python" {
		t.Errorf("Command = %q", l.Command)
	}
	if len(l.Args) != 1 || l.Args[0] != string(filepath.Separator)+"server.py" {
		t.Errorf("Args = %v, want ${pathSeparator} expanded", l.Args)
	}
	if l.Env["ARMIS_CLIENT_ID"] != "id" || l.Env["FROM_FILE"] != "2" || l.Env["EXTRA"] != "x" {
		t.Errorf("Env = %v, want envFile merged with inline env winning", l.Env)
	}
}

func TestExpandVSCodeVars(t *testing.T) {
	home, _ := os.UserHomeDir()
	t.Setenv("ARMIS_TEST_VAR", "val")
	tests := map[string]string{
		"${userHome}/x":         home + "/x",
		"${workspaceFolder}/y":  "/ws/y",
		"${env:ARMIS_TEST_VAR}": "val",
		"${unknown}":            "${unknown}",
		"plain":                 "plain",
	}
	for in, want := range tests {
		if got := expandVSCodeVars(in, "/ws"); got != want {
			t.Errorf("expandVSCodeVars(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeReportsHandshakeToolsAndToolCall(t *testing.T) {
	d := newDoctorRun(DoctorOptions{Handshake: true, Timeout: 10 * time.Second})
	d.probe("scanner", "", helperLaunch("ok"))
	d.probe("scanner", "Cursor", helperLaunch("ok"))

	checks := checkMap(d.report)
	wantStatus(t, checks, "scanner/live handshake", StatusOK)
	tools := wantStatus(t, checks, "scanner/tools", StatusOK)
	if !strings.Contains(tools.Detail, "debug_config") {
		t.Errorf("tools detail = %q, want tool names", tools.Detail)
	}
	call := wantStatus(t, checks, "scanner/tool call", StatusOK)
	if !strings.Contains(call.Detail, "Auth method: JWT") {
		t.Errorf("tool call detail = %q, want debug_config summary", call.Detail)
	}
	// The identical second launch is reported by reference, not re-spawned.
	dup := wantStatus(t, checks, "scanner/Cursor launch", StatusOK)
	if !strings.Contains(dup.Detail, "same launch command") {
		t.Errorf("dedup detail = %q", dup.Detail)
	}
	if _, ok := checks["scanner/Cursor live handshake"]; ok {
		t.Error("identical launch was probed twice")
	}
	if d.report.Artifacts["scanner/debug_config.txt"] == "" {
		t.Error("debug_config output not kept as an artifact")
	}
}

func TestProbeFailures(t *testing.T) {
	tests := []struct {
		mode    string
		key     string
		wantFix FixAction
	}{
		{"notools", "scanner/tools", FixReinstall},
		{"toolerror", "scanner/tool call", FixNone},
		{"error", "scanner/live handshake", FixNone},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			d := newDoctorRun(DoctorOptions{Handshake: true, Timeout: 10 * time.Second})
			d.probe("scanner", "", helperLaunch(tt.mode))
			c := wantStatus(t, checkMap(d.report), tt.key, StatusFail)
			if c.Fix != tt.wantFix {
				t.Errorf("fix = %q, want %q", c.Fix, tt.wantFix)
			}
			if c.Remediation == "" {
				t.Error("failing check has no remediation")
			}
		})
	}
}

func TestLaunchHint(t *testing.T) {
	launch := serverLaunch{Command: `C:\Users\u\.armis\plugins\armis-appsec-mcp\.venv\Scripts\python.exe`, Args: []string{"server.py"}}
	tests := []struct {
		name    string
		err     error
		stderr  string
		wantFix FixAction
		want    string
	}{
		{"venv base python gone", errors.New("no response to initialize: server exited"), `No Python at '"C:\Python311\python.exe'`, FixReinstall, "base Python"},
		{"missing module", errors.New("no response"), "ModuleNotFoundError: No module named 'mcp'", FixReinstall, "dependencies"},
		{"missing interpreter", errors.New("starting process: exec: file does not exist: The system cannot find the file specified."), "", FixReinstall, "missing"},
		{"antivirus", errors.New("starting process: Operation did not complete successfully because the file contains a virus"), "", FixNone, "Antivirus"},
		{"applocker", errors.New("starting process: This program is blocked by group policy."), "", FixNone, "AppLocker"},
		{"timeout", errors.New("timed out waiting for initialize response after 15s"), "", FixNone, "--timeout"},
		{"stdout noise", errors.New(`invalid response (non-JSON on stdout: "hello")`), "", FixNone, "stdout"},
		{"unknown", errors.New("weird"), "", FixNone, "server.py"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint, fix := launchHint(tt.err, tt.stderr, launch)
			if fix != tt.wantFix {
				t.Errorf("fix = %q, want %q", fix, tt.wantFix)
			}
			if !strings.Contains(hint, tt.want) {
				t.Errorf("hint = %q, want it to mention %q", hint, tt.want)
			}
		})
	}
}

func TestNetworkHint(t *testing.T) {
	tests := map[string]string{
		"ERR ConnectError [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed": "SSL_CERT_FILE",
		"ERR ProxyError 407 Proxy Authentication Required":                            "HTTPS_PROXY value",
		"ERR ConnectError [Errno 11001] getaddrinfo failed":                           "PAC",
		"ERR Something": "HTTPS_PROXY / SSL_CERT_FILE",
	}
	for out, want := range tests {
		if got := networkHint(out, "/p/.env"); !strings.Contains(got, want) {
			t.Errorf("networkHint(%q) = %q, want it to mention %q", out, got, want)
		}
	}
}

func TestServerAPIURL(t *testing.T) {
	t.Setenv("APPSEC_API_URL", "")
	t.Setenv("APPSEC_ENV", "")
	if got := serverAPIURL(nil); got != appsecProdURL {
		t.Errorf("default = %q", got)
	}
	if got := serverAPIURL(map[string]string{"APPSEC_ENV": "dev"}); got != appsecDevURL {
		t.Errorf("dev = %q", got)
	}
	if got := serverAPIURL(map[string]string{"APPSEC_ENV": "dev", "APPSEC_API_URL": "https://x"}); got != "https://x" {
		t.Errorf("override = %q", got)
	}
}

func TestCheckVenvBase(t *testing.T) {
	dir := t.TempDir()
	report := &DoctorReport{}
	if !checkVenvBase(report, "scanner", dir) {
		t.Error("checkVenvBase() without pyvenv.cfg = false, want true")
	}

	mustWrite(t, filepath.Join(dir, "pyvenv.cfg"), "home = "+dir+"\nversion = 3.12\n")
	if !checkVenvBase(report, "scanner", dir) {
		t.Error("checkVenvBase() with existing home = false, want true")
	}

	mustWrite(t, filepath.Join(dir, "pyvenv.cfg"), "home = "+filepath.Join(dir, "gone")+"\n")
	if checkVenvBase(report, "scanner", dir) {
		t.Error("checkVenvBase() with missing home = true, want false")
	}
	if len(report.Checks) != 1 || report.Checks[0].Status != StatusFail || report.Checks[0].Fix != FixReinstall {
		t.Errorf("checks = %+v, want one fail with FixReinstall", report.Checks)
	}
}

func TestCheckCredentialsBOMAndSecrets(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	mustWrite(t, envFile, "\xEF\xBB\xBFARMIS_CLIENT_ID=the-id\nARMIS_CLIENT_SECRET=the-secret\n")

	report := &DoctorReport{}
	env := checkCredentials(report, "scanner", envFile)
	if env["ARMIS_CLIENT_ID"] != "the-id" {
		t.Errorf("env = %v, want BOM stripped from the first key", env)
	}
	checks := checkMap(report)
	wantStatus(t, checks, "scanner/credentials file", StatusWarn)
	wantStatus(t, checks, "scanner/credentials", StatusOK)
	if strings.Contains(report.Artifacts["scanner/env-keys.txt"], "the-secret") {
		t.Error("env-keys artifact contains a secret value")
	}
	if len(report.secrets) != 2 {
		t.Errorf("secrets = %d, want 2 collected for scrubbing", len(report.secrets))
	}
}

func TestReportFixes(t *testing.T) {
	r := &DoctorReport{}
	if r.Fixes() != nil {
		t.Error("empty report has fixes")
	}
	r.add("a", "ok", StatusOK, "").fix(FixReinstall, "")
	if r.Fixes() != nil {
		t.Error("fix on an ok check was counted")
	}
	r.add("a", "b", StatusWarn, "").fix(FixReregister, "")
	if f := r.Fixes(); len(f) != 1 || f[0] != FixReregister {
		t.Errorf("Fixes() = %v, want [reregister]", f)
	}
	r.add("a", "c", StatusFail, "").fix(FixReinstall, "")
	if f := r.Fixes(); len(f) != 1 || f[0] != FixReinstall {
		t.Errorf("Fixes() = %v, want [reinstall] to subsume reregister", f)
	}
}

// writeVSCodeFixture builds a VS Code user data dir that exhibits the
// problems the doctor should catch.
func writeVSCodeFixture(t *testing.T, root, goodCommand string) {
	t.Helper()
	user := filepath.Join(root, "User")
	mustWrite(t, filepath.Join(user, "mcp.json"), `{
  // added by hand
  "servers": {
    "armis-appsec": {"type": "stdio", "command": "`+filepath.ToSlash(goodCommand)+`"},
  },
}`)
	mustWrite(t, filepath.Join(user, "settings.json"), `{
  "chat.mcp.enabled": false,
  "chat.agent.enabled": false,
  "mcp": {"servers": {"armis-appsec": {"command": "/no/such/python"}}},
}`)
	mustWrite(t, filepath.Join(user, "profiles", "abc123", "mcp.json"), `{"servers": {"other": {"command": "node"}}}`)
	mustWrite(t, filepath.Join(user, "globalStorage", "storage.json"),
		`{"userDataProfiles": [{"location": "abc123", "name": "Work"}]}`)
}

func TestCheckVSCodeFindsConfigProblems(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	writeVSCodeFixture(t, root, os.Args[0])
	mustWrite(t, filepath.Join(workspace, ".vscode", "mcp.json"), `{"servers": {"armis-appsec": {"command": "/no/such/python"}}}`)
	stubVSCode(t, []vscodeVariant{{Name: "VS Code", Root: root}})

	d := newDoctorRun(DoctorOptions{WorkspaceDir: workspace})
	checkVSCode(d, "/plugin", true)
	checks := checkMap(d.report)

	wantStatus(t, checks, "vscode/VS Code (user mcp.json)", StatusOK)
	wantStatus(t, checks, "vscode/VS Code (user settings.json)", StatusFail)
	dup := wantStatus(t, checks, "vscode/VS Code duplicates", StatusWarn)
	if !strings.Contains(dup.Detail, "2 times") {
		t.Errorf("duplicates detail = %q", dup.Detail)
	}
	profile := wantStatus(t, checks, "vscode/VS Code profile", StatusWarn)
	if !strings.Contains(profile.Detail, `"Work"`) {
		t.Errorf("profile detail = %q, want the profile's display name", profile.Detail)
	}
	settings := wantStatus(t, checks, "vscode/VS Code settings", StatusFail)
	if !strings.Contains(settings.Detail, "chat.mcp.enabled") || !strings.Contains(settings.Detail, "chat.agent.enabled") {
		t.Errorf("settings detail = %q", settings.Detail)
	}
	wantStatus(t, checks, "vscode/VS Code log", StatusInfo)
	wantStatus(t, checks, "vscode/workspace .vscode/mcp.json", StatusFail)
	wantStatus(t, checks, "vscode/Copilot", StatusInfo)
}

func TestCheckVSCodeNotRegistered(t *testing.T) {
	stable, insiders := t.TempDir(), t.TempDir()
	for _, root := range []string{stable, insiders} {
		mustWrite(t, filepath.Join(root, "User", "settings.json"), `{}`)
	}
	stubVSCode(t, []vscodeVariant{{Name: "VS Code", Root: stable}, {Name: "VS Code Insiders", Root: insiders}})

	d := newDoctorRun(DoctorOptions{WorkspaceDir: t.TempDir()})
	checkVSCode(d, "/plugin", false)
	checks := checkMap(d.report)

	if c := wantStatus(t, checks, "vscode/VS Code", StatusWarn); !strings.Contains(c.Remediation, "armis-cli install") {
		t.Errorf("stable hint = %q", c.Remediation)
	}
	if c := wantStatus(t, checks, "vscode/VS Code Insiders", StatusWarn); !strings.Contains(c.Remediation, `"envFile"`) {
		t.Errorf("insiders hint = %q, want a paste-in snippet", c.Remediation)
	}
	wantStatus(t, checks, "vscode/VS Code settings", StatusOK)
}

func TestCheckVSCodeSkipsManifestConfig(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "User", "mcp.json"), `{"servers": {"armis-appsec": {"command": "/no/such/python"}}}`)
	stubVSCode(t, []vscodeVariant{{Name: "VS Code", Root: root}})

	d := newDoctorRun(DoctorOptions{WorkspaceDir: t.TempDir()})
	d.manifestConfigs[filepath.Clean(filepath.Join(root, "User", "mcp.json"))] = true
	checkVSCode(d, "/plugin", true)
	if _, ok := checkMap(d.report)["vscode/VS Code (user mcp.json)"]; ok {
		t.Error("config already covered by the manifest check was reported again")
	}
}

func TestCheckVSCodeNoVSCode(t *testing.T) {
	stubVSCode(t, nil)
	d := newDoctorRun(DoctorOptions{})
	checkVSCode(d, "/plugin", false)
	if len(d.report.Checks) != 0 {
		t.Errorf("checks = %+v, want none when VS Code isn't installed or registered", d.report.Checks)
	}
}

func TestCheckVSCodeLog(t *testing.T) {
	logName := "mcpServer.mcp.config.usrlocal.armis-appsec.log"
	tests := []struct {
		name    string
		content string
		want    CheckStatus
		detail  string
	}{
		{"error after start", "[info] Connection state: Running\n[error] Connection state: Error Process exited with code 1\n", StatusWarn, "exited with code 1"},
		{"recovered", "[error] spawn ENOENT\n[info] Connection state: Running\n", StatusOK, "no errors"},
		{"empty", "", StatusInfo, "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			mustWrite(t, filepath.Join(root, "logs", "20260101T000000", "window1", logName), "stale")
			mustWrite(t, filepath.Join(root, "logs", "20260102T000000", "window1", logName), tt.content)
			old := time.Now().Add(-time.Hour)
			_ = os.Chtimes(filepath.Join(root, "logs", "20260101T000000", "window1", logName), old, old)

			report := &DoctorReport{}
			checkVSCodeLog(report, vscodeVariant{Name: "VS Code", Root: root})
			c := wantStatus(t, checkMap(report), "vscode/VS Code log", tt.want)
			if !strings.Contains(c.Detail, tt.detail) {
				t.Errorf("detail = %q, want %q", c.Detail, tt.detail)
			}
		})
	}
}

func TestPolicyProblems(t *testing.T) {
	out := "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\VSCode\r\n" +
		"    ChatMCP    REG_SZ    registry\r\n" +
		"    ChatAgentMode    REG_DWORD    0x0\r\n" +
		"    UpdateMode    REG_SZ    none\r\n"
	values := parseRegQuery(out)
	if values["ChatMCP"] != "registry" || values["ChatAgentMode"] != "0x0" {
		t.Fatalf("parseRegQuery() = %v", values)
	}
	problems := policyProblems("HKLM", values)
	if len(problems) != 2 {
		t.Errorf("policyProblems() = %v, want ChatMCP and ChatAgentMode", problems)
	}
	if p := policyProblems("HKLM", map[string]string{"ChatMCP": "all", "ChatAgentMode": "0x1"}); len(p) != 0 {
		t.Errorf("policyProblems() for permissive policy = %v", p)
	}
}

func TestWriteSupportBundleScrubsSecrets(t *testing.T) {
	report := &DoctorReport{secrets: []string{"super-secret-value"}}
	report.add("scanner", "live handshake", StatusFail, "auth failed for super-secret-value")
	report.artifact("stderr/x.txt", "Traceback: token super-secret-value rejected\n")
	report.artifact("system.txt", "os: windows/amd64\n")

	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := WriteSupportBundle(report, path, "1.2.3"); err != nil {
		t.Fatalf("WriteSupportBundle() error = %v", err)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()

	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if strings.Contains(string(b), "super-secret-value") {
			t.Errorf("%s contains the secret: %s", f.Name, b)
		}
		if f.Name == "report.json" {
			var decoded DoctorReport
			if err := json.Unmarshal(b, &decoded); err != nil || len(decoded.Checks) != 1 {
				t.Errorf("report.json = %s (err %v)", b, err)
			}
		}
	}
	for _, want := range []string{"report.json", "README.txt", "stderr/x.txt", "system.txt"} {
		if !names[want] {
			t.Errorf("bundle missing %s; has %v", want, names)
		}
	}
}

func TestMaskURLUserinfo(t *testing.T) {
	if got := maskURLUserinfo("http://user:pw@proxy:8080"); got != "http://***@proxy:8080" {
		t.Errorf("maskURLUserinfo() = %q", got)
	}
}

func TestSetEnvFileVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	mustWrite(t, path, "\xEF\xBB\xBF# creds\r\nARMIS_CLIENT_ID=old\r\nSSL_CERT_FILE=/ca.pem\r\n")

	if err := SetEnvFileVars(path, [][2]string{{"ARMIS_CLIENT_ID", "new"}, {"HTTPS_PROXY", "http://p:8080"}}); err != nil {
		t.Fatalf("SetEnvFileVars() error = %v", err)
	}
	b, _ := os.ReadFile(path) //nolint:gosec // test temp dir
	want := "# creds\nARMIS_CLIENT_ID=new\nSSL_CERT_FILE=/ca.pem\nHTTPS_PROXY=http://p:8080\n"
	if string(b) != want {
		t.Errorf("content = %q, want %q", b, want)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("no backup written: %v", err)
	}
	if err := SetEnvFileVars(path, [][2]string{{"X", "a\nB=c"}}); err == nil {
		t.Error("SetEnvFileVars() accepted a value with a newline")
	}
}

// TestWriteEnvFromValuesKeepsOtherVars pins that re-entering credentials
// doesn't drop a proxy or CA setting the doctor (or the user) added.
func TestWriteEnvFromValuesKeepsOtherVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	mustWrite(t, path, "ARMIS_CLIENT_ID=a\nARMIS_CLIENT_SECRET=b\nHTTPS_PROXY=http://p:8080\n")
	if err := WriteEnvFromValues(path, "c", "d"); err != nil {
		t.Fatal(err)
	}
	env, _ := parseEnvFile(path)
	if env["ARMIS_CLIENT_ID"] != "c" || env["ARMIS_CLIENT_SECRET"] != "d" || env["HTTPS_PROXY"] != "http://p:8080" {
		t.Errorf("env = %v", env)
	}
}

// stubNetwork replaces the network probe and system proxy lookup. probe
// receives the env the probe would run with.
func stubNetwork(t *testing.T, proxy string, probe func(env map[string]string) (string, error)) {
	t.Helper()
	origProbe, origLookup := networkProbe, systemProxyLookup
	networkProbe = func(_ string, env map[string]string, _ string, _ time.Duration) (string, error) { return probe(env) }
	systemProxyLookup = func(string) string { return proxy }
	t.Cleanup(func() { networkProbe, systemProxyLookup = origProbe, origLookup })
}

func TestCheckServerNetworkProxyFix(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "SSL_CERT_FILE"} {
		t.Setenv(k, "")
	}
	connectErr := errors.New("ERR ConnectError [Errno 11001] getaddrinfo failed (CA: certifi)")
	viaProxy := func(env map[string]string) (string, error) {
		if env["HTTPS_PROXY"] != "" {
			return "HTTP 401 (CA: certifi)", nil
		}
		return connectErr.Error(), connectErr
	}

	t.Run("system proxy works", func(t *testing.T) {
		stubNetwork(t, "http://user:pw@proxy.corp:8080", viaProxy)
		envFile := filepath.Join(t.TempDir(), ".env")
		mustWrite(t, envFile, "ARMIS_CLIENT_ID=id\n")

		d := newDoctorRun(DoctorOptions{})
		checkServerNetwork(d, "scanner", "python", map[string]string{}, envFile)
		c := wantStatus(t, checkMap(d.report), "scanner/server network", StatusFail)
		if c.Fix != FixSetProxy || strings.Contains(c.Remediation, "pw") {
			t.Errorf("check = %+v, want FixSetProxy with the password masked", c)
		}
		if f := d.report.Fixes(); len(f) != 1 || f[0] != FixSetProxy {
			t.Fatalf("Fixes() = %v", f)
		}
		desc, err := d.report.ApplyEnvFix()
		if err != nil || strings.Contains(desc, "pw") {
			t.Fatalf("ApplyEnvFix() = %q, %v", desc, err)
		}
		env, _ := parseEnvFile(envFile)
		if env["HTTPS_PROXY"] != "http://user:pw@proxy.corp:8080" || env["ARMIS_CLIENT_ID"] != "id" { // #nosec G101 -- test fixture
			t.Errorf(".env after fix = %v", env)
		}
	})

	t.Run("system proxy also fails", func(t *testing.T) {
		stubNetwork(t, "http://proxy.corp:8080", func(map[string]string) (string, error) { return connectErr.Error(), connectErr })
		d := newDoctorRun(DoctorOptions{})
		checkServerNetwork(d, "scanner", "python", map[string]string{}, "/p/.env")
		c := wantStatus(t, checkMap(d.report), "scanner/server network", StatusFail)
		if c.Fix != FixNone || !strings.Contains(c.Remediation, "also failed") {
			t.Errorf("check = %+v", c)
		}
	})

	t.Run("proxy already configured", func(t *testing.T) {
		stubNetwork(t, "http://proxy.corp:8080", viaProxy)
		d := newDoctorRun(DoctorOptions{})
		checkServerNetwork(d, "scanner", "python", map[string]string{"HTTPS_PROXY": "http://other:1"}, "/p/.env")
		if c := checkMap(d.report)["scanner/server network"]; c.Fix != FixNone {
			t.Errorf("proxy fix offered although HTTPS_PROXY is set: %+v", c)
		}
	})

	t.Run("reachable", func(t *testing.T) {
		stubNetwork(t, "", func(map[string]string) (string, error) { return "HTTP 401 (CA: system store)", nil })
		d := newDoctorRun(DoctorOptions{})
		checkServerNetwork(d, "scanner", "python", map[string]string{}, "/p/.env")
		wantStatus(t, checkMap(d.report), "scanner/server network", StatusOK)
	})
}

func TestNetworkHintTLSByCASource(t *testing.T) {
	old := networkHint("ERR ConnectError [SSL: CERTIFICATE_VERIFY_FAILED] (CA: certifi)", "/p/.env")
	if !strings.Contains(old, "armis-cli mcp update") {
		t.Errorf("certifi hint = %q, want update suggestion", old)
	}
	sys := networkHint("ERR ConnectError [SSL: CERTIFICATE_VERIFY_FAILED] (CA: system store)", "/p/.env")
	if strings.Contains(sys, "mcp update") || !strings.Contains(sys, "system certificate store") {
		t.Errorf("system-store hint = %q", sys)
	}
}

func TestIsConnectFailure(t *testing.T) {
	for out, want := range map[string]bool{
		"ERR ConnectError [Errno 11001] getaddrinfo failed":                           true,
		"ERR ConnectTimeout timed out":                                                true,
		"ERR ConnectError [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed": false,
		"ERR ProxyError 407":                                                          false,
	} {
		if got := isConnectFailure(out); got != want {
			t.Errorf("isConnectFailure(%q) = %v, want %v", out, got, want)
		}
	}
}
