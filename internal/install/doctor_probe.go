package install

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// maxStderrCapture bounds how much of a spawned server's stderr the doctor
// keeps for the support bundle (CWE-770).
const maxStderrCapture = 64 << 10 // 64 KB

// slowStartThreshold is the handshake latency above which the doctor warns
// that the server starts slowly — typically real-time antivirus scanning the
// venv on first launch.
const slowStartThreshold = 5 * time.Second

// debugConfigTool is the scanner's diagnostic tool; calling it proves the
// server executes tool calls end to end, not just the handshake.
const debugConfigTool = "debug_config"

// serverLaunch is everything needed to start an MCP stdio server the way an
// editor would: the command, its arguments, and the environment the editor
// adds on top of its own (envFile contents plus inline env).
type serverLaunch struct {
	Command string
	Args    []string
	EnvFile string
	Env     map[string]string
}

// key identifies launches that would behave identically, so the doctor spawns
// each distinct configuration only once.
func (l serverLaunch) key() string {
	keys := make([]string, 0, len(l.Env))
	for k := range l.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(l.Command)
	for _, a := range l.Args {
		b.WriteString("\x00" + a)
	}
	b.WriteString("\x00envFile=" + l.EnvFile)
	for _, k := range keys {
		b.WriteString("\x00" + k + "=" + l.Env[k])
	}
	return b.String()
}

// commandLine renders the launch as a command the user can paste into a
// terminal to reproduce the failure.
func (l serverLaunch) commandLine() string {
	parts := make([]string, 0, len(l.Args)+1)
	for _, p := range append([]string{l.Command}, l.Args...) {
		if strings.ContainsAny(p, " \t") {
			p = `"` + p + `"`
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}

// probeResult is what a live MCP session with the server reported.
type probeResult struct {
	ServerName    string
	ServerVersion string
	Tools         []string
	ToolsErr      error
	DebugConfig   string
	DebugErr      error
}

type mcpInitResult struct {
	ServerInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

// mcpHandshake spawns command as an MCP stdio server and runs a short session:
// initialize, then tools/list, then (when the server offers it) a
// debug_config tool call. Only the initialize step decides the returned
// error; later steps report their own errors on the result so the caller can
// tell "won't start" apart from "starts but tools are broken".
//
// The process is always killed and waited-on before returning, so stderr can
// be read back safely (os/exec only finishes copying stderr into the buffer
// once Wait returns). The returned string is the full (capped) stderr.
func mcpHandshake(command string, args []string, env map[string]string, timeout time.Duration) (*probeResult, string, error) {
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}

	// armis:ignore cwe:78 cwe:88 reason:command/args come from the CLI's own recorded install paths or the user's own editor config, not remote input
	cmd := exec.Command(command, args...) //nolint:gosec // command/args are the CLI's own recorded install paths / user's editor config
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
		_ = stdin.Close()
		return nil, "", fmt.Errorf("opening stdout: %w", err)
	}
	stderrBuf := &cappedBuffer{max: maxStderrCapture}
	cmd.Stderr = stderrBuf

	// Start() failing means Wait() will never run to close these pipes for us
	// (that cleanup is documented as conditional on a successful Start), so
	// close them ourselves rather than leaking the file descriptors.
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, "", fmt.Errorf("starting process: %w", err)
	}

	result, opErr := runMCPSession(stdin, stdout, timeout)

	// armis:ignore cwe:404 reason:best-effort cleanup of a short-lived diagnostic subprocess we just spawned
	_ = cmd.Process.Kill()
	// On the timeout path, the session's reader goroutine may still be
	// blocked reading stdout when we get here. os/exec's docs warn it is
	// "incorrect to call Wait before all reads from the pipe have completed"
	// because Wait closes this same pipe as part of its own cleanup — close
	// it here first so the unblock is explicit and ordered rather than racing
	// Wait's internal close.
	_ = stdout.Close()
	_ = stdin.Close()
	_ = cmd.Wait()

	stderr := strings.TrimSpace(stderrBuf.String())
	if opErr != nil {
		return nil, stderr, opErr
	}
	return result, stderr, nil
}

// rpcMessage is a JSON-RPC response or notification read from the server.
type rpcMessage struct {
	ID     *int            `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// mcpSession drives JSON-RPC over the server's stdio. Every read shares one
// deadline so a hung server can't stretch the doctor past its timeout.
type mcpSession struct {
	stdin    io.Writer
	lines    chan []byte
	readErr  chan error
	deadline time.Time
}

func runMCPSession(stdin io.WriteCloser, stdout io.ReadCloser, timeout time.Duration) (*probeResult, error) {
	s := &mcpSession{
		stdin:    stdin,
		lines:    make(chan []byte, 16),
		readErr:  make(chan error, 1),
		deadline: time.Now().Add(timeout),
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), maxHandshakeLineSize)
		for scanner.Scan() {
			s.lines <- append([]byte(nil), scanner.Bytes()...)
		}
		s.readErr <- scanner.Err()
	}()

	initRaw, err := s.call(1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{jsonKeyName: "armis-cli-doctor", jsonKeyVersion: "1.0"},
	}, timeout)
	if err != nil {
		return nil, err
	}
	var init mcpInitResult
	if err := json.Unmarshal(initRaw, &init); err != nil {
		return nil, fmt.Errorf("invalid initialize result: %w", err)
	}
	res := &probeResult{ServerName: init.ServerInfo.Name, ServerVersion: init.ServerInfo.Version}

	if err := s.notify("notifications/initialized"); err != nil {
		res.ToolsErr = err
		return res, nil
	}

	toolsRaw, err := s.call(2, "tools/list", map[string]interface{}{}, timeout)
	if err != nil {
		res.ToolsErr = err
		return res, nil
	}
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		res.ToolsErr = fmt.Errorf("invalid tools/list result: %w", err)
		return res, nil
	}
	for _, t := range tools.Tools {
		res.Tools = append(res.Tools, t.Name)
	}

	for _, name := range res.Tools {
		if name != debugConfigTool {
			continue
		}
		callRaw, err := s.call(3, "tools/call", map[string]interface{}{
			jsonKeyName: debugConfigTool,
			"arguments": map[string]interface{}{},
		}, timeout)
		if err != nil {
			res.DebugErr = err
			break
		}
		text, isErr := toolCallText(callRaw)
		if isErr {
			res.DebugErr = fmt.Errorf("tool returned an error: %s", text)
		}
		res.DebugConfig = text
		break
	}
	return res, nil
}

func (s *mcpSession) notify(method string) error {
	b, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": method})
	if err != nil {
		return err
	}
	if _, err := s.stdin.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("writing %s: %w", method, err)
	}
	return nil
}

// call sends a request and waits for the response carrying the same id,
// skipping notifications and log lines the server may interleave.
func (s *mcpSession) call(id int, method string, params interface{}, timeout time.Duration) (json.RawMessage, error) {
	b, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	if _, err := s.stdin.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("writing %s request: %w", method, err)
	}

	wait := time.Until(s.deadline)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return nil, fmt.Errorf("timed out waiting for %s response after %s", method, wait.Round(time.Millisecond))
		case err := <-s.readErr:
			s.readErr <- err // keep it for any later call
			if errors.Is(err, bufio.ErrTooLong) {
				return nil, fmt.Errorf("response exceeded %d bytes", maxHandshakeLineSize)
			}
			if err != nil {
				return nil, fmt.Errorf("no response to %s: %w", method, err)
			}
			return nil, fmt.Errorf("no response to %s: server exited", method)
		case line := <-s.lines:
			var msg rpcMessage
			if err := json.Unmarshal(line, &msg); err != nil {
				if id == 1 {
					// Anything but JSON on stdout before initialize means the
					// server (or a wrapper script) is printing to stdout,
					// which corrupts the MCP stream for every client.
					return nil, fmt.Errorf("invalid response (non-JSON on stdout: %q): %w", truncate(string(line), 120), err)
				}
				continue
			}
			if msg.ID == nil || *msg.ID != id {
				continue
			}
			if msg.Error != nil {
				return nil, fmt.Errorf("server returned error: %s", msg.Error.Message)
			}
			if len(msg.Result) == 0 || string(msg.Result) == "null" {
				return nil, fmt.Errorf("response missing result")
			}
			return msg.Result, nil
		}
	}
}

// toolCallText joins the text content blocks of a tools/call result.
func toolCallText(raw json.RawMessage) (string, bool) {
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", true
	}
	var parts []string
	for _, c := range r.Content {
		if c.Type == "text" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, "\n"), r.IsError
}

// cappedBuffer keeps the last max bytes written to it.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	c.buf.Write(p)
	if over := c.buf.Len() - c.max; over > 0 {
		c.buf.Next(over)
	}
	return n, nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// tail returns the last n bytes of s.
func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

// launchHint maps a failed launch to a remediation and, when the CLI can
// repair it itself, the fix action. It recognizes the failures most common on
// Windows, where they otherwise surface as an opaque process error.
func launchHint(err error, stderr string, launch serverLaunch) (string, FixAction) {
	msg := strings.ToLower(err.Error())
	se := strings.ToLower(stderr)
	manual := "To see the full error, run the server by hand: " + launch.commandLine()

	switch {
	case strings.Contains(se, "no python at"):
		return "The venv's base Python interpreter was removed or moved (e.g. Python was uninstalled or upgraded). The venv must be rebuilt.", FixReinstall
	case strings.Contains(se, "modulenotfounderror") || strings.Contains(se, "importerror"):
		return "The server's Python dependencies are missing or broken. The venv must be rebuilt.", FixReinstall
	case strings.Contains(msg, "executable file not found") || strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "cannot find the file") || strings.Contains(msg, "cannot find the path"):
		return "The server's Python interpreter is missing.", FixReinstall
	case strings.Contains(msg, "virus") || strings.Contains(msg, "potentially unwanted"):
		return "Antivirus blocked or quarantined the server's python.exe. Ask IT to allow " + launch.Command + " and re-run with --fix.", FixNone
	case strings.Contains(msg, "access is denied") || strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "blocked by group policy") || strings.Contains(msg, "operation did not complete"):
		return "The OS refused to start " + launch.Command + ". On managed Windows machines this is usually AppLocker, WDAC, or antivirus blocking executables under your user profile — ask IT to allow it. " + manual, FixNone
	case strings.Contains(msg, "timed out"):
		return "The server didn't answer in time. First start after install or an antivirus scan can be slow: retry with --timeout 60s. If it's slow every time, ask IT to exclude the plugin directory from real-time scanning. " + manual, FixNone
	case strings.Contains(msg, "non-json on stdout"):
		return "Something prints to stdout before the MCP stream starts, which breaks every MCP client. " + manual, FixNone
	}
	return manual, FixNone
}

// --- Server-runtime network probe ---

// networkProbeScript makes one HTTPS request with the same library (httpx) and
// defaults (certifi CA bundle, HTTPS_PROXY/SSL_CERT_FILE from the environment)
// the MCP server uses. The CLI's own Go HTTP stack uses the OS certificate
// store and PAC proxy settings, so a Go-side check can pass while the server
// fails — this probe measures what the server will actually experience.
//
// Newer plugin versions trust the OS certificate store via truststore unless
// SSL_CERT_FILE is set; the probe does the same when truststore is installed
// in the venv, and reports which CA source it used.
const networkProbeScript = `import os, sys
ca = "certifi"
if os.environ.get("SSL_CERT_FILE"):
    ca = "SSL_CERT_FILE"
else:
    try:
        import truststore
        truststore.inject_into_ssl()
        ca = "system store"
    except Exception:
        pass
try:
    import httpx
    r = httpx.get(sys.argv[1], timeout=15)
    print("HTTP", r.status_code, "(CA: " + ca + ")")
except Exception as e:
    print("ERR", type(e).__name__, str(e)[:500], "(CA: " + ca + ")")
    sys.exit(1)
`

// systemProxyScript prints the HTTPS proxy the OS is configured with
// (Windows registry / macOS System Settings), as Python's urllib sees it.
// PAC-only configurations aren't visible this way.
const systemProxyScript = `import urllib.request
p = urllib.request.getproxies()
print(p.get("https") or p.get("http") or "")
`

// networkProbe and systemProxyLookup are vars so tests can stub them.
var (
	networkProbe      = runNetworkProbe
	systemProxyLookup = lookupSystemProxy
)

// lookupSystemProxy returns the OS-configured proxy URL, or "" if none.
func lookupSystemProxy(python string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// armis:ignore cwe:78 cwe:88 reason:python is the CLI's own recorded venv interpreter; the script is a constant
	out, err := exec.CommandContext(ctx, python, "-c", systemProxyScript).Output() //nolint:gosec // constant script, venv interpreter
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(out))
	if p != "" && !strings.Contains(p, "://") {
		p = "http://" + p
	}
	return p
}

// envHTTPSProxy is the proxy variable the server's HTTP client reads.
const envHTTPSProxy = "HTTPS_PROXY"

// hasProxyEnv reports whether a proxy is already configured for the server,
// either in its env file or the inherited environment.
func hasProxyEnv(env map[string]string) bool {
	for _, k := range []string{envHTTPSProxy, "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if env[k] != "" || os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// isConnectFailure reports whether probe output is a connection-level
// failure (as opposed to TLS or HTTP errors) that a proxy could explain.
func isConnectFailure(output string) bool {
	o := strings.ToLower(output)
	for _, s := range []string{"connecterror", "connecttimeout", "timed out", "getaddrinfo", "name or service not known", "nodename", "network is unreachable", "connection refused"} {
		if strings.Contains(o, s) && !strings.Contains(o, "certificate") {
			return true
		}
	}
	return false
}

const (
	appsecProdURL = "https://moose.armis.com/api/v1"
	appsecDevURL  = "https://moose-dev.armis.com/api/v1"
)

// serverAPIURL resolves the API URL the scanner server will call, mirroring
// scanner_core.py: APPSEC_API_URL wins, else APPSEC_ENV picks dev or prod.
func serverAPIURL(env map[string]string) string {
	get := func(k string) string {
		if v := env[k]; v != "" {
			return v
		}
		return os.Getenv(k)
	}
	if u := get("APPSEC_API_URL"); u != "" {
		return u
	}
	if strings.EqualFold(get("APPSEC_ENV"), "dev") {
		return appsecDevURL
	}
	return appsecProdURL
}

// runNetworkProbe runs networkProbeScript with the server's interpreter and
// environment and returns its single line of output.
func runNetworkProbe(python string, env map[string]string, url string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// armis:ignore cwe:78 cwe:88 reason:python is the CLI's own recorded venv interpreter; the script is a constant and url is passed as a separate argv element
	cmd := exec.CommandContext(ctx, python, "-c", networkProbeScript, url) //nolint:gosec // constant script, venv interpreter
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdout := &cappedBuffer{max: 4096}
	stderr := &cappedBuffer{max: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	result := strings.TrimSpace(stdout.String())
	if ctx.Err() != nil {
		return result, fmt.Errorf("timed out after %s", timeout)
	}
	if err != nil {
		if result == "" {
			result = tail(stderr.String(), 500)
		}
		if result == "" {
			result = err.Error()
		}
		return result, errors.New(result)
	}
	return result, nil
}

// networkHint maps a failed network probe to a remediation. envFile is where
// the server reads extra environment variables from.
func networkHint(output, envFile string) string {
	o := strings.ToLower(output)
	switch {
	case strings.Contains(o, "certificate_verify_failed") || strings.Contains(o, "certificate verify failed") ||
		strings.Contains(o, "self-signed") || strings.Contains(o, "unable to get local issuer"):
		if strings.Contains(o, "(ca: certifi)") {
			return "Your network re-signs HTTPS traffic (TLS inspection, e.g. Zscaler or Netskope) and this version of the MCP server doesn't trust that certificate — it uses its own CA bundle, not the Windows certificate store. " +
				"Update the server (armis-cli mcp update) to a version that uses the system certificate store, or export your organization's root CA as a PEM (Base-64 .cer) file and add SSL_CERT_FILE=<path to that file> to " + envFile + ", then restart VS Code."
		}
		return "The server's Python runtime doesn't trust the certificate the Armis API presented, even with the system certificate store. If your network uses TLS inspection, ask IT to install the inspection root CA in the system certificate store, or export it as a PEM file and add SSL_CERT_FILE=<path to that file> to " + envFile + ", then restart VS Code."
	case strings.Contains(o, "proxyerror") || strings.Contains(o, "407"):
		return "The proxy rejected the request. Check the HTTPS_PROXY value in " + envFile + " (including credentials if your proxy requires them)."
	case strings.Contains(o, "connecterror") || strings.Contains(o, "connecttimeout") || strings.Contains(o, "timed out") ||
		strings.Contains(o, "getaddrinfo") || strings.Contains(o, "name or service not known") || strings.Contains(o, "nodename"):
		return "The server's Python runtime can't reach the Armis API. Python ignores Windows proxy/PAC settings: if you're behind a corporate proxy, add HTTPS_PROXY=http://<proxy-host>:<port> to " + envFile + " and restart VS Code."
	}
	return "The server's Python runtime couldn't reach the Armis API. Add HTTPS_PROXY / SSL_CERT_FILE to " + envFile + " if your network requires a proxy or TLS inspection."
}
