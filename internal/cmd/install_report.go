package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

const (
	formatHuman = "human"
	formatJSON  = "json"

	reportOK   = "ok"
	reportFail = "fail"
	reportWarn = "warn"
	reportSkip = "skip"

	credsWritten = "written"
	credsKept    = "kept"
	credsRotated = "rotated"
	credsNone    = "none"
	credsFailed  = "failed"

	pluginReportName = "armis-appsec-mcp"
)

// installOptions carries the flags shared by the install paths.
type installOptions struct {
	force             bool
	withKnowledge     bool
	rotateCredentials bool
	// jetbrainsProject is the project directory for the jetbrains target.
	jetbrainsProject string
	format           string
	// stdout receives the JSON document; nil means os.Stdout.
	stdout io.Writer
}

func (o installOptions) json() bool { return o.format == formatJSON }

func (o installOptions) out() io.Writer {
	if o.stdout != nil {
		return o.stdout
	}
	return os.Stdout
}

// parseOutputFormat validates a --format value for install and uninstall.
func parseOutputFormat(v string) (string, error) {
	switch v {
	case formatHuman, formatJSON:
		return v, nil
	default:
		return "", fmt.Errorf("invalid --format value %q: must be human or json", v)
	}
}

type hookReport struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type clientReport struct {
	Client string      `json:"client"`
	Label  string      `json:"label"`
	Status string      `json:"status"`
	Detail string      `json:"detail,omitempty"`
	Files  []string    `json:"files,omitempty"`
	Hook   *hookReport `json:"hook,omitempty"`
}

type pluginReport struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Path           string `json:"path"`
	AlreadyCurrent bool   `json:"already_current"`
	Pinned         bool   `json:"pinned"`
}

type knowledgeReport struct {
	Status     string   `json:"status"`
	Version    string   `json:"version,omitempty"`
	UpToDate   bool     `json:"up_to_date"`
	Registered []string `json:"registered"`
	Warnings   []string `json:"warnings"`
	EnvPath    string   `json:"env_path,omitempty"`
}

type credentialFileReport struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type credentialsReport struct {
	Status string                 `json:"status"`
	Detail string                 `json:"detail,omitempty"`
	Files  []credentialFileReport `json:"files"`
}

// installReport is the machine-readable record of an install run. It is
// filled in alongside the human output and only rendered in JSON mode.
type installReport struct {
	Clients     []*clientReport   `json:"clients"`
	Plugin      *pluginReport     `json:"plugin"`
	Knowledge   *knowledgeReport  `json:"knowledge"`
	Credentials credentialsReport `json:"credentials"`
	Error       string            `json:"error,omitempty"`
}

func newInstallReport() *installReport {
	return &installReport{
		Clients:     []*clientReport{},
		Credentials: credentialsReport{Status: credsNone, Files: []credentialFileReport{}},
	}
}

// client returns the entry for id, creating it on first use.
func (r *installReport) client(id, label string) *clientReport {
	for _, c := range r.Clients {
		if c.Client == id {
			return c
		}
	}
	c := &clientReport{Client: id, Label: label, Status: reportSkip}
	r.Clients = append(r.Clients, c)
	return c
}

// failedTargetsError names every target whose registration failed or whose
// native hook could not be installed, so a partial install exits non-zero.
// It is derived from the recorded client results, which are also what the JSON
// document reports.
func (r *installReport) failedTargetsError() error {
	var failed []string
	for _, c := range r.Clients {
		if c.Status == reportFail {
			failed = append(failed, c.Label)
		}
		if c.Hook != nil && c.Hook.Status == reportWarn {
			failed = append(failed, c.Label+" (hooks)")
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("install failed for: %s", strings.Join(failed, ", "))
}

func (r *installReport) idForLabel(label string) string {
	for _, c := range r.Clients {
		if c.Label == label {
			return c.Client
		}
	}
	return label
}

func (c *clientReport) ok(files ...string) {
	c.Status = reportOK
	c.Detail = ""
	c.Files = files
}

func (c *clientReport) fail(err error) {
	c.Status = reportFail
	c.Detail = err.Error()
}

// setPlugin records the plugin that was installed. The first call wins, so the
// shared plugin is not replaced by the Claude Code cache copy.
func (r *installReport) setPlugin(version, path string, alreadyCurrent bool) {
	if r.Plugin != nil {
		return
	}
	r.Plugin = &pluginReport{Name: pluginReportName, Version: version, Path: path, AlreadyCurrent: alreadyCurrent, Pinned: install.EffectivePin() != ""}
}

func (r *installReport) setKnowledge(res knowledgeResult, envPath string) {
	k := &knowledgeReport{
		Version:    res.shortSHA,
		UpToDate:   res.upToDate,
		Registered: make([]string, 0, len(res.registered)),
		Warnings:   append([]string{}, res.warnings...),
	}
	for _, name := range res.registered {
		k.Registered = append(k.Registered, r.idForLabel(name))
	}
	switch {
	case len(res.registered) > 0 && len(res.warnings) == 0:
		k.Status = reportOK
	case len(res.registered) > 0:
		k.Status = reportWarn
	case res.skipped && len(res.warnings) == 0:
		k.Status = reportSkip
	default:
		k.Status = reportFail
	}
	if res.shortSHA != "" {
		k.EnvPath = envPath
	}
	r.Knowledge = k
}

// registerEditorReported registers the scanner in one editor, prints the
// result line and records it. It reports whether registration succeeded.
func registerEditorReported(rep *installReport, e install.Editor, pluginDir string, manifest *install.Manifest, kt *knowledgeTargets) bool {
	c := rep.client(string(e.ID), e.Name)
	if err := e.Register(pluginDir); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", e.Name, err)
		c.fail(err)
		return false
	}
	fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Name)
	c.ok(e.ConfigPath())
	manifest.AddEditor(e.ID, e.ConfigPath(), install.ConfigFormat(e.ID))
	kt.editors = append(kt.editors, e)
	return true
}

// installEditorHookReported installs the native hook for an editor that has
// one. A failure is a warning: the MCP registration stands without it.
func installEditorHookReported(rep *installReport, e install.Editor, pluginDir string) {
	hc, ok := install.HookClientByID(install.HookClientID(e.ID))
	if !ok {
		return
	}
	c := rep.client(string(e.ID), e.Name)
	if err := install.InstallNativeHook(hc, pluginDir); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ %s (hooks): %v\n", e.Name, err)
		c.Hook = &hookReport{Status: reportWarn, Detail: err.Error()}
		return
	}
	c.Hook = &hookReport{Status: reportOK}
}

// registerCodexReported registers the scanner MCP server and the native hook
// for Codex CLI. It reports whether the MCP registration succeeded.
func registerCodexReported(rep *installReport, pluginDir string, manifest *install.Manifest, kt *knowledgeTargets) bool {
	c := rep.client(targetCodex, "Codex CLI")
	registered := false
	if err := install.RegisterCodexMCP(pluginDir); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Codex CLI (MCP): %v\n", err)
		c.fail(err)
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (MCP)\n")
		c.ok(install.CodexConfigPath())
		manifest.SetCodex(install.CodexConfigPath())
		kt.codex = true
		registered = true
	}
	if hc, ok := install.HookClientByID(install.HookClientCodex); ok {
		if err := install.InstallNativeHook(hc, pluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Codex CLI (hooks): %v\n", err)
			c.Hook = &hookReport{Status: reportWarn, Detail: err.Error()}
		} else {
			fmt.Fprintf(os.Stderr, "  ✓ Codex CLI (hooks)\n")
			c.Hook = &hookReport{Status: reportOK}
		}
	}
	return registered
}

// finishInstall renders the JSON document in JSON mode and passes err through
// so the exit code is unchanged. A fatal error is also carried in the document
// so a caller reading only stdout can tell why it is incomplete.
func finishInstall(opts installOptions, rep *installReport, err error) error {
	if !opts.json() {
		return err
	}
	if err != nil {
		rep.Error = err.Error()
	}
	if werr := writeJSONReport(opts.out(), rep); werr != nil && err == nil {
		return werr
	}
	return err
}

func writeJSONReport(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("writing JSON output: %w", err)
	}
	return nil
}

// credentialTracker follows the .env files an install run manages so their
// outcome can be reported and, on request, rotated.
type credentialTracker struct {
	files []*trackedEnv
}

type trackedEnv struct {
	path    string
	existed bool
	// managed is set once the step that owns the file succeeded; files of a
	// failed or skipped install step are left alone.
	managed bool
}

// watch records whether the file exists before the install step that may
// write it, so call it ahead of that step.
func (t *credentialTracker) watch(path string) *trackedEnv {
	_, err := os.Stat(path)
	f := &trackedEnv{path: path, existed: err == nil}
	t.files = append(t.files, f)
	return f
}

// finish settles every managed file. With rotate set and both credentials in
// the environment it overwrites them; otherwise it only reports what the
// install left behind. The returned error is non-nil only when a requested
// rotation failed, and never contains the secret.
func (t *credentialTracker) finish(rotate bool) (credentialsReport, error) {
	rep := credentialsReport{Status: credsNone, Files: []credentialFileReport{}}

	id := os.Getenv("ARMIS_CLIENT_ID")
	secret := os.Getenv("ARMIS_CLIENT_SECRET")
	canRotate := rotate && id != "" && secret != ""
	if rotate && !canRotate {
		rep.Detail = "ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET are not both set; credentials were not rotated"
		fmt.Fprintf(os.Stderr, "  ⚠ %s\n", rep.Detail)
	}

	failed := 0
	for _, f := range t.files {
		if !f.managed {
			continue
		}
		entry := credentialFileReport{Path: f.path}

		if canRotate {
			outcome, err := install.RotateEnvCredentials(f.path, id, secret)
			switch {
			case err != nil:
				entry.Status = credsFailed
				entry.Detail = err.Error()
				failed++
				fmt.Fprintf(os.Stderr, "  ✗ Credentials not rotated in %s: %v\n", f.path, err)
			case !f.existed:
				entry.Status = credsWritten
			case outcome == install.CredentialsRotated:
				entry.Status = credsRotated
				fmt.Fprintf(os.Stderr, "  ✓ Credentials rotated in %s\n", f.path)
			default:
				entry.Status = credsKept
			}
		} else {
			_, statErr := os.Stat(f.path)
			switch {
			case f.existed:
				entry.Status = credsKept
			case statErr == nil:
				entry.Status = credsWritten
			default:
				entry.Status = credsNone
			}
		}
		rep.Files = append(rep.Files, entry)
	}

	rep.Status = overallCredentialStatus(rep.Files)
	if failed > 0 {
		return rep, fmt.Errorf("rotating credentials failed for %d of %d files", failed, len(rep.Files))
	}
	return rep, nil
}

func overallCredentialStatus(files []credentialFileReport) string {
	var rotated, written, kept bool
	for _, f := range files {
		switch f.Status {
		case credsFailed:
			return credsFailed
		case credsRotated:
			rotated = true
		case credsWritten:
			written = true
		case credsKept:
			kept = true
		}
	}
	switch {
	case rotated:
		return credsRotated
	case written:
		return credsWritten
	case kept:
		return credsKept
	default:
		return credsNone
	}
}
