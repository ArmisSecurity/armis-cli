package cmd

import (
	"io"
	"os"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

type uninstallStep struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type uninstallPluginFiles struct {
	Status          string `json:"status"`
	Detail          string `json:"detail,omitempty"`
	CredentialsKept bool   `json:"credentials_kept"`
}

type uninstallKnowledgeReport struct {
	Status   string   `json:"status"`
	Removed  []string `json:"removed"`
	Warnings []string `json:"warnings"`
}

// uninstallReport is the machine-readable record of an uninstall run. It is
// filled in alongside the human output and only rendered in JSON mode.
type uninstallReport struct {
	Clients     []*clientReport           `json:"clients"`
	Knowledge   *uninstallKnowledgeReport `json:"knowledge"`
	PluginFiles *uninstallPluginFiles     `json:"plugin_files"`
	PreCommit   *uninstallStep            `json:"pre_commit"`
	Warnings    []string                  `json:"warnings"`
	Error       string                    `json:"error,omitempty"`
}

func newUninstallReport() *uninstallReport {
	return &uninstallReport{Clients: []*clientReport{}, Warnings: []string{}}
}

func (r *uninstallReport) client(id, label string) *clientReport {
	return clientEntry(&r.Clients, id, label)
}

func (r *uninstallReport) warned(id, label, detail string) {
	c := r.client(id, label)
	c.Status = reportWarn
	c.Detail = detail
}

func knowledgeUninstallReport(removed, warnings []string) *uninstallKnowledgeReport {
	k := &uninstallKnowledgeReport{Status: reportOK, Removed: append([]string{}, removed...), Warnings: append([]string{}, warnings...)}
	if len(warnings) > 0 {
		k.Status = reportWarn
	}
	return k
}

func (r *uninstallReport) removed(id, label string) {
	c := r.client(id, label)
	c.Status = reportOK
	c.Detail = "removed"
}

func (r *uninstallReport) failed(id, label, detail string) {
	c := r.client(id, label)
	c.Status = reportFail
	c.Detail = detail
}

// hook attaches a hook-removal result to the client it belongs to. A
// successful removal is only recorded for a client already in the report, so
// the document does not list every hook-capable client on every run.
func (r *uninstallReport) hook(hc install.HookClient, err error) {
	id := string(hc.ID)
	if err == nil {
		for _, c := range r.Clients {
			if c.Client == id {
				c.Hook = &hookReport{Status: reportOK}
			}
		}
		return
	}
	r.client(id, hc.Name).Hook = &hookReport{Status: reportWarn, Detail: err.Error()}
}

// editorIDForName resolves a display name from the uninstaller back to a client id.
func editorIDForName(name string) (string, bool) {
	for _, e := range install.AllEditors {
		if e.Name == name {
			return string(e.ID), true
		}
	}
	return "", false
}

// editorWarning records an uninstaller warning of the form "<Name>: <detail>".
func (r *uninstallReport) editorWarning(w string) {
	name, detail, ok := strings.Cut(w, ": ")
	if ok {
		if id, found := editorIDForName(name); found {
			r.failed(id, name, detail)
			return
		}
	}
	r.Warnings = append(r.Warnings, w)
}

func finishUninstall(format string, out io.Writer, rep *uninstallReport, err error) error {
	if format != formatJSON {
		return err
	}
	if out == nil {
		out = os.Stdout
	}
	return finishJSONReport(out, rep, &rep.Error, err)
}
