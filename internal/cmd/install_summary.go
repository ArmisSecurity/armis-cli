package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

const (
	serverScanner   = "armis-appsec"
	serverKnowledge = "armis-knowledge"
)

// installSummary is what an install run registered, for the closing summary.
type installSummary struct {
	targets knowledgeTargets
	// knowledge lists the agents (by display name) the knowledge bridge was
	// registered in; empty when it wasn't installed.
	knowledge []string
}

// printInstallSummary lists every MCP server written, per agent with the
// config file it went into, and how to confirm the editor actually loaded it.
func printInstallSummary(w io.Writer, s installSummary) {
	if !s.targets.hasWork() {
		return
	}
	withKnowledge := make(map[string]bool, len(s.knowledge))
	for _, n := range s.knowledge {
		withKnowledge[n] = true
	}
	serversFor := func(name string) string {
		if withKnowledge[name] {
			return serverScanner + ", " + serverKnowledge
		}
		return serverScanner
	}

	type row struct{ name, path string }
	var rows []row
	editors := append([]install.Editor(nil), s.targets.editors...)
	sort.Slice(editors, func(i, j int) bool { return editors[i].Name < editors[j].Name })
	hasVSCode := false
	for _, e := range editors {
		rows = append(rows, row{e.Name, e.ConfigPath()})
		if e.ID == install.EditorVSCode {
			hasVSCode = true
		}
	}
	if s.targets.claude {
		rows = append(rows, row{"Claude Code", "plugin registry (~/.claude)"})
	}
	if s.targets.codex {
		rows = append(rows, row{"Codex CLI", install.CodexConfigPath()})
	}

	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "MCP servers written:")
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %s\n      servers: %s\n      config:  %s\n", r.name, serversFor(r.name), r.path)
	}
	if len(s.knowledge) > 0 {
		_, _ = fmt.Fprintf(w, "  %s is a separate server from %s, with its own credentials file.\n", serverKnowledge, serverScanner)
	}

	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "To verify:")
	_, _ = fmt.Fprintln(w, "  1. Restart your editors.")
	if hasVSCode {
		_, _ = fmt.Fprintf(w, "  2. VS Code: Command Palette > \"MCP: List Servers\" — %s should be listed and Running.\n", strings.Join(serverNames(len(s.knowledge) > 0), " and "))
		_, _ = fmt.Fprintln(w, "     Then use Copilot Chat in Agent mode. Being written to mcp.json doesn't mean VS Code loaded the server:")
		_, _ = fmt.Fprintln(w, "     if it is missing or blocked, open Output > MCP, and ask your GitHub organization admin whether the")
		_, _ = fmt.Fprintln(w, "     \"MCP servers in Copilot\" policy is enabled.")
		_, _ = fmt.Fprintln(w, "  3. Run: armis-cli mcp doctor")
	} else {
		_, _ = fmt.Fprintln(w, "  2. Run: armis-cli mcp doctor")
	}
}

func serverNames(withKnowledge bool) []string {
	if withKnowledge {
		return []string{serverScanner, serverKnowledge}
	}
	return []string{serverScanner}
}
