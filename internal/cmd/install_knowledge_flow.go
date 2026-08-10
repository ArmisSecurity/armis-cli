package cmd

import (
	"errors"
	"fmt"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

// knowledgeTargets is the set of agents knowledge should be registered for —
// always the same set the user picked for the scanner.
type knowledgeTargets struct {
	editors []install.Editor
	claude  bool
	codex   bool
}

// hasWork reports whether any agent was selected.
func (t knowledgeTargets) hasWork() bool {
	return len(t.editors) > 0 || t.claude || t.codex
}

// knowledgeResult summarizes what happened, for the caller to render.
type knowledgeResult struct {
	registered []string
	warnings   []string
	shortSHA   string
	skipped    bool
}

// installKnowledgeFor downloads the knowledge bridge and registers it for the
// given agents, recording the result in m when non-nil.
//
// It never returns an error: knowledge is additive, and the scanner is the
// primary product, so any failure degrades to a warning the caller prints while
// the scanner install stands. Callers must not turn a warning into a non-zero
// exit.
func installKnowledgeFor(t knowledgeTargets, force bool, m *install.Manifest) knowledgeResult {
	var res knowledgeResult

	if !t.hasWork() {
		res.skipped = true
		return res
	}

	ki := install.NewKnowledgeMCPInstaller(knowledgeEnvForDev(useDev))

	if err := ki.Fetch(force); err != nil && !errors.Is(err, install.ErrAlreadyCurrent) {
		res.skipped = true
		res.warnings = append(res.warnings, fmt.Sprintf("Knowledge: %v", err))
		return res
	}
	res.shortSHA = ki.ShortSHA()

	var mk *install.ManifestKnowledge
	if m != nil {
		mk = m.EnsureKnowledge(ki.PluginDir(), ki.InstalledSHA())
	}

	for _, e := range t.editors {
		if err := ki.RegisterEditor(e); err != nil {
			res.warnings = append(res.warnings, fmt.Sprintf("Knowledge %s: %v", e.Name, err))
			continue
		}
		res.registered = append(res.registered, e.Name)
		if mk != nil {
			mk.AddEditor(e.ID, e.ConfigPath(), install.ConfigFormat(e.ID))
		}
	}

	if t.claude {
		if err := ki.RegisterClaude(); err != nil {
			res.warnings = append(res.warnings, fmt.Sprintf("Knowledge Claude Code: %v", err))
		} else {
			res.registered = append(res.registered, "Claude Code")
			if mk != nil {
				mk.SetClaude(ki.ClaudeCacheDir())
			}
		}
	}

	if t.codex {
		if err := ki.RegisterCodex(); err != nil {
			res.warnings = append(res.warnings, fmt.Sprintf("Knowledge Codex CLI: %v", err))
		} else {
			res.registered = append(res.registered, "Codex CLI")
			if mk != nil {
				mk.SetCodex(install.CodexConfigPath())
			}
		}
	}

	return res
}
