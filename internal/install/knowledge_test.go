package install

import (
	"errors"
	"strings"
	"testing"
)

// TestKnowledgePluginName pins the variant×env → plugin-name mapping against the
// exact names declared in the knowledge marketplace.json. If the marketplace
// renames a plugin, this test should fail and be updated in lockstep.
func TestKnowledgePluginName(t *testing.T) {
	cases := []struct {
		variant  KnowledgeVariant
		env      KnowledgeEnv
		wantName string
		wantRef  string
	}{
		{KnowledgeVariantMCP, KnowledgeEnvProd, "armis-knowledge", "armis-knowledge@armis-knowledge"},
		{KnowledgeVariantMCP, KnowledgeEnvStage, "armis-knowledge-stage", "armis-knowledge-stage@armis-knowledge"},
		{KnowledgeVariantMCP, KnowledgeEnvDev, "armis-knowledge-dev", "armis-knowledge-dev@armis-knowledge"},
		{KnowledgeVariantSkills, KnowledgeEnvProd, "armis-knowledge-skills", "armis-knowledge-skills@armis-knowledge"},
		{KnowledgeVariantSkills, KnowledgeEnvStage, "armis-knowledge-skills-stage", "armis-knowledge-skills-stage@armis-knowledge"},
		{KnowledgeVariantSkills, KnowledgeEnvDev, "armis-knowledge-skills-dev", "armis-knowledge-skills-dev@armis-knowledge"},
	}
	for _, tc := range cases {
		ki := NewKnowledgeInstaller(tc.variant, tc.env)
		if got := ki.PluginName(); got != tc.wantName {
			t.Errorf("PluginName(%s,%s) = %q, want %q", tc.variant, tc.env, got, tc.wantName)
		}
		if got := ki.PluginRef(); got != tc.wantRef {
			t.Errorf("PluginRef(%s,%s) = %q, want %q", tc.variant, tc.env, got, tc.wantRef)
		}
	}
}

// fakeRunner records the claude CLI invocations and returns scripted responses
// keyed by the subcommand (args[1], e.g. "marketplace" or "install").
type fakeRunner struct {
	calls   [][]string
	outputs map[string]string
	errs    map[string]error
}

func (f *fakeRunner) run(_ string, args ...string) (string, error) {
	f.calls = append(f.calls, args)
	key := ""
	if len(args) >= 2 {
		key = args[1] // "marketplace", "install", "uninstall", or "list"
	}
	return f.outputs[key], f.errs[key]
}

func newInstallerWithRunner(f *fakeRunner) *KnowledgeInstaller {
	return &KnowledgeInstaller{
		Variant:    KnowledgeVariantSkills,
		Env:        KnowledgeEnvProd,
		claudePath: "/usr/local/bin/claude", // pre-resolved so resolveClaude is a no-op
		runner:     f.run,
	}
}

func TestKnowledgeInstall_HappyPath(t *testing.T) {
	// Empty plugin list → sibling not installed → no swap, just add + install.
	f := &fakeRunner{outputs: map[string]string{}, errs: map[string]error{}}
	ki := newInstallerWithRunner(f)

	replaced, err := ki.Install()
	if err != nil {
		t.Fatalf("Install() = %v, want nil", err)
	}
	if replaced != "" {
		t.Fatalf("Install() replaced = %q, want empty (no sibling installed)", replaced)
	}

	if len(f.calls) != 3 {
		t.Fatalf("expected 3 CLI calls, got %d: %v", len(f.calls), f.calls)
	}
	// First: query for the conflicting sibling variant.
	assertArgs(t, f.calls[0], []string{"plugin", "list"})
	// Then add the marketplace by repo.
	assertArgs(t, f.calls[1], []string{"plugin", "marketplace", "add", knowledgeMarketplaceRepo})
	// Then install the plugin@marketplace ref.
	assertArgs(t, f.calls[2], []string{"plugin", "install", "armis-knowledge-skills@armis-knowledge"})
}

// Installing a variant when its sibling is present swaps the sibling out first.
func TestKnowledgeInstall_SwapsSibling(t *testing.T) {
	// We install skills; the mcp sibling (armis-knowledge@armis-knowledge) is
	// present in the plugin list, so it must be uninstalled before install.
	f := &fakeRunner{
		outputs: map[string]string{"list": "armis-knowledge@armis-knowledge"},
		errs:    map[string]error{},
	}
	ki := newInstallerWithRunner(f) // installs skills (prod)

	replaced, err := ki.Install()
	if err != nil {
		t.Fatalf("Install() = %v, want nil", err)
	}
	if replaced != "armis-knowledge@armis-knowledge" {
		t.Fatalf("Install() replaced = %q, want the mcp sibling ref", replaced)
	}

	// Expect: list, uninstall sibling, marketplace add, install.
	if len(f.calls) != 4 {
		t.Fatalf("expected 4 CLI calls, got %d: %v", len(f.calls), f.calls)
	}
	assertArgs(t, f.calls[0], []string{"plugin", "list"})
	assertArgs(t, f.calls[1], []string{"plugin", "uninstall", "--yes", "armis-knowledge@armis-knowledge"})
	assertArgs(t, f.calls[2], []string{"plugin", "marketplace", "add", knowledgeMarketplaceRepo})
	assertArgs(t, f.calls[3], []string{"plugin", "install", "armis-knowledge-skills@armis-knowledge"})
}

// The plugin-list query must full-match the ref: a bare "armis-knowledge-skills"
// line (this variant, not the sibling) must not be mistaken for the mcp sibling.
func TestKnowledgeInstall_NoFalseSwapOnSubstring(t *testing.T) {
	f := &fakeRunner{
		// Only the skills variant itself is listed; the mcp ref is absent.
		outputs: map[string]string{"list": "armis-knowledge-skills@armis-knowledge"},
		errs:    map[string]error{},
	}
	ki := newInstallerWithRunner(f) // installs skills

	replaced, err := ki.Install()
	if err != nil {
		t.Fatalf("Install() = %v, want nil", err)
	}
	if replaced != "" {
		t.Fatalf("Install() replaced = %q, want empty — sibling is not installed", replaced)
	}
	// No uninstall call should appear.
	for _, c := range f.calls {
		if len(c) >= 2 && c[1] == "uninstall" {
			t.Fatalf("unexpected uninstall call: %v", f.calls)
		}
	}
}

// A marketplace already registered ("add" fails) must not block install.
func TestKnowledgeInstall_MarketplaceAlreadyAdded(t *testing.T) {
	f := &fakeRunner{
		outputs: map[string]string{"marketplace": "marketplace already exists"},
		errs:    map[string]error{"marketplace": errors.New("exit status 1")},
	}
	ki := newInstallerWithRunner(f)

	if _, err := ki.Install(); err != nil {
		t.Fatalf("Install() with pre-existing marketplace = %v, want nil", err)
	}
}

// An install that reports "already installed" via output should be idempotent.
func TestKnowledgeInstall_PluginAlreadyInstalled(t *testing.T) {
	f := &fakeRunner{
		outputs: map[string]string{"install": "Plugin already installed"},
		errs:    map[string]error{"install": errors.New("exit status 1")},
	}
	ki := newInstallerWithRunner(f)

	if _, err := ki.Install(); err != nil {
		t.Fatalf("Install() already-installed = %v, want nil", err)
	}
}

// A genuine install failure surfaces both the install output and (since install
// failed) the marketplace-add output for diagnosis.
func TestKnowledgeInstall_InstallFails(t *testing.T) {
	f := &fakeRunner{
		outputs: map[string]string{
			"marketplace": "could not reach github",
			"install":     "plugin not found in marketplace",
		},
		errs: map[string]error{
			"marketplace": errors.New("exit status 1"),
			"install":     errors.New("exit status 1"),
		},
	}
	ki := newInstallerWithRunner(f)

	_, err := ki.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error")
	}
	if !strings.Contains(err.Error(), "plugin not found in marketplace") {
		t.Errorf("error missing install output: %v", err)
	}
	if !strings.Contains(err.Error(), "could not reach github") {
		t.Errorf("error missing marketplace-add diagnostic: %v", err)
	}
}

// A failing install must preserve the underlying error via %w (errors.Is), and
// still report the sibling ref that was already swapped out before the failure.
func TestKnowledgeInstall_FailurePreservesWrapAndReplaced(t *testing.T) {
	sentinel := errors.New("boom")
	f := &fakeRunner{
		outputs: map[string]string{"list": "armis-knowledge@armis-knowledge"}, // mcp sibling present
		errs:    map[string]error{"install": sentinel},
	}
	ki := newInstallerWithRunner(f) // installs skills; swaps mcp first

	replaced, err := ki.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Install() error does not wrap the install error: %v", err)
	}
	if replaced != "armis-knowledge@armis-knowledge" {
		t.Errorf("replaced = %q, want the swapped-out sibling ref even on failure", replaced)
	}
}

// When marketplace add fails but emits no stdout, the diagnostic must fall back
// to the add error's own message rather than being dropped.
func TestKnowledgeInstall_AddErrFallbackWhenNoOutput(t *testing.T) {
	f := &fakeRunner{
		outputs: map[string]string{"install": "install exploded"}, // addOut empty
		errs: map[string]error{
			"marketplace": errors.New("network is unreachable"),
			"install":     errors.New("exit 1"),
		},
	}
	ki := newInstallerWithRunner(f)

	_, err := ki.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error")
	}
	if !strings.Contains(err.Error(), "network is unreachable") {
		t.Errorf("error missing add-error fallback diagnostic: %v", err)
	}
}

func TestPluginListed(t *testing.T) {
	const skills = "armis-knowledge-skills@armis-knowledge"
	const mcp = "armis-knowledge@armis-knowledge"

	cases := []struct {
		name string
		out  string
		ref  string
		want bool
	}{
		{"exact line", skills, skills, true},
		{"decorated line", "  ❯ " + skills, skills, true},
		{"among many", "foo@bar\n  ❯ " + mcp + "\nbaz@qux", mcp, true},
		{"mcp not matched inside skills line", "  ❯ " + skills, mcp, false},
		{"absent", "other@thing", skills, false},
		{"empty", "", skills, false},
		{"whole token amid prose matches", "Installed " + skills + " successfully", skills, true},
		{"ref only as glued fragment not matched", "see armis-knowledge@armis-knowledgeX for docs", mcp, false},
	}
	for _, tc := range cases {
		if got := pluginListed(tc.out, tc.ref); got != tc.want {
			t.Errorf("%s: pluginListed(%q, %q) = %v, want %v", tc.name, tc.out, tc.ref, got, tc.want)
		}
	}
}

func TestIsAlreadyInstalled(t *testing.T) {
	cases := map[string]bool{
		"Plugin already installed":      true,
		"marketplace already exists":    true,
		"ALREADY INSTALLED (uppercase)": true,
		"Successfully installed plugin": false,
		"error: network unreachable":    false,
		"":                              false,
	}
	for out, want := range cases {
		if got := isAlreadyInstalled(out); got != want {
			t.Errorf("isAlreadyInstalled(%q) = %v, want %v", out, got, want)
		}
	}
}

func TestKnowledgeUninstall_HappyPath(t *testing.T) {
	f := &fakeRunner{outputs: map[string]string{}, errs: map[string]error{}}
	ki := newInstallerWithRunner(f)

	if err := ki.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v, want nil", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected 1 CLI call, got %d: %v", len(f.calls), f.calls)
	}
	assertArgs(t, f.calls[0], []string{"plugin", "uninstall", "--yes", "armis-knowledge-skills@armis-knowledge"})
}

// Uninstalling a plugin that isn't installed is idempotent (treated as success).
func TestKnowledgeUninstall_NotInstalled(t *testing.T) {
	f := &fakeRunner{
		outputs: map[string]string{"uninstall": "Plugin not installed"},
		errs:    map[string]error{"uninstall": errors.New("exit status 1")},
	}
	ki := newInstallerWithRunner(f)

	if err := ki.Uninstall(); err != nil {
		t.Fatalf("Uninstall() not-installed = %v, want nil", err)
	}
}

func TestIsNotInstalled(t *testing.T) {
	cases := map[string]bool{
		"Plugin not installed":     true,
		"plugin not found":         true,
		"Successfully uninstalled": false,
		"error: permission denied": false,
		"":                         false,
	}
	for out, want := range cases {
		if got := isNotInstalled(out); got != want {
			t.Errorf("isNotInstalled(%q) = %v, want %v", out, got, want)
		}
	}
}

func TestResolveClaude_NotFound(t *testing.T) {
	ki := &KnowledgeInstaller{Variant: KnowledgeVariantSkills, Env: KnowledgeEnvProd}
	// Force resolution to fail by pointing findClaude at an empty candidate set.
	orig := claudeCandidates
	claudeCandidates = []string{"definitely-not-a-real-binary-xyz"}
	defer func() { claudeCandidates = orig }()

	err := ki.CheckClaudeCLI()
	if err == nil {
		t.Fatal("CheckClaudeCLI() = nil, want error when claude is absent")
	}
	if !errors.Is(err, ErrClaudeCLINotFound) {
		t.Errorf("CheckClaudeCLI() error = %v, want wrapping ErrClaudeCLINotFound", err)
	}
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
