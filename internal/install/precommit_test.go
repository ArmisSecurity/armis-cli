package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallPreCommit(t *testing.T) {
	t.Run("creates pre-commit hook in empty repo", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		opts := PreCommitOpts{FailOpen: false}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("InstallPreCommit() error = %v", err)
		}

		hookPath := filepath.Join(repoRoot, ".git", "hooks", "pre-commit")
		data, err := os.ReadFile(hookPath) //nolint:gosec // G304: test reading from t.TempDir()
		if err != nil {
			t.Fatalf("reading hook: %v", err)
		}

		content := string(data)
		if !strings.Contains(content, preCommitMarkerStart) {
			t.Error("missing start marker")
		}
		if !strings.Contains(content, preCommitMarkerEnd) {
			t.Error("missing end marker")
		}
		if !strings.Contains(content, "#!/bin/sh") {
			t.Error("missing shebang")
		}

		info, _ := os.Stat(hookPath)
		if info.Mode()&0o111 == 0 {
			t.Error("hook file is not executable")
		}
	})

	t.Run("appends to existing pre-commit hook", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		hookPath := filepath.Join(gitDir, "pre-commit")
		existing := "#!/bin/sh\necho existing hook\n"
		if err := os.WriteFile(hookPath, []byte(existing), 0o755); err != nil { //nolint:gosec // executable hook for test
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		opts := PreCommitOpts{FailOpen: false}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("InstallPreCommit() error = %v", err)
		}

		data, _ := os.ReadFile(hookPath) //nolint:gosec // G304: test reading from t.TempDir()
		content := string(data)
		if !strings.Contains(content, "echo existing hook") {
			t.Error("existing hook content was lost")
		}
		if !strings.Contains(content, preCommitMarkerStart) {
			t.Error("armis section was not appended")
		}
	})

	t.Run("idempotent - does not duplicate", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		opts := PreCommitOpts{FailOpen: false}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("first install: %v", err)
		}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("second install: %v", err)
		}

		hookPath := filepath.Join(gitDir, "pre-commit")
		data, _ := os.ReadFile(hookPath) //nolint:gosec // G304: test reading from t.TempDir()
		count := strings.Count(string(data), preCommitMarkerStart)
		if count != 1 {
			t.Errorf("expected 1 marker, got %d", count)
		}
	})

	t.Run("fail-open mode uses conditional", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		opts := PreCommitOpts{FailOpen: true}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("InstallPreCommit() error = %v", err)
		}

		hookPath := filepath.Join(gitDir, "pre-commit")
		data, _ := os.ReadFile(hookPath) //nolint:gosec // G304: test reading from t.TempDir()
		content := string(data)
		if !strings.Contains(content, "fail-open") {
			t.Error("fail-open mode not reflected in hook content")
		}
		if strings.Contains(content, "exec ") {
			t.Error("fail-open mode should not use exec (would exit on failure)")
		}
	})

	t.Run("fallback when plugin pre-commit not found", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		// Plugin dir without git-hooks/pre-commit
		pluginDir := t.TempDir()

		opts := PreCommitOpts{FailOpen: false}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("InstallPreCommit() error = %v", err)
		}

		hookPath := filepath.Join(gitDir, "pre-commit")
		data, _ := os.ReadFile(hookPath) //nolint:gosec // G304: test reading from t.TempDir()
		content := string(data)
		if !strings.Contains(content, "armis-cli scan repo") {
			t.Error("fallback should call armis-cli directly")
		}
		if !strings.Contains(content, "--changed=staged") {
			t.Error("fallback should use --changed=staged")
		}
	})

	t.Run("creates hooks directory if missing", func(t *testing.T) {
		repoRoot := t.TempDir()
		// Only create .git, not .git/hooks
		if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0o750); err != nil {
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		opts := PreCommitOpts{FailOpen: false}
		if err := InstallPreCommit(repoRoot, pluginDir, opts); err != nil {
			t.Fatalf("InstallPreCommit() error = %v", err)
		}

		hookPath := filepath.Join(repoRoot, ".git", "hooks", "pre-commit")
		if _, err := os.Stat(hookPath); os.IsNotExist(err) {
			t.Error("hook file was not created")
		}
	})
}

func TestRemovePreCommit(t *testing.T) {
	t.Run("removes armis section", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		opts := PreCommitOpts{FailOpen: false}
		_ = InstallPreCommit(repoRoot, pluginDir, opts)

		if err := RemovePreCommit(repoRoot); err != nil {
			t.Fatalf("RemovePreCommit() error = %v", err)
		}

		hookPath := filepath.Join(gitDir, "pre-commit")
		if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
			t.Error("hook file should be removed when only armis content exists")
		}
	})

	t.Run("preserves non-armis content", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}

		hookPath := filepath.Join(gitDir, "pre-commit")
		content := "#!/bin/sh\necho my hook\n" + preCommitMarkerStart + "\nexec armis-cli scan\n" + preCommitMarkerEnd + "\n"
		if err := os.WriteFile(hookPath, []byte(content), 0o755); err != nil { //nolint:gosec // executable hook for test
			t.Fatal(err)
		}

		if err := RemovePreCommit(repoRoot); err != nil {
			t.Fatalf("RemovePreCommit() error = %v", err)
		}

		data, err := os.ReadFile(hookPath) //nolint:gosec // G304: test reading from t.TempDir()
		if err != nil {
			t.Fatalf("hook file should still exist: %v", err)
		}
		result := string(data)
		if !strings.Contains(result, "echo my hook") {
			t.Error("non-armis content was lost")
		}
		if strings.Contains(result, preCommitMarkerStart) {
			t.Error("armis marker should be removed")
		}
	})

	t.Run("noop when no hook file", func(t *testing.T) {
		repoRoot := t.TempDir()
		if err := RemovePreCommit(repoRoot); err != nil {
			t.Fatalf("RemovePreCommit() error = %v, expected nil", err)
		}
	})
}

func TestIsPreCommitInstalled(t *testing.T) {
	t.Run("returns true when installed", func(t *testing.T) {
		repoRoot := t.TempDir()
		gitDir := filepath.Join(repoRoot, ".git", "hooks")
		if err := os.MkdirAll(gitDir, 0o750); err != nil {
			t.Fatal(err)
		}
		pluginDir := setupFakePluginDirWithPreCommit(t)

		_ = InstallPreCommit(repoRoot, pluginDir, PreCommitOpts{})

		if !IsPreCommitInstalled(repoRoot) {
			t.Error("expected IsPreCommitInstalled to return true")
		}
	})

	t.Run("returns false when not installed", func(t *testing.T) {
		repoRoot := t.TempDir()
		if IsPreCommitInstalled(repoRoot) {
			t.Error("expected IsPreCommitInstalled to return false")
		}
	})
}

func setupFakePluginDirWithPreCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitHooksDir := filepath.Join(dir, "git-hooks")
	if err := os.MkdirAll(gitHooksDir, 0o750); err != nil {
		t.Fatal(err)
	}
	preCommitScript := "#!/bin/sh\n# Fake pre-commit for testing\nexit 0\n"
	if err := os.WriteFile(filepath.Join(gitHooksDir, "pre-commit"), []byte(preCommitScript), 0o755); err != nil { //nolint:gosec // executable hook for test
		t.Fatal(err)
	}
	return dir
}
