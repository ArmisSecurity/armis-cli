package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

const testSecret = "s3cr3t-value-that-must-not-leak"

// throwawayHome points HOME at a temp dir so editor configs, hook configs and
// plugin dirs land there.
func throwawayHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	return home
}

func decodeReport(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, raw)
	}
	return doc
}

func clientByID(t *testing.T, doc map[string]interface{}, id string) map[string]interface{} {
	t.Helper()
	clients, _ := doc["clients"].([]interface{})
	for _, c := range clients {
		m, _ := c.(map[string]interface{})
		if m["client"] == id {
			return m
		}
	}
	t.Fatalf("client %q not in report: %v", id, doc["clients"])
	return nil
}

func TestInstallReportClients(t *testing.T) {
	tests := []struct {
		name       string
		withAdapt  bool
		breakCfg   bool
		wantStatus string
		wantHook   string
		wantDetail string
	}{
		{name: "success with hook installed", withAdapt: true, wantStatus: "ok", wantHook: "ok"},
		{name: "client failure", withAdapt: true, breakCfg: true, wantStatus: "fail", wantHook: "ok", wantDetail: "mcp.json"},
		{name: "hook warning keeps the client ok", withAdapt: false, wantStatus: "ok", wantHook: "warn", wantDetail: "hook adapter not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := throwawayHome(t)
			pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
			if err := os.MkdirAll(filepath.Join(pluginDir, "hooks"), 0o750); err != nil {
				t.Fatal(err)
			}
			if tt.withAdapt {
				if err := os.WriteFile(filepath.Join(pluginDir, "hooks", "cursor_pre_tool.py"), []byte("#"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			cursor, ok := install.EditorByID(install.EditorCursor)
			if !ok {
				t.Fatal("cursor editor missing")
			}
			if tt.breakCfg {
				if err := os.MkdirAll(cursor.ConfigPath(), 0o750); err != nil {
					t.Fatal(err)
				}
			}

			rep := newInstallReport()
			rep.setPlugin("1.4.2", pluginDir, false)
			manifest := install.NewManifest(pluginDir, "1.4.2")
			var kt knowledgeTargets

			var registered bool
			captureStderr(t, func() {
				registered = registerEditorReported(rep, cursor, pluginDir, manifest, &kt)
				installEditorHookReported(rep, cursor, pluginDir)
			})
			if registered == tt.breakCfg {
				t.Fatalf("registered = %v, breakCfg = %v", registered, tt.breakCfg)
			}

			var out bytes.Buffer
			opts := installOptions{format: formatJSON, stdout: &out}
			if err := finishInstall(opts, rep, nil); err != nil {
				t.Fatalf("finishInstall() error = %v", err)
			}

			doc := decodeReport(t, out.Bytes())
			c := clientByID(t, doc, "cursor")
			if c["label"] != "Cursor" || c["status"] != tt.wantStatus {
				t.Errorf("client = %v, want label Cursor and status %s", c, tt.wantStatus)
			}
			hook, _ := c["hook"].(map[string]interface{})
			if hook["status"] != tt.wantHook {
				t.Errorf("hook = %v, want status %s", hook, tt.wantHook)
			}
			detail := ""
			if tt.wantStatus == "fail" {
				detail, _ = c["detail"].(string)
			} else if hook != nil {
				detail, _ = hook["detail"].(string)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Errorf("detail %q does not contain %q", detail, tt.wantDetail)
			}
			if tt.wantStatus == "ok" {
				files, _ := c["files"].([]interface{})
				if len(files) != 1 || files[0] != cursor.ConfigPath() {
					t.Errorf("files = %v, want [%s]", files, cursor.ConfigPath())
				}
			}

			plugin, _ := doc["plugin"].(map[string]interface{})
			if plugin["name"] != "armis-appsec-mcp" || plugin["version"] != "1.4.2" || plugin["path"] != pluginDir {
				t.Errorf("plugin = %v", plugin)
			}
			if doc["knowledge"] != nil {
				t.Errorf("knowledge = %v, want null", doc["knowledge"])
			}
			creds, _ := doc["credentials"].(map[string]interface{})
			if creds["status"] != "none" {
				t.Errorf("credentials = %v, want none", creds)
			}
		})
	}
}

func TestInstallTargetsJSON(t *testing.T) {
	t.Run("advisory targets", func(t *testing.T) {
		throwawayHome(t)
		var out bytes.Buffer
		var err error
		stderr := captureStderr(t, func() {
			err = installTargets([]string{"jetbrains", "devin", "aider"}, installOptions{format: formatJSON, stdout: &out})
		})
		if err != nil {
			t.Fatalf("installTargets() error = %v", err)
		}
		if !strings.Contains(stderr, "JetBrains: MCP servers are configured per-project") {
			t.Errorf("human text should still go to stderr, got %q", stderr)
		}
		doc := decodeReport(t, out.Bytes())
		for id, want := range map[string]string{"jetbrains": "warn", "devin": "warn", "aider": "skip"} {
			if got := clientByID(t, doc, id)["status"]; got != want {
				t.Errorf("%s status = %v, want %s", id, got, want)
			}
		}
		if doc["plugin"] != nil || doc["knowledge"] != nil {
			t.Errorf("plugin and knowledge should be null, got %v / %v", doc["plugin"], doc["knowledge"])
		}
		if _, hasErr := doc["error"]; hasErr {
			t.Errorf("unexpected error field: %v", doc["error"])
		}
	})

	t.Run("fatal error is returned and recorded", func(t *testing.T) {
		throwawayHome(t)
		var out bytes.Buffer
		var err error
		captureStderr(t, func() {
			err = installTargets([]string{"nonexistent-editor"}, installOptions{format: formatJSON, stdout: &out})
		})
		if err == nil {
			t.Fatal("expected an error so the exit code stays non-zero")
		}
		doc := decodeReport(t, out.Bytes())
		if msg, _ := doc["error"].(string); !strings.Contains(msg, "unknown editor") {
			t.Errorf("error field = %q", msg)
		}
		if clients, _ := doc["clients"].([]interface{}); clients == nil {
			t.Error("clients must be an array, not null")
		}
	})

	t.Run("human mode writes nothing to stdout", func(t *testing.T) {
		throwawayHome(t)
		var out bytes.Buffer
		captureStderr(t, func() {
			_ = installTargets([]string{"aider"}, installOptions{format: formatHuman, stdout: &out})
		})
		if out.Len() != 0 {
			t.Errorf("stdout = %q, want empty", out.String())
		}
	})
}

func TestRunInstallFormatFlags(t *testing.T) {
	set := func(t *testing.T, name, value string) {
		t.Helper()
		if err := installCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f := installCmd.Flags().Lookup(name)
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	}

	t.Run("rejects an unknown format", func(t *testing.T) {
		throwawayHome(t)
		set(t, "format", "yaml")
		err := runInstall(installCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "must be human or json") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("json cannot be combined with interactive", func(t *testing.T) {
		throwawayHome(t)
		set(t, "format", "json")
		set(t, "interactive", "true")
		var err error
		raw := captureStdout(t, func() { err = runInstall(installCmd, nil) })
		if err == nil || !strings.Contains(err.Error(), "--interactive cannot be combined") {
			t.Errorf("err = %v", err)
		}
		if doc := decodeReport(t, []byte(raw)); !strings.Contains(fmt.Sprint(doc["error"]), "--interactive cannot be combined") {
			t.Errorf("error field = %v", doc["error"])
		}
	})

	t.Run("json reports a rejected --plugin-version", func(t *testing.T) {
		throwawayHome(t)
		set(t, "format", "json")
		set(t, "plugin-version", "not-a-version")
		t.Cleanup(func() { _ = install.SetVersionPin("") })
		var err error
		raw := captureStdout(t, func() { err = runInstall(installCmd, nil) })
		if err == nil {
			t.Fatal("expected an error for an invalid --plugin-version")
		}
		if doc := decodeReport(t, []byte(raw)); doc["error"] != err.Error() {
			t.Errorf("error field = %v, want %q", doc["error"], err.Error())
		}
	})

	t.Run("-f json writes one document to the process stdout", func(t *testing.T) {
		throwawayHome(t)
		set(t, "format", "json")

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		t.Cleanup(func() { os.Stdout = oldStdout })

		captureStderr(t, func() { err = runInstall(installCmd, []string{"aider"}) })
		_ = w.Close()
		os.Stdout = oldStdout
		raw, _ := io.ReadAll(r)
		_ = r.Close()

		if err != nil {
			t.Fatalf("runInstall() error = %v", err)
		}
		decodeReport(t, raw)
	})
}

// TestCredentialTrackerFinish covers --rotate-credentials against the files an
// install run manages.
func TestCredentialTrackerFinish(t *testing.T) {
	const (
		oldID  = "old-id"
		newID  = "new-id"
		oldSec = "old-secret-value"
	)

	tests := []struct {
		name        string
		rotate      bool
		envID       string
		envSecret   string
		existing    *string
		perm        os.FileMode
		installs    bool // the install step itself writes the file (file absent before)
		wantStatus  string
		wantFile    string
		wantContent []string
		wantDetail  string
	}{
		{
			name:        "changed credentials are rotated",
			rotate:      true,
			envID:       newID,
			envSecret:   testSecret,
			existing:    strPtr("ARMIS_CLIENT_ID=" + oldID + "\nARMIS_CLIENT_SECRET=" + oldSec + "\n"),
			perm:        0o600,
			wantStatus:  "rotated",
			wantFile:    "rotated",
			wantContent: []string{"ARMIS_CLIENT_ID=" + newID, "ARMIS_CLIENT_SECRET=" + testSecret},
		},
		{
			name:        "unchanged credentials are kept",
			rotate:      true,
			envID:       oldID,
			envSecret:   oldSec,
			existing:    strPtr("ARMIS_CLIENT_ID=" + oldID + "\nARMIS_CLIENT_SECRET=" + oldSec + "\n"),
			perm:        0o600,
			wantStatus:  "kept",
			wantFile:    "kept",
			wantContent: []string{"ARMIS_CLIENT_ID=" + oldID, "ARMIS_CLIENT_SECRET=" + oldSec},
		},
		{
			name:        "no .env is created",
			rotate:      true,
			envID:       newID,
			envSecret:   testSecret,
			wantStatus:  "written",
			wantFile:    "written",
			wantContent: []string{"ARMIS_CLIENT_ID=" + newID, "ARMIS_CLIENT_SECRET=" + testSecret},
		},
		{
			name:        "other keys are kept",
			rotate:      true,
			envID:       newID,
			envSecret:   testSecret,
			existing:    strPtr("HTTPS_PROXY=http://proxy:3128\nARMIS_CLIENT_ID=" + oldID + "\nARMIS_CLIENT_SECRET=" + oldSec + "\nSSL_CERT_FILE=/ca.pem\n"),
			perm:        0o600,
			wantStatus:  "rotated",
			wantFile:    "rotated",
			wantContent: []string{"HTTPS_PROXY=http://proxy:3128", "SSL_CERT_FILE=/ca.pem", "ARMIS_CLIENT_ID=" + newID, "ARMIS_CLIENT_SECRET=" + testSecret},
		},
		{
			name:        "a loose file mode ends up 0600",
			rotate:      true,
			envID:       newID,
			envSecret:   testSecret,
			existing:    strPtr("ARMIS_CLIENT_ID=" + oldID + "\nARMIS_CLIENT_SECRET=" + oldSec + "\n"),
			perm:        0o644,
			wantStatus:  "rotated",
			wantFile:    "rotated",
			wantContent: []string{"ARMIS_CLIENT_ID=" + newID, "ARMIS_CLIENT_SECRET=" + testSecret},
		},
		{
			name:        "a file the install just wrote counts as written",
			rotate:      true,
			envID:       newID,
			envSecret:   testSecret,
			installs:    true,
			wantStatus:  "written",
			wantFile:    "written",
			wantContent: []string{"ARMIS_CLIENT_ID=" + newID, "ARMIS_CLIENT_SECRET=" + testSecret},
		},
		{
			name:        "without the flag an existing file is untouched",
			rotate:      false,
			envID:       newID,
			envSecret:   testSecret,
			existing:    strPtr("ARMIS_CLIENT_ID=" + oldID + "\nARMIS_CLIENT_SECRET=" + oldSec + "\n"),
			perm:        0o600,
			wantStatus:  "kept",
			wantFile:    "kept",
			wantContent: []string{"ARMIS_CLIENT_ID=" + oldID, "ARMIS_CLIENT_SECRET=" + oldSec},
		},
		{
			name:       "without the flag a missing file stays missing",
			rotate:     false,
			envID:      newID,
			envSecret:  testSecret,
			wantStatus: "none",
			wantFile:   "none",
		},
		{
			name:        "rotation without environment credentials leaves files as they are",
			rotate:      true,
			existing:    strPtr("ARMIS_CLIENT_ID=" + oldID + "\nARMIS_CLIENT_SECRET=" + oldSec + "\n"),
			perm:        0o600,
			wantStatus:  "kept",
			wantFile:    "kept",
			wantContent: []string{"ARMIS_CLIENT_ID=" + oldID, "ARMIS_CLIENT_SECRET=" + oldSec},
			wantDetail:  "not rotated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := throwawayHome(t)
			t.Setenv("ARMIS_CLIENT_ID", tt.envID)
			t.Setenv("ARMIS_CLIENT_SECRET", tt.envSecret)

			envPath := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp", ".env")
			if err := os.MkdirAll(filepath.Dir(envPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if tt.existing != nil {
				if err := os.WriteFile(envPath, []byte(*tt.existing), tt.perm); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(envPath, tt.perm); err != nil {
					t.Fatal(err)
				}
			}

			var tracker credentialTracker
			f := tracker.watch(envPath)
			f.managed = true
			if tt.installs {
				if err := os.WriteFile(envPath, []byte("ARMIS_CLIENT_ID="+tt.envID+"\nARMIS_CLIENT_SECRET="+tt.envSecret+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			var creds credentialsReport
			var err error
			stderr := captureStderr(t, func() { creds, err = tracker.finish(tt.rotate) })
			if err != nil {
				t.Fatalf("finish() error = %v", err)
			}
			if creds.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", creds.Status, tt.wantStatus)
			}
			if len(creds.Files) != 1 || creds.Files[0].Path != envPath || creds.Files[0].Status != tt.wantFile {
				t.Errorf("files = %+v, want one entry %s %s", creds.Files, envPath, tt.wantFile)
			}
			if tt.wantDetail != "" && !strings.Contains(creds.Detail, tt.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", creds.Detail, tt.wantDetail)
			}

			if tt.wantContent != nil {
				b, readErr := os.ReadFile(filepath.Clean(envPath))
				if readErr != nil {
					t.Fatal(readErr)
				}
				lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
				if len(lines) != len(tt.wantContent) {
					t.Errorf("file = %q, want lines %v", b, tt.wantContent)
				}
				for _, want := range tt.wantContent {
					found := false
					for _, l := range lines {
						found = found || l == want
					}
					if !found {
						t.Errorf("file is missing %q:\n%s", want, b)
					}
				}
				if runtime.GOOS != "windows" && tt.rotate && creds.Files[0].Status != "kept" {
					info, statErr := os.Stat(envPath)
					if statErr != nil {
						t.Fatal(statErr)
					}
					if perm := info.Mode().Perm(); perm != 0o600 {
						t.Errorf("mode = %o, want 600", perm)
					}
				}
			} else if _, statErr := os.Stat(envPath); !os.IsNotExist(statErr) {
				t.Errorf("file should not exist, stat err = %v", statErr)
			}

			if _, statErr := os.Stat(envPath + ".bak"); !os.IsNotExist(statErr) {
				t.Errorf(".env.bak must not be left behind, stat err = %v", statErr)
			}

			encoded, _ := json.Marshal(creds)
			if strings.Contains(string(encoded), tt.envSecret) && tt.envSecret != "" {
				t.Errorf("JSON output leaks the secret: %s", encoded)
			}
			if strings.Contains(stderr, tt.envSecret) && tt.envSecret != "" {
				t.Errorf("stderr leaks the secret: %q", stderr)
			}
		})
	}
}

func TestCredentialTrackerSkipsUnmanagedFiles(t *testing.T) {
	home := throwawayHome(t)
	t.Setenv("ARMIS_CLIENT_ID", "new-id")
	t.Setenv("ARMIS_CLIENT_SECRET", testSecret)

	managedPath := filepath.Join(home, "managed", ".env")
	skippedPath := filepath.Join(home, "skipped", ".env")

	var tracker credentialTracker
	tracker.watch(managedPath).managed = true
	tracker.watch(skippedPath)

	var creds credentialsReport
	var err error
	captureStderr(t, func() { creds, err = tracker.finish(true) })
	if err != nil {
		t.Fatalf("finish() error = %v", err)
	}
	if len(creds.Files) != 1 || creds.Files[0].Path != managedPath {
		t.Errorf("files = %+v, want only %s", creds.Files, managedPath)
	}
	if _, statErr := os.Stat(skippedPath); !os.IsNotExist(statErr) {
		t.Errorf("unmanaged file must not be created, stat err = %v", statErr)
	}
}

func TestCredentialTrackerRotationFailure(t *testing.T) {
	home := throwawayHome(t)
	t.Setenv("ARMIS_CLIENT_ID", "new-id")
	t.Setenv("ARMIS_CLIENT_SECRET", testSecret)

	// A directory in place of the .env makes the read fail.
	envPath := filepath.Join(home, ".env")
	if err := os.MkdirAll(envPath, 0o750); err != nil {
		t.Fatal(err)
	}

	var tracker credentialTracker
	tracker.watch(envPath).managed = true

	var creds credentialsReport
	var err error
	stderr := captureStderr(t, func() { creds, err = tracker.finish(true) })
	if err == nil {
		t.Fatal("a failed rotation must return an error")
	}
	if creds.Status != "failed" || creds.Files[0].Status != "failed" {
		t.Errorf("creds = %+v, want failed", creds)
	}
	encoded, _ := json.Marshal(creds)
	for _, s := range []string{string(encoded), stderr, err.Error()} {
		if strings.Contains(s, testSecret) {
			t.Errorf("output leaks the secret: %q", s)
		}
	}
}

func TestSettleCredentialsAndFinishInstall(t *testing.T) {
	home := throwawayHome(t)
	t.Setenv("ARMIS_CLIENT_ID", "new-id")
	t.Setenv("ARMIS_CLIENT_SECRET", testSecret)

	envPath := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp", ".env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte("ARMIS_CLIENT_ID=old\nARMIS_CLIENT_SECRET=older\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var tracker credentialTracker
	tracker.watch(envPath).managed = true
	rep := newInstallReport()
	var out bytes.Buffer
	opts := installOptions{rotateCredentials: true, format: formatJSON, stdout: &out}

	var err error
	captureStderr(t, func() {
		err = settleCredentials(opts, rep, &tracker)
		err = finishInstall(opts, rep, err)
	})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(out.String(), testSecret) {
		t.Errorf("stdout leaks the secret: %s", out.String())
	}
	doc := decodeReport(t, out.Bytes())
	creds, _ := doc["credentials"].(map[string]interface{})
	if creds["status"] != "rotated" {
		t.Errorf("credentials = %v, want rotated", creds)
	}
}

func TestFinishInstallPassesErrorThrough(t *testing.T) {
	boom := errors.New("boom")
	var out bytes.Buffer
	err := finishInstall(installOptions{format: formatJSON, stdout: &out}, newInstallReport(), boom)
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want boom", err)
	}
	if doc := decodeReport(t, out.Bytes()); doc["error"] != "boom" {
		t.Errorf("error field = %v", doc["error"])
	}
}

func TestSetKnowledgeStatus(t *testing.T) {
	tests := []struct {
		name string
		res  knowledgeResult
		want string
	}{
		{"registered", knowledgeResult{registered: []string{"Cursor"}, shortSHA: "abc1234"}, "ok"},
		{"registered with warnings", knowledgeResult{registered: []string{"Cursor"}, warnings: []string{"x"}, shortSHA: "abc1234"}, "warn"},
		{"fetch failed", knowledgeResult{skipped: true, warnings: []string{"Knowledge: boom"}}, "fail"},
		{"no targets", knowledgeResult{skipped: true}, "skip"},
		{"nothing registered", knowledgeResult{shortSHA: "abc1234"}, "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := newInstallReport()
			rep.client("cursor", "Cursor")
			rep.setKnowledge(tt.res, "/k/.env")
			if rep.Knowledge.Status != tt.want {
				t.Errorf("status = %q, want %q", rep.Knowledge.Status, tt.want)
			}
		})
	}

	t.Run("registered clients are reported by id", func(t *testing.T) {
		rep := newInstallReport()
		rep.client("cursor", "Cursor")
		rep.client("claude", "Claude Code")
		rep.setKnowledge(knowledgeResult{registered: []string{"Cursor", "Claude Code"}, shortSHA: "abc1234"}, "/k/.env")
		if got := strings.Join(rep.Knowledge.Registered, ","); got != "cursor,claude" {
			t.Errorf("registered = %q", got)
		}
	})
}
