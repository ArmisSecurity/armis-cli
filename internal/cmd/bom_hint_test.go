package cmd

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
	"github.com/spf13/cobra"
)

// TestShellArg: a value that is not valid UTF-8 or holds a control
// character becomes the placeholder; any other value is quoted for the shell
// of this build.
func TestShellArg(t *testing.T) {
	for _, in := range []string{"my\tapp", "two\nlines", "esc\x1b[2J", "c1\x9bbyte", "bad\xffutf8"} {
		if got := shellArg(in, "<v>"); got != "<v>" {
			t.Errorf("shellArg(%q) = %s, want the placeholder", in, got)
		}
	}
	for _, in := range []string{"./app", "my app", "it's", `C:\src\app`} {
		if got, want := shellArg(in, "<v>"), shellQuoteFor(runtime.GOOS)(in); got != want {
			t.Errorf("shellArg(%q) = %s, want %s, as quoted for %s", in, got, want, runtime.GOOS)
		}
	}
}

// TestShellQuoteFor: a Windows build quotes for PowerShell, others for a
// POSIX shell. "it's" tells the two apart.
func TestShellQuoteFor(t *testing.T) {
	for goos, want := range map[string]string{
		"windows": `'it''s'`,
		"linux":   `'it'\''s'`,
		"darwin":  `'it'\''s'`,
	} {
		if got := shellQuoteFor(goos)("it's"); got != want {
			t.Errorf("shellQuoteFor(%q)(\"it's\") = %s, want %s", goos, got, want)
		}
	}
	if got, want := shellQuote("it's"), shellQuoteFor(runtime.GOOS)("it's"); got != want {
		t.Errorf("this build quotes as %s, want %s for %s", got, want, runtime.GOOS)
	}
}

// TestPosixQuote: a value pastes back into sh, and zsh, as the same
// argument. Runs on every OS; the shells only where they exist.
func TestPosixQuote(t *testing.T) {
	rows := []struct{ in, want string }{
		{"./my-app", "./my-app"},
		{"ghcr.io/org/app:1.2", "ghcr.io/org/app:1.2"},
		{"a,b.go", "a,b.go"},
		{"a=b", "'a=b'"},
		{"a==ls", "'a==ls'"},
		{"x=a:=ls", "'x=a:=ls'"},
		{"a~b", "'a~b'"},
		{"my app", "'my app'"},
		{"wow!", "'wow!'"},
		{"$HOME/x", "'$HOME/x'"},
		{"a`id`b", "'a`id`b'"},
		{"it's", `'it'\''s'`},
		{`back\slash "q"`, `'back\slash "q"'`},
		{`C:\src\app`, `'C:\src\app'`},
		{"=t1", "'=t1'"},
		{"~/boms", "'~/boms'"},
		{"#tag", "'#tag'"},
		{"", "''"},
		{"ok ünïcode 服务", "'ok ünïcode 服务'"},
	}
	// Each shell reads the value back; zsh also with MAGIC_EQUAL_SUBST,
	// which expands = and ~ inside a word.
	type shell struct{ path, setup string }
	var shells []shell
	if runtime.GOOS != "windows" {
		if path, err := exec.LookPath("sh"); err == nil {
			shells = append(shells, shell{path, ""})
		}
		if path, err := exec.LookPath("zsh"); err == nil {
			shells = append(shells, shell{path, ""}, shell{path, "setopt MAGIC_EQUAL_SUBST; "})
		}
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			got := posixQuote(row.in)
			if got != row.want {
				t.Fatalf("posixQuote(%q) = %s, want %s", row.in, got, row.want)
			}
			for _, sh := range shells {
				out, err := exec.Command(sh.path, "-c", sh.setup+"printf %s "+got).CombinedOutput() //nolint:gosec // test input from the table
				if err != nil || string(out) != row.in {
					t.Errorf("%s %sread %s back as %q (%v), want %q", sh.path, sh.setup, got, out, err, row.in)
				}
			}
		})
	}
}

// TestPowerShellQuote: a value pastes back into PowerShell as the same
// argument. Runs on every OS; the round trip only where PowerShell exists,
// as on Windows. The script goes in as -EncodedCommand, so no other quoting
// layer is involved, and passes the value to a function, in argument mode.
func TestPowerShellQuote(t *testing.T) {
	rows := []struct{ in, want string }{
		{`C:\src\app`, `C:\src\app`},
		{`.\my-app`, `.\my-app`},
		{"./-x", "./-x"},
		{"eu1", "eu1"},
		{"my app", "'my app'"},
		{`C:\Program Files\app`, `'C:\Program Files\app'`},
		{"it's", "'it''s'"},
		{"a\u2019b\u2018c", "'a\u2019\u2019b\u2018\u2018c'"},
		{"$env:HOME", "'$env:HOME'"},
		{"a`b", "'a`b'"},
		{"a,b.go", "'a,b.go'"},
		{"@splat", "'@splat'"},
		{"#tag", "'#tag'"},
		{"a=b", "'a=b'"},
		{"--%", "'--%'"},
		{`say "hi"`, `'say "hi"'`},
		{"", "''"},
	}
	var ps string
	for _, name := range []string{"pwsh", "powershell"} {
		if path, err := exec.LookPath(name); err == nil {
			ps = path
			break
		}
	}
	for _, row := range rows {
		t.Run(row.in, func(t *testing.T) {
			got := powerShellQuote(row.in)
			if got != row.want {
				t.Fatalf("powerShellQuote(%q) = %s, want %s", row.in, got, row.want)
			}
			if ps == "" {
				return
			}
			// f takes the value in argument mode, as a command such as
			// armis-cli does, then writes it back.
			script := "[Console]::OutputEncoding = [Text.Encoding]::UTF8; function f { [Console]::Out.Write([string]$args[0]) }; f " + got
			u16 := utf16.Encode([]rune(script))
			raw := make([]byte, 2*len(u16))
			for i, c := range u16 {
				binary.LittleEndian.PutUint16(raw[2*i:], c)
			}
			out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)).Output() //nolint:gosec // test input from the table
			if err != nil || strings.TrimPrefix(string(out), "\ufeff") != row.in {
				t.Errorf("%s read %s back as %q (%v), want %q", ps, got, out, err, row.in)
			}
		})
	}
}

// TestScanBOMCommand covers the scan command named for an older server: the
// target, the upload flags that change what is uploaded, then the BOM flags.
func TestScanBOMCommand(t *testing.T) {
	setupBOMRunEnv(t, "https://127.0.0.1:1")
	rows := []struct {
		name  string
		set   func()
		build func() string
		want  string
	}{
		{"repo defaults", func() {}, func() string { return scanBOMCommand("repo", ".", bomRepoUploadFlags()) },
			"armis-cli scan repo . --bom all"},
		{"repo with every flag", func() {
			includeFiles, includeTests = []string{"src/a.go", "my file.go"}, true
			bomOnlyTypes, bomOnlyFormat, bomOnlyOutput = []string{"sbom", "cbom"}, "cyclonedx-1.6", "out dir"
		}, func() string { return scanBOMCommand("repo", shellArg("./my app", "<path>"), bomRepoUploadFlags()) },
			"armis-cli scan repo './my app' --include-files 'src/a.go,my file.go' --include-tests --bom sbom,cbom --bom-format cyclonedx-1.6 --bom-output 'out dir'"},
		{"image by name with --pull", func() { pullPolicy = "always" },
			func() string {
				return scanBOMCommand("image", bomImageTarget([]string{"nginx:1.27"}), bomImagePullFlags())
			},
			"armis-cli scan image nginx:1.27 --pull always --bom all"},
		{"image by name, default --pull", func() {},
			func() string {
				return scanBOMCommand("image", bomImageTarget([]string{"nginx:1.27"}), bomImagePullFlags())
			},
			"armis-cli scan image nginx:1.27 --bom all"},
		{"--tarball ignores --pull", func() { tarballPath, pullPolicy = "./img.tar", "never" },
			func() string { return scanBOMCommand("image", bomImageTarget(nil), bomImagePullFlags()) },
			"armis-cli scan image --tarball ./img.tar --bom all"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			bomOnlyTypes, bomOnlyFormat, bomOnlyOutput = defaultBOMOnlyTypes(), scan.BOMFormatCycloneDX17, ""
			includeFiles, includeTests, tarballPath, pullPolicy = nil, false, "", defaultPullPolicy
			row.set()
			if got := row.build(); got != row.want {
				t.Errorf("got  %s\nwant %s", got, row.want)
			}
		})
	}
}

// TestOldServerHint checks the whole message for an older server: the exact
// text for a plain path and a path with a space, and that everything after
// "run: " is a command line a POSIX shell splits back into the arguments.
func TestOldServerHint(t *testing.T) {
	setupBOMRunEnv(t, "https://127.0.0.1:1")
	const prefix = "this Armis server does not support BOM-only scans yet; run: "
	rows := []struct {
		name     string
		kind     string
		target   string
		set      func()
		flags    func() []string
		wantText string // checked when set
		wantArgs []string
	}{
		{name: "a plain path", kind: "repo", target: "./app", flags: bomRepoUploadFlags,
			wantText: prefix + "armis-cli scan repo ./app --bom all",
			wantArgs: []string{"armis-cli", "scan", "repo", "./app", "--bom", "all"}},
		{name: "a path with a space", kind: "repo", target: "my app", flags: bomRepoUploadFlags,
			wantText: prefix + "armis-cli scan repo 'my app' --bom all",
			wantArgs: []string{"armis-cli", "scan", "repo", "my app", "--bom", "all"}},
		{name: "shell characters everywhere", kind: "repo", target: "it's $HOME `x` wow!",
			set: func() {
				includeFiles, includeTests = []string{"a b.go", "c$d.go"}, true
				bomOnlyTypes, bomOnlyFormat, bomOnlyOutput = []string{"sbom", "cbom"}, "cyclonedx-1.6", "out 'dir'!"
			},
			flags: bomRepoUploadFlags,
			wantArgs: []string{"armis-cli", "scan", "repo", "it's $HOME `x` wow!", "--include-files", "a b.go,c$d.go", "--include-tests",
				"--bom", "sbom,cbom", "--bom-format", "cyclonedx-1.6", "--bom-output", "out 'dir'!"}},
		{name: "a path with a tab is a placeholder", kind: "repo", target: "my\tapp", flags: bomRepoUploadFlags,
			wantText: prefix + "armis-cli scan repo <path> --bom all"},
		{name: "a path with a line break is a placeholder", kind: "repo", target: "my\napp", flags: bomRepoUploadFlags,
			wantText: prefix + "armis-cli scan repo <path> --bom all"},
		{name: "an image with a control character is a placeholder", kind: "image", target: "app\x1b:1", flags: bomImagePullFlags,
			wantText: prefix + "armis-cli scan image <image> --bom all"},
		{name: "an image by name with --pull", kind: "image", target: "nginx:1.27",
			set:      func() { pullPolicy = "always" },
			flags:    bomImagePullFlags,
			wantText: prefix + "armis-cli scan image nginx:1.27 --pull always --bom all",
			wantArgs: []string{"armis-cli", "scan", "image", "nginx:1.27", "--pull", "always", "--bom", "all"}},
	}
	sh, shErr := exec.LookPath("sh")
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			bomOnlyTypes, bomOnlyFormat, bomOnlyOutput = defaultBOMOnlyTypes(), scan.BOMFormatCycloneDX17, ""
			includeFiles, includeTests, tarballPath, pullPolicy = nil, false, "", defaultPullPolicy
			if row.set != nil {
				row.set()
			}
			placeholder := "<path>"
			if row.kind == "image" {
				placeholder = "<image>"
			}
			err := bomScanError(row.kind, shellArg(row.target, placeholder), row.flags())(context.Background(),
				fmt.Errorf("failed to trigger scan: %w", api.ErrBOMScanUnsupported))
			text := err.Error()
			if row.wantText != "" && text != row.wantText {
				t.Errorf("message = %q\nwant      %q", text, row.wantText)
			}
			command, ok := strings.CutPrefix(text, prefix)
			if !ok {
				t.Fatalf("message = %q, want it to start with %q", text, prefix)
			}
			if row.wantArgs == nil {
				return // a placeholder is for the user to fill in
			}
			if shErr != nil || runtime.GOOS == "windows" {
				t.Skip("no POSIX shell to split the command")
			}
			// As if typed: sh -c 'printf "%s\n" "$@"' _ <command>
			out, err := exec.Command(sh, "-c", `sh -c 'printf "%s\n" "$@"' _ `+command).Output() //nolint:gosec // test input from the table
			if err != nil {
				t.Fatalf("sh: %v", err)
			}
			got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
			if !reflect.DeepEqual(got, row.wantArgs) {
				t.Errorf("sh split %s into\n%q\nwant\n%q", command, got, row.wantArgs)
			}
		})
	}
}

// TestOldServerHintTenantFlags runs the real command line against an older
// server: --tenant-id, --region and --dev typed on the command line are in
// the suggested command, values from the environment are not, and no
// credential ever is.
func TestOldServerHintTenantFlags(t *testing.T) {
	const secret = "s3cr3t-token-value"
	const prefix = "this Armis server does not support BOM-only scans yet; run: "
	rows := []struct {
		name   string
		image  bool
		region string // ARMIS_REGION
		args   []string
		want   string // after the target
	}{
		{name: "from the environment", want: " --bom all"},
		{name: "a region from the environment stays out", region: "eu1", want: " --bom all"},
		{name: "typed tenant, region and dev", args: []string{"--tenant-id", "tenant 7", "--region", "eu1", "--dev", "--token", secret},
			want: " --tenant-id 'tenant 7' --region eu1 --dev --bom all"},
		{name: "--dev=false is left out", args: []string{"--dev=false", "--tenant-id", "t-1"}, want: " --tenant-id t-1 --bom all"},
		{name: "typed timeouts are carried over", args: []string{"--scan-timeout", "90", "--upload-timeout", "30", "--tenant-id", "t-1"},
			want: " --tenant-id t-1 --scan-timeout 90 --upload-timeout 30 --bom all"},
		{name: "default timeouts typed as such are still carried", args: []string{"--scan-timeout=60"}, want: " --scan-timeout 60 --bom all"},
		{name: "bom image carries a typed timeout", image: true, args: []string{"--upload-timeout", "30", "--token", secret},
			want: " --upload-timeout 30 --bom all"},
		{name: "bom image with a typed tenant", image: true, args: []string{"--tenant-id", "t-1", "--token", secret},
			want: " --tenant-id t-1 --bom all"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			setupBOMRunEnv(t, testutil.GetMockServerURLWithConfig(t, testutil.MockAPIConfig{
				ScanStatus: http.StatusUnprocessableEntity, ScanBody: oldServerBody,
			}))
			t.Setenv("ARMIS_API_TOKEN", secret)
			t.Setenv("ARMIS_TENANT_ID", "env-tenant")
			t.Setenv("ARMIS_REGION", row.region)
			origDev, origRegion := useDev, region
			t.Cleanup(func() {
				resetBOMFlags(t)
				for _, name := range []string{"tenant-id", "region", "dev", "token"} {
					resetParsedFlag(t, rootCmd.PersistentFlags(), name)
				}
				useDev, region = origDev, origRegion
				rootCmd.SetArgs(nil)
			})
			t.Chdir(t.TempDir())
			resetBOMFlags(t)
			args := []string{"bom", "repo", createTestRepo(t)}
			want := prefix + "armis-cli scan repo " + shellArg(args[2], "<path>") + row.want
			if row.image {
				tarball := writeDockerSaveTar(t, "app.tar")
				args = []string{"bom", "image", "--tarball", tarball}
				want = prefix + "armis-cli scan image --tarball " + shellArg(tarball, "<file>") + row.want
			}
			rootCmd.SetArgs(append(append(args, "--no-progress", "--poll-interval", "10ms"), row.args...))
			var err error
			_ = testutil.CaptureStderr(t, func() { err = Execute() })
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v\nwant    %s", err, want)
			}
			for _, leak := range []string{secret, "--token", "--client-id", "--client-secret", "env-tenant"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("hint %q holds %q", err, leak)
				}
			}
		})
	}
}

// TestBOMTenantFlagsNeverNameCredentials: with every credential flag typed,
// the tenant flags hold none of them.
func TestBOMTenantFlagsNeverNameCredentials(t *testing.T) {
	origTenant, origRegion, origDev := tenantID, region, useDev
	origToken, origID, origSecret := token, clientID, clientSecret
	t.Cleanup(func() {
		for _, name := range []string{"tenant-id", "region", "dev", "token", "client-id", "client-secret"} {
			resetParsedFlag(t, rootCmd.PersistentFlags(), name)
		}
		tenantID, region, useDev = origTenant, origRegion, origDev
		token, clientID, clientSecret = origToken, origID, origSecret
	})
	for name, value := range map[string]string{
		"token": "tok-SECRET", "client-id": "id-SECRET", "client-secret": "secret-SECRET",
		"tenant-id": "t-1", "region": "eu1", "dev": "true",
	} {
		if err := rootCmd.PersistentFlags().Set(name, value); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
	}
	got := strings.Join(bomTenantFlags(bomRepoCmd), " ")
	if got != "--tenant-id t-1 --region eu1 --dev" {
		t.Errorf("bomTenantFlags = %q, want the tenant flags only", got)
	}
	if strings.Contains(got, "SECRET") || strings.Contains(got, "--token") || strings.Contains(got, "--client") {
		t.Errorf("bomTenantFlags = %q names a credential", got)
	}
}

// TestWantGitHints: scan repo and bom repo send git hints for a full upload
// only, not with --include-files or --changed.
func TestWantGitHints(t *testing.T) {
	origFiles, origChanged := includeFiles, changedRef
	t.Cleanup(func() {
		includeFiles, changedRef = origFiles, origChanged
		_ = scanRepoCmd.Flags().Set("changed", "")
		scanRepoCmd.Flags().Lookup("changed").Changed = false
	})
	rows := []struct {
		name    string
		cmd     *cobra.Command
		files   []string
		changed bool
		want    bool
	}{
		{"scan repo, full upload", scanRepoCmd, nil, false, true},
		{"scan repo --include-files", scanRepoCmd, []string{"a.go"}, false, false},
		{"scan repo --changed", scanRepoCmd, nil, true, false},
		{"bom repo, full upload", bomRepoCmd, nil, false, true},
		{"bom repo --include-files", bomRepoCmd, []string{"a.go"}, false, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			includeFiles = row.files
			_ = scanRepoCmd.Flags().Set("changed", "")
			scanRepoCmd.Flags().Lookup("changed").Changed = false
			if row.changed {
				if err := scanRepoCmd.Flags().Set("changed", "staged"); err != nil {
					t.Fatalf("set --changed: %v", err)
				}
			}
			if got := wantGitHints(row.cmd); got != row.want {
				t.Errorf("wantGitHints = %v, want %v", got, row.want)
			}
		})
	}
}

// TestOldServerHintDashTargets: a repo path that starts with - is printed as
// ./-x, which cobra parses as the same path, not as a flag; an image name
// that starts with - is a placeholder.
func TestOldServerHintDashTargets(t *testing.T) {
	setupBOMRunEnv(t, "https://127.0.0.1:1")
	const prefix = "this Armis server does not support BOM-only scans yet; run: "
	rows := []struct {
		name       string
		image      bool
		target     string
		wantText   string
		wantTarget string // "" for a placeholder
	}{
		{name: "repo -x", target: "-x", wantText: prefix + "armis-cli scan repo ./-x --bom all", wantTarget: "-x"},
		{name: "repo --weird dir", target: "--weird dir", wantText: prefix + "armis-cli scan repo './--weird dir' --bom all", wantTarget: "--weird dir"},
		{name: "repo ./-x stays", target: "./-x", wantText: prefix + "armis-cli scan repo ./-x --bom all", wantTarget: "-x"},
		{name: "image -x", image: true, target: "-x", wantText: prefix + "armis-cli scan image <image> --bom all"},
	}
	sh, shErr := exec.LookPath("sh")
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			kind, target := "repo", repoTargetArg(row.target)
			if row.image {
				kind, target = "image", bomImageTarget([]string{row.target})
			}
			err := bomScanError(kind, target, nil)(context.Background(), api.ErrBOMScanUnsupported)
			if err.Error() != row.wantText {
				t.Fatalf("message = %q\nwant      %q", err, row.wantText)
			}
			if row.wantTarget == "" || shErr != nil || runtime.GOOS == "windows" {
				return
			}
			command := strings.TrimPrefix(err.Error(), prefix)
			out, runErr := exec.Command(sh, "-c", `sh -c 'printf "%s\n" "$@"' _ `+command).Output() //nolint:gosec // test input from the table
			if runErr != nil {
				t.Fatalf("sh: %v", runErr)
			}
			args := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
			// Parse what follows "armis-cli scan repo" as cobra does, with the
			// flags the line can hold.
			var got []string
			c := &cobra.Command{Use: "repo [path]", Args: cobra.MaximumNArgs(1), SilenceErrors: true, SilenceUsage: true,
				RunE: func(_ *cobra.Command, a []string) error { got = a; return nil }}
			c.Flags().StringSlice("bom", nil, "")
			c.Flags().String("bom-format", "", "")
			c.Flags().String("bom-output", "", "")
			c.Flags().StringSlice("include-files", nil, "")
			c.Flags().Bool("include-tests", false, "")
			c.SetArgs(args[3:])
			if err := c.Execute(); err != nil {
				t.Fatalf("cobra rejects %q: %v", args[3:], err)
			}
			if len(got) != 1 || filepath.Clean(got[0]) != filepath.Clean(row.wantTarget) {
				t.Errorf("cobra read the target as %q, want %q", got, row.wantTarget)
			}
		})
	}
}
