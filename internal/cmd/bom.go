package cmd

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/spf13/cobra"
)

// The --type, --format and --output values of bom repo and bom image. They
// are not the scan --bom variables: --type has a default, --bom has none.
var (
	bomOnlyTypes  []string
	bomOnlyFormat string
	bomOnlyOutput string
)

// defaultBOMOnlyTypes is the --type default: the combined BOM, one file. It
// is applied when --type is not given, not as the flag's default, so that
// --type= stays an error, as --bom= is.
func defaultBOMOnlyTypes() []string { return []string{scan.BOMTypeAll} }

// bomTenantNote says what every bom command needs from the tenant, its exit
// codes, and which shells the older-server command is quoted for. It starts
// with a line break, so the paragraph before it in Long ends in one and the
// help shows a blank line between them.
const bomTenantNote = `
BOM generation must be enabled for your tenant; without it, each type
prints a "not available" warning and no BOM is written.

Exit codes: 0 when at least one BOM was written and none failed to download;
2 when no BOM was written or a built BOM could not be downloaded; 1 on errors;
130 on Ctrl+C.

On a server without BOM-only scans, the error ends in the matching scan --bom
command, quoted to paste into sh, bash or zsh, or into PowerShell on Windows;
cmd.exe is not supported.`

var bomCmd = &cobra.Command{
	Use:   "bom",
	Short: "Build BOMs without a security scan",
	Long: `Build the BOMs (bills of materials) of a repository or a container image and
download them, without a security scan: a software BOM (sbom), an AI-BOM
(aibom), a CBOM (cbom), or the combined BOM of all three (all).

Without --type, the combined BOM is built: one file with every type.
` + bomTenantNote,
	Example: `  $ armis-cli bom repo .
  $ armis-cli bom repo . --type aibom,cbom
  $ armis-cli bom image python:3.12-slim --type sbom --format spdx
  $ armis-cli bom image --tarball ./image.tar --output -`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Cobra does not chain PersistentPreRunE to the root's; see scanCmd.
		if rootCmd != nil && rootCmd.PersistentPreRunE != nil {
			if err := rootCmd.PersistentPreRunE(cmd, args); err != nil {
				return err
			}
		}
		typeFlag := cmd.Flag("type")
		if err := checkBOMOnlyFlags(typeFlag != nil && typeFlag.Changed); err != nil {
			return err
		}
		return validateTimeouts()
	},
}

// checkBOMOnlyFlags checks --type, --format and --output before auth and
// upload, normalizing the types and format in place, with the checks scan
// repo and scan image run on --bom: the values, each type and format pair,
// the output, and a default .armis that is not a plain directory. typeSet
// reports whether --type was given; without it the type is all.
func checkBOMOnlyFlags(typeSet bool) error {
	names := cmdutil.BOMCommandFlags
	if !typeSet {
		bomOnlyTypes = defaultBOMOnlyTypes()
		names.DefaultTypes = true
	}
	types, format, err := cmdutil.NormalizeBOMFlags(names, bomOnlyTypes, true, bomOnlyFormat)
	if err != nil {
		return err
	}
	bomOnlyTypes, bomOnlyFormat = types, format
	if err := cmdutil.ValidateBOMFlags(names, bomOnlyTypes, bomOnlyFormat, bomOnlyOutput); err != nil {
		return err
	}
	if err := cmdutil.RefuseFileNameOutput(names, bomOnlyOutput, bomOnlyTypes); err != nil {
		return err
	}
	if bomOnlyOutput == "" {
		return scan.CheckDefaultOutputDir(scan.BOMLabel(bomOnlyTypes[0]))
	}
	return nil
}

// bomOnlyOptions returns the options of a BOM-only scan of target, as typed.
func bomOnlyOptions(target string) *scan.SBOMVEXOptions {
	return &scan.SBOMVEXOptions{BOM: &scan.BOMOptions{
		Types:  bomOnlyTypes,
		Format: bomOnlyFormat,
		Output: bomOnlyOutput,
		Target: target,
		Only:   true,
	}}
}

// newBOMClient authenticates and returns the API client and tenant ID, as
// the scan subcommands do.
func newBOMClient(ctx context.Context) (*api.Client, string, error) {
	authProvider, err := getAuthProvider(ctx)
	if err != nil {
		return nil, "", err
	}
	// Defensive nil-check, as in scan repo: getAuthProvider returns
	// (non-nil, nil) on success.
	if authProvider == nil {
		return nil, "", fmt.Errorf("internal error: nil auth provider")
	}
	tid, err := authProvider.GetTenantID(ctx)
	if err != nil {
		return nil, "", err
	}
	baseURL := resolveDataPlaneURL(ctx, authProvider)
	client, err := api.NewClient(baseURL, authProvider, debug, time.Duration(uploadTimeout)*time.Minute,
		clientOptionsForBaseURL(baseURL)...)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create API client: %w", err)
	}
	return client, tid, nil
}

// bomOnlyExit is the exit error of a finished BOM-only scan: bomExit's for a
// built BOM that could not be downloaded, and exit 2 as well when no
// requested BOM was written, since writing them is all the command does.
func bomOnlyExit(result *model.ScanResult) error {
	if err := bomExit(result, nil); err != nil {
		return err
	}
	if result != nil && len(result.BOMWritten) > 0 {
		return nil
	}
	labels := make([]string, 0, len(bomOnlyTypes))
	for _, t := range bomOnlyTypes {
		labels = append(labels, scan.BOMLabel(t))
	}
	var scanID string
	if result != nil {
		scanID = result.ScanID
	}
	return &output.ErrBOMIncomplete{ScanID: scanID, Labels: labels, NotWritten: true}
}

// bomScanError returns the error handler of a BOM-only scan of kind (repo or
// image). target and flags are as scanBOMCommand takes them. A server that
// predates BOM-only scans gets a plain message ending in the scan command
// that gives the same BOMs, unquoted after "run: " so it can be pasted into
// a shell as printed; any other error is handled as a failed scan.
func bomScanError(kind, target string, flags []string) func(context.Context, error) error {
	return func(ctx context.Context, err error) error {
		if errors.Is(err, api.ErrBOMScanUnsupported) {
			return fmt.Errorf("%w; run: %s", api.ErrBOMScanUnsupported, scanBOMCommand(kind, target, flags))
		}
		return handleScanError(ctx, err)
	}
}

// bomTenantFlags are the global flags typed on the command line that choose
// the tenant and the environment (--tenant-id, --region, --dev), for the scan
// command of an older server. Values from the environment stay implicit, and
// credentials (--token, --client-id, --client-secret) are never repeated.
func bomTenantFlags(cmd *cobra.Command) []string {
	typed := func(name string) bool {
		f := cmd.Flag(name)
		return f != nil && f.Changed
	}
	var flags []string
	if typed("tenant-id") {
		flags = append(flags, "--tenant-id", shellArg(tenantID, "<tenant-id>"))
	}
	if typed("region") {
		flags = append(flags, "--region", shellArg(region, "<region>"))
	}
	if typed("dev") && useDev {
		flags = append(flags, "--dev")
	}
	return flags
}

// bomTypedFlags are the global flags typed on the command line that the scan
// command of an older server needs as well: the tenant flags, and
// --scan-timeout and --upload-timeout, since the full scan takes longer.
func bomTypedFlags(cmd *cobra.Command) []string {
	flags := bomTenantFlags(cmd)
	for _, f := range []struct {
		name  string
		value int
	}{{"scan-timeout", scanTimeout}, {"upload-timeout", uploadTimeout}} {
		if fl := cmd.Flag(f.name); fl != nil && fl.Changed {
			flags = append(flags, "--"+f.name, strconv.Itoa(f.value))
		}
	}
	return flags
}

// scanBOMCommand is the scan command that downloads the requested BOMs with
// a security scan: target as typed (a path, an image name, or --tarball and
// a file), then flags (the tenant and timeout flags typed, and the upload
// flags given that change what is uploaded, such as --include-files or
// --pull), then the types, and the format and output directory when they
// are not the defaults. target and flags are already quoted with shellArg.
func scanBOMCommand(kind, target string, flags []string) string {
	parts := append([]string{"armis-cli", "scan", kind, target}, flags...)
	parts = append(parts, "--bom", strings.Join(bomOnlyTypes, ","))
	if bomOnlyFormat != scan.BOMFormatCycloneDX17 {
		parts = append(parts, "--bom-format", bomOnlyFormat)
	}
	if bomOnlyOutput != "" {
		parts = append(parts, "--bom-output", shellArg(bomOnlyOutput, "<dir>"))
	}
	return strings.Join(parts, " ")
}

// shellArg returns s ready to paste into the shell the printed command is
// meant for, quoted by shellQuote. A value that is not valid UTF-8 or has a
// control character, such as a tab, a line break or a C1 byte that 8-bit
// terminals read as an escape, cannot be printed as typed, so placeholder
// (such as <path>) stands in for it rather than a different value.
func shellArg(s, placeholder string) string {
	if !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return placeholder
	}
	return shellQuote(s)
}

// shellQuote quotes a value for the shell of this build: PowerShell on
// Windows, a POSIX shell (sh, bash, zsh) elsewhere. cmd.exe is not
// supported: it keeps single quotes as part of the value.
var shellQuote = shellQuoteFor(runtime.GOOS)

// shellQuoteFor returns the quoting function for goos.
func shellQuoteFor(goos string) func(string) string {
	if goos == "windows" {
		return powerShellQuote
	}
	return posixQuote
}

// posixQuote quotes s for sh, bash and zsh: as is when it holds only
// letters, digits and _ . / : @ + , -, which no shell treats specially, else
// in single quotes. So = and ~ are always quoted, as zsh can expand them
// anywhere in a word (MAGIC_EQUAL_SUBST), and so is a leading #. Inside
// single quotes only the quote character is special: each one closes the
// quotes, adds a backslash-escaped quote and opens them again. Single quotes
// also keep bash's ! history expansion off.
func posixQuote(s string) string {
	const plain = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:@+,-"
	if s != "" && strings.Trim(s, plain) == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// powerShellQuote quotes s for PowerShell: as is when it holds only letters,
// digits and _ . / \ : + -, so a path such as C:\src\app stays as typed,
// else in single quotes, inside which nothing expands. A quote inside them
// is written twice; PowerShell reads the curly single quotes U+2018 to
// U+201B as quotes too, so they are doubled the same way. , @ # $ ` = ~ and
// spaces are quoted, as PowerShell reads them as operators, splatting,
// comments, variables, escapes or separators.
func powerShellQuote(s string) string {
	const plain = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./\\:+-"
	if s != "" && strings.Trim(s, plain) == "" {
		return s
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		if strings.ContainsRune("'\u2018\u2019\u201a\u201b", r) {
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

func init() {
	bomCmd.PersistentFlags().StringSliceVar(&bomOnlyTypes, "type", nil,
		"BOM types, comma-separated or repeated: sbom, aibom, cbom, all (the combined BOM, one file) (default: all)")
	bomCmd.PersistentFlags().StringVar(&bomOnlyFormat, "format", scan.BOMFormatCycloneDX17,
		"BOM format: cyclonedx-1.7, cyclonedx-1.6, spdx-2.3, spdx-3.0.1, or the aliases cyclonedx, spdx")
	bomCmd.PersistentFlags().StringVar(&bomOnlyOutput, "output", "",
		"Directory for BOM files, or - to write one BOM to stdout (default: .armis)")
	_ = bomCmd.RegisterFlagCompletionFunc("type", bomTypeCompletions())
	_ = bomCmd.RegisterFlagCompletionFunc("format", bomFormatCompletions())
	addUploadFlags(bomCmd)
	if rootCmd != nil {
		rootCmd.AddCommand(bomCmd)
	}
}
