package cmd

import (
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/scan/repo"
	"github.com/spf13/cobra"
)

var bomRepoCmd = &cobra.Command{
	Use:   "repo [path]",
	Short: "Build the BOMs of a local repository",
	Long: `Build the BOMs of a local repository without a security scan, and download
them to .armis/<repo>-bom-<type>.json (.spdx.json for SPDX). The upload is the
one scan repo makes.

Without --type, the combined BOM is built: one file with every type.
` + bomTenantNote,
	Example: `  $ armis-cli bom repo .
  $ armis-cli bom repo . --type aibom,cbom
  $ armis-cli bom repo . --type sbom --format spdx
  $ armis-cli bom repo . --type all --format cyclonedx-1.6 --output ./boms
  $ armis-cli bom repo . --type cbom --output - > cbom.json`,
	// The path is optional and defaults to the current directory, as in scan repo.
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// PersistentPreRunE has checked --type, --format and --output.
		repoPath := repoArg(args)
		if err := checkRepoPath(repoPath); err != nil {
			return err
		}
		var fileList *repo.FileList
		if len(includeFiles) > 0 {
			var err error
			if fileList, err = parseIncludeFiles(repoPath); err != nil {
				return err
			}
		}

		client, tid, err := newBOMClient(cmd.Context())
		if err != nil {
			return err
		}
		// No findings are fetched, so there is no page limit and no
		// exploitability filter. Git hints are sent as scan repo sends them:
		// the server names the BOM root after the repository and commit.
		scanner := repo.NewScanner(client, noProgress, tid, 0, includeTests, time.Duration(scanTimeout)*time.Minute, false).
			WithSBOMVEXOptions(bomOnlyOptions(repoPath))
		if wantGitHints(cmd) {
			scanner = scanner.WithGitHints()
		}
		if pollInterval > 0 {
			scanner = scanner.WithPollInterval(pollInterval)
		}
		if fileList != nil {
			scanner = scanner.WithIncludeFiles(fileList)
			// The BOMs are built from the upload, which holds only these files.
			cli.PrintWarning("BOMs cover only the uploaded files")
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		// armis:ignore cwe:22 reason:repoPath is from direct CLI argument; validated as existing directory above
		result, err := scanner.Scan(ctx, repoPath)
		if err != nil {
			return bomScanError("repo", repoTargetArg(repoPath), append(bomTypedFlags(cmd), bomRepoUploadFlags()...))(ctx, err)
		}
		return bomOnlyExit(result)
	},
}

// repoTargetArg is the repository path for the scan repo command of an
// older server. A path that starts with - would read as a flag there, so it
// gets a ./ prefix, which names the same directory.
func repoTargetArg(path string) string {
	if strings.HasPrefix(path, "-") {
		path = "./" + path
	}
	return shellArg(path, "<path>")
}

// bomRepoUploadFlags are the flags given to bom repo that change the upload,
// for the scan repo command of an older server.
func bomRepoUploadFlags() []string {
	var flags []string
	if len(includeFiles) > 0 {
		// armis:ignore cwe:78 reason:text printed for the user to paste, never executed; shellArg quotes every value
		flags = append(flags, "--include-files", shellArg(strings.Join(includeFiles, ","), "<files>"))
	}
	if includeTests {
		flags = append(flags, "--include-tests")
	}
	return flags
}

func init() {
	bomRepoCmd.Flags().StringSliceVar(&includeFiles, "include-files", nil, includeFilesUsage)
	bomRepoCmd.Flags().BoolVar(&includeTests, "include-tests", false, includeTestsUsage)
	bomCmd.AddCommand(bomRepoCmd)
}
