package cmd

import (
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/scan/image"
	"github.com/spf13/cobra"
)

var bomImageCmd = &cobra.Command{
	Use:   "image [image-name]",
	Short: "Build the BOMs of a container image",
	Long: `Build the BOMs of a container image without a security scan, and download
them to .armis/<image>-bom-<type>.json (.spdx.json for SPDX). The image is
read as scan image reads it: exported with Docker or Podman by name, or from
--tarball, and the BOMs name it.

Without --type, the combined BOM is built: one file with every type.
` + bomTenantNote,
	Example: `  $ armis-cli bom image python:3.12-slim
  $ armis-cli bom image nginx:1.27 --type sbom,cbom --pull always
  $ armis-cli bom image --tarball ./image.tar --type sbom --format spdx
  $ armis-cli bom image --tarball ./image.tar --output -`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// PersistentPreRunE has checked --type, --format and --output.
		if err := checkImageTarget(args); err != nil {
			return err
		}

		client, tid, err := newBOMClient(cmd.Context())
		if err != nil {
			return err
		}
		// No findings are fetched, so there is no page limit and no
		// exploitability filter.
		scanner := image.NewScanner(client, noProgress, tid, 0, false, time.Duration(scanTimeout)*time.Minute, false).
			WithPullPolicy(pullPolicy).
			WithSBOMVEXOptions(bomOnlyOptions(imageTarget(args)))
		if pollInterval > 0 {
			scanner = scanner.WithPollInterval(pollInterval)
		}

		ctx, cancel := NewSignalContext()
		defer cancel()

		result, err := scanImageTarget(ctx, scanner, args, bomScanError("image", bomImageTarget(args), append(bomTypedFlags(cmd), bomImagePullFlags()...)))
		if err != nil {
			return err
		}
		return bomOnlyExit(result)
	},
}

// bomImageTarget is the target of bom image for the scan image command line:
// --tarball and the file, which wins over an image name, or the name. A name
// that starts with - would read as a flag, and is no valid image name, so
// the placeholder stands in for it.
func bomImageTarget(args []string) string {
	if tarballPath != "" {
		// armis:ignore cwe:78 reason:text printed for the user to paste, never executed; shellArg quotes every value
		return "--tarball " + shellArg(tarballPath, "<file>")
	}
	name := imageTarget(args)
	if strings.HasPrefix(name, "-") {
		return "<image>"
	}
	return shellArg(name, "<image>")
}

// bomImagePullFlags is --pull as given to bom image, for the scan image
// command of an older server: none for --tarball, which ignores it, or for
// the default policy.
func bomImagePullFlags() []string {
	if tarballPath != "" || pullPolicy == defaultPullPolicy {
		return nil
	}
	// armis:ignore cwe:78 reason:text printed for the user to paste, never executed; shellArg quotes every value
	return []string{"--pull", shellArg(pullPolicy, "<policy>")}
}

func init() {
	bomImageCmd.Flags().StringVar(&tarballPath, "tarball", "", tarballUsage)
	bomImageCmd.Flags().StringVar(&pullPolicy, "pull", defaultPullPolicy, pullUsage)
	bomCmd.AddCommand(bomImageCmd)
}
