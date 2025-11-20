package cmd

import (
        "context"
        "fmt"
        "os"

        "github.com/silk-security/Moose-CLI/internal/api"
        "github.com/silk-security/Moose-CLI/internal/model"
        "github.com/silk-security/Moose-CLI/internal/output"
        "github.com/silk-security/Moose-CLI/internal/scan/image"
        "github.com/spf13/cobra"
)

var (
        tarballPath string
)

var scanImageCmd = &cobra.Command{
        Use:   "image [image-name]",
        Short: "Scan a container image",
        Long:  `Scan a local or remote container image for security vulnerabilities.`,
        Args:  cobra.MaximumNArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
                if tarballPath == "" && len(args) == 0 {
                        return fmt.Errorf("either provide an image name or use --tarball flag")
                }

                token, err := getToken()
                if err != nil {
                        return err
                }

                tid, err := getTenantID()
                if err != nil {
                        return err
                }

                client := api.NewClient(apiBaseURL, token)
                scanner := image.NewScanner(client, noProgress, tid, pageLimit)

                ctx := context.Background()
                var result *model.ScanResult

                if tarballPath != "" {
                        result, err = scanner.ScanTarball(ctx, tarballPath)
                } else {
                        imageName := args[0]
                        result, err = scanner.ScanImage(ctx, imageName)
                }

                if err != nil {
                        return fmt.Errorf("scan failed: %w", err)
                }

                formatter, err := output.GetFormatter(format)
                if err != nil {
                        return err
                }

                if err := formatter.Format(result, os.Stdout); err != nil {
                        return fmt.Errorf("failed to format output: %w", err)
                }

                output.ExitIfNeeded(result, failOn, exitCode)
                return nil
        },
}

func init() {
        scanImageCmd.Flags().StringVar(&tarballPath, "tarball", "", "Path to a container image tarball")
        scanCmd.AddCommand(scanImageCmd)
}
