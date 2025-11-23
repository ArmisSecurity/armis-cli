package cmd

import (
        "context"
        "fmt"
        "os"
        "time"

        "github.com/silk-security/armis-cli/internal/api"
        "github.com/silk-security/armis-cli/internal/model"
        "github.com/silk-security/armis-cli/internal/output"
        "github.com/silk-security/armis-cli/internal/scan/image"
        "github.com/silk-security/armis-cli/internal/util"
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

                limit, err := getPageLimit()
                if err != nil {
                        return err
                }

                baseURL := getAPIBaseURL()
                if baseURL == "" {
                        return fmt.Errorf("API base URL not configured: use --dev flag for development environment")
                }

                client := api.NewClient(baseURL, token, debug)
                timeoutDuration := time.Duration(timeout) * time.Minute
                scanner := image.NewScanner(client, noProgress, tid, limit, includeTests, timeoutDuration, includeNonExploitable)

                ctx := context.Background()
                var result *model.ScanResult

                if tarballPath != "" {
                        sanitizedPath, err := util.SanitizePath(tarballPath)
                        if err != nil {
                                return fmt.Errorf("invalid tarball path: %w", err)
                        }
                        result, err = scanner.ScanTarball(ctx, sanitizedPath)
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

                opts := output.FormatOptions{
                        GroupBy:  groupBy,
                        RepoPath: "",
                }

                if err := formatter.FormatWithOptions(result, os.Stdout, opts); err != nil {
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
