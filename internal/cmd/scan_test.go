package cmd

import (
	"bytes"
	"testing"
)

const (
	testToken    = "test-token"
	testTenantID = "test-tenant"
)

func TestScanCmd(t *testing.T) {
	t.Run("scan command exists", func(t *testing.T) {
		if scanCmd == nil {
			t.Fatal("scanCmd should not be nil")
		}
		if scanCmd.Use != "scan" {
			t.Errorf("Expected Use 'scan', got %s", scanCmd.Use)
		}
	})

	t.Run("scan command has subcommands", func(t *testing.T) {
		subcommands := scanCmd.Commands()
		if len(subcommands) < 2 {
			t.Errorf("Expected at least 2 subcommands (repo, image), got %d", len(subcommands))
		}

		hasRepo := false
		hasImage := false
		for _, cmd := range subcommands {
			if cmd.Use == "repo [path]" {
				hasRepo = true
			}
			if cmd.Use == "image [image-name]" {
				hasImage = true
			}
		}

		if !hasRepo {
			t.Error("Expected 'repo' subcommand")
		}
		if !hasImage {
			t.Error("Expected 'image' subcommand")
		}
	})

	t.Run("scan command flags", func(t *testing.T) {
		flags := scanCmd.PersistentFlags()

		if flags.Lookup("include-tests") == nil {
			t.Error("Expected --include-tests flag")
		}
		if flags.Lookup("scan-timeout") == nil {
			t.Error("Expected --scan-timeout flag")
		}
		if flags.Lookup("upload-timeout") == nil {
			t.Error("Expected --upload-timeout flag")
		}
		if flags.Lookup("include-non-exploitable") == nil {
			t.Error("Expected --include-non-exploitable flag")
		}
		if flags.Lookup("group-by") == nil {
			t.Error("Expected --group-by flag")
		}
	})
}

func TestScanRepoCmd(t *testing.T) {
	t.Run("repo command exists", func(t *testing.T) {
		if scanRepoCmd == nil {
			t.Fatal("scanRepoCmd should not be nil")
		}
		if scanRepoCmd.Use != "repo [path]" {
			t.Errorf("Expected Use 'repo [path]', got %s", scanRepoCmd.Use)
		}
	})

	t.Run("repo command requires exactly one arg", func(t *testing.T) {
		err := scanRepoCmd.Args(scanRepoCmd, []string{})
		if err == nil {
			t.Error("Expected error when no args provided")
		}

		err = scanRepoCmd.Args(scanRepoCmd, []string{"path1", "path2"})
		if err == nil {
			t.Error("Expected error when too many args provided")
		}

		err = scanRepoCmd.Args(scanRepoCmd, []string{"path"})
		if err != nil {
			t.Errorf("Expected no error with one arg, got %v", err)
		}
	})

	t.Run("repo command fails without token", func(t *testing.T) {
		token = ""
		tenantID = "test-tenant"
		useDev = true
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
		}()

		var buf bytes.Buffer
		scanRepoCmd.SetOut(&buf)
		scanRepoCmd.SetErr(&buf)

		err := scanRepoCmd.RunE(scanRepoCmd, []string{"/tmp/test"})
		if err == nil {
			t.Error("Expected error when token not set")
		}
	})

	t.Run("repo command fails without tenant ID", func(t *testing.T) {
		token = testToken
		tenantID = ""
		useDev = true
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
		}()

		err := scanRepoCmd.RunE(scanRepoCmd, []string{"/tmp/test"})
		if err == nil {
			t.Error("Expected error when tenant ID not set")
		}
	})

	t.Run("repo command fails without base URL", func(t *testing.T) {
		token = testToken
		tenantID = testTenantID
		useDev = false
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
		}()

		err := scanRepoCmd.RunE(scanRepoCmd, []string{"/tmp/test"})
		if err == nil {
			t.Error("Expected error when base URL not configured")
		}
	})
}

func TestScanImageCmd(t *testing.T) {
	t.Run("image command exists", func(t *testing.T) {
		if scanImageCmd == nil {
			t.Fatal("scanImageCmd should not be nil")
		}
		if scanImageCmd.Use != "image [image-name]" {
			t.Errorf("Expected Use 'image [image-name]', got %s", scanImageCmd.Use)
		}
	})

	t.Run("image command accepts zero or one arg", func(t *testing.T) {
		err := scanImageCmd.Args(scanImageCmd, []string{})
		if err != nil {
			t.Errorf("Expected no error with zero args, got %v", err)
		}

		err = scanImageCmd.Args(scanImageCmd, []string{"alpine:latest"})
		if err != nil {
			t.Errorf("Expected no error with one arg, got %v", err)
		}

		err = scanImageCmd.Args(scanImageCmd, []string{"image1", "image2"})
		if err == nil {
			t.Error("Expected error when too many args provided")
		}
	})

	t.Run("image command has tarball flag", func(t *testing.T) {
		flags := scanImageCmd.Flags()
		if flags.Lookup("tarball") == nil {
			t.Error("Expected --tarball flag")
		}
	})

	t.Run("image command fails without image or tarball", func(t *testing.T) {
		tarballPath = ""
		token = testToken
		tenantID = testTenantID
		useDev = true
		defer func() {
			tarballPath = ""
			token = ""
			tenantID = ""
			useDev = false
		}()

		err := scanImageCmd.RunE(scanImageCmd, []string{})
		if err == nil {
			t.Error("Expected error when neither image nor tarball provided")
		}
	})

	t.Run("image command fails without token", func(t *testing.T) {
		token = ""
		tenantID = testTenantID
		useDev = true
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
		}()

		err := scanImageCmd.RunE(scanImageCmd, []string{"alpine:latest"})
		if err == nil {
			t.Error("Expected error when token not set")
		}
	})

	t.Run("image command fails without tenant ID", func(t *testing.T) {
		token = testToken
		tenantID = ""
		useDev = true
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
		}()

		err := scanImageCmd.RunE(scanImageCmd, []string{"alpine:latest"})
		if err == nil {
			t.Error("Expected error when tenant ID not set")
		}
	})

	t.Run("image command fails without base URL", func(t *testing.T) {
		token = testToken
		tenantID = testTenantID
		useDev = false
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
		}()

		err := scanImageCmd.RunE(scanImageCmd, []string{"alpine:latest"})
		if err == nil {
			t.Error("Expected error when base URL not configured")
		}
	})

	t.Run("image command fails with invalid page limit", func(t *testing.T) {
		token = testToken
		tenantID = testTenantID
		useDev = true
		pageLimit = 5000
		defer func() {
			token = ""
			tenantID = ""
			useDev = false
			pageLimit = 500
		}()

		err := scanImageCmd.RunE(scanImageCmd, []string{"alpine:latest"})
		if err == nil {
			t.Error("Expected error when page limit is invalid")
		}
	})
}

func TestRootCmd(t *testing.T) {
	t.Run("root command exists", func(t *testing.T) {
		if rootCmd == nil {
			t.Fatal("rootCmd should not be nil")
		}
		if rootCmd.Use != "armis-cli" {
			t.Errorf("Expected Use 'armis-cli', got %s", rootCmd.Use)
		}
	})

	t.Run("root command has persistent flags", func(t *testing.T) {
		flags := rootCmd.PersistentFlags()

		if flags.Lookup("token") == nil {
			t.Error("Expected --token flag")
		}
		if flags.Lookup("dev") == nil {
			t.Error("Expected --dev flag")
		}
		if flags.Lookup("format") == nil {
			t.Error("Expected --format flag")
		}
		if flags.Lookup("no-progress") == nil {
			t.Error("Expected --no-progress flag")
		}
		if flags.Lookup("fail-on") == nil {
			t.Error("Expected --fail-on flag")
		}
		if flags.Lookup("exit-code") == nil {
			t.Error("Expected --exit-code flag")
		}
		if flags.Lookup("tenant-id") == nil {
			t.Error("Expected --tenant-id flag")
		}
		if flags.Lookup("page-limit") == nil {
			t.Error("Expected --page-limit flag")
		}
		if flags.Lookup("debug") == nil {
			t.Error("Expected --debug flag")
		}
	})

	t.Run("root command has scan subcommand", func(t *testing.T) {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Use == "scan" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected 'scan' subcommand on root")
		}
	})
}
