package progress

import (
        "io"
        "os"

        "github.com/schollz/progressbar/v3"
)

func IsCI() bool {
        ciEnvVars := []string{
                "CI",
                "CONTINUOUS_INTEGRATION",
                "GITHUB_ACTIONS",
                "GITLAB_CI",
                "CIRCLECI",
                "JENKINS_URL",
                "TRAVIS",
                "BITBUCKET_BUILD_NUMBER",
                "AZURE_PIPELINES",
        }

        for _, envVar := range ciEnvVars {
                if os.Getenv(envVar) != "" {
                        return true
                }
        }
        return false
}

func NewReader(r io.Reader, size int64, description string, disabled bool) io.Reader {
        if disabled || IsCI() {
                return r
        }

        bar := progressbar.DefaultBytes(
                size,
                description,
        )

        reader := progressbar.NewReader(r, bar)
        return &reader
}

func NewWriter(w io.Writer, size int64, description string, disabled bool) io.Writer {
        if disabled || IsCI() {
                return w
        }

        bar := progressbar.DefaultBytes(
                size,
                description,
        )

        return io.MultiWriter(w, bar)
}
