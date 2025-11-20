package progress

import (
        "fmt"
        "io"
        "os"
        "time"

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

type Spinner struct {
        message  string
        disabled bool
        stopChan chan bool
        doneChan chan bool
}

func NewSpinner(message string, disabled bool) *Spinner {
        return &Spinner{
                message:  message,
                disabled: disabled,
                stopChan: make(chan bool),
                doneChan: make(chan bool),
        }
}

func (s *Spinner) Start() {
        if s.disabled || IsCI() {
                fmt.Println(s.message)
                return
        }

        go func() {
                spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
                i := 0
                for {
                        select {
                        case <-s.stopChan:
                                fmt.Print("\r\033[K")
                                close(s.doneChan)
                                return
                        default:
                                fmt.Printf("\r%s %s", spinner[i%len(spinner)], s.message)
                                i++
                                time.Sleep(100 * time.Millisecond)
                        }
                }
        }()
}

func (s *Spinner) Stop() {
        if s.disabled || IsCI() {
                return
        }
        close(s.stopChan)
        <-s.doneChan
}

func (s *Spinner) UpdateMessage(message string) {
        s.message = message
}
