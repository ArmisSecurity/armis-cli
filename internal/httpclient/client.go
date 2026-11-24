// Package httpclient provides an HTTP client with retry and backoff support.
package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/cenkalti/backoff/v4"
)

// Config contains configuration options for the HTTP client.
type Config struct {
	RetryMax       int
	RetryWaitMin   time.Duration
	RetryWaitMax   time.Duration
	Timeout        time.Duration
	DisableTimeout bool
	DisableRetry   bool // When true, no retries are attempted (for non-rewindable streaming bodies)
}

// Client is an HTTP client with retry and backoff support.
type Client struct {
	httpClient *http.Client
	config     Config
}

// NewClient creates a new HTTP client with the given configuration.
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 && !cfg.DisableTimeout {
		cfg.Timeout = 30 * time.Second
	}
	if !cfg.DisableRetry && cfg.RetryMax == 0 {
		cfg.RetryMax = 3
	}
	if cfg.RetryWaitMin == 0 {
		cfg.RetryWaitMin = 1 * time.Second
	}
	if cfg.RetryWaitMax == 0 {
		cfg.RetryWaitMax = 10 * time.Second
	}

	httpClient := &http.Client{
		// Resolve proxies from the OS configuration (WinINET/PAC on Windows),
		// not just environment variables — see ProxyAwareTransport.
		Transport: ProxyAwareTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("redirects are not allowed (attempted redirect to %s)", req.URL.Host)
		},
	}
	if !cfg.DisableTimeout {
		httpClient.Timeout = cfg.Timeout
	}

	return &Client{
		httpClient: httpClient,
		config:     cfg,
	}
}

// StatusError is a 5xx answer: the error of an attempt that Do retries, and
// of Do itself when the last attempt gets one. Body is the start of the
// answer's body, at most maxErrorBodyBytes of it.
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("server error: %d - %s", e.StatusCode, e.Body)
}

// Do executes an HTTP request with retry and backoff.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.DoObserved(req, nil)
}

// DoObserved is Do, and tells failed, when not nil, the error of each attempt
// that fails (a network error, or a *StatusError), whether or not it is then
// retried. A caller whose request changes state on the server can tell from it
// that a later answer is to a retry, after an earlier attempt took effect.
func (c *Client) DoObserved(req *http.Request, failed func(error)) (*http.Response, error) {
	var resp *http.Response
	var err error

	attempt := func() error {
		// Regenerate request body for retries if GetBody is set.
		// This is necessary because the body is consumed after each attempt.
		if req.GetBody != nil {
			newBody, bodyErr := req.GetBody()
			if bodyErr != nil {
				return backoff.Permanent(fmt.Errorf("failed to regenerate request body: %w", bodyErr))
			}
			req.Body = newBody
		}

		// armis:ignore cwe:918 reason:URL validated by api.Client caller (HTTPS enforced, no redirects)
		resp, err = c.httpClient.Do(req) //nolint:gosec // G704: URL is from API client, validated before use
		if err != nil {                  // armis:ignore cwe:918 reason:URL validated upstream by api.Client (HTTPS enforced)
			// Close response body if present to prevent resource leaks
			// (some HTTP errors may return both a response and an error)
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close() //nolint:errcheck // best-effort cleanup in error path
			}
			return err
		}

		if resp.StatusCode >= 500 {
			// Read one byte past the cap to know whether the body was cut.
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes+1))
			_ = resp.Body.Close() // #nosec G104 - error not critical in error path
			bodyStr := errorBodyText(body)
			if readErr != nil {
				bodyStr = "<body read failed>"
			}
			return &StatusError{StatusCode: resp.StatusCode, Body: bodyStr}
		}

		return nil
	}
	operation := func() error {
		attemptErr := attempt()
		var permanent *backoff.PermanentError
		if attemptErr != nil && failed != nil && !errors.As(attemptErr, &permanent) {
			failed(attemptErr)
		}
		return attemptErr
	}

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if c.config.DisableRetry {
		// No retries: execute once (for streaming bodies that cannot be rewound)
		err = operation()
	} else {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = c.config.RetryWaitMin
		b.MaxInterval = c.config.RetryWaitMax
		b.MaxElapsedTime = c.config.RetryWaitMax * time.Duration(c.config.RetryMax)

		err = backoff.Retry(operation, backoff.WithContext(b, ctx))
	}
	if err != nil {
		return nil, err
	}

	// Defensive check: resp should never be nil at this point since operation
	// returned nil error only after a successful request with resp assigned.
	// This check guards against potential future code changes.
	if resp == nil {
		return nil, fmt.Errorf("unexpected nil response after successful operation")
	}

	return resp, nil
}

// maxErrorBodyBytes caps how much of a 5xx response body goes into the error
// message: enough for an API's JSON error detail, while a proxy's HTML error
// page cannot flood the terminal or a CI log.
const maxErrorBodyBytes = 1024

// errorBodyText renders a 5xx body read with a limit of maxErrorBodyBytes+1
// bytes, cut at a UTF-8 boundary and marked when it was longer.
func errorBodyText(body []byte) string {
	if len(body) <= maxErrorBodyBytes {
		return string(body)
	}
	cut := body[:maxErrorBodyBytes]
	for len(cut) > 0 && !utf8.Valid(cut) {
		cut = cut[:len(cut)-1]
	}
	return string(cut) + "… (truncated)"
}
