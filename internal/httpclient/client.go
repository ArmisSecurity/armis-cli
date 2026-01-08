// Package httpclient provides an HTTP client with retry and backoff support.
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// Config contains configuration options for the HTTP client.
type Config struct {
	RetryMax       int
	RetryWaitMin   time.Duration
	RetryWaitMax   time.Duration
	Timeout        time.Duration
	DisableTimeout bool
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
	if cfg.RetryMax == 0 {
		cfg.RetryMax = 3
	}
	if cfg.RetryWaitMin == 0 {
		cfg.RetryWaitMin = 1 * time.Second
	}
	if cfg.RetryWaitMax == 0 {
		cfg.RetryWaitMax = 10 * time.Second
	}

	httpClient := &http.Client{}
	if !cfg.DisableTimeout {
		httpClient.Timeout = cfg.Timeout
	}

	return &Client{
		httpClient: httpClient,
		config:     cfg,
	}
}

// Do executes an HTTP request with retry and backoff.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	operation := func() error {
		// Regenerate request body for retries if GetBody is set.
		// This is necessary because the body is consumed after each attempt.
		if req.GetBody != nil {
			newBody, bodyErr := req.GetBody()
			if bodyErr != nil {
				return backoff.Permanent(fmt.Errorf("failed to regenerate request body: %w", bodyErr))
			}
			req.Body = newBody
		}

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode >= 500 {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close() // #nosec G104 - error not critical in error path
			return fmt.Errorf("server error: %d - %s", resp.StatusCode, string(body))
		}

		return nil
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = c.config.RetryWaitMin
	b.MaxInterval = c.config.RetryWaitMax
	b.MaxElapsedTime = c.config.RetryWaitMax * time.Duration(c.config.RetryMax)

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	err = backoff.Retry(operation, backoff.WithContext(b, ctx))
	if err != nil {
		return nil, err
	}

	return resp, nil
}
