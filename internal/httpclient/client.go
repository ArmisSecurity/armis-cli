package httpclient

import (
        "context"
        "fmt"
        "io"
        "net/http"
        "time"

        "github.com/cenkalti/backoff/v4"
)

type Config struct {
        RetryMax       int
        RetryWaitMin   time.Duration
        RetryWaitMax   time.Duration
        Timeout        time.Duration
        DisableTimeout bool
}

type Client struct {
        httpClient *http.Client
        config     Config
}

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

func (c *Client) Do(req *http.Request) (*http.Response, error) {
        var resp *http.Response
        var err error

        operation := func() error {
                resp, err = c.httpClient.Do(req)
                if err != nil {
                        return err
                }

                if resp.StatusCode >= 500 {
                        body, _ := io.ReadAll(resp.Body)
                        resp.Body.Close()
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
