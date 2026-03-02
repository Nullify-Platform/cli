package client

import (
	"bytes"
	"io"
	"math"
	"math/rand"
	"net/http"
	"time"
)

// retryTransport wraps an http.RoundTripper and retries on 429 and 5xx errors
// with exponential backoff.
type retryTransport struct {
	transport    http.RoundTripper
	maxRetries   int
	initialDelay time.Duration
	maxDelay     time.Duration
}

// NewRetryTransport wraps the given transport with retry logic for 429 and 5xx errors.
func NewRetryTransport(transport http.RoundTripper) http.RoundTripper {
	return &retryTransport{
		transport:    transport,
		maxRetries:   3,
		initialDelay: 500 * time.Millisecond,
		maxDelay:     30 * time.Second,
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Buffer the request body so we can replay it on retries.
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= t.maxRetries; attempt++ {
		if attempt > 0 && bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err = t.transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		if !t.shouldRetry(resp.StatusCode) || attempt == t.maxRetries {
			return resp, nil
		}

		// Drain and close the response body before retrying
		resp.Body.Close()

		delay := t.backoffDelay(attempt)
		select {
		case <-time.After(delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	return resp, err
}

func (t *retryTransport) shouldRetry(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= 500
}

func (t *retryTransport) backoffDelay(attempt int) time.Duration {
	delay := float64(t.initialDelay) * math.Pow(2, float64(attempt))
	if delay > float64(t.maxDelay) {
		delay = float64(t.maxDelay)
	}
	// Add jitter: 0.5x to 1.5x
	jitter := 0.5 + rand.Float64()
	return time.Duration(delay * jitter)
}
