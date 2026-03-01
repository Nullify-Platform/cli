package client

import (
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

func newRetryTransport(transport http.RoundTripper) http.RoundTripper {
	return &retryTransport{
		transport:    transport,
		maxRetries:   3,
		initialDelay: 500 * time.Millisecond,
		maxDelay:     30 * time.Second,
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= t.maxRetries; attempt++ {
		resp, err = t.transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		if !t.shouldRetry(resp.StatusCode) || attempt == t.maxRetries {
			return resp, nil
		}

		// Drain and close the body before retrying
		resp.Body.Close()

		delay := t.backoffDelay(attempt)
		time.Sleep(delay)
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
