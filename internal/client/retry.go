package client

import (
	"bytes"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// retryTransport wraps an http.RoundTripper and retries on 429 and 5xx errors
// with exponential backoff. 5xx is only retried for idempotent methods so a
// POST/PATCH that may have committed server-side is never replayed.
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

		if !shouldRetry(req.Method, resp.StatusCode) || attempt == t.maxRetries {
			return resp, nil
		}

		delay := t.retryDelay(resp, attempt)

		// Drain and close the response body before retrying so the underlying
		// connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()

		select {
		case <-time.After(delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	return resp, err
}

// shouldRetry decides whether a response is worth retrying. 429 is always safe to
// retry (the server rejected the request without processing it). 5xx is retried
// only for idempotent methods; replaying a POST/PATCH risks duplicating work that
// may have already committed before the server errored.
func shouldRetry(method string, statusCode int) bool {
	if statusCode == http.StatusTooManyRequests {
		return true
	}
	if statusCode >= 500 {
		return isIdempotent(method)
	}
	return false
}

func isIdempotent(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// retryDelay honors a Retry-After header when the server provides one (capped at
// maxDelay), otherwise falls back to jittered exponential backoff.
func (t *retryTransport) retryDelay(resp *http.Response, attempt int) time.Duration {
	if d := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); d > 0 {
		if d > t.maxDelay {
			return t.maxDelay
		}
		return d
	}
	return t.backoffDelay(attempt)
}

// parseRetryAfter parses a Retry-After header value, which may be either an
// integer number of seconds or an HTTP-date. Returns 0 if absent/invalid.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := when.Sub(now); d > 0 {
			return d
		}
	}
	return 0
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
