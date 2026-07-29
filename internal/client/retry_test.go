package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// rtFunc adapts a function to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newResp(status int, hdr map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(""))}
}

// fastRetryTransport returns a retryTransport with negligible delays for tests.
func fastRetryTransport(inner http.RoundTripper) *retryTransport {
	return &retryTransport{
		transport:    inner,
		maxRetries:   3,
		initialDelay: time.Millisecond,
		maxDelay:     5 * time.Millisecond,
	}
}

func TestShouldRetry(t *testing.T) {
	cases := []struct {
		method string
		status int
		want   bool
	}{
		{http.MethodGet, 500, true},
		{http.MethodGet, 503, true},
		{http.MethodPut, 500, true},
		{http.MethodDelete, 502, true},
		{http.MethodPost, 500, false},  // non-idempotent: never replay on 5xx
		{http.MethodPatch, 503, false}, // non-idempotent
		{http.MethodPost, 429, true},   // 429 = not processed, safe to retry
		{http.MethodPatch, 429, true},
		{http.MethodGet, 200, false},
		{http.MethodGet, 404, false},
		{http.MethodGet, 400, false},
	}
	for _, c := range cases {
		if got := shouldRetry(c.method, c.status); got != c.want {
			t.Errorf("shouldRetry(%s, %d) = %v, want %v", c.method, c.status, got, c.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"  10  ", 10 * time.Second},
		{"notanumber", 0},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{now.Add(-30 * time.Second).Format(http.TimeFormat), 0}, // past date
	}
	for _, c := range cases {
		if got := parseRetryAfter(c.in, now); got != c.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRetryDelayHonorsRetryAfterCappedAtMax(t *testing.T) {
	tr := fastRetryTransport(nil) // maxDelay 5ms
	resp := newResp(429, map[string]string{"Retry-After": "100"})
	if d := tr.retryDelay(resp, 0); d != tr.maxDelay {
		t.Errorf("retryDelay capped = %v, want %v", d, tr.maxDelay)
	}
	// No header -> falls back to backoff (>0).
	if d := tr.retryDelay(newResp(429, nil), 0); d <= 0 {
		t.Errorf("backoff fallback = %v, want > 0", d)
	}
}

func TestRoundTripRetriesIdempotentOn5xx(t *testing.T) {
	calls := 0
	inner := rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return newResp(500, nil), nil
	})
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	resp, err := fastRetryTransport(inner).RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	if calls != 4 { // 1 initial + 3 retries
		t.Errorf("calls = %d, want 4", calls)
	}
}

func TestRoundTripDoesNotRetryPostOn5xx(t *testing.T) {
	calls := 0
	inner := rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return newResp(503, nil), nil
	})
	req, _ := http.NewRequest(http.MethodPost, "http://x", strings.NewReader("payload"))
	_, err := fastRetryTransport(inner).RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if calls != 1 {
		t.Errorf("POST retried on 5xx: calls = %d, want 1", calls)
	}
}

func TestRoundTripRetriesPostOn429AndReplaysBody(t *testing.T) {
	var bodies []string
	var mu sync.Mutex
	calls := 0
	inner := rtFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		calls++
		c := calls
		mu.Unlock()
		if c < 3 {
			return newResp(429, nil), nil
		}
		return newResp(200, nil), nil
	})
	req, _ := http.NewRequest(http.MethodPost, "http://x", strings.NewReader("payload"))
	resp, err := fastRetryTransport(inner).RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if len(bodies) != 3 {
		t.Fatalf("attempts = %d, want 3", len(bodies))
	}
	for i, b := range bodies {
		if b != "payload" {
			t.Errorf("attempt %d body = %q, want payload (body not replayed)", i, b)
		}
	}
}

func TestRoundTripStopsOnContextCancel(t *testing.T) {
	inner := rtFunc(func(r *http.Request) (*http.Response, error) {
		return newResp(500, nil), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the backoff wait
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://x", nil)
	_, err := fastRetryTransport(inner).RoundTrip(req)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
}
