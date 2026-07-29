package client

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRefreshingHTTPClientFetchesInitialToken(t *testing.T) {
	calls := 0
	hc, err := NewRefreshingHTTPClient("acme.nullify.ai", func() (string, error) {
		calls++
		return "tok", nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if hc == nil || hc.Transport == nil {
		t.Fatal("expected an http client with a transport")
	}
	if calls != 1 {
		t.Errorf("token provider calls = %d, want 1 (initial fetch)", calls)
	}
}

func TestNewRefreshingHTTPClientFailsFastOnTokenError(t *testing.T) {
	_, err := NewRefreshingHTTPClient("acme.nullify.ai", func() (string, error) {
		return "", errors.New("no creds")
	})
	if err == nil {
		t.Fatal("expected error when initial token fetch fails")
	}
}

// stubTransport records the Authorization header on every request.
type stubTransport struct {
	mu    sync.Mutex
	auths []string
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.auths = append(s.auths, req.Header.Get("Authorization"))
	s.mu.Unlock()
	return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
}

// The transport must refresh the bearer token once the cache TTL elapses, so a
// long-running MCP session keeps a valid Authorization header instead of using
// a stale value forever. Without this the PR's whole motivation is undermined.
func TestRefreshingAuthTransportRefreshesAfterTTL(t *testing.T) {
	var calls int32
	provider := func() (string, error) {
		n := atomic.AddInt32(&calls, 1)
		return "tok" + url.QueryEscape(time.Now().Format("150405.000000")) + "_" + url.QueryEscape(string(rune('0'+n))), nil
	}

	initialToken, err := provider()
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	stub := &stubTransport{}
	tr := &refreshingAuthTransport{
		nullifyHost:   "acme.nullify.ai",
		tokenProvider: provider,
		transport:     stub,
		cachedToken:   initialToken,
		cachedAt:      time.Now(),
		cacheTTL:      10 * time.Millisecond,
	}

	req1, _ := http.NewRequest("GET", "https://api.acme.nullify.ai/", nil)
	if _, err := tr.RoundTrip(req1); err != nil {
		t.Fatalf("RoundTrip 1: %v", err)
	}

	// Wait past the TTL so the next call must refresh.
	time.Sleep(25 * time.Millisecond)

	req2, _ := http.NewRequest("GET", "https://api.acme.nullify.ai/", nil)
	if _, err := tr.RoundTrip(req2); err != nil {
		t.Fatalf("RoundTrip 2: %v", err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.auths) != 2 {
		t.Fatalf("got %d requests, want 2", len(stub.auths))
	}
	if stub.auths[0] == stub.auths[1] {
		t.Errorf("token was not refreshed after TTL: %q == %q", stub.auths[0], stub.auths[1])
	}
	// Initial seed token + at least one refresh in tokenProvider.
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("tokenProvider called %d times, want >= 2 (seed + refresh)", calls)
	}
}

// On token-provider failure mid-session the transport must fall back to the
// last good token rather than dropping authentication entirely.
func TestRefreshingAuthTransportFallsBackOnRefreshError(t *testing.T) {
	var providerCalls int32
	failing := func() (string, error) {
		atomic.AddInt32(&providerCalls, 1)
		return "", errors.New("provider down")
	}
	stub := &stubTransport{}
	tr := &refreshingAuthTransport{
		nullifyHost:   "acme.nullify.ai",
		tokenProvider: failing,
		transport:     stub,
		cachedToken:   "good-token",
		cachedAt:      time.Now().Add(-time.Hour),
		cacheTTL:      time.Second,
	}
	req, _ := http.NewRequest("GET", "https://api.acme.nullify.ai/", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.auths) != 1 || stub.auths[0] != "Bearer good-token" {
		t.Errorf("Authorization = %q, want Bearer good-token (fell back to cached)", stub.auths)
	}
	if providerCalls != 1 {
		t.Errorf("tokenProvider calls = %d, want 1", providerCalls)
	}
}
