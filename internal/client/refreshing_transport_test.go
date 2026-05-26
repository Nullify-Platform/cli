package client

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func newRefreshingTransport(initial string, tp TokenProvider, inner http.RoundTripper) *refreshingAuthTransport {
	return &refreshingAuthTransport{
		nullifyHost:   "acme.nullify.ai",
		tokenProvider: tp,
		transport:     inner,
		cachedToken:   initial,
		cachedAt:      time.Now(),
		cacheTTL:      time.Hour, // keep getToken from refreshing on TTL during 401 tests
	}
}

// bearerRouter returns the status mapped to the request's bearer token.
func bearerRouter(byToken map[string]int) (http.RoundTripper, func() int) {
	var mu sync.Mutex
	calls := 0
	rt := rtFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		status, ok := byToken[tok]
		if !ok {
			status = http.StatusUnauthorized
		}
		return newResp(status, nil), nil
	})
	return rt, func() int { mu.Lock(); defer mu.Unlock(); return calls }
}

func TestRefreshOn401RetriesWithNewToken(t *testing.T) {
	refreshCalls := 0
	tp := func() (string, error) { refreshCalls++; return "fresh", nil }
	inner, _ := bearerRouter(map[string]int{"stale": 401, "fresh": 200})
	tr := newRefreshingTransport("stale", tp, inner)

	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200 after refresh", resp.StatusCode)
	}
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1", refreshCalls)
	}
}

func TestNo401MeansNoRefresh(t *testing.T) {
	refreshCalls := 0
	tp := func() (string, error) { refreshCalls++; return "fresh", nil }
	inner, calls := bearerRouter(map[string]int{"good": 200})
	tr := newRefreshingTransport("good", tp, inner)

	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if refreshCalls != 0 {
		t.Errorf("refreshCalls = %d, want 0 (no 401)", refreshCalls)
	}
	if calls() != 1 {
		t.Errorf("inner calls = %d, want 1", calls())
	}
}

func TestRefreshFailureSurfaces401(t *testing.T) {
	tp := func() (string, error) { return "", io.ErrUnexpectedEOF }
	inner, _ := bearerRouter(map[string]int{"stale": 401})
	tr := newRefreshingTransport("stale", tp, inner)

	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401 surfaced when refresh fails", resp.StatusCode)
	}
}

func TestRefreshReplaysBodyOn401(t *testing.T) {
	tp := func() (string, error) { return "fresh", nil }
	var bodies []string
	var mu sync.Mutex
	inner := rtFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if strings.HasSuffix(r.Header.Get("Authorization"), "stale") {
			return newResp(401, nil), nil
		}
		return newResp(200, nil), nil
	})
	tr := newRefreshingTransport("stale", tp, inner)

	req, _ := http.NewRequest(http.MethodPost, "http://x", strings.NewReader("payload"))
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if len(bodies) != 2 {
		t.Fatalf("attempts = %d, want 2", len(bodies))
	}
	if bodies[0] != "payload" || bodies[1] != "payload" {
		t.Errorf("body not replayed across 401 retry: %q", bodies)
	}
}

func TestForceRefreshIsStormSafe(t *testing.T) {
	var refreshCalls int
	var mu sync.Mutex
	tp := func() (string, error) {
		mu.Lock()
		refreshCalls++
		mu.Unlock()
		return "fresh", nil
	}
	inner, _ := bearerRouter(map[string]int{"stale": 401, "fresh": 200})
	tr := newRefreshingTransport("stale", tp, inner)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
			resp, err := tr.RoundTrip(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1 (storm should dedup)", refreshCalls)
	}
}

func TestGetTokenRefreshesOnTTLExpiry(t *testing.T) {
	refreshCalls := 0
	tp := func() (string, error) { refreshCalls++; return "new", nil }
	tr := newRefreshingTransport("old", tp, rtFunc(func(*http.Request) (*http.Response, error) {
		return newResp(200, nil), nil
	}))
	tr.cacheTTL = time.Millisecond
	tr.cachedAt = time.Now().Add(-time.Hour) // expired

	got := tr.getToken(nil)
	if got != "new" {
		t.Errorf("getToken = %q, want new (TTL expired)", got)
	}
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1", refreshCalls)
	}
}
