package client

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// originRecorder plays both servers: the API host answers each path from
// redirects (a 302 to that Location) or 200, and every other host answers
// 200. It records the Authorization header each host received.
type originRecorder struct {
	redirects map[string]string
	mu        sync.Mutex
	seen      []seenRequest
}

type seenRequest struct{ url, auth string }

func (o *originRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	o.mu.Lock()
	o.seen = append(o.seen, seenRequest{r.URL.String(), r.Header.Get("Authorization")})
	o.mu.Unlock()
	if r.URL.Host == "api.acme.nullify.ai" {
		if loc, ok := o.redirects[r.URL.Path]; ok {
			resp := newResp(http.StatusFound, map[string]string{"Location": loc})
			resp.Request = r
			return resp, nil
		}
	}
	resp := newResp(http.StatusOK, nil)
	resp.Request = r
	return resp, nil
}

func (o *originRecorder) authFor(url string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, s := range o.seen {
		if s.url == url {
			return s.auth, true
		}
	}
	return "", false
}

func newOriginRecorder() *originRecorder {
	return &originRecorder{redirects: map[string]string{
		"/to-foreign":  "https://bucket.s3.amazonaws.com/report?X-Amz-Signature=x",
		"/to-same":     "https://api.acme.nullify.ai/landing",
		"/to-plain":    "http://api.acme.nullify.ai/plain",
		"/to-userinfo": "https://user:pw@api.acme.nullify.ai/userinfo",
	}}
}

// clients returns one http.Client per transport, wired as the CLI wires
// them: the retry transport over the bearer transport over origin.
func clients(origin http.RoundTripper) map[string]*http.Client {
	static := &authTransport{nullifyHost: "acme.nullify.ai", token: "secret", transport: origin}
	refreshing := &refreshingAuthTransport{
		nullifyHost:     "acme.nullify.ai",
		tokenProvider:   func() (string, error) { return "secret", nil },
		refreshProvider: func() (string, error) { return "refreshed", nil },
		transport:       origin,
		cachedToken:     "secret",
		cachedAt:        time.Now(),
		cacheTTL:        time.Hour,
		failureBackoff:  time.Minute,
	}
	return map[string]*http.Client{
		"authTransport":           {Transport: NewRetryTransport(static)},
		"refreshingAuthTransport": {Transport: NewRetryTransport(refreshing)},
	}
}

func TestBearerGoesOnlyToTheAPIHost(t *testing.T) {
	tests := []struct {
		name     string
		get      string
		seenURL  string
		wantAuth string
	}{
		{"same-host request carries the bearer", "https://api.acme.nullify.ai/findings", "https://api.acme.nullify.ai/findings", "Bearer secret"},
		{"explicit port 443 is the API host", "https://api.acme.nullify.ai:443/findings", "https://api.acme.nullify.ai:443/findings", "Bearer secret"},
		{"redirect to another host carries none", "https://api.acme.nullify.ai/to-foreign", "https://bucket.s3.amazonaws.com/report?X-Amz-Signature=x", ""},
		{"redirect back to the API host carries none", "https://api.acme.nullify.ai/to-same", "https://api.acme.nullify.ai/landing", ""},
		{"downgrade redirect carries none", "https://api.acme.nullify.ai/to-plain", "http://api.acme.nullify.ai/plain", ""},
		{"redirect with userinfo carries none", "https://api.acme.nullify.ai/to-userinfo", "https://user:pw@api.acme.nullify.ai/userinfo", ""},
		{"direct request to another host carries none", "https://bucket.s3.amazonaws.com/upload", "https://bucket.s3.amazonaws.com/upload", ""},
		{"lookalike host carries none", "https://api.acme.nullify.ai.evil.example/x", "https://api.acme.nullify.ai.evil.example/x", ""},
		{"other port carries none", "https://api.acme.nullify.ai:8443/x", "https://api.acme.nullify.ai:8443/x", ""},
		{"plain http carries none", "http://api.acme.nullify.ai/x", "http://api.acme.nullify.ai/x", ""},
	}
	for _, tt := range tests {
		for _, name := range []string{"authTransport", "refreshingAuthTransport"} {
			t.Run(name+"/"+tt.name, func(t *testing.T) {
				origin := newOriginRecorder()
				client := clients(origin)[name]

				req, _ := http.NewRequest(http.MethodGet, tt.get, nil)
				// A caller-set header must not survive off the API host either.
				req.Header.Set("Authorization", "Bearer caller-set")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
				resp.Body.Close()

				auth, ok := origin.authFor(tt.seenURL)
				if !ok {
					t.Fatalf("no request reached %s; saw %v", tt.seenURL, origin.seen)
				}
				if auth != tt.wantAuth {
					t.Errorf("Authorization at %s = %q, want %q", tt.seenURL, auth, tt.wantAuth)
				}
			})
		}
	}
}

// A 401 from a host that never got the bearer says nothing about the token,
// so it must not burn a forced refresh.
func TestRefreshingTransportDoesNotRefreshForForeignHost(t *testing.T) {
	refreshes := 0
	origin := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("bearer sent to %s", r.URL)
		}
		return newResp(http.StatusUnauthorized, nil), nil
	})
	tr := newRefreshingTransportWithRefresher("secret",
		func() (string, error) { return "secret", nil },
		func() (string, error) { refreshes++; return "refreshed", nil },
		origin)

	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.amazonaws.com/x", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want the foreign 401 passed through", resp.StatusCode)
	}
	if refreshes != 0 {
		t.Errorf("refreshes = %d, want 0", refreshes)
	}
}
