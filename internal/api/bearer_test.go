package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// bearerRecorder answers every request, redirecting the API host's /to-*
// paths, and records the Authorization each URL received.
type bearerRecorder struct {
	mu   sync.Mutex
	auth map[string]string
}

func (b *bearerRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	b.auth[r.URL.String()] = r.Header.Get("Authorization")
	b.mu.Unlock()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}
	redirects := map[string]string{
		"/to-foreign":  "https://bucket.s3.amazonaws.com/report?X-Amz-Signature=x",
		"/to-same":     "https://api.acme.nullify.ai/landing",
		"/to-plain":    "http://api.acme.nullify.ai/plain",
		"/to-subdomai": "https://evil.api.acme.nullify.ai/sub",
	}
	if loc, ok := redirects[r.URL.Path]; ok && r.URL.Host == "api.acme.nullify.ai" {
		resp.StatusCode = http.StatusFound
		resp.Header.Set("Location", loc)
	}
	return resp, nil
}

// The generated client sends the token only to the API host it was built
// for, over https, and never on a redirect hop: not to another host, not
// over http, and not back to its own host by way of a redirect.
func TestGeneratedClientSendsTheTokenOnlyToItsAPIHost(t *testing.T) {
	rec := &bearerRecorder{auth: map[string]string{}}
	c := NewClient("acme.nullify.ai", "secret", nil)
	c.HTTPClient.Transport = rec

	for _, path := range []string{"/ok", "/to-foreign", "/to-same", "/to-plain", "/to-subdomai"} {
		_, err := c.do(context.Background(), http.MethodGet, c.BaseURL+path, nil)
		require.NoError(t, err, path)
	}
	_, err := c.do(context.Background(), http.MethodGet, "https://api.other.nullify.ai/x", nil)
	require.NoError(t, err)
	_, err = c.do(context.Background(), http.MethodGet, "http://api.acme.nullify.ai/x", nil)
	require.NoError(t, err)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Equal(t, "Bearer secret", rec.auth["https://api.acme.nullify.ai/ok"])
	require.Equal(t, "Bearer secret", rec.auth["https://api.acme.nullify.ai/to-foreign"], "the first hop is the API host")
	for _, url := range []string{
		"https://bucket.s3.amazonaws.com/report?X-Amz-Signature=x",
		"https://api.acme.nullify.ai/landing",
		"http://api.acme.nullify.ai/plain",
		"https://evil.api.acme.nullify.ai/sub",
		"https://api.other.nullify.ai/x",
		"http://api.acme.nullify.ai/x",
	} {
		auth, seen := rec.auth[url]
		require.True(t, seen, url)
		require.Empty(t, auth, url)
	}
}
