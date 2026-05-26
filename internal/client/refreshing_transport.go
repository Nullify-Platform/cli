package client

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nullify-platform/cli/internal/logger"
)

// TokenProvider is a function that returns a valid token.
type TokenProvider func() (string, error)

// refreshingAuthTransport wraps authTransport and refreshes the token proactively.
type refreshingAuthTransport struct {
	nullifyHost   string
	tokenProvider TokenProvider
	transport     http.RoundTripper

	mu          sync.RWMutex
	cachedToken string
	cachedAt    time.Time
	cacheTTL    time.Duration
}

// NewRefreshingHTTPClient returns an *http.Client whose transport injects a
// Nullify bearer token (refreshed on a TTL) and retries transient failures. It
// is suitable for driving the generated api.Client in long-running processes
// like the MCP server, where a token fetched at startup would otherwise expire.
func NewRefreshingHTTPClient(nullifyHost string, tokenProvider TokenProvider) (*http.Client, error) {
	// Fetch an initial token so startup fails fast on auth problems.
	token, err := tokenProvider()
	if err != nil {
		return nil, err
	}

	t := &refreshingAuthTransport{
		nullifyHost:   nullifyHost,
		tokenProvider: tokenProvider,
		transport:     http.DefaultTransport,
		cachedToken:   token,
		cachedAt:      time.Now(),
		cacheTTL:      5 * time.Minute,
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: NewRetryTransport(t),
	}, nil
}

// NewRefreshingNullifyClient creates a NullifyClient that automatically refreshes
// its auth token, suitable for long-running processes like MCP servers.
func NewRefreshingNullifyClient(nullifyHost string, tokenProvider TokenProvider) (*NullifyClient, error) {
	httpClient, err := NewRefreshingHTTPClient(nullifyHost, tokenProvider)
	if err != nil {
		return nil, err
	}

	apiHost := nullifyHost
	if !strings.HasPrefix(nullifyHost, "api.") {
		apiHost = "api." + nullifyHost
	}

	return &NullifyClient{
		Host:       nullifyHost,
		BaseURL:    "https://" + apiHost,
		Token:      "", // Token is managed by the refreshing transport; do not use this field directly.
		HttpClient: httpClient,
	}, nil
}

func (t *refreshingAuthTransport) getToken(ctx context.Context) string {
	t.mu.RLock()
	if time.Since(t.cachedAt) < t.cacheTTL {
		token := t.cachedToken
		t.mu.RUnlock()
		return token
	}
	t.mu.RUnlock()

	// Double-checked locking
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.cachedAt) < t.cacheTTL {
		return t.cachedToken
	}

	newToken, err := t.tokenProvider()
	if err != nil {
		// Fall back to cached token; log so the user can diagnose 401s
		logger.L(ctx).Warn("token refresh failed, using cached token", logger.Err(err))
		return t.cachedToken
	}

	t.cachedToken = newToken
	t.cachedAt = time.Now()
	return t.cachedToken
}

func (t *refreshingAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token := t.getToken(req.Context())

	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("User-Agent", "Nullify-CLI/mcp")
	return t.transport.RoundTrip(r)
}
