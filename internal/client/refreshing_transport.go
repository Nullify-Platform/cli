package client

import (
	"net/http"
	"sync"
	"time"
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

// NewRefreshingNullifyClient creates a NullifyClient that automatically refreshes
// its auth token, suitable for long-running processes like MCP servers.
func NewRefreshingNullifyClient(nullifyHost string, tokenProvider TokenProvider) (*NullifyClient, error) {
	// Get initial token
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

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: NewRetryTransport(t),
	}

	return &NullifyClient{
		Host:       nullifyHost,
		BaseURL:    "https://" + nullifyHost,
		Token:      "", // Token is managed by the refreshing transport; do not use this field directly.
		HttpClient: httpClient,
	}, nil
}

func (t *refreshingAuthTransport) getToken() string {
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
		// Fall back to cached token
		return t.cachedToken
	}

	t.cachedToken = newToken
	t.cachedAt = time.Now()
	return t.cachedToken
}

func (t *refreshingAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token := t.getToken()

	r := req.Clone(req.Context())
	r.URL.Scheme = "https"
	r.URL.Host = t.nullifyHost
	r.Host = t.nullifyHost
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("User-Agent", "Nullify-CLI/mcp")
	return t.transport.RoundTrip(r)
}
