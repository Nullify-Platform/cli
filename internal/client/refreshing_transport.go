package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nullify-platform/cli/internal/logger"
)

// TokenProvider is a function that returns a valid token.
type TokenProvider func() (string, error)

// ErrTokenNotRefreshable reports that the active token source yields a fixed
// string, so retrying after a 401 cannot produce a different token.
var ErrTokenNotRefreshable = errors.New("token source cannot be refreshed")

// refreshingAuthTransport wraps authTransport and refreshes the token proactively.
type refreshingAuthTransport struct {
	nullifyHost   string
	tokenProvider TokenProvider
	// refreshProvider mints a genuinely new token, ignoring any cached expiry.
	// Distinct from tokenProvider, which returns the stored token untouched
	// while it still looks valid.
	refreshProvider TokenProvider
	transport       http.RoundTripper

	mu          sync.RWMutex
	cachedToken string
	cachedAt    time.Time
	// providerRetryAfter and refreshRetryAfter are separate clocks because
	// tokenProvider and refreshProvider are separate functions: one failing
	// says nothing about the other.
	providerRetryAfter time.Time
	refreshRetryAfter  time.Time
	cacheTTL           time.Duration
	failureBackoff     time.Duration
}

// NewRefreshingHTTPClient returns an *http.Client whose transport injects a
// Nullify bearer token (refreshed on a TTL) and retries transient failures. It
// is suitable for driving the generated api.Client in long-running processes
// like the MCP server, where a token fetched at startup would otherwise expire.
// refreshProvider is used to recover from a 401 and must bypass any cached
// expiry; passing tokenProvider for both makes the 401 retry a no-op.
func NewRefreshingHTTPClient(nullifyHost string, tokenProvider, refreshProvider TokenProvider) (*http.Client, error) {
	// Fetch an initial token so startup fails fast on auth problems.
	token, err := tokenProvider()
	if err != nil {
		return nil, err
	}

	t := &refreshingAuthTransport{
		nullifyHost:     nullifyHost,
		tokenProvider:   tokenProvider,
		refreshProvider: refreshProvider,
		transport:       http.DefaultTransport,
		cachedToken:     token,
		cachedAt:        time.Now(),
		cacheTTL:        5 * time.Minute,
		failureBackoff:  30 * time.Second,
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: NewRetryTransport(t),
	}, nil
}

// NewRefreshingNullifyClient creates a NullifyClient that automatically refreshes
// its auth token, suitable for long-running processes like MCP servers.
func NewRefreshingNullifyClient(nullifyHost string, tokenProvider, refreshProvider TokenProvider) (*NullifyClient, error) {
	httpClient, err := NewRefreshingHTTPClient(nullifyHost, tokenProvider, refreshProvider)
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

// fresh reports whether the cached token can be served without consulting the
// provider: either it is still within its TTL, or a recent provider failure is
// still inside its backoff window. Callers must hold t.mu.
func (t *refreshingAuthTransport) fresh() bool {
	return time.Since(t.cachedAt) < t.cacheTTL || time.Now().Before(t.providerRetryAfter)
}

func (t *refreshingAuthTransport) getToken(ctx context.Context) string {
	t.mu.RLock()
	if t.fresh() {
		token := t.cachedToken
		t.mu.RUnlock()
		return token
	}
	t.mu.RUnlock()

	// Double-checked locking
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fresh() {
		return t.cachedToken
	}

	newToken, err := t.tokenProvider()
	if err != nil {
		// Fall back to cached token; log so the user can diagnose 401s. Hold
		// off on the next attempt so a persistently failing provider does not
		// put a blocking refresh in front of every single request.
		t.providerRetryAfter = time.Now().Add(t.failureBackoff)
		logger.L(ctx).Warn("token refresh failed, using cached token", logger.Err(err))
		return t.cachedToken
	}

	t.providerRetryAfter = time.Time{}
	t.cachedToken = newToken
	t.cachedAt = time.Now()
	return t.cachedToken
}

// forceRefresh fetches a new token regardless of the cache TTL, returning "" when
// it cannot produce one the caller has not already tried. It is storm-safe: if
// another goroutine already replaced staleToken (e.g. several concurrent requests
// hit a 401 at once), the already-refreshed token is reused instead of fetching
// again. A refresh that makes no progress arms a backoff window, so a session
// whose credentials the server keeps rejecting does not put a blocking refresh in
// front of every request for the rest of its life.
func (t *refreshingAuthTransport) forceRefresh(ctx context.Context, staleToken string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cachedToken != staleToken {
		return t.cachedToken
	}
	if time.Now().Before(t.refreshRetryAfter) {
		return ""
	}

	newToken, err := t.refreshProvider()
	if err != nil {
		t.refreshRetryAfter = time.Now().Add(t.failureBackoff)
		// A fixed token source has nothing to re-fetch, so the 401 is final
		// rather than a failure worth warning about.
		if errors.Is(err, ErrTokenNotRefreshable) {
			logger.L(ctx).Debug("token source cannot be refreshed, surfacing 401")
		} else {
			logger.L(ctx).Warn("forced token refresh failed after 401", logger.Err(err))
		}
		return ""
	}
	// Neither an empty token nor the one the server just rejected is progress.
	// Leave the cache alone rather than replacing a working token with junk or
	// re-fetching the same rejected string on every subsequent request.
	if newToken == "" || newToken == staleToken {
		t.refreshRetryAfter = time.Now().Add(t.failureBackoff)
		logger.L(ctx).Warn("forced token refresh returned no new token, surfacing 401")
		return ""
	}

	t.providerRetryAfter = time.Time{}
	t.refreshRetryAfter = time.Time{}
	t.cachedToken = newToken
	t.cachedAt = time.Now()
	return newToken
}

func (t *refreshingAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Buffer the body so the request can be replayed if the first attempt 401s.
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		bodyBytes = b
	}

	attempt := func(token string) (*http.Response, error) {
		r := req.Clone(req.Context())
		if bodyBytes != nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("User-Agent", "Nullify-CLI/mcp")
		return t.transport.RoundTrip(r)
	}

	token := t.getToken(req.Context())
	resp, err := attempt(token)
	if err != nil {
		return nil, err
	}

	// The cached token can be invalid before its TTL elapses (revocation, server
	// session kill, clock skew). On a 401, force a refresh and retry once before
	// surfacing the failure.
	if resp.StatusCode == http.StatusUnauthorized {
		if newToken := t.forceRefresh(req.Context(), token); newToken != "" && newToken != token {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			return attempt(newToken)
		}
	}

	return resp, nil
}
